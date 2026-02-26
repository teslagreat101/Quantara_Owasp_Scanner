"""
Stripe Subscription & Billing Integration
Handles payments, subscriptions, and webhook events.
Updated for direct User-based billing (removed Multi-Tenancy).
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
import uuid

import stripe
from fastapi import HTTPException, Request, status, Depends
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger(__name__)

from backend.database import (
    SubscriptionTier, SubscriptionStatus,
    get_db_session, User
)
from backend.firebase_config import db as firestore_db
from google.cloud import firestore as google_firestore

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "sk_test_...")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_...")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "pk_test_...")

# Price IDs for different tiers
STRIPE_PRICE_IDS = {
    SubscriptionTier.PRO: os.getenv("STRIPE_PRO_PRICE_ID", "price_pro_monthly"),
    SubscriptionTier.ENTERPRISE: os.getenv("STRIPE_ELITE_PRICE_ID", "price_enterprise_monthly"),
}

# Canonical plan name used in Firestore (always "pro" / "elite" / "free")
TIER_TO_PLAN = {
    SubscriptionTier.FREE: "free",
    SubscriptionTier.PRO: "pro",
    SubscriptionTier.ENTERPRISE: "elite",
}

PLAN_LIMITS = {
    "free": 5,
    "pro": 50,
    "elite": 1000000,
}

TIER_CONFIG = {
    SubscriptionTier.FREE: {
        "monthly_scan_limit": 5,
        "max_scan_duration_minutes": 30,
        "storage_limit_mb": 100,
        "features": [
            "5 scans / month",
            "OWASP Top 10 detection",
            "Basic vulnerability reports",
            "Community support",
        ],
        "price_monthly": 0,
        "display_name": "Free",
        "description": "Get started with essential security scanning at no cost.",
    },
    SubscriptionTier.PRO: {
        "monthly_scan_limit": 50,
        "max_scan_duration_minutes": 120,
        "storage_limit_mb": 1000,
        "features": [
            "50 scans / month",
            "Full OWASP Top 10:2025 coverage",
            "AI-powered remediation",
            "Quantara HTTP scanner",
            "Attack chain correlation",
            "Priority email support",
        ],
        "price_monthly": 5,
        "display_name": "Pro",
        "description": "Advanced scanning for professional security teams.",
    },
    SubscriptionTier.ENTERPRISE: {
        "monthly_scan_limit": 1000000,
        "max_scan_duration_minutes": 480,
        "storage_limit_mb": 50000,
        "features": [
            "Unlimited scans",
            "All Pro features",
            "Multi-LLM AI Copilot (Gemini/Claude/GPT)",
            "OAST out-of-band detection",
            "Attack surface crawler",
            "FP reduction pipeline",
            "Dedicated support & SLA",
        ],
        "price_monthly": 15,
        "display_name": "Elite",
        "description": "Enterprise-grade intelligence for security operations centers.",
    },
}

# Initialize Stripe
stripe.api_key = STRIPE_SECRET_KEY

# ═══════════════════════════════════════════════════════════════════════════════
# Customer Management
# ═══════════════════════════════════════════════════════════════════════════════

def create_stripe_customer(user: User) -> str:
    """Create a Stripe customer for a user."""
    try:
        customer = stripe.Customer.create(
            email=user.email,
            name=user.full_name or user.username,
            metadata={
                "user_id": user.id,
                "firebase_uid": user.firebase_uid or "",
            }
        )
        return customer.id
    except stripe.error.StripeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create Stripe customer: {str(e)}"
        )

# ═══════════════════════════════════════════════════════════════════════════════
# Checkout & Subscription Creation
# ═══════════════════════════════════════════════════════════════════════════════

def create_checkout_session(
    user: User,
    tier: SubscriptionTier,
    success_url: str,
    cancel_url: str,
) -> Dict[str, Any]:
    """Create a Stripe checkout session for subscription."""
    if tier == SubscriptionTier.FREE:
        raise HTTPException(status_code=400, detail="Cannot create checkout for free tier")

    price_id = STRIPE_PRICE_IDS.get(tier)
    if not price_id:
        raise HTTPException(status_code=400, detail=f"Price ID not configured for tier {tier.value}")

    try:
        if not user.stripe_customer_id:
            user.stripe_customer_id = create_stripe_customer(user)
            db = get_db_session()
            try:
                db_user = db.query(User).filter(User.id == user.id).first()
                if db_user:
                    db_user.stripe_customer_id = user.stripe_customer_id
                    db.commit()
            finally:
                db.close()

        session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=success_url,
            cancel_url=cancel_url,
            subscription_data={
                "metadata": {
                    "user_id": user.id,
                    "tier": tier.value,
                    "firebase_uid": user.firebase_uid or "",
                }
            },
            metadata={
                "user_id": user.id,
                "tier": tier.value,
                "firebase_uid": user.firebase_uid or "",
            }
        )
        return {"session_id": session.id, "url": session.url}
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Stripe Error: {str(e)}")

# ═══════════════════════════════════════════════════════════════════════════════
# Tier Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _apply_tier_limits(user: User):
    """Apply limits based on tier."""
    config = TIER_CONFIG.get(user.subscription_tier, TIER_CONFIG[SubscriptionTier.FREE])
    user.monthly_scan_limit = config["monthly_scan_limit"]
    user.storage_limit_mb = config["storage_limit_mb"]


def _sync_firestore_subscription(
    firebase_uid: str,
    plan_name: str,
    customer_id: str,
    subscription_id: str,
    subscription_status: str,
):
    """Push subscription state to Firestore so the frontend stays in sync."""
    if not firebase_uid:
        return
    try:
        limit = PLAN_LIMITS.get(plan_name, 5)
        user_ref = firestore_db.collection("users").document(firebase_uid)
        user_ref.set(
            {
                "plan": plan_name,
                "stripeCustomerId": customer_id,
                "stripeSubscriptionId": subscription_id,
                "subscriptionStatus": subscription_status,
                "scanLimit": limit,
                "updated_at": google_firestore.SERVER_TIMESTAMP,
            },
            merge=True,
        )
    except Exception as e:
        logger.warning(f"Firestore sync error: {e}")


def _tier_from_stripe_subscription(subscription) -> SubscriptionTier:
    """Derive our tier from the Stripe subscription's price ID."""
    items = subscription.get("items", {}).get("data", [])
    if items:
        price_id = items[0].get("price", {}).get("id", "")
        if price_id == STRIPE_PRICE_IDS.get(SubscriptionTier.ENTERPRISE):
            return SubscriptionTier.ENTERPRISE
        if price_id == STRIPE_PRICE_IDS.get(SubscriptionTier.PRO):
            return SubscriptionTier.PRO
    # Fallback: check metadata
    meta_tier = subscription.get("metadata", {}).get("tier", "")
    try:
        return SubscriptionTier(meta_tier)
    except ValueError:
        return SubscriptionTier.FREE


# ═══════════════════════════════════════════════════════════════════════════════
# Webhook Handlers
# ═══════════════════════════════════════════════════════════════════════════════

def _handle_checkout_completed(data: Dict, db: Session):
    """Handle checkout.session.completed."""
    user_id = data.get("metadata", {}).get("user_id")
    tier_val = data.get("metadata", {}).get("tier")
    firebase_uid = data.get("metadata", {}).get("firebase_uid", "")

    if not user_id:
        return

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return

    subscription_id = data.get("subscription", "")
    customer_id = data.get("customer", "")

    if subscription_id:
        user.stripe_subscription_id = subscription_id
        user.stripe_customer_id = customer_id or user.stripe_customer_id
        user.subscription_status = SubscriptionStatus.ACTIVE
        if tier_val:
            try:
                user.subscription_tier = SubscriptionTier(tier_val)
            except ValueError:
                pass
        _apply_tier_limits(user)
        db.commit()

    plan_name = TIER_TO_PLAN.get(user.subscription_tier, "free")
    _sync_firestore_subscription(firebase_uid, plan_name, customer_id, subscription_id, "active")


def _handle_subscription_updated(data: Dict, db: Session):
    """Handle customer.subscription.updated."""
    subscription_id = data.get("id", "")
    customer_id = data.get("customer", "")
    stripe_status = data.get("status", "active")

    # Derive cancel-at-period-end state
    cancel_at_end = data.get("cancel_at_period_end", False)

    user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
    if not user:
        # Try by customer_id
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
    if not user:
        return

    # Map Stripe status to internal status
    status_map = {
        "active": SubscriptionStatus.ACTIVE,
        "past_due": SubscriptionStatus.PAST_DUE,
        "canceled": SubscriptionStatus.CANCELLED,
        "unpaid": SubscriptionStatus.PAST_DUE,
        "trialing": SubscriptionStatus.ACTIVE,
        "incomplete": SubscriptionStatus.PAST_DUE,
    }
    user.subscription_status = status_map.get(stripe_status, SubscriptionStatus.ACTIVE)

    # Update tier from new price
    new_tier = _tier_from_stripe_subscription(data)
    user.subscription_tier = new_tier
    _apply_tier_limits(user)
    db.commit()

    plan_name = TIER_TO_PLAN.get(new_tier, "free")
    internal_status = "cancelled" if cancel_at_end else stripe_status
    _sync_firestore_subscription(
        user.firebase_uid or "",
        plan_name,
        customer_id,
        subscription_id,
        internal_status,
    )


def _handle_subscription_deleted(data: Dict, db: Session):
    """Handle customer.subscription.deleted (hard cancel)."""
    subscription_id = data.get("id", "")
    customer_id = data.get("customer", "")

    user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
    if not user:
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
    if not user:
        return

    user.subscription_status = SubscriptionStatus.CANCELLED
    user.subscription_tier = SubscriptionTier.FREE
    _apply_tier_limits(user)
    db.commit()

    _sync_firestore_subscription(
        user.firebase_uid or "",
        "free",
        customer_id,
        subscription_id,
        "cancelled",
    )


def _handle_invoice_payment_succeeded(data: Dict, db: Session):
    """Handle invoice.payment_succeeded — keep subscription active."""
    subscription_id = data.get("subscription", "")
    customer_id = data.get("customer", "")

    if not subscription_id:
        return

    user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
    if not user:
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
    if not user:
        return

    user.subscription_status = SubscriptionStatus.ACTIVE
    db.commit()

    plan_name = TIER_TO_PLAN.get(user.subscription_tier, "free")
    _sync_firestore_subscription(
        user.firebase_uid or "",
        plan_name,
        customer_id,
        subscription_id,
        "active",
    )


def _handle_invoice_payment_failed(data: Dict, db: Session):
    """Handle invoice.payment_failed — mark past_due."""
    subscription_id = data.get("subscription", "")
    customer_id = data.get("customer", "")

    if not subscription_id:
        return

    user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()
    if not user:
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
    if not user:
        return

    user.subscription_status = SubscriptionStatus.PAST_DUE
    db.commit()

    _sync_firestore_subscription(
        user.firebase_uid or "",
        TIER_TO_PLAN.get(user.subscription_tier, "free"),
        customer_id,
        subscription_id,
        "past_due",
    )


def handle_stripe_webhook(payload: bytes, signature: str, db: Session) -> bool:
    """Route Stripe webhooks to the correct handler."""
    try:
        event = stripe.Webhook.construct_event(payload, signature, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    event_type = event["type"]
    data = event["data"]["object"]

    handlers = {
        "checkout.session.completed": _handle_checkout_completed,
        "customer.subscription.updated": _handle_subscription_updated,
        "customer.subscription.deleted": _handle_subscription_deleted,
        "invoice.payment_succeeded": _handle_invoice_payment_succeeded,
        "invoice.payment_failed": _handle_invoice_payment_failed,
    }

    handler = handlers.get(event_type)
    if handler:
        handler(data, db)
        return True

    return False

# ═══════════════════════════════════════════════════════════════════════════════
# Billing Service
# ═══════════════════════════════════════════════════════════════════════════════

class BillingService:
    @staticmethod
    def get_plans():
        """Return plans in the format expected by the frontend."""
        plans = []
        for tier, config in TIER_CONFIG.items():
            price = config["price_monthly"]
            price_str = "Free" if price == 0 else f"${price}"
            plans.append({
                "id": TIER_TO_PLAN.get(tier, tier.value),  # "free" / "pro" / "elite"
                "name": config.get("display_name", tier.value.capitalize()),
                "description": config.get("description", ""),
                "price_cents": price * 100,
                "price_formatted": price_str,
                "interval": "month",
                "features": config["features"],
                "popular": tier == SubscriptionTier.PRO,
                "scan_limit": config["monthly_scan_limit"],
            })
        return plans

    @staticmethod
    def create_billing_portal_session(user_id: str, return_url: str) -> Dict[str, Any]:
        """Create a Stripe Customer Portal session so the user can manage
        their payment methods, invoices, and subscription from Stripe's UI."""
        db_sql = get_db_session()
        try:
            user = db_sql.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            if not user.stripe_customer_id:
                raise HTTPException(
                    status_code=400,
                    detail="No Stripe customer associated with this account. Subscribe to a plan first."
                )
            try:
                session = stripe.billing_portal.Session.create(
                    customer=user.stripe_customer_id,
                    return_url=return_url,
                )
                return {"url": session.url}
            except stripe.error.StripeError as e:
                raise HTTPException(status_code=400, detail=str(e))
        finally:
            db_sql.close()

    @staticmethod
    def get_subscription(user_id: str) -> Dict[str, Any]:
        """Get full subscription status including usage."""
        db_sql = get_db_session()
        try:
            user = db_sql.query(User).filter(User.id == user_id).first()
            if not user:
                return {"status": "none", "tier": "free", "scans_used": 0, "scans_limit": 5}

            plan_name = TIER_TO_PLAN.get(user.subscription_tier, "free")
            scans_used = 0
            scans_limit = user.monthly_scan_limit or PLAN_LIMITS.get(plan_name, 5)
            current_period_end = None

            # Pull accurate period_end from Stripe when available
            if user.stripe_subscription_id:
                try:
                    stripe_sub = stripe.Subscription.retrieve(user.stripe_subscription_id)
                    period_end_ts = stripe_sub.get("current_period_end")
                    if period_end_ts:
                        current_period_end = datetime.fromtimestamp(period_end_ts, tz=timezone.utc).isoformat()
                except Exception as e:
                    logger.warning(f"Stripe subscription retrieve error: {e}")

            if current_period_end is None:
                current_period_end = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

            # Enrich with Firestore usage
            if user.firebase_uid:
                try:
                    user_ref = firestore_db.collection("users").document(user.firebase_uid)
                    doc = user_ref.get()
                    if doc.exists:
                        data = doc.to_dict()
                        scans_used = data.get("scansUsedThisMonth", 0)
                        scans_limit = data.get("scanLimit", scans_limit)
                except Exception as e:
                    logger.warning(f"Firestore error in get_subscription: {e}")

            return {
                "id": user.stripe_subscription_id or f"sub_local_{user.id[:8]}",
                "status": user.subscription_status.value,
                "tier": user.subscription_tier.value,
                "plan_name": plan_name,
                "scans_used": scans_used,
                "scans_limit": scans_limit,
                "current_period_end": current_period_end,
                "cancel_at_period_end": False,
            }
        finally:
            db_sql.close()

    @staticmethod
    def create_checkout_session(user_id: str, plan_id: str, success_url: str, cancel_url: str) -> Dict[str, Any]:
        db = get_db_session()
        try:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise ValueError("User not found")

            tier = SubscriptionTier.FREE
            if plan_id == "pro":
                tier = SubscriptionTier.PRO
            elif plan_id in ["elite", "enterprise"]:
                tier = SubscriptionTier.ENTERPRISE

            return create_checkout_session(user, tier, success_url, cancel_url)
        finally:
            db.close()

    @staticmethod
    def get_payment_methods(user_id: str) -> List[Dict]:
        """Retrieve saved payment methods from Stripe."""
        db_sql = get_db_session()
        try:
            user = db_sql.query(User).filter(User.id == user_id).first()
            if not user or not user.stripe_customer_id:
                return []
            try:
                result = stripe.PaymentMethod.list(
                    customer=user.stripe_customer_id,
                    type="card",
                )
                methods = []
                for pm in result.data:
                    card = pm.get("card", {})
                    methods.append({
                        "id": pm["id"],
                        "brand": card.get("brand", "unknown"),
                        "last4": card.get("last4", "****"),
                        "exp_month": card.get("exp_month"),
                        "exp_year": card.get("exp_year"),
                        "is_default": False,  # updated below
                    })

                # Mark default payment method
                if user.stripe_subscription_id:
                    try:
                        sub = stripe.Subscription.retrieve(user.stripe_subscription_id)
                        default_pm = sub.get("default_payment_method") or ""
                        for m in methods:
                            if m["id"] == default_pm:
                                m["is_default"] = True
                    except Exception:
                        pass

                return methods
            except stripe.error.StripeError as e:
                logger.warning(f"Stripe get_payment_methods error: {e}")
                return []
        finally:
            db_sql.close()

    @staticmethod
    def get_invoices(user_id: str) -> List[Dict]:
        """Retrieve invoices from Stripe."""
        db_sql = get_db_session()
        try:
            user = db_sql.query(User).filter(User.id == user_id).first()
            if not user or not user.stripe_customer_id:
                return []
            try:
                result = stripe.Invoice.list(
                    customer=user.stripe_customer_id,
                    limit=24,
                )
                invoices = []
                for inv in result.data:
                    invoices.append({
                        "id": inv["id"],
                        "number": inv.get("number", ""),
                        "amount_paid": inv.get("amount_paid", 0),
                        "amount_due": inv.get("amount_due", 0),
                        "currency": inv.get("currency", "usd"),
                        "status": inv.get("status", ""),
                        "period_start": datetime.fromtimestamp(inv["period_start"], tz=timezone.utc).isoformat() if inv.get("period_start") else None,
                        "period_end": datetime.fromtimestamp(inv["period_end"], tz=timezone.utc).isoformat() if inv.get("period_end") else None,
                        "hosted_invoice_url": inv.get("hosted_invoice_url", ""),
                        "invoice_pdf": inv.get("invoice_pdf", ""),
                    })
                return invoices
            except stripe.error.StripeError as e:
                logger.warning(f"Stripe get_invoices error: {e}")
                return []
        finally:
            db_sql.close()

    @staticmethod
    def get_usage(user_id: str) -> Dict:
        """Get actual usage statistics from Firestore."""
        db_sql = get_db_session()
        try:
            user = db_sql.query(User).filter(User.id == user_id).first()
            if not user:
                return {"scans_this_month": 0, "storage_used_mb": 0}

            if user.firebase_uid:
                try:
                    user_ref = firestore_db.collection("users").document(user.firebase_uid)
                    doc = user_ref.get()
                    if doc.exists:
                        data = doc.to_dict()
                        return {
                            "scans_this_month": data.get("scansUsedThisMonth", 0),
                            "scan_limit": data.get("scanLimit", 5),
                            "storage_used_mb": 0,
                            "plan": data.get("plan", "free"),
                        }
                except Exception as e:
                    logger.error(f"Error fetching Firestore usage: {e}")

            return {"scans_this_month": 0, "storage_used_mb": 0, "plan": "free"}
        finally:
            db_sql.close()

    @staticmethod
    def cancel_subscription(user_id: str) -> bool:
        """Cancel subscription in Stripe at period end."""
        db_sql = get_db_session()
        try:
            user = db_sql.query(User).filter(User.id == user_id).first()
            if not user or not user.stripe_subscription_id:
                return False

            try:
                stripe.Subscription.modify(
                    user.stripe_subscription_id,
                    cancel_at_period_end=True,
                )
                user.subscription_status = SubscriptionStatus.CANCELLED
                db_sql.commit()

                if user.firebase_uid:
                    user_ref = firestore_db.collection("users").document(user.firebase_uid)
                    user_ref.update({"subscriptionStatus": "cancelled"})

                return True
            except Exception as e:
                logger.error(f"Stripe cancel error: {e}")
                return False
        finally:
            db_sql.close()

    @staticmethod
    def handle_webhook(payload: bytes, signature: str) -> bool:
        db = get_db_session()
        try:
            return handle_stripe_webhook(payload, signature, db)
        finally:
            db.close()

    # ── Admin helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def get_admin_revenue_summary() -> Dict[str, Any]:
        """Fetch revenue data from Stripe for the admin dashboard."""
        try:
            # MRR: sum of active subscription amounts
            subscriptions = stripe.Subscription.list(status="active", limit=100)
            mrr_cents = 0
            for sub in subscriptions.auto_paging_iter():
                for item in sub.get("items", {}).get("data", []):
                    price = item.get("price", {})
                    unit_amount = price.get("unit_amount", 0) or 0
                    interval = price.get("recurring", {}).get("interval", "month")
                    if interval == "year":
                        unit_amount = unit_amount // 12
                    mrr_cents += unit_amount

            # Recent charges (last 30 days)
            since_ts = int((datetime.now(timezone.utc) - timedelta(days=30)).timestamp())
            charges = stripe.Charge.list(created={"gte": since_ts}, limit=100)
            revenue_30d = sum(c.get("amount", 0) for c in charges.auto_paging_iter() if c.get("paid"))

            return {
                "mrr_cents": mrr_cents,
                "mrr_formatted": f"${mrr_cents / 100:,.2f}",
                "revenue_30d_cents": revenue_30d,
                "revenue_30d_formatted": f"${revenue_30d / 100:,.2f}",
                "active_subscriptions": subscriptions.total_count if hasattr(subscriptions, "total_count") else len(list(subscriptions.auto_paging_iter())),
            }
        except stripe.error.StripeError as e:
            logger.error(f"Stripe admin summary error: {e}")
            return {
                "mrr_cents": 0,
                "mrr_formatted": "$0.00",
                "revenue_30d_cents": 0,
                "revenue_30d_formatted": "$0.00",
                "active_subscriptions": 0,
                "error": str(e),
            }


# Singleton instance
billing_service = BillingService()

# Compatibility aliasing
get_subscription = BillingService.get_subscription
