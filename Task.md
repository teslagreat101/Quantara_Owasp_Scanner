# Task.md — Quantum Protocol v5.0 Master Implementation Checklist

> **Legend:** ✅ Done · ⚠️ Partial · ❌ Missing/Broken · 🔴 Critical · 🟡 High · 🔵 Medium · ⚪ Low

---

## 1. Subscription & Pricing Tier System

### 1.1 Tier Definitions & Data Models
- [x] ✅ Subscription tiers defined in `backend/database.py` (`FREE`, `PRO`, `Elite`)
- [x] ✅ `SubscriptionTier` and `SubscriptionStatus` enums exist
- [x] ✅ User model has `stripe_customer_id`, `stripe_subscription_id`, `monthly_scan_limit`, `storage_limit_mb`
- [x] ✅ Tier configs in `backend/billing.py` (scan limits: 5 / 50 / 1M, prices: $0/$5/$15)
- [ ] 🔴 `check_subscription_access()` in `backend/auth.py` is a stub — **always returns True** — must enforce actual tier limits
- [ ] 🔴 No scan-count check before scan start in `backend/main.py` `POST /api/v1/scan/start`
- [ ] 🟡 No monthly quota auto-reset job (Firestore only resets manually; SQL `monthly_scan_limit` never decremented/reset)
- [ ] 🔵 Username defaults to email — add display name support

### 1.2 Firebase Firestore Sync (Real-Time User Records)
- [x] ✅ Firestore write on new user registration (`auth.py` → `users/{uid}` `.set()`)
- [x] ✅ Firestore write on Stripe checkout completion (`billing.py` → `users/{uid}` `.update()`)
- [x] ✅ Firestore atomic scan counter increment (`auth.py` → `Increment(1)`)
- [x] ✅ Firestore plan reset in `main.py` line 1141 (`scansUsedThisMonth=0`)
- [ ] 🔴 **Dual-write inconsistency**: SQL DB and Firestore can diverge — no reconciliation — add reconcile function or pick one source of truth
- [ ] 🔴 Firestore rules: `/scans/{scanId}` subcollections rule (`allow read, write: if isSignedIn()`) is too permissive — must check `customer_id == request.auth.uid`
- [ ] 🔴 Firestore plan mapping uses `"elite"` for Enterprise tier in billing.py but `"enterprise"` elsewhere — fix to be consistent
- [ ] 🟡 `users/{uid}` Firestore doc not created when user registers via email/password (only on first API call) — create on register
- [ ] 🟡 No Firestore index on `users` collection (only `scans` indexed) — add composite index
- [ ] 🔵 `billingCycleEnd` in Firestore set to `+30 days from signup` instead of actual Stripe period end — sync from Stripe webhook
- [ ] 🔵 `last_active_at` only updated on scan completion — update on login too

### 1.3 Subscription Tier Enforcement
- [ ] 🔴 **Frontend gate missing**: No check in `/dashboard/scanner` before starting a scan if user has exhausted quota
- [ ] 🔴 **Backend gate missing**: `POST /api/v1/scan/start` doesn't call `check_usage_limits()` before queuing scan
- [ ] 🟡 No tier-based module access restriction (free tier should only access `basic_scan` modules)
- [ ] 🟡 No "Upgrade to scan more" CTA in `/dashboard/scanner` when quota reached
- [ ] 🔵 No storage limit enforcement (storage_limit_mb defined but never checked)
- [ ] ⚪ No usage warning at 80% quota consumption

---

## 2. Stripe Payment Integration

### 2.1 Stripe Configuration
- [x] ✅ `STRIPE_SECRET_KEY` and `STRIPE_PUBLISHABLE_KEY` configured in `.env`
- [x] ✅ `STRIPE_PRO_PRICE_ID` and `STRIPE_ELITE_PRICE_ID` configured
- [ ] 🔴 `STRIPE_WEBHOOK_SECRET` in `.env` is **incomplete** (`whsec` with no value) — must set real webhook secret from Stripe dashboard
- [ ] 🟡 `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` defined in `.env` but unused in frontend — either implement embedded Stripe or remove

### 2.2 Checkout & Subscription Flow
- [x] ✅ `create_checkout_session()` in `billing.py` — creates Stripe Checkout with subscription mode
- [x] ✅ `cancel_subscription()` cancels at period end
- [x] ✅ Checkout success webhook (`checkout.session.completed`) handled — updates SQL + Firestore
- [ ] 🔴 **Missing webhooks**: `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.payment_failed`, `invoice.payment_succeeded` — must handle all for production billing
- [ ] 🟡 `current_period_end` in `get_subscription()` is hardcoded to `datetime.utcnow()` — must read from Stripe API
- [ ] 🟡 No subscription upgrade/downgrade mid-cycle support
- [ ] 🔵 No Stripe Customer Portal link for self-service plan management

### 2.3 Payment Methods & Invoices
- [ ] 🔴 `get_payment_methods()` in `billing.py` returns **empty list always** (stub) — implement via `stripe.PaymentMethod.list(customer_id)`
- [ ] 🔴 `get_invoices()` in `billing.py` returns **empty list always** (stub) — implement via `stripe.Invoice.list(customer=customer_id)`
- [ ] 🟡 Invoice download action in `/billing/page.tsx` only shows toast — implement actual PDF download via Stripe hosted invoice URL
- [ ] 🔵 Add card management UI (set default, remove card)

### 2.4 Admin Billing Dashboard
- [ ] 🔴 `/admin/billing/page.tsx` is a **full placeholder** showing "Treasury Synchronizing" with hardcoded `$0.00` — must implement real revenue data from Stripe
- [ ] 🟡 No MRR/ARR metrics displayed
- [ ] 🟡 No subscription breakdown by tier
- [ ] 🔵 No churn/dunning visibility

---

## 3. Scanner Routing — Smart Target Detection

> The three scanners must be routed based on what the user wants to scan.

### 3.1 Routing Logic (to implement in `scanner_engine/orchestrator.py` or `backend/main.py`)

| Target Type | Scanner to Route To | How to Detect |
|-------------|-------------------|---------------|
| Live web URL (http/https non-GitHub) | `owasp_Scanner` | URL starts with `http(s)://` AND not `github.com` |
| GitHub repo URL | `quantum_protocol` (PQC + code scan) | URL contains `github.com` |
| Local directory path | `code_security_scanner` | `os.path.isdir(target)` |
| Raw code snippet | `code_security_scanner` | `scan_type == "code"` |

- [ ] 🔴 **No routing exists** — all scans currently run the same 16 OWASP modules regardless of target type — implement `detect_scan_target_type(target)` function
- [ ] 🔴 Implement `route_scan(target, scan_type)` in `scanner_engine/orchestrator.py` that dispatches to correct scanner
- [ ] 🔴 `backend/main.py` `execute_scan()` must call router, not hardcode `run_module_scan()`
- [ ] 🟡 Add `target_type` field to `ScanRequest` model for explicit override (`"url"`, `"github"`, `"local"`, `"code"`)
- [ ] 🟡 Frontend `/dashboard/scanner` scan launcher must show different input modes (URL input vs directory path vs GitHub URL)

### 3.2 owasp_Scanner — Live Web Application Scanning
- [x] ✅ Scanner modules exist in `Centralize_Scanners/owasp_Scanner/` (22 .py files)
- [x] ✅ Modules imported into `scanner_engine/orchestrator.py`
- [ ] 🔴 `owasp_Scanner` modules are designed for **file/directory scanning** — they do NOT make HTTP requests to live URLs — need to add HTTP fetching layer (`httpx`/`requests`) that fetches page source, JS files, headers, etc. and feeds content to existing analyzers
- [ ] 🟡 Add HTTP header analysis (security headers, CORS, CSP, HSTS)
- [ ] 🟡 Add endpoint crawling (discover all URLs on target domain)
- [ ] 🔵 Add SSL/TLS analysis for live targets
- [ ] 🔵 `owasp_Scanner/engine.py` — confirm entry point function signature for live URL scan

### 3.3 quantum_protocol — GitHub/Codebase PQC Scanning
- [x] ✅ `quantum_protocol/core/engine.py` `scan_local_directory()` implemented
- [x] ✅ 20 analyzers available with PQC + OWASP coverage
- [x] ✅ CryptoFinding model with HNDL, quantum risk, agility score
- [ ] 🔴 `quantum_protocol` only **partially integrated** into orchestrator (3 of 20 analyzers via conditional import) — integrate all 20 analyzers properly
- [ ] 🔴 No GitHub repo cloning logic — when user provides `github.com/user/repo` URL, must `git clone` to temp dir then scan — implement `clone_and_scan_github_repo(url)`
- [ ] 🟡 `quantum_protocol/cli.py` entry point works but `backend/main.py` doesn't call it for GitHub targets
- [ ] 🟡 `CryptoFinding` → `UnifiedFinding` normalization needed (different data model from owasp_Scanner findings)
- [ ] 🔵 Expose PQC-specific metrics in scan results (quantum_risk_score, crypto_agility_score, HNDL count)

### 3.4 code_security_scanner — Local/GitHub Code Security Scanning
- [x] ✅ `code_security_scanner/scanner.py` `CodeSecurityScanner` class fully implemented
- [x] ✅ Multi-agent pipeline: DiscoveryAgent → VerificationAgent → AssessmentAgent
- [x] ✅ Data flow / taint analysis implemented
- [x] ✅ `ValidatedFinding` model with certainty, patch suggestions, taint flow
- [ ] 🔴 **Completely orphaned** — NOT imported or called anywhere in `scanner_engine/orchestrator.py` or `backend/main.py`
- [ ] 🔴 Must add `code_security_scanner` as a scanner route in orchestrator
- [ ] 🔴 Must normalize `ValidatedFinding` → `UnifiedFinding` format for API response
- [ ] 🟡 `code_security_scanner` also needs GitHub clone support (same as quantum_protocol)
- [ ] 🔵 Expose multi-agent verdict (CONFIRMED/VERIFIED/ASSESSED) and patch suggestions in frontend findings panel

---

## 4. Backend ↔ Scanner Wiring

### 4.1 Celery Scan Worker
- [x] ✅ Celery configured with Redis broker in `backend/scan_worker.py`
- [x] ✅ `execute_scan_job` task exists with retry logic
- [ ] 🔴 `_run_scan()` in `scan_worker.py` is a **stub** — always returns 0 findings — must call `run_module_scan()` or the scan router
- [ ] 🟡 Celery worker (`scan_worker.py`) is **not used** by `main.py` (uses `BackgroundTasks` instead) — either wire Celery or remove it; pick one execution model
- [ ] 🔵 If keeping Celery: ensure `execute_scan_job` publishes findings to Redis/SSE channel during scan, not just at completion

### 4.2 SSE Real-Time Streaming
- [x] ✅ SSE endpoint `/api/v1/scan/{scan_id}/stream` implemented in `main.py`
- [x] ✅ Publishes: `finding`, `log`, `status`, `complete` event types
- [x] ✅ `redis_client.py` `ScanStateManager` with `publish_finding()`, `publish_log()`, `publish_status()`
- [x] ✅ In-memory fallback when Redis unavailable
- [ ] 🟡 SSE reads from **in-memory dict** (`scans[scan_id]["events"]`) not from Redis — if running multiple workers, findings from other workers won't appear — wire SSE to Redis pub/sub for multi-worker support
- [ ] 🔵 No SSE reconnection logic on the frontend (EventSource auto-reconnects but state is lost)

### 4.3 WebSocket Auto-Publishing
- [x] ✅ `WebSocketManager` fully implemented (`backend/websocket_manager.py`)
- [x] ✅ `/ws` endpoint exists in `main.py`
- [x] ✅ `broadcast_scan_update()` method available
- [ ] 🟡 `execute_scan()` in `main.py` does **not call** `ws_manager.broadcast_scan_update()` after normalizing findings — add: `await ws_manager.broadcast_scan_update(scan_id, normalized_finding)` in the finding loop
- [ ] 🔵 WebSocket `subscribe_scan` message type handled but doesn't filter broadcast to only subscribed scans

### 4.4 Orchestrator Module Coverage
- [x] ✅ 16 modules registered in `UNIFIED_MODULE_REGISTRY`
- [x] ✅ 6 scan profiles: `quick`, `standard`, `full`, `owasp-top-10`, `cloud`, `api`
- [x] ✅ `compute_scan_scores()` and `deduplicate_findings()` working
- [ ] 🟡 `quantum_protocol` analyzers only conditionally imported — if import fails, 3 modules silently disabled with warning — make import failure explicit/testable
- [ ] 🟡 `scanner_engine/ssrf_scanner.py` registered as Phase 3 module but verify it handles live URL targets (HTTP requests)

---

## 5. Frontend /dashboard/scanner — Real-Time Telemetry

### 5.1 Scan Configuration Panel
- [x] ✅ `ScanConfigPanel` component exists
- [x] ✅ Module selector, profile selector present
- [ ] 🔴 No **scan type selector** UI — user cannot choose between URL scan / GitHub scan / local code scan — must differentiate input types with clear labels and matching input fields
- [ ] 🔴 No **subscription limit gate** — user can attempt to start scan even if quota exhausted — add preflight check using `useBilling()` hook data
- [ ] 🟡 No GitHub URL validation (ensure entered URL is a valid GitHub repo before sending)
- [ ] 🔵 No estimated scan time display per module/profile

### 5.2 Live Feed & Execution Stream
- [x] ✅ `LiveFeedPanel`, `ExecutionStream`, `PhaseTracker` components exist
- [x] ✅ `useScanner()` hook consumes SSE stream
- [x] ✅ `RealTimeFindingsPanel` receives findings via props and renders them
- [ ] 🟡 **Scanner type indicator** missing — UI should display which scanner is actively running (OWASP Live / Quantum PQC / Code Security)
- [ ] 🟡 No **per-module progress bar** showing which of the 16 modules is currently executing
- [ ] 🔵 No findings count live counter updating in page title or tab badge
- [ ] 🔵 `PhaseTracker` phases should reflect actual scanner phases (not generic labels)

### 5.3 Findings Display
- [x] ✅ `FindingsTable` with paginated results
- [x] ✅ Severity color coding, expandable details
- [x] ✅ Severity filter
- [ ] 🟡 No **scanner source badge** per finding (which scanner detected it: owasp/quantum/code-agent)
- [ ] 🟡 `ValidatedFinding` multi-agent verdict (certainty %, patch suggestion, taint flow) not shown in UI
- [ ] 🟡 PQC-specific finding fields (HNDL flag, quantum risk, migration guidance) not rendered
- [ ] 🔵 No bulk actions on findings (mark as false positive, export selection)
- [ ] 🔵 No finding deduplication indicator in UI

### 5.4 AI Copilot Panel
- [x] ✅ `AISecurityPanel`, `AIInsightSidebar`, `ChatInput` components exist
- [ ] 🟡 Verify AI copilot calls `backend/ai_remediation.py` endpoint — confirm API route exists and is wired
- [ ] 🔵 Ensure AI panel shows PQC migration guidance from `CryptoFinding.migration` field

### 5.5 Dashboard Stats & History
- [x] ✅ `scan-history.tsx`, `scan-charts.tsx` exist
- [x] ✅ `useDashboardStats()` hook used
- [ ] 🟡 `StatsCards` shows `plan`, `scansUsedThisMonth`, `scanLimit` from `useBilling()` — confirm real-time update after scan completes
- [ ] 🔵 No scan history filter by scanner type (OWASP / Quantum / Code)

---

## 6. Scanner File Organization & Placement

### 6.1 Current Correct Locations (Centralize_Scanners/)
- [x] ✅ `Centralize_Scanners/owasp_Scanner/` — OWASP web scanning modules (22 files)
- [x] ✅ `Centralize_Scanners/quantum_protocol/` — PQC + advanced code scanning (30+ files)
- [x] ✅ `Centralize_Scanners/code_security_scanner/` — Multi-agent semantic code analysis (5 files)
- [x] ✅ `Centralize_Scanners/scanner_engine/` — Unified orchestrator and routing layer (4 files)

### 6.2 Import Path Verification
- [x] ✅ `backend/main.py` adds `Centralize_Scanners/` to `sys.path` at startup
- [x] ✅ `scanner_engine.orchestrator` imports from `owasp_Scanner/` (Phase 1 modules)
- [ ] 🔴 `scanner_engine.orchestrator` does **NOT import** from `code_security_scanner/` — add import
- [ ] 🔴 `scanner_engine.orchestrator` imports only 3 of 20 `quantum_protocol/` analyzers — import all 20
- [ ] 🟡 `scan_worker.py` has `sys.path` not set — may fail when running as Celery worker process — add same path setup as `main.py`
- [ ] 🔵 `owasp_Scanner/test_smoke.py` should be moved to `backend/tests/` or a top-level `tests/` folder

### 6.3 Scanner Entry Points (Confirm & Document)

| Scanner | Entry Module | Entry Function | Input | Output |
|---------|-------------|----------------|-------|--------|
| owasp_Scanner | `scanner_engine/orchestrator.py` | `run_module_scan(module_key, target, scan_type)` | file/dir path | list[UnifiedFinding] |
| quantum_protocol | `quantum_protocol/core/engine.py` | `scan_local_directory(path, scan_mode)` | dir path | ScanSummary |
| code_security_scanner | `code_security_scanner/scanner.py` | `CodeSecurityScanner().scan_directory(path)` | dir path | SecurityScanResult |

- [ ] 🟡 Verify all three entry point functions can be called from `backend/main.py` without error (import test)
- [ ] 🟡 Verify `quantum_protocol` `scan_local_directory()` works on a cloned GitHub repo directory
- [ ] 🟡 Verify `CodeSecurityScanner().scan_directory()` returns `SecurityScanResult` with `ValidatedFinding` list

---

## 7. End-to-End Integration Tests

- [ ] 🔴 No integration test for full scan cycle: start → SSE stream → findings in DB → complete
- [ ] 🔴 No test for subscription enforcement (should reject scan if quota exceeded)
- [ ] 🟡 `backend/tests/test_api.py` — run and fix any failing tests
- [ ] 🟡 `backend/tests/test_docker.py` — run and verify Docker stack boots cleanly
- [ ] 🟡 Add test: `POST /api/v1/scan/start` with GitHub URL → verify quantum_protocol router called
- [ ] 🟡 Add test: `POST /api/v1/scan/start` with https:// URL → verify owasp_Scanner router called
- [ ] 🟡 Add test: `POST /api/v1/scan/start` with local path → verify code_security_scanner called
- [ ] 🔵 Add test for Stripe webhook (`checkout.session.completed`) → verify Firestore + SQL updated
- [ ] 🔵 Add test for scan-limit enforcement via subscription tier

---

## 8. Environment & Infrastructure

- [ ] 🔴 `STRIPE_WEBHOOK_SECRET` in `.env` is incomplete — must be set to real `whsec_...` value from Stripe dashboard → Settings → Webhooks
- [ ] 🟡 `.env.template` — verify all required keys are documented with placeholder values
- [ ] 🔵 `docker-compose.yml` — verify Celery worker `PYTHONPATH` includes `Centralize_Scanners/`
- [ ] 🔵 Firestore security rules — update subcollection rule to check `customer_id`
- [ ] ⚪ `secret-scanner-1eb18-firebase-adminsdk-fbsvc-7516bbf2c8.json` committed to repo — should be in `.gitignore` and referenced via env var

---

## Priority Order (Suggested Implementation Sequence)

### Phase A — Core Wiring (Makes scans actually work)
1. Implement smart scanner routing in `scanner_engine/orchestrator.py`
2. Integrate `code_security_scanner` into orchestrator
3. Fully integrate all `quantum_protocol` analyzers
4. Add GitHub clone logic for GitHub URL targets
5. Add HTTP fetch layer to `owasp_Scanner` for live URL targets
6. Fix `scan_worker.py` stub → call real scanner

### Phase B — Real-Time & Frontend
7. Wire WebSocket auto-publish in `execute_scan()`
8. Add scan type selector UI in `/dashboard/scanner`
9. Add subscription limit gate before scan start
10. Show scanner source badge and PQC fields in findings panel

### Phase C — Billing & Subscriptions
11. Implement `check_subscription_access()` enforcement
12. Fix Stripe webhook secret + add missing webhook handlers
13. Implement `get_payment_methods()` and `get_invoices()`
14. Fix Firestore/SQL dual-write consistency
15. Build admin billing dashboard with real Stripe data

### Phase D — Polish & Tests
16. Write integration tests for scan routing
17. Fix Firestore security rules
18. Move Firebase service account key out of repo
19. Fix `.env` STRIPE_WEBHOOK_SECRET
