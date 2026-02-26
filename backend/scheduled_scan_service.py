"""
Quantum Protocol v5.0 — Scheduled Scan Service
Cron-based scan scheduling with Celery Beat.

Phase 8.6: Scheduled & Recurring Scans
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class ScheduleFrequency(Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


@dataclass
class ScheduledScan:
    id: str
    name: str
    target: str
    modules: List[str]
    scan_profile: str
    frequency: str  # daily, weekly, monthly
    schedule_time: str  # HH:MM format
    day_of_week: Optional[int] = None  # 0-6 for weekly (Monday=0)
    day_of_month: Optional[int] = None  # 1-31 for monthly
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    is_active: bool = True
    created_at: str = None
    notify_email: Optional[str] = None


class ScheduledScanService:
    """Service for managing scheduled scans."""

    def __init__(self):
        # In-memory storage - would use database in production
        self._schedules: Dict[str, ScheduledScan] = {}

    def create_schedule(
        self,
        name: str,
        target: str,
        modules: List[str],
        frequency: str,
        schedule_time: str,
        scan_profile: str = "full",
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
        notify_email: Optional[str] = None
    ) -> ScheduledScan:
        """Create a new scheduled scan."""
        import uuid
        
        schedule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        # Calculate next run
        next_run = self._calculate_next_run(frequency, schedule_time, day_of_week, day_of_month)
        
        schedule = ScheduledScan(
            id=schedule_id,
            name=name,
            target=target,
            modules=modules,
            scan_profile=scan_profile,
            frequency=frequency,
            schedule_time=schedule_time,
            day_of_week=day_of_week,
            day_of_month=day_of_month,
            next_run=next_run.isoformat() if next_run else None,
            is_active=True,
            created_at=now,
            notify_email=notify_email
        )
        
        self._schedules[schedule_id] = schedule
        return schedule

    def _calculate_next_run(
        self,
        frequency: str,
        schedule_time: str,
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None
    ) -> Optional[datetime]:
        """Calculate the next run time for a schedule."""
        now = datetime.now(timezone.utc)
        hour, minute = map(int, schedule_time.split(":"))
        
        if frequency == "daily":
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run
        
        elif frequency == "weekly" and day_of_week is not None:
            # Find next occurrence of this day of week
            days_ahead = day_of_week - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            next_run = now + timedelta(days=days_ahead)
            next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
            return next_run
        
        elif frequency == "monthly" and day_of_month is not None:
            # Simple monthly scheduling
            if now.day < day_of_month:
                next_run = now.replace(day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0)
            else:
                # Next month
                if now.month == 12:
                    next_run = now.replace(year=now.year + 1, month=1, day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0)
                else:
                    next_run = now.replace(month=now.month + 1, day=day_of_month, hour=hour, minute=minute, second=0, microsecond=0)
            return next_run
        
        return None

    def list_schedules(self, user_id: str = "current") -> List[ScheduledScan]:
        """List all scheduled scans for a user."""
        return [s for s in self._schedules.values() if s.is_active]

    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        """Get a specific schedule."""
        return self._schedules.get(schedule_id)

    def update_schedule(self, schedule_id: str, **updates) -> Optional[ScheduledScan]:
        """Update a scheduled scan."""
        if schedule_id not in self._schedules:
            return None
        
        schedule = self._schedules[schedule_id]
        for key, value in updates.items():
            if hasattr(schedule, key):
                setattr(schedule, key, value)
        
        # Recalculate next run if schedule changed
        if any(k in updates for k in ["frequency", "schedule_time", "day_of_week", "day_of_month"]):
            schedule.next_run = self._calculate_next_run(
                schedule.frequency, schedule.schedule_time,
                schedule.day_of_week, schedule.day_of_month
            ).isoformat() if self._calculate_next_run(schedule.frequency, schedule.schedule_time,
                schedule.day_of_week, schedule.day_of_month) else None
        
        return schedule

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete (deactivate) a scheduled scan."""
        if schedule_id not in self._schedules:
            return False
        
        self._schedules[schedule_id].is_active = False
        return True

    def get_due_schedules(self) -> List[ScheduledScan]:
        """Get all schedules that are due to run."""
        now = datetime.now(timezone.utc)
        due = []
        
        for schedule in self._schedules.values():
            if not schedule.is_active:
                continue
            
            if schedule.next_run:
                next_run = datetime.fromisoformat(schedule.next_run.replace('Z', '+00:00'))
                if next_run <= now:
                    due.append(schedule)
        
        return due

    def mark_schedule_run(self, schedule_id: str):
        """Mark a schedule as having run and update next_run."""
        if schedule_id not in self._schedules:
            return
        
        schedule = self._schedules[schedule_id]
        schedule.last_run = datetime.now(timezone.utc).isoformat()
        
        # Calculate next run
        next_run = self._calculate_next_run(
            schedule.frequency, schedule.schedule_time,
            schedule.day_of_week, schedule.day_of_month
        )
        schedule.next_run = next_run.isoformat() if next_run else None


class ScanComparisonService:
    """Service for comparing scan results."""

    @staticmethod
    def compare_scans(scan1_findings: List[dict], scan2_findings: List[dict]) -> dict:
        """Compare two scans and identify new, fixed, and persistent findings."""
        
        # Create lookup by finding hash
        scan1_by_hash = {ScanComparisonService._finding_hash(f): f for f in scan1_findings}
        scan2_by_hash = {ScanComparisonService._finding_hash(f): f for f in scan2_findings}
        
        scan1_hashes = set(scan1_by_hash.keys())
        scan2_hashes = set(scan2_by_hash.keys())
        
        # Find differences
        new_findings = [scan2_by_hash[h] for h in (scan2_hashes - scan1_hashes)]
        fixed_findings = [scan1_by_hash[h] for h in (scan1_hashes - scan2_hashes)]
        persistent_findings = [scan2_by_hash[h] for h in (scan1_hashes & scan2_hashes)]
        
        return {
            "new_findings": new_findings,
            "fixed_findings": fixed_findings,
            "persistent_findings": persistent_findings,
            "regression_detected": len(new_findings) > 0,
            "summary": {
                "previous_total": len(scan1_findings),
                "current_total": len(scan2_findings),
                "new": len(new_findings),
                "fixed": len(fixed_findings),
                "persistent": len(persistent_findings)
            }
        }

    @staticmethod
    def _finding_hash(finding: dict) -> str:
        """Generate a hash for a finding for comparison."""
        import hashlib
        # Hash based on file, line, and title for uniqueness
        content = f"{finding.get('file')}:{finding.get('line_number')}:{finding.get('title')}"
        return hashlib.md5(content.encode()).hexdigest()[:12]


# Singleton instances
scheduled_scan_service = ScheduledScanService()
scan_comparison_service = ScanComparisonService()
