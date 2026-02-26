"""
Quantum Protocol v5.0 — Team Collaboration Service
Finding assignment, workflow, and team features.

Phase 8.7: Team Collaboration
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import uuid


class FindingStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    VERIFIED = "verified"
    WONT_FIX = "wont_fix"
    FALSE_POSITIVE = "false_positive"


class UserRole(Enum):
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    DEVELOPER = "developer"
    VIEWER = "viewer"


@dataclass
class FindingComment:
    id: str
    finding_id: str
    user_id: str
    user_name: str
    content: str
    created_at: str
    updated_at: Optional[str] = None


@dataclass
class TeamFinding:
    finding_id: str
    scan_id: str
    status: str
    assigned_to: Optional[str] = None
    assigned_by: Optional[str] = None
    assigned_at: Optional[str] = None
    comments: List[FindingComment] = field(default_factory=list)
    status_history: List[dict] = field(default_factory=list)
    created_at: str = None
    updated_at: Optional[str] = None


@dataclass
class TeamMember:
    user_id: str
    name: str
    email: str
    role: str
    joined_at: str
    last_active: Optional[str] = None


class TeamCollaborationService:
    """Service for team collaboration on security findings."""

    def __init__(self):
        self._findings: Dict[str, TeamFinding] = {}
        self._team_members: Dict[str, TeamMember] = {}
        self._activity_feed: List[dict] = []

    def assign_finding(self, finding_id: str, scan_id: str, assigned_to: str, assigned_by: str) -> TeamFinding:
        """Assign a finding to a team member."""
        key = f"{scan_id}:{finding_id}"
        
        if key not in self._findings:
            self._findings[key] = TeamFinding(
                finding_id=finding_id,
                scan_id=scan_id,
                status=FindingStatus.OPEN.value,
                created_at=datetime.now(timezone.utc).isoformat()
            )
        
        finding = self._findings[key]
        finding.assigned_to = assigned_to
        finding.assigned_by = assigned_by
        finding.assigned_at = datetime.now(timezone.utc).isoformat()
        finding.updated_at = datetime.now(timezone.utc).isoformat()
        
        # Log status change
        finding.status_history.append({
            "status": "assigned",
            "from": None,
            "to": assigned_to,
            "by": assigned_by,
            "at": finding.assigned_at
        })
        
        # Add to activity feed
        self._add_activity(
            type="finding_assigned",
            finding_id=finding_id,
            scan_id=scan_id,
            user_id=assigned_by,
            details={"assigned_to": assigned_to}
        )
        
        return finding

    def update_finding_status(
        self,
        finding_id: str,
        scan_id: str,
        new_status: str,
        updated_by: str,
        comment: Optional[str] = None
    ) -> TeamFinding:
        """Update the status of a finding."""
        key = f"{scan_id}:{finding_id}"
        
        if key not in self._findings:
            raise ValueError(f"Finding not found: {finding_id}")
        
        finding = self._findings[key]
        old_status = finding.status
        finding.status = new_status
        finding.updated_at = datetime.now(timezone.utc).isoformat()
        
        # Log status change
        finding.status_history.append({
            "from": old_status,
            "to": new_status,
            "by": updated_by,
            "at": finding.updated_at,
            "comment": comment
        })
        
        # Add to activity feed
        self._add_activity(
            type="status_changed",
            finding_id=finding_id,
            scan_id=scan_id,
            user_id=updated_by,
            details={
                "from_status": old_status,
                "to_status": new_status,
                "comment": comment
            }
        )
        
        return finding

    def add_comment(self, finding_id: str, scan_id: str, user_id: str, user_name: str, content: str) -> FindingComment:
        """Add a comment to a finding."""
        key = f"{scan_id}:{finding_id}"
        
        if key not in self._findings:
            # Auto-create finding entry
            self._findings[key] = TeamFinding(
                finding_id=finding_id,
                scan_id=scan_id,
                status=FindingStatus.OPEN.value,
                created_at=datetime.now(timezone.utc).isoformat()
            )
        
        comment = FindingComment(
            id=str(uuid.uuid4()),
            finding_id=finding_id,
            user_id=user_id,
            user_name=user_name,
            content=content,
            created_at=datetime.now(timezone.utc).isoformat()
        )
        
        self._findings[key].comments.append(comment)
        self._findings[key].updated_at = comment.created_at
        
        # Add to activity feed
        self._add_activity(
            type="comment_added",
            finding_id=finding_id,
            scan_id=scan_id,
            user_id=user_id,
            details={"comment_preview": content[:100]}
        )
        
        return comment

    def get_finding_details(self, finding_id: str, scan_id: str) -> Optional[TeamFinding]:
        """Get full details of a finding including comments and history."""
        key = f"{scan_id}:{finding_id}"
        return self._findings.get(key)

    def get_team_findings(self, scan_id: Optional[str] = None, status: Optional[str] = None) -> List[TeamFinding]:
        """Get team findings with optional filters."""
        findings = list(self._findings.values())
        
        if scan_id:
            findings = [f for f in findings if f.scan_id == scan_id]
        
        if status:
            findings = [f for f in findings if f.status == status]
        
        return findings

    def add_team_member(self, user_id: str, name: str, email: str, role: str) -> TeamMember:
        """Add a team member."""
        member = TeamMember(
            user_id=user_id,
            name=name,
            email=email,
            role=role,
            joined_at=datetime.now(timezone.utc).isoformat()
        )
        
        self._team_members[user_id] = member
        
        self._add_activity(
            type="member_joined",
            user_id=user_id,
            details={"name": name, "role": role}
        )
        
        return member

    def get_team_members(self) -> List[TeamMember]:
        """Get all team members."""
        return list(self._team_members.values())

    def get_activity_feed(self, limit: int = 50) -> List[dict]:
        """Get team activity feed."""
        return sorted(
            self._activity_feed,
            key=lambda x: x["timestamp"],
            reverse=True
        )[:limit]

    def _add_activity(self, type: str, user_id: Optional[str] = None, finding_id: Optional[str] = None,
                     scan_id: Optional[str] = None, details: Optional[dict] = None):
        """Add an activity to the feed."""
        activity = {
            "id": str(uuid.uuid4()),
            "type": type,
            "user_id": user_id,
            "finding_id": finding_id,
            "scan_id": scan_id,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        self._activity_feed.append(activity)
        
        # Keep only last 1000 activities
        if len(self._activity_feed) > 1000:
            self._activity_feed = self._activity_feed[-1000:]


class RBACService:
    """Role-Based Access Control for scans and projects."""

    PERMISSIONS = {
        UserRole.ADMIN: ["*"],  # All permissions
        UserRole.SECURITY_ENGINEER: [
            "scan:create", "scan:read", "scan:update", "scan:delete",
            "finding:read", "finding:update", "finding:assign",
            "report:read", "report:generate", "setting:read", "setting:update"
        ],
        UserRole.DEVELOPER: [
            "scan:read",
            "finding:read", "finding:update_status", "finding:comment",
            "report:read"
        ],
        UserRole.VIEWER: [
            "scan:read",
            "finding:read",
            "report:read"
        ]
    }

    def __init__(self):
        self._scan_permissions: Dict[str, Dict[str, str]] = {}  # scan_id -> {user_id -> role}

    def check_permission(self, user_role: str, permission: str) -> bool:
        """Check if a role has a specific permission."""
        try:
            role = UserRole(user_role)
            permissions = self.PERMISSIONS.get(role, [])
            return "*" in permissions or permission in permissions
        except ValueError:
            return False

    def assign_scan_role(self, scan_id: str, user_id: str, role: str):
        """Assign a role to a user for a specific scan."""
        if scan_id not in self._scan_permissions:
            self._scan_permissions[scan_id] = {}
        
        self._scan_permissions[scan_id][user_id] = role

    def get_scan_role(self, scan_id: str, user_id: str) -> Optional[str]:
        """Get a user's role for a specific scan."""
        return self._scan_permissions.get(scan_id, {}).get(user_id)


# Singleton instances
team_collaboration = TeamCollaborationService()
rbac_service = RBACService()
