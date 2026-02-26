"""
Quantum Protocol v5.0 — Threat Modeling Integration
STRIDE-based threat modeling with attack surface diagrams.

Phase 8.10: Threat Modeling Integration
"""

import json
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib


class STRIDECategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass
class Threat:
    id: str
    title: str
    description: str
    stride_category: str
    severity: str  # critical, high, medium, low
    finding_ids: List[str]  # Linked findings
    affected_components: List[str]
    mitigations: List[str]
    risk_score: float  # 0-10


@dataclass
class AttackPath:
    id: str
    name: str
    entry_point: str
    target: str
    steps: List[Dict]
    likelihood: str  # high, medium, low
    impact: str  # high, medium, low
    linked_threats: List[str]


@dataclass
class AttackSurface:
    component: str
    exposure: str  # internet, internal, restricted
    interfaces: List[str]
    data_types: List[str]
    trust_boundaries_crossed: int
    risk_level: str  # high, medium, low


class ThreatModelingService:
    """Generate threat models from scan results."""

    # Mapping of finding categories to STRIDE categories
    CATEGORY_TO_STRIDE = {
        "authentication": STRIDECategory.SPOOFING,
        "authorization": STRIDECategory.ELEVATION_OF_PRIVILEGE,
        "injection": STRIDECategory.TAMPERING,
        "input_validation": STRIDECategory.TAMPERING,
        "cryptography": STRIDECategory.INFORMATION_DISCLOSURE,
        "sensitive_data": STRIDECategory.INFORMATION_DISCLOSURE,
        "logging": STRIDECategory.REPUDIATION,
        "availability": STRIDECategory.DENIAL_OF_SERVICE,
        "secrets": STRIDECategory.INFORMATION_DISCLOSURE,
        "ssrf": STRIDECategory.SPOOFING,
    }

    def __init__(self):
        self._threat_cache: Dict[str, List[Threat]] = {}
        self._attack_paths_cache: Dict[str, List[AttackPath]] = {}

    def generate_threat_model(self, scan_id: str, findings: List[Dict]) -> Dict:
        """Generate a complete threat model from scan findings."""
        
        # Generate threats based on findings
        threats = self._identify_threats(findings)
        
        # Identify attack surface
        attack_surface = self._identify_attack_surface(findings)
        
        # Generate attack paths
        attack_paths = self._generate_attack_paths(threats, attack_surface)
        
        # Create risk heat map
        heat_map = self._generate_risk_heat_map(threats)
        
        # Store in cache
        self._threat_cache[scan_id] = threats
        self._attack_paths_cache[scan_id] = attack_paths
        
        return {
            "scan_id": scan_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "threats": [asdict(t) for t in threats],
            "attack_surface": [asdict(a) for a in attack_surface],
            "attack_paths": [asdict(p) for p in attack_paths],
            "stride_summary": self._summarize_stride(threats),
            "risk_heat_map": heat_map,
            "total_threats": len(threats),
            "critical_threats": sum(1 for t in threats if t.severity == "critical"),
        }

    def _identify_threats(self, findings: List[Dict]) -> List[Threat]:
        """Identify threats from findings using STRIDE."""
        threats = []
        
        for finding in findings:
            category = finding.get("category", "").lower()
            severity = finding.get("severity", "medium").lower()
            
            # Map to STRIDE category
            stride_cat = self.CATEGORY_TO_STRIDE.get(
                category, 
                STRIDECategory.INFORMATION_DISCLOSURE
            )
            
            # Generate threat
            threat_id = f"T-{hashlib.md5(finding.get('id', '').encode()).hexdigest()[:8]}"
            
            threat = Threat(
                id=threat_id,
                title=finding.get("title", "Unknown Threat"),
                description=finding.get("description", "No description"),
                stride_category=stride_cat.value,
                severity=severity,
                finding_ids=[finding.get("id")],
                affected_components=[finding.get("file", "Unknown")],
                mitigations=[finding.get("remediation", "No remediation provided")],
                risk_score=self._calculate_risk_score(severity, finding)
            )
            
            threats.append(threat)
        
        # Sort by risk score
        threats.sort(key=lambda t: t.risk_score, reverse=True)
        
        return threats

    def _calculate_risk_score(self, severity: str, finding: Dict) -> float:
        """Calculate risk score (0-10) based on severity and factors."""
        base_scores = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0
        }
        
        score = base_scores.get(severity, 5.0)
        
        # Adjust based on confidence
        confidence = finding.get("confidence", 1.0)
        score *= confidence
        
        # Cap at 10
        return min(10.0, score)

    def _identify_attack_surface(self, findings: List[Dict]) -> List[AttackSurface]:
        """Identify attack surface from findings."""
        
        # Group findings by file/component
        component_findings = {}
        for finding in findings:
            file = finding.get("file", "Unknown")
            if file not in component_findings:
                component_findings[file] = []
            component_findings[file].append(finding)
        
        attack_surfaces = []
        
        for component, comp_findings in component_findings.items():
            # Determine exposure level
            critical_count = sum(1 for f in comp_findings if f.get("severity") == "critical")
            high_count = sum(1 for f in comp_findings if f.get("severity") == "high")
            
            if critical_count > 0:
                risk_level = "high"
            elif high_count > 0:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            # Extract interfaces (simplified - would need code analysis)
            interfaces = list(set(
                f.get("injection_type", "API") 
                for f in comp_findings 
                if "injection" in f.get("category", "").lower()
            )) or ["API", "Internal"]
            
            surface = AttackSurface(
                component=component,
                exposure="internet" if "api" in component.lower() or "endpoint" in component.lower() else "internal",
                interfaces=interfaces,
                data_types=["PII", "Credentials", "Session Data"],  # Simplified
                trust_boundaries_crossed=1 if risk_level == "high" else 0,
                risk_level=risk_level
            )
            
            attack_surfaces.append(surface)
        
        # Sort by risk level
        risk_order = {"high": 0, "medium": 1, "low": 2}
        attack_surfaces.sort(key=lambda a: risk_order.get(a.risk_level, 3))
        
        return attack_surfaces

    def _generate_attack_paths(self, threats: List[Threat], attack_surfaces: List[AttackSurface]) -> List[AttackPath]:
        """Generate potential attack paths through the system."""
        
        paths = []
        
        # High-risk surfaces with spoofing/injection threats create attack paths
        high_risk_surfaces = [s for s in attack_surfaces if s.risk_level == "high"]
        spoofing_threats = [t for t in threats if t.stride_category == "Spoofing"]
        elevation_threats = [t for t in threats if t.stride_category == "Elevation of Privilege"]
        
        # Generate paths based on combinations
        for i, surface in enumerate(high_risk_surfaces[:3]):  # Top 3
            # Entry point attack
            if spoofing_threats:
                path = AttackPath(
                    id=f"AP-{i}-SPOOF",
                    name=f"Authentication Bypass via {surface.component}",
                    entry_point=surface.interfaces[0] if surface.interfaces else "API",
                    target=surface.component,
                    steps=[
                        {"step": 1, "action": "Identify weak authentication", "prerequisite": "Network access"},
                        {"step": 2, "action": "Exploit spoofing vulnerability", "prerequisite": spoofing_threats[0].title},
                        {"step": 3, "action": "Gain unauthorized access", "prerequisite": "Successful spoofing"}
                    ],
                    likelihood="high" if surface.risk_level == "high" else "medium",
                    impact="high",
                    linked_threats=[t.id for t in spoofing_threats[:2]]
                )
                paths.append(path)
            
            # Privilege escalation path
            if elevation_threats:
                path = AttackPath(
                    id=f"AP-{i}-PRIV",
                    name=f"Privilege Escalation in {surface.component}",
                    entry_point=surface.component,
                    target="System/Admin Access",
                    steps=[
                        {"step": 1, "action": "Gain low-privilege access", "prerequisite": "Valid credentials"},
                        {"step": 2, "action": "Exploit privilege escalation", "prerequisite": elevation_threats[0].title},
                        {"step": 3, "action": "Execute with elevated privileges", "prerequisite": "Successful escalation"}
                    ],
                    likelihood="medium",
                    impact="critical",
                    linked_threats=[t.id for t in elevation_threats[:2]]
                )
                paths.append(path)
        
        return paths

    def _generate_risk_heat_map(self, threats: List[Threat]) -> Dict:
        """Generate a risk heat map based on STRIDE categories."""
        
        stride_counts = {cat.value: {"count": 0, "risk_sum": 0} for cat in STRIDECategory}
        
        for threat in threats:
            cat = threat.stride_category
            if cat in stride_counts:
                stride_counts[cat]["count"] += 1
                stride_counts[cat]["risk_sum"] += threat.risk_score
        
        # Calculate average risk per category
        heat_map = {}
        for cat, data in stride_counts.items():
            avg_risk = data["risk_sum"] / data["count"] if data["count"] > 0 else 0
            heat_map[cat] = {
                "count": data["count"],
                "average_risk": round(avg_risk, 2),
                "heat_level": "high" if avg_risk > 7 else "medium" if avg_risk > 4 else "low"
            }
        
        return heat_map

    def _summarize_stride(self, threats: List[Threat]) -> Dict:
        """Summarize threats by STRIDE category."""
        summary = {cat.value: 0 for cat in STRIDECategory}
        
        for threat in threats:
            if threat.stride_category in summary:
                summary[threat.stride_category] += 1
        
        return summary

    def generate_attack_surface_diagram(self, scan_id: str) -> Dict:
        """Generate data for an attack surface diagram."""
        
        if scan_id not in self._threat_cache:
            return {"error": "Threat model not found. Generate threat model first."}
        
        threats = self._threat_cache[scan_id]
        
        # Create node/link diagram data
        nodes = []
        links = []
        
        # Add attack surface components as nodes
        components = set()
        for threat in threats:
            components.update(threat.affected_components)
        
        for i, comp in enumerate(components):
            threat_count = sum(1 for t in threats if comp in t.affected_components)
            nodes.append({
                "id": f"comp-{i}",
                "name": comp.split("/")[-1] if "/" in comp else comp,
                "type": "component",
                "threat_count": threat_count,
                "risk_level": "high" if threat_count > 2 else "medium" if threat_count > 0 else "low"
            })
        
        # Add threats as nodes and link to components
        for threat in threats:
            threat_node = {
                "id": threat.id,
                "name": threat.title[:30] + "..." if len(threat.title) > 30 else threat.title,
                "type": "threat",
                "category": threat.stride_category,
                "severity": threat.severity
            }
            nodes.append(threat_node)
            
            # Link threat to components
            for i, comp in enumerate(components):
                if comp in threat.affected_components:
                    links.append({
                        "source": threat.id,
                        "target": f"comp-{i}",
                        "type": "affects"
                    })
        
        return {
            "nodes": nodes,
            "links": links,
            "layout": "force-directed"
        }


# Singleton instance
threat_modeling = ThreatModelingService()
