"""
Neo4j Graph Client — Quantum Protocol v5.0
==========================================
Models vulnerability relationships as a directed property graph.
Stores assets, endpoints, vulnerabilities, credentials, services,
user roles, impacts, and remediations as nodes.

Automatically builds attack paths, privilege escalation chains,
data exfiltration routes, and lateral movement risk from scan results.

Falls back to in-memory graph if Neo4j is not available.
"""

import os
import hashlib
import logging
from datetime import datetime
from typing import Any, Optional, List, Dict, Tuple

logger = logging.getLogger(__name__)

# ── Neo4j driver (optional dependency) ────────────────────────────────────────
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logger.warning("neo4j-driver not installed. Install with: pip install neo4j")

NEO4J_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

# ── Severity ordering ──────────────────────────────────────────────────────────
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ── Module relationship map (which modules can escalate to which) ──────────────
LEADS_TO_MAP: Dict[str, List[str]] = {
    "injection":    ["misconfig", "endpoint", "ssrf"],
    "misconfig":    ["endpoint", "frontend_js", "injection"],
    "endpoint":     ["injection", "ssrf", "misconfig"],
    "ssrf":         ["injection", "endpoint"],
    "frontend_js":  ["misconfig", "endpoint"],
}


# ══════════════════════════════════════════════════════════════════════════════
# Graph node / edge type models
# ══════════════════════════════════════════════════════════════════════════════

class GraphNode:
    """Represents a node in the vulnerability graph."""
    __slots__ = ("id", "type", "label", "severity", "properties")

    def __init__(
        self,
        node_id: str,
        node_type: str,
        label: str,
        severity: str = "info",
        properties: Optional[Dict] = None,
    ):
        self.id         = node_id
        self.type       = node_type
        self.label      = label
        self.severity   = severity
        self.properties = properties or {}

    def to_dict(self) -> Dict:
        return {
            "id":         self.id,
            "type":       self.type,
            "label":      self.label,
            "severity":   self.severity,
            "properties": self.properties,
        }


class GraphEdge:
    """Represents a directed relationship in the vulnerability graph."""
    __slots__ = ("source", "target", "type", "properties")

    def __init__(
        self,
        source: str,
        target: str,
        edge_type: str,
        properties: Optional[Dict] = None,
    ):
        self.source     = source
        self.target     = target
        self.type       = edge_type
        self.properties = properties or {}

    def to_dict(self) -> Dict:
        return {
            "source":     self.source,
            "target":     self.target,
            "type":       self.type,
            "properties": self.properties,
        }


# ══════════════════════════════════════════════════════════════════════════════
# In-memory graph store
# ══════════════════════════════════════════════════════════════════════════════

class InMemoryGraph:
    """
    Simple in-memory directed graph for when Neo4j is not configured.
    Used as a transparent fallback — same API as the Neo4j backend.
    """

    def __init__(self):
        self._graphs: Dict[str, Dict] = {}

    def store(self, scan_id: str, nodes: List[GraphNode], edges: List[GraphEdge]):
        self._graphs[scan_id] = {
            "nodes": {n.id: n for n in nodes},
            "edges": edges,
        }

    def get(self, scan_id: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        g = self._graphs.get(scan_id, {})
        return list(g.get("nodes", {}).values()), g.get("edges", [])

    def has(self, scan_id: str) -> bool:
        return scan_id in self._graphs

    def bfs_shortest_path(
        self, scan_id: str, start_id: str, target_id: str
    ) -> Optional[List[str]]:
        """BFS shortest path between two node IDs."""
        _, edges = self.get(scan_id)
        adj: Dict[str, List[str]] = {}
        for e in edges:
            adj.setdefault(e.source, []).append(e.target)

        if start_id == target_id:
            return [start_id]

        visited = {start_id}
        queue: List[List[str]] = [[start_id]]
        while queue:
            path = queue.pop(0)
            node = path[-1]
            for nb in adj.get(node, []):
                if nb == target_id:
                    return path + [nb]
                if nb not in visited:
                    visited.add(nb)
                    queue.append(path + [nb])
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Neo4j Client
# ══════════════════════════════════════════════════════════════════════════════

class Neo4jClient:
    """
    Enterprise-grade Neo4j graph client for vulnerability relationship modeling.

    Responsibilities:
    - Ingest scan findings as graph nodes (Asset, Vulnerability, Endpoint,
      Credential, Service, UserRole, Impact, Remediation)
    - Build relationships (HAS_VULNERABILITY, EXPOSES, GRANTS_ACCESS,
      CONNECTED_TO, LEADS_TO, ESCALATES_TO)
    - Compute attack paths via shortest-path algorithms
    - Generate breach simulation timelines
    - Expose rich graph data for frontend visualization

    Falls back to InMemoryGraph if Neo4j is unavailable.
    """

    def __init__(self):
        self._driver    = None
        self._connected = False
        self._fallback  = InMemoryGraph()

        if NEO4J_AVAILABLE and NEO4J_PASSWORD:
            try:
                self._driver = GraphDatabase.driver(
                    NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
                )
                self._driver.verify_connectivity()
                self._connected = True
                self._init_schema()
                logger.info("Neo4j connected at %s", NEO4J_URI)
            except Exception as exc:
                logger.warning(
                    "Neo4j unavailable (%s). Using in-memory graph fallback.", exc
                )
        else:
            if not NEO4J_AVAILABLE:
                logger.info("neo4j-driver not installed — using in-memory graph.")
            else:
                logger.info("NEO4J_PASSWORD not set — using in-memory graph.")

    # ── Schema ────────────────────────────────────────────────────────────────

    def _init_schema(self):
        """Create uniqueness constraints so MERGE is idempotent."""
        if not self._connected:
            return
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Asset)          REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Vulnerability)  REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Endpoint)       REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Credential)     REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Service)        REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:UserRole)       REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Impact)         REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Remediation)    REQUIRE n.id IS UNIQUE",
        ]
        with self._driver.session() as s:
            for c in constraints:
                try:
                    s.run(c)
                except Exception:
                    pass

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def mode(self) -> str:
        return "neo4j" if self._connected else "memory"

    def close(self):
        if self._driver:
            self._driver.close()

    # ══════════════════════════════════════════════════════════════════════════
    # Ingestion
    # ══════════════════════════════════════════════════════════════════════════

    def ingest_scan_findings(
        self, scan_id: str, target: str, findings: List[Dict]
    ) -> Dict:
        """
        Transform normalised scan findings into a property graph.

        Node types created:
          Asset          — the scanned target
          Service        — scanner module (injection_scanner, misconfig_engine …)
          Vulnerability  — each finding (OWASP-tagged, CWE-tagged)
          Endpoint       — file paths / API endpoints where findings live
          Credential     — matched secrets / tokens / keys
          UserRole       — roles implicitly granted by auth-bypass vulns
          Impact         — aggregated breach impact node
          Remediation    — consolidated fix action node

        Relationship types created:
          CONNECTED_TO   Asset → Service
          HAS_VULNERABILITY  Service → Vulnerability
          EXPOSES        Vulnerability → Endpoint
          GRANTS_ACCESS  Vulnerability → Credential / UserRole
          LEADS_TO       Vulnerability → Impact (high/critical)
          ESCALATES_TO   Vulnerability → Vulnerability (cross-module chain)
        """
        nodes, edges = self._build_graph(scan_id, target, findings)

        if self._connected:
            self._write_to_neo4j(nodes, edges)
        else:
            self._fallback.store(scan_id, nodes, edges)

        return {
            "mode":                  self.mode,
            "nodes_created":         len(nodes),
            "relationships_created": len(edges),
            "scan_id":               scan_id,
        }

    def _build_graph(
        self, scan_id: str, target: str, findings: List[Dict]
    ) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Pure graph construction — framework-agnostic."""
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        seen:  set             = set()

        ts = datetime.utcnow().isoformat()

        def add_node(n: GraphNode):
            if n.id not in seen:
                seen.add(n.id)
                nodes.append(n)

        # ── Root Asset ──────────────────────────────────────────────────────
        asset_id = f"asset:{scan_id}"
        add_node(GraphNode(asset_id, "Asset", target[:60],
                           properties={"scan_id": scan_id, "target": target, "ts": ts}))

        # ── Service nodes (one per scanner module) ───────────────────────────
        module_ids: Dict[str, str] = {}
        for f in findings:
            mod = f.get("module") or f.get("module_name") or "scanner"
            svc_id = f"svc:{scan_id}:{mod}"
            if mod not in module_ids:
                module_ids[mod] = svc_id
                add_node(GraphNode(svc_id, "Service",
                                   f.get("module_name") or mod,
                                   properties={"module": mod, "scan_id": scan_id}))
                edges.append(GraphEdge(asset_id, svc_id, "CONNECTED_TO"))

        # ── Per-finding nodes ────────────────────────────────────────────────
        crit_high: List[Dict] = []

        for f in findings[:50]:          # cap at 50 nodes for performance
            vuln_id = f"vuln:{f['id']}"
            sev     = f.get("severity", "info")
            mod     = f.get("module") or f.get("module_name") or "scanner"

            add_node(GraphNode(
                vuln_id, "Vulnerability",
                (f.get("title") or "Unknown")[:60],
                severity=sev,
                properties={
                    "owasp":       f.get("owasp", ""),
                    "cwe":         f.get("cwe", ""),
                    "confidence":  f.get("confidence", 0.5),
                    "remediation": f.get("remediation", ""),
                    "scan_id":     scan_id,
                    "module":      mod,
                },
            ))
            svc_id = module_ids.get(mod, asset_id)
            edges.append(GraphEdge(svc_id, vuln_id, "HAS_VULNERABILITY",
                                   {"severity": sev}))

            # Endpoint node
            file_path = f.get("file") or f.get("endpoint") or ""
            if file_path:
                ep_id = f"ep:{scan_id}:{hashlib.md5(file_path.encode()).hexdigest()[:8]}"
                add_node(GraphNode(ep_id, "Endpoint", file_path[:60],
                                   properties={"path": file_path, "scan_id": scan_id}))
                edges.append(GraphEdge(vuln_id, ep_id, "EXPOSES"))

            # Credential node
            if f.get("matched_content"):
                cred_id    = f"cred:{f['id']}"
                cred_hash  = hashlib.sha256(
                    f["matched_content"].encode()
                ).hexdigest()[:12]
                add_node(GraphNode(
                    cred_id, "Credential",
                    f"[{mod}] secret",
                    severity=sev,
                    properties={
                        "content_hash": cred_hash,
                        "cred_type":    mod,
                        "scan_id":      scan_id,
                    },
                ))
                edges.append(GraphEdge(vuln_id, cred_id, "GRANTS_ACCESS"))

            # Auth-bypass → UserRole grant
            if any(kw in (f.get("title") or "").lower()
                   for kw in ("auth bypass", "privilege", "role", "admin")):
                role_id = f"role:{scan_id}:admin"
                add_node(GraphNode(role_id, "UserRole", "Admin Role",
                                   severity="high",
                                   properties={"scan_id": scan_id}))
                edges.append(GraphEdge(vuln_id, role_id, "GRANTS_ACCESS"))

            if sev in ("critical", "high"):
                crit_high.append({"vuln_id": vuln_id, "f": f})

        # ── Cross-module escalation edges ────────────────────────────────────
        for i, a in enumerate(findings[:50]):
            for b in findings[i + 1:50]:
                a_mod = a.get("module", "")
                b_mod = b.get("module", "")
                if b_mod in LEADS_TO_MAP.get(a_mod, []):
                    a_sev = SEV_RANK.get(a.get("severity", "info"), 0)
                    b_sev = SEV_RANK.get(b.get("severity", "info"), 0)
                    rel   = "ESCALATES_TO" if b_sev > a_sev else "LEADS_TO"
                    edges.append(GraphEdge(
                        f"vuln:{a['id']}", f"vuln:{b['id']}", rel,
                        {"computed": True}
                    ))

        # ── Impact + Remediation aggregation nodes ────────────────────────────
        if crit_high:
            impact_id = f"impact:{scan_id}"
            add_node(GraphNode(impact_id, "Impact", "Data Breach Risk",
                               severity="critical",
                               properties={"scan_id": scan_id}))
            for item in crit_high[:4]:
                edges.append(GraphEdge(item["vuln_id"], impact_id, "LEADS_TO"))

            rem_id = f"rem:{scan_id}"
            add_node(GraphNode(rem_id, "Remediation", "Remediation Plan",
                               properties={"scan_id": scan_id}))
            edges.append(GraphEdge(impact_id, rem_id, "CONNECTED_TO"))

        return nodes, edges

    # ── Neo4j writer ────────────────────────────────────────────────────────

    def _write_to_neo4j(self, nodes: List[GraphNode], edges: List[GraphEdge]):
        if not self._connected:
            return
        with self._driver.session() as s:
            for n in nodes:
                label = n.type
                props = {"id": n.id, "label": n.label, "severity": n.severity,
                         **n.properties}
                s.run(
                    f"MERGE (x:{label} {{id: $id}}) SET x += $props",
                    id=n.id, props=props
                )
            for e in edges:
                s.run(
                    f"""
                    MATCH (a {{id: $src}})
                    MATCH (b {{id: $tgt}})
                    MERGE (a)-[r:{e.type}]->(b)
                    SET r += $props
                    """,
                    src=e.source, tgt=e.target, props=e.properties
                )

    # ══════════════════════════════════════════════════════════════════════════
    # Query: Asset Risk Graph
    # ══════════════════════════════════════════════════════════════════════════

    def get_asset_risk_graph(self, scan_id: str) -> Dict:
        """
        Return the full node/edge graph for the given scan.
        Used by the frontend force-directed visualisation.
        """
        if self._connected:
            return self._query_full_graph_neo4j(scan_id)

        nodes, edges = self._fallback.get(scan_id)
        return {
            "nodes":  [n.to_dict() for n in nodes],
            "edges":  [e.to_dict() for e in edges],
            "mode":   "memory",
            "count":  {"nodes": len(nodes), "edges": len(edges)},
        }

    def _query_full_graph_neo4j(self, scan_id: str) -> Dict:
        nodes, edges = [], []
        with self._driver.session() as s:
            for rec in s.run(
                "MATCH (n) WHERE n.scan_id = $sid RETURN n, labels(n) AS lbs",
                sid=scan_id
            ):
                nd, lbs = rec["n"], rec["lbs"]
                nodes.append({
                    "id":         nd.get("id", str(nd.id)),
                    "type":       lbs[0] if lbs else "Unknown",
                    "label":      nd.get("label", "")[:60],
                    "severity":   nd.get("severity", "info"),
                    "properties": dict(nd),
                })
            for rec in s.run(
                """
                MATCH (a)-[r]->(b)
                WHERE a.scan_id = $sid AND b.scan_id = $sid
                RETURN a.id AS src, b.id AS tgt, type(r) AS rel, properties(r) AS props
                """,
                sid=scan_id
            ):
                edges.append({
                    "source":     rec["src"],
                    "target":     rec["tgt"],
                    "type":       rec["rel"],
                    "properties": dict(rec["props"] or {}),
                })
        return {"nodes": nodes, "edges": edges, "mode": "neo4j",
                "count": {"nodes": len(nodes), "edges": len(edges)}}

    # ══════════════════════════════════════════════════════════════════════════
    # Query: Attack Paths
    # ══════════════════════════════════════════════════════════════════════════

    def get_attack_paths(self, scan_id: str) -> List[Dict]:
        """
        Compute attack paths for a given scan.
        Returns ordered list from entry point to highest-impact node.
        Algorithms used:
          - BFS shortest path (memory mode)
          - Neo4j shortestPath() (graph mode)
        """
        if self._connected:
            return self._query_attack_paths_neo4j(scan_id)
        return self._compute_attack_paths_memory(scan_id)

    def _query_attack_paths_neo4j(self, scan_id: str) -> List[Dict]:
        paths = []
        with self._driver.session() as s:
            result = s.run(
                """
                MATCH path = shortestPath(
                    (a:Asset {scan_id: $sid})-[*..6]->(v:Vulnerability)
                )
                WHERE v.severity IN ['critical', 'high']
                RETURN path, length(path) AS hops, v.severity AS risk
                ORDER BY
                    CASE v.severity
                        WHEN 'critical' THEN 0
                        WHEN 'high'     THEN 1
                        ELSE 2
                    END,
                    hops ASC
                LIMIT 6
                """,
                sid=scan_id,
            )
            for rec in result:
                path_nodes = []
                for nd in rec["path"].nodes:
                    lbs = list(nd.labels)
                    path_nodes.append({
                        "id":       nd.get("id", str(nd.id)),
                        "label":    nd.get("label", nd.get("name", ""))[:40],
                        "type":     lbs[0] if lbs else "Unknown",
                        "severity": nd.get("severity", "info"),
                    })
                paths.append({
                    "nodes":      path_nodes,
                    "hops":       rec["hops"],
                    "risk_level": rec["risk"],
                    "path_type":  self._classify_path(path_nodes),
                })
        return paths

    def _compute_attack_paths_memory(self, scan_id: str) -> List[Dict]:
        nodes, edges = self._fallback.get(scan_id)
        if not nodes:
            return []

        node_map = {n.id: n for n in nodes}
        adj: Dict[str, List[str]] = {}
        for e in edges:
            adj.setdefault(e.source, []).append(e.target)

        # Entry: Asset node
        asset_nodes = [n for n in nodes if n.type == "Asset"]
        if not asset_nodes:
            return []
        start_id = asset_nodes[0].id

        # Targets: high/critical vulns + credentials + impact
        targets = [
            n.id for n in nodes
            if n.type in ("Vulnerability", "Credential", "Impact")
            and SEV_RANK.get(n.severity, 0) >= 2
        ]

        paths = []
        for tgt_id in targets[:6]:
            raw = self._bfs(adj, start_id, tgt_id)
            if raw:
                path_nodes = [
                    {
                        "id":       nid,
                        "label":    node_map[nid].label if nid in node_map else nid,
                        "type":     node_map[nid].type  if nid in node_map else "Unknown",
                        "severity": node_map[nid].severity if nid in node_map else "info",
                    }
                    for nid in raw
                ]
                tgt_node = node_map.get(tgt_id)
                paths.append({
                    "nodes":      path_nodes,
                    "hops":       len(raw) - 1,
                    "risk_level": tgt_node.severity if tgt_node else "info",
                    "path_type":  self._classify_path(path_nodes),
                })

        # Sort by severity then length
        paths.sort(
            key=lambda p: (-SEV_RANK.get(p["risk_level"], 0), p["hops"])
        )
        return paths[:6]

    @staticmethod
    def _bfs(adj: Dict[str, List[str]], start: str, target: str) -> Optional[List[str]]:
        if start == target:
            return [start]
        visited = {start}
        queue: List[List[str]] = [[start]]
        while queue:
            path = queue.pop(0)
            for nb in adj.get(path[-1], []):
                if nb == target:
                    return path + [nb]
                if nb not in visited:
                    visited.add(nb)
                    queue.append(path + [nb])
        return None

    @staticmethod
    def _classify_path(path_nodes: List[Dict]) -> str:
        types = {n["type"] for n in path_nodes}
        if "Credential" in types:
            return "Credential Theft"
        if "UserRole" in types:
            return "Privilege Escalation"
        if len(path_nodes) > 4:
            return "Lateral Movement"
        return "Direct Exploitation"

    # ══════════════════════════════════════════════════════════════════════════
    # Query: Breach Simulation
    # ══════════════════════════════════════════════════════════════════════════

    def get_breach_simulation(self, scan_id: str, findings: List[Dict]) -> Dict:
        """
        Generate an attacker-perspective breach simulation.

        Returns:
          - breach_probability      (0-100)
          - risk_level              (critical / high / medium)
          - attack_timeline         (MITRE-mapped steps)
          - impact_assessment       (affected areas)
          - attack_paths            (from get_attack_paths)
          - estimated_dwell_time
          - findings_summary
          - mitre_techniques
        """
        critical = [f for f in findings if f.get("severity") == "critical"]
        high     = [f for f in findings if f.get("severity") == "high"]
        medium   = [f for f in findings if f.get("severity") == "medium"]
        has_creds = any(f.get("matched_content") for f in findings)
        has_injection = any(
            "injection" in (f.get("module") or "") for f in findings
        )
        has_ssrf = any("ssrf" in (f.get("module") or "") for f in findings)
        has_misconfig = any(
            "misconfig" in (f.get("module") or "") for f in findings
        )

        risk_score         = len(critical) * 30 + len(high) * 15 + len(medium) * 5
        breach_probability = min(95, risk_score)
        risk_level = (
            "critical" if breach_probability > 70
            else "high"   if breach_probability > 40
            else "medium"
        )

        # ── Build MITRE-mapped timeline ──────────────────────────────────────
        timeline = []
        step = 1

        if critical or high:
            timeline.append({
                "step":          step,
                "phase":         "Initial Access",
                "action":        f"Exploit {(critical or high)[0].get('title', 'vulnerability')} as entry",
                "impact":        "System foothold established",
                "severity":      (critical or high)[0].get("severity", "high"),
                "technique":     "T1190 — Exploit Public-Facing Application",
                "time_estimate": "< 5 min",
            })
            step += 1

        if has_ssrf:
            timeline.append({
                "step":          step,
                "phase":         "Discovery",
                "action":        "SSRF probe to enumerate internal services and cloud metadata",
                "impact":        "Internal network topology exposed",
                "severity":      "high",
                "technique":     "T1046 — Network Service Discovery",
                "time_estimate": "5-15 min",
            })
            step += 1

        if has_injection:
            timeline.append({
                "step":          step,
                "phase":         "Execution",
                "action":        "Inject payload through vulnerable endpoint",
                "impact":        "Remote code/query execution",
                "severity":      "critical",
                "technique":     "T1059 — Command and Scripting Interpreter",
                "time_estimate": "5-15 min",
            })
            step += 1

        if has_creds:
            timeline.append({
                "step":          step,
                "phase":         "Credential Access",
                "action":        "Extract exposed credentials / API keys from source artifacts",
                "impact":        "Authentication bypass; multi-system access",
                "severity":      "critical",
                "technique":     "T1552 — Unsecured Credentials",
                "time_estimate": "1-5 min",
            })
            step += 1

        if high or has_misconfig:
            timeline.append({
                "step":          step,
                "phase":         "Privilege Escalation",
                "action":        "Leverage misconfiguration or auth bypass for elevated privilege",
                "impact":        "Admin / root access acquired",
                "severity":      "high",
                "technique":     "T1068 — Exploitation for Privilege Escalation",
                "time_estimate": "10-30 min",
            })
            step += 1

        timeline.append({
            "step":          step,
            "phase":         "Collection & Exfiltration",
            "action":        "Enumerate, archive, and exfiltrate sensitive data",
            "impact":        "Full data breach · potential ransomware deployment",
            "severity":      "critical",
            "technique":     "T1041 — Exfiltration Over C2 Channel",
            "time_estimate": "30-90 min",
        })

        # ── Impact areas ────────────────────────────────────────────────────
        impact_areas = []
        if has_injection:
            impact_areas.append({
                "area":        "Database Integrity",
                "risk":        "critical",
                "description": "SQL/NoSQL injection enables arbitrary data read, write, or deletion",
            })
        if has_creds:
            impact_areas.append({
                "area":        "Authentication & Identity",
                "risk":        "critical",
                "description": "Exposed credentials enable account takeover across services",
            })
        if has_ssrf:
            impact_areas.append({
                "area":        "Internal Network",
                "risk":        "high",
                "description": "SSRF enables lateral movement to internal APIs and cloud metadata",
            })
        if has_misconfig:
            impact_areas.append({
                "area":        "Compliance Posture",
                "risk":        "high",
                "description": "Misconfigurations violate OWASP, CIS, and PCI-DSS standards",
            })
        if critical:
            impact_areas.append({
                "area":        "Business Continuity",
                "risk":        "critical",
                "description": f"{len(critical)} critical vulnerabilities threaten system availability",
            })

        dwell_min = len(timeline) * 10
        dwell_max = len(timeline) * 40

        return {
            "breach_probability":  breach_probability,
            "risk_level":          risk_level,
            "attack_timeline":     timeline,
            "impact_assessment":   impact_areas,
            "attack_paths":        self.get_attack_paths(scan_id),
            "estimated_dwell_time": f"{dwell_min}–{dwell_max} min",
            "mitre_techniques":    list({t["technique"] for t in timeline}),
            "findings_summary": {
                "critical": len(critical),
                "high":     len(high),
                "medium":   len(medium),
                "total":    len(findings),
            },
            "mode": self.mode,
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

_neo4j_client: Optional[Neo4jClient] = None


def get_neo4j_client() -> Neo4jClient:
    """Return (or create) the process-global Neo4j client."""
    global _neo4j_client
    if _neo4j_client is None:
        _neo4j_client = Neo4jClient()
    return _neo4j_client
