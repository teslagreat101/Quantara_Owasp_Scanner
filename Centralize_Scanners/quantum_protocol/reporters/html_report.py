"""
Quantum Protocol v4.0 — Enterprise HTML Report Generator
Professional security assessment report with interactive charts,
OWASP coverage dashboard, executive summary, and detailed findings.
"""
from __future__ import annotations
import html
import json
from datetime import datetime
from quantum_protocol.models.findings import ScanSummary, CryptoFinding
from quantum_protocol.models.enums import RiskLevel


def generate_html_report(summary: ScanSummary) -> str:
    """Generate a comprehensive HTML security report."""

    findings_json = json.dumps([_finding_to_dict(f) for f in summary.findings[:500]], default=str)
    owasp_json = json.dumps(summary.owasp_coverage or {})
    vuln_cat_json = json.dumps(summary.vuln_by_category or {})
    compliance_json = json.dumps(summary.compliance_summary or {})

    score_color = "#22c55e" if summary.overall_security_score >= 80 else "#f59e0b" if summary.overall_security_score >= 50 else "#ef4444"

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quantum Protocol v4.0 — Security Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
.container{{max-width:1400px;margin:0 auto;padding:24px}}
.header{{text-align:center;padding:40px 0;border-bottom:1px solid #334155}}
.header h1{{font-size:2rem;background:linear-gradient(135deg,#38bdf8,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}}
.header .version{{color:#94a3b8;font-size:0.9rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin:24px 0}}
.card{{background:#1e293b;border-radius:12px;padding:20px;border:1px solid #334155}}
.card h3{{font-size:0.85rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px}}
.card .value{{font-size:2rem;font-weight:700}}
.card .value.critical{{color:#ef4444}}.card .value.high{{color:#f97316}}.card .value.medium{{color:#f59e0b}}.card .value.good{{color:#22c55e}}
.score-ring{{width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:2rem;font-weight:800;border:4px solid {score_color};color:{score_color}}}
.section{{margin:32px 0}}.section h2{{font-size:1.3rem;color:#f8fafc;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #334155}}
table{{width:100%;border-collapse:collapse;font-size:0.85rem}}
th{{background:#1e293b;color:#94a3b8;text-align:left;padding:10px 12px;border-bottom:2px solid #334155;position:sticky;top:0}}
td{{padding:8px 12px;border-bottom:1px solid #1e293b}}
tr:hover td{{background:#1e293b}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600}}
.badge-critical{{background:#7f1d1d;color:#fca5a5}}.badge-high{{background:#7c2d12;color:#fdba74}}
.badge-medium{{background:#78350f;color:#fde047}}.badge-low{{background:#1e3a5f;color:#7dd3fc}}
.badge-info{{background:#1e293b;color:#94a3b8}}
.bar-chart{{display:flex;flex-direction:column;gap:6px}}
.bar-row{{display:flex;align-items:center;gap:8px}}.bar-row .label{{width:280px;font-size:0.8rem;text-align:right;color:#94a3b8}}
.bar-row .bar{{height:20px;border-radius:4px;min-width:4px}}.bar-row .count{{font-size:0.8rem;color:#cbd5e1;width:30px}}
.filter-bar{{display:flex;gap:8px;margin:16px 0;flex-wrap:wrap}}
.filter-btn{{background:#1e293b;border:1px solid #475569;color:#e2e8f0;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:0.8rem}}
.filter-btn:hover,.filter-btn.active{{background:#334155;border-color:#818cf8}}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <h1>QUANTUM PROTOCOL v4.0</h1>
    <div class="version">Full-Spectrum Security Assessment Report | Generated {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>
    <div style="margin-top:8px;color:#94a3b8">Source: {html.escape(summary.source)} | Mode: {summary.scan_mode} | {summary.files_scanned} files in {summary.duration_seconds:.1f}s</div>
</div>

<div class="grid">
    <div class="card" style="text-align:center">
        <h3>Overall Security Score</h3>
        <div class="score-ring">{summary.overall_security_score:.0f}</div>
    </div>
    <div class="card"><h3>Total Findings</h3><div class="value">{summary.total_findings}</div></div>
    <div class="card"><h3>Critical</h3><div class="value critical">{summary.critical_count}</div></div>
    <div class="card"><h3>High</h3><div class="value high">{summary.high_count}</div></div>
    <div class="card"><h3>Secrets Exposed</h3><div class="value critical">{summary.secrets_count}</div></div>
    <div class="card"><h3>OWASP Vulns</h3><div class="value high">{summary.vuln_count}</div></div>
</div>

<div class="grid" style="grid-template-columns:repeat(4,1fr)">
    <div class="card"><h3>Quantum Risk</h3><div class="value {"critical" if summary.quantum_risk_score>50 else "medium" if summary.quantum_risk_score>20 else "good"}">{summary.quantum_risk_score:.0f}/100</div></div>
    <div class="card"><h3>Secrets Exposure</h3><div class="value {"critical" if summary.secrets_exposure_score>50 else "medium" if summary.secrets_exposure_score>20 else "good"}">{summary.secrets_exposure_score:.0f}/100</div></div>
    <div class="card"><h3>Vulnerability Risk</h3><div class="value {"critical" if summary.vuln_risk_score>50 else "medium" if summary.vuln_risk_score>20 else "good"}">{summary.vuln_risk_score:.0f}/100</div></div>
    <div class="card"><h3>Crypto Agility</h3><div class="value {"good" if summary.crypto_agility_score>70 else "medium" if summary.crypto_agility_score>40 else "critical"}">{summary.crypto_agility_score:.0f}/100</div></div>
</div>

<div class="section">
    <h2>OWASP Top 10:2025 Coverage</h2>
    <div class="bar-chart" id="owaspChart"></div>
</div>

<div class="section">
    <h2>Vulnerability Categories</h2>
    <div class="bar-chart" id="vulnChart"></div>
</div>

<div class="section">
    <h2>Detailed Findings</h2>
    <div class="filter-bar">
        <button class="filter-btn active" onclick="filterFindings('all')">All ({summary.total_findings})</button>
        <button class="filter-btn" onclick="filterFindings('Critical')">Critical ({summary.critical_count})</button>
        <button class="filter-btn" onclick="filterFindings('High')">High ({summary.high_count})</button>
        <button class="filter-btn" onclick="filterFindings('Medium')">Medium ({summary.medium_count})</button>
        <button class="filter-btn" onclick="filterFindings('secret')">Secrets ({summary.secrets_count})</button>
        <button class="filter-btn" onclick="filterFindings('vuln')">Vulns ({summary.vuln_count})</button>
    </div>
    <div style="overflow-x:auto;max-height:600px;overflow-y:auto">
    <table><thead><tr>
        <th>Risk</th><th>Category</th><th>File</th><th>Line</th><th>Finding</th><th>CWE</th><th>Confidence</th>
    </tr></thead><tbody id="findingsTable"></tbody></table>
    </div>
</div>

<div class="section">
    <h2>Compliance Summary</h2>
    <div class="bar-chart" id="complianceChart"></div>
</div>
</div>

<script>
const findings = {findings_json};
const owaspData = {owasp_json};
const vulnCatData = {vuln_cat_json};
const compData = {compliance_json};
const colors = {{"Critical":"#ef4444","High":"#f97316","Medium":"#f59e0b","Low":"#3b82f6","Info":"#64748b"}};

function renderBarChart(el, data, color) {{
    const max = Math.max(...Object.values(data), 1);
    el.innerHTML = Object.entries(data).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
        `<div class="bar-row"><span class="label">${{k}}</span><div class="bar" style="width:${{Math.max(v/max*400,4)}}px;background:${{color||"#818cf8"}}"></div><span class="count">${{v}}</span></div>`
    ).join("");
}}

renderBarChart(document.getElementById("owaspChart"), owaspData, "#818cf8");
renderBarChart(document.getElementById("vulnChart"), vulnCatData, "#38bdf8");
renderBarChart(document.getElementById("complianceChart"), compData, "#c084fc");

function renderFindings(list) {{
    document.getElementById("findingsTable").innerHTML = list.map(f=>
        `<tr><td><span class="badge badge-${{f.risk.toLowerCase()}}">${{f.risk}}</span></td><td>${{f.category}}</td><td title="${{f.file}}">${{f.file.split("/").pop()}}</td><td>${{f.line}}</td><td>${{f.note.substring(0,80)}}</td><td>${{f.cwe||""}}</td><td>${{(f.confidence*100).toFixed(0)}}%</td></tr>`
    ).join("");
}}
function filterFindings(type) {{
    document.querySelectorAll(".filter-btn").forEach(b=>b.classList.remove("active"));
    event.target.classList.add("active");
    if(type==="all") renderFindings(findings);
    else if(type==="secret") renderFindings(findings.filter(f=>f.is_secret));
    else if(type==="vuln") renderFindings(findings.filter(f=>f.is_vuln));
    else renderFindings(findings.filter(f=>f.risk===type));
}}
renderFindings(findings);
</script>
</body></html>'''


def _finding_to_dict(f: CryptoFinding) -> dict:
    return {
        "risk": f.risk.value,
        "category": f.family.vuln_category.value,
        "file": f.file,
        "line": f.line_number,
        "algorithm": f.algorithm,
        "note": f.pattern_note,
        "cwe": f.cwe_id or "",
        "confidence": f.confidence,
        "is_secret": f.is_secret,
        "is_vuln": f.family.is_vuln,
        "compliance": f.compliance_violations,
    }
