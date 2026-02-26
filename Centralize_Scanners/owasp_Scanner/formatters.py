"""
Quantum Protocol v3.5 — Report Generators

Output formats with full secrets/credentials coverage:
  - JSON, SARIF 2.1, CSV, HTML Dashboard, Plain text summary
"""

from __future__ import annotations
import csv, io, json
from pathlib import Path
from quantum_protocol.models.findings import ScanSummary


def export_json(summary: ScanSummary, indent: int = 2) -> str:
    return summary.to_json(indent=indent)

def export_sarif(summary: ScanSummary) -> str:
    return json.dumps(summary.to_sarif(), indent=2, default=str)

def export_csv(summary: ScanSummary) -> str:
    rows = summary.to_csv_rows()
    if not rows: return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def export_summary(summary: ScanSummary) -> str:
    """Rich terminal-friendly summary with secrets section."""
    s = summary
    bar = "=" * 76
    thin = "-" * 76

    lines = [
        "", bar,
        "   QUANTUM PROTOCOL v3.5 — Security Scan Report",
        "   Cryptographic Vulnerabilities + Secrets & Credential Exposure",
        bar,
        f"  Scan ID          : {s.scan_id}",
        f"  Source            : {s.source}",
        f"  Mode             : {s.scan_mode}  |  Duration: {s.duration_seconds:.1f}s",
        f"  Files Scanned    : {s.files_scanned}  |  Skipped: {s.files_skipped}",
        f"  Languages        : {', '.join(s.languages_detected) or 'none'}",
        thin,
        "  FINDINGS OVERVIEW",
        thin,
        f"  Total            : {s.total_findings}",
        f"  Critical         : {s.critical_count}",
        f"  High             : {s.high_count}",
        f"  Medium           : {s.medium_count}",
        f"  Low              : {s.low_count}",
        f"  HNDL-Relevant    : {s.hndl_count}",
        f"  PQC-Ready        : {s.pqc_ready_count}",
    ]

    # ── SECRETS SECTION ──────────────────────────────────────────────
    if s.secrets_count > 0:
        lines.extend([
            thin,
            "  EXPOSED SECRETS & CREDENTIALS",
            thin,
            f"  Secrets Found    : {s.secrets_count}  ({s.secrets_critical} CRITICAL)",
        ])
        if s.secrets_by_provider:
            lines.append(f"  By Provider:")
            for provider, count in list(s.secrets_by_provider.items())[:15]:
                lines.append(f"    {provider:<25}: {count}")
        if s.attack_surface_summary:
            lines.append(f"  Attack Surface:")
            for surface, count in list(s.attack_surface_summary.items())[:10]:
                lines.append(f"    {surface:<35}: {count}")

    # ── SCORES ───────────────────────────────────────────────────────
    def _score_tag(val, high_bad=True):
        if high_bad:
            if val >= 70: return "[CRITICAL]"
            if val >= 40: return "[HIGH]"
            if val >= 15: return "[MODERATE]"
            return "[LOW]"
        else:
            if val >= 70: return "[GOOD]"
            if val >= 40: return "[FAIR]"
            return "[POOR]"

    lines.extend([
        thin,
        "  SECURITY SCORES",
        thin,
        f"  Overall Security : {s.overall_security_score:.1f}/100  {_score_tag(s.overall_security_score, high_bad=False)}",
        f"  Quantum Risk     : {s.quantum_risk_score:.1f}/100  {_score_tag(s.quantum_risk_score)}",
        f"  Secrets Exposure : {s.secrets_exposure_score:.1f}/100  {_score_tag(s.secrets_exposure_score)}",
        f"  Crypto Agility   : {s.crypto_agility_score:.1f}/100  {_score_tag(s.crypto_agility_score, high_bad=False)}",
    ])

    # ── COMPLIANCE ───────────────────────────────────────────────────
    if s.compliance_summary:
        lines.extend([thin, "  COMPLIANCE VIOLATIONS", thin])
        for fw, count in s.compliance_summary.items():
            lines.append(f"    {fw:<28}: {count} violation(s)")

    # ── DETAILED FINDINGS ────────────────────────────────────────────
    if s.findings:
        lines.extend([thin, "  DETAILED FINDINGS (sorted by risk)", thin])
        sorted_f = sorted(s.findings, key=lambda f: (-f.risk.numeric, -f.confidence, f.file))
        for f in sorted_f:
            icon = {"Critical": "[!!!]", "High": "[!! ]", "Medium": "[!  ]",
                    "Low": "[.  ]", "Info": "[i  ]"}.get(f.risk.value, "[?  ]")
            kind = "SECRET" if f.is_secret else "CRYPTO"
            lines.append(
                f"  {icon} {f.risk.value:8s}  [{kind:6s}]  {f.file}:{f.line_number}  "
                f"{f.algorithm}  (conf={f.confidence:.0%})"
            )
            lines.append(f"           {f.pattern_note}")
            if f.is_secret:
                if f.secret_provider:
                    lines.append(f"           Provider: {f.secret_provider}  |  Surface: {f.attack_surface or 'unknown'}")
                action = f.migration.get("action", "")
                if action:
                    lines.append(f"           -> ACTION: {action}")
            else:
                repl = (f.migration.get("kem") or f.migration.get("sign") or
                        f.migration.get("replacement") or f.migration.get("hybrid_kem") or "")
                if repl:
                    lines.append(f"           -> Migrate to: {repl}")
            if f.cwe_id:
                lines.append(f"           CWE: {f.cwe_id}")
            if f.compliance_violations:
                lines.append(f"           Compliance: {', '.join(f.compliance_violations)}")
            lines.append("")

    if s.errors:
        lines.extend([thin, f"  ERRORS ({len(s.errors)})", thin])
        for err in s.errors[:20]:
            lines.append(f"    {err}")

    lines.extend([bar, ""])
    return "\n".join(lines)


def export_html_dashboard(summary: ScanSummary) -> str:
    """Self-contained HTML dashboard with secrets section."""
    s = summary
    findings_json = json.dumps([f.to_dict() for f in s.findings], default=str)

    # Build dynamic sections in Python (avoids f-string nesting issues)
    provider_html = ""
    if s.secrets_by_provider:
        cards = "".join(
            f'<div class="cd"><div class="cl">{p}</div><div class="cv se">{c}</div></div>'
            for p, c in list(s.secrets_by_provider.items())[:12]
        )
        provider_html = f'<h2>Exposed Secrets by Provider</h2><div class="g" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr))">{cards}</div>'

    surface_html = ""
    if s.attack_surface_summary:
        rows = "".join(f"<tr><td>{srf}</td><td>{cnt}</td></tr>" for srf, cnt in s.attack_surface_summary.items())
        surface_html = f'<h2>Attack Surface Map</h2><table><thead><tr><th>Surface</th><th>Exposed Secrets</th></tr></thead><tbody>{rows}</tbody></table>'

    compliance_html = ""
    if s.compliance_summary:
        rows = "".join(f"<tr><td>{fw}</td><td>{c}</td></tr>" for fw, c in s.compliance_summary.items())
        compliance_html = f'<h2>Compliance Violations</h2><table><thead><tr><th>Framework</th><th>Violations</th></tr></thead><tbody>{rows}</tbody></table>'

    overall_class = "pq" if s.overall_security_score >= 70 else "me" if s.overall_security_score >= 40 else "cr"
    qr_class = "cr" if s.quantum_risk_score >= 70 else "hi" if s.quantum_risk_score >= 40 else "me" if s.quantum_risk_score >= 15 else "lo"
    se_class = "cr" if s.secrets_exposure_score >= 70 else "hi" if s.secrets_exposure_score >= 40 else "me" if s.secrets_exposure_score >= 15 else "lo"
    ag_class = "pq" if s.crypto_agility_score >= 70 else "me" if s.crypto_agility_score >= 40 else "cr"
    overall_bg = "var(--pq)" if s.overall_security_score >= 70 else "var(--me)" if s.overall_security_score >= 40 else "var(--cr)"

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quantum Protocol v3.5 — Scan Report</title>
<style>
:root{{--bg:#0f1117;--sf:#1a1d27;--bd:#2a2d3a;--tx:#e4e4e7;--mu:#71717a;--ac:#6366f1;
--cr:#ef4444;--hi:#f97316;--me:#eab308;--lo:#3b82f6;--in:#6b7280;--pq:#10b981;--se:#f43f5e}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--tx);padding:2rem}}
.c{{max-width:1400px;margin:0 auto}}
h1{{font-size:1.8rem;margin-bottom:.3rem}}
h2{{font-size:1.2rem;margin:1.5rem 0 .75rem;color:var(--ac)}}
.sub{{color:var(--mu);margin-bottom:2rem;font-size:.9rem}}
.g{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.75rem;margin-bottom:1.5rem}}
.cd{{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:1rem}}
.cl{{font-size:.7rem;color:var(--mu);text-transform:uppercase;letter-spacing:.04em}}
.cv{{font-size:1.8rem;font-weight:700;margin-top:.15rem}}
.cv.cr{{color:var(--cr)}}.cv.hi{{color:var(--hi)}}.cv.me{{color:var(--me)}}
.cv.lo{{color:var(--lo)}}.cv.pq{{color:var(--pq)}}.cv.se{{color:var(--se)}}
table{{width:100%;border-collapse:collapse;background:var(--sf);border-radius:10px;overflow:hidden;margin-bottom:1.5rem}}
th,td{{padding:.6rem .8rem;text-align:left;border-bottom:1px solid var(--bd);font-size:.8rem}}
th{{background:#12141d;color:var(--mu);font-weight:600;text-transform:uppercase;font-size:.7rem}}
tr:hover td{{background:#1e2130}}
.b{{display:inline-block;padding:.15rem .5rem;border-radius:5px;font-size:.7rem;font-weight:600}}
.b-cr{{background:#ef444420;color:var(--cr)}}.b-hi{{background:#f9731620;color:var(--hi)}}
.b-me{{background:#eab30820;color:var(--me)}}.b-lo{{background:#3b82f620;color:var(--lo)}}
.b-in{{background:#6b728020;color:var(--in)}}
.b-sec{{background:#f43f5e20;color:var(--se)}}.b-cry{{background:#6366f120;color:var(--ac)}}
.sb{{height:8px;border-radius:4px;background:var(--bd);margin-top:.4rem;overflow:hidden}}
.sf{{height:100%;border-radius:4px}}
.fb{{display:flex;gap:.4rem;margin-bottom:.75rem;flex-wrap:wrap}}
.fn{{padding:.3rem .6rem;border:1px solid var(--bd);border-radius:6px;background:var(--sf);color:var(--tx);cursor:pointer;font-size:.75rem}}
.fn.ac{{border-color:var(--ac);background:#6366f120}}
.m{{font-family:'JetBrains Mono','Fira Code',monospace;font-size:.75rem}}
</style></head><body>
<div class="c">
<h1>Quantum Protocol v3.5 — Security Scan Report</h1>
<p class="sub">Scan ID: {s.scan_id} | Source: {s.source} | {s.duration_seconds:.1f}s | {s.files_scanned} files | {len(s.languages_detected)} languages</p>

<div class="g">
<div class="cd"><div class="cl">Overall Security</div><div class="cv {overall_class}">{s.overall_security_score:.0f}</div><div class="sb"><div class="sf" style="width:{s.overall_security_score}%;background:{overall_bg}"></div></div></div>
<div class="cd"><div class="cl">Total Findings</div><div class="cv">{s.total_findings}</div></div>
<div class="cd"><div class="cl">Critical</div><div class="cv cr">{s.critical_count}</div></div>
<div class="cd"><div class="cl">High</div><div class="cv hi">{s.high_count}</div></div>
<div class="cd"><div class="cl">Secrets Exposed</div><div class="cv se">{s.secrets_count}</div></div>
<div class="cd"><div class="cl">HNDL Risk</div><div class="cv hi">{s.hndl_count}</div></div>
<div class="cd"><div class="cl">PQC Ready</div><div class="cv pq">{s.pqc_ready_count}</div></div>
</div>

<div class="g" style="grid-template-columns:repeat(4,1fr)">
<div class="cd"><div class="cl">Quantum Risk</div><div class="cv {qr_class}">{s.quantum_risk_score:.0f}/100</div></div>
<div class="cd"><div class="cl">Secrets Exposure</div><div class="cv {se_class}">{s.secrets_exposure_score:.0f}/100</div></div>
<div class="cd"><div class="cl">Crypto Agility</div><div class="cv {ag_class}">{s.crypto_agility_score:.0f}/100</div></div>
<div class="cd"><div class="cl">Secrets Critical</div><div class="cv se">{s.secrets_critical}</div></div>
</div>

{provider_html}

{surface_html}

{compliance_html}

<h2>All Findings</h2>
<div class="fb">
<button class="fn ac" onclick="filterT('all')">All ({s.total_findings})</button>
<button class="fn" onclick="filterT('secret')">Secrets ({s.secrets_count})</button>
<button class="fn" onclick="filterT('crypto')">Crypto ({s.total_findings - s.secrets_count})</button>
<button class="fn" onclick="filterT('Critical')">Critical ({s.critical_count})</button>
<button class="fn" onclick="filterT('High')">High ({s.high_count})</button>
</div>
<table><thead><tr><th>Type</th><th>Risk</th><th>File</th><th>Line</th><th>Algorithm / Provider</th><th>Conf</th><th>CWE</th><th>Note</th></tr></thead>
<tbody id="tb"></tbody></table>
</div>
<script>
const F={findings_json};
const tb=document.getElementById('tb');
function render(d){{tb.innerHTML=d.map(f=>{{
const r=f.risk,isSec=f.is_secret;
const rb=`<span class="b b-${{r.toLowerCase()}}">${{r}}</span>`;
const tb2=isSec?`<span class="b b-sec">SECRET</span>`:`<span class="b b-cry">CRYPTO</span>`;
return`<tr data-risk="${{r}}" data-type="${{isSec?'secret':'crypto'}}">
<td>${{tb2}}</td><td>${{rb}}</td><td class="m">${{f.file}}</td><td>${{f.line_number}}</td>
<td>${{isSec?(f.secret_provider||f.algorithm):f.algorithm}}</td>
<td>${{(f.confidence*100).toFixed(0)}}%</td><td>${{f.cwe_id||''}}</td>
<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${{f.pattern_note}}</td></tr>`;
}}).join('')}}
function filterT(t){{
document.querySelectorAll('.fn').forEach(b=>b.classList.remove('ac'));
event.target.classList.add('ac');
if(t==='all')render(F);
else if(t==='secret')render(F.filter(f=>f.is_secret));
else if(t==='crypto')render(F.filter(f=>!f.is_secret));
else render(F.filter(f=>f.risk===t));
}}
render(F);
</script></body></html>"""


def export_to_file(summary: ScanSummary, output_path: str, fmt: str = "json") -> None:
    exporters = {"json": export_json, "sarif": export_sarif, "csv": export_csv,
                 "html": export_html_dashboard, "summary": export_summary}
    exporter = exporters.get(fmt)
    if not exporter:
        raise ValueError(f"Unsupported format: {fmt}")
    Path(output_path).write_text(exporter(summary), encoding="utf-8")
