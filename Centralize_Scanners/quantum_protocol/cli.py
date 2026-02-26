"""
Quantum Protocol v4.0 — CLI Interface
Full-spectrum security scanner with OWASP Top 10:2025 coverage.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from quantum_protocol.models.enums import ScanMode, OutputFormat
from quantum_protocol.core.engine import (
    scan_directory, build_file_reports, build_compliance_summary,
    build_secrets_by_provider, build_attack_surface_summary,
    compute_quantum_risk_score, compute_agility_score,
    compute_secrets_exposure_score, compute_overall_security_score,
    compute_vuln_risk_score, build_owasp_coverage, build_vuln_by_category,
)
from quantum_protocol.models.findings import ScanSummary


def main():
    parser = argparse.ArgumentParser(
        prog="quantum-protocol",
        description="Quantum Protocol v4.0 — Full-Spectrum Security Scanner\n"
                    "OWASP Top 10:2025 | Secrets | Crypto | Cloud | API | Frontend | Recon",
    )
    parser.add_argument("path", help="Directory or file to scan")
    parser.add_argument("-m", "--mode", default="full",
                        choices=[m.value for m in ScanMode],
                        help="Scan mode (default: full)")
    parser.add_argument("-f", "--format", default="summary",
                        choices=[f.value for f in OutputFormat],
                        help="Output format (default: summary)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--max-files", type=int, default=50_000)
    parser.add_argument("--min-confidence", type=float, default=0.30)
    parser.add_argument("--version", action="version", version="Quantum Protocol v4.0.0")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(1)

    mode = ScanMode(args.mode)
    start = time.time()

    # Progress callback
    def progress(fname, idx, total):
        if args.verbose:
            print(f"  [{idx}/{total}] {fname}", file=sys.stderr)

    findings, errors, scanned, skipped, languages = scan_directory(
        target, mode, progress, args.max_files
    )

    # Filter by confidence
    findings = [f for f in findings if f.confidence >= args.min_confidence]

    duration = time.time() - start

    # Compute scores
    qr = compute_quantum_risk_score(findings)
    ag = compute_agility_score(findings)
    se = compute_secrets_exposure_score(findings)
    vr = compute_vuln_risk_score(findings)
    overall = compute_overall_security_score(qr, se, ag, vr)

    summary = ScanSummary(
        scan_id=f"QP-{int(time.time())}",
        scanner_version="4.0.0",
        source=str(target),
        source_type="directory" if target.is_dir() else "file",
        scan_mode=mode.value,
        started_at="",
        completed_at="",
        duration_seconds=round(duration, 2),
        files_scanned=scanned,
        files_skipped=skipped,
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.risk.value == "Critical"),
        high_count=sum(1 for f in findings if f.risk.value == "High"),
        medium_count=sum(1 for f in findings if f.risk.value == "Medium"),
        low_count=sum(1 for f in findings if f.risk.value == "Low"),
        info_count=sum(1 for f in findings if f.risk.value == "Info"),
        hndl_count=sum(1 for f in findings if f.hndl_relevant),
        pqc_ready_count=sum(1 for f in findings if f.family.is_pqc_safe),
        secrets_count=sum(1 for f in findings if f.is_secret),
        secrets_critical=sum(1 for f in findings if f.is_secret and f.risk.value == "Critical"),
        secrets_by_provider=build_secrets_by_provider(findings),
        attack_surface_summary=build_attack_surface_summary(findings),
        vuln_count=sum(1 for f in findings if f.family.is_vuln),
        vuln_by_category=build_vuln_by_category(findings),
        owasp_coverage=build_owasp_coverage(findings),
        recon_count=sum(1 for f in findings if f.family.is_recon),
        quantum_risk_score=qr,
        crypto_agility_score=ag,
        secrets_exposure_score=se,
        vuln_risk_score=vr,
        overall_security_score=overall,
        languages_detected=sorted(languages),
        compliance_summary=build_compliance_summary(findings),
        findings=findings,
        file_reports=build_file_reports(findings),
        errors=errors,
    )

    # Output
    fmt = OutputFormat(args.format)
    if fmt == OutputFormat.JSON:
        output = summary.to_json()
    elif fmt == OutputFormat.SARIF:
        output = json.dumps(summary.to_sarif(), indent=2)
    elif fmt == OutputFormat.CSV:
        import csv, io
        buf = io.StringIO()
        rows = summary.to_csv_rows()
        if rows:
            w = csv.DictWriter(buf, fieldnames=rows[0].keys())
            w.writeheader()
            w.writerows(rows)
        output = buf.getvalue()
    else:
        output = _format_summary(summary)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


def _format_summary(s: ScanSummary) -> str:
    lines = [
        "",
        "╔══════════════════════════════════════════════════════════════╗",
        "║         QUANTUM PROTOCOL v4.0 — SCAN RESULTS               ║",
        "║     Full-Spectrum Security Scanner + OWASP Top 10:2025      ║",
        "╚══════════════════════════════════════════════════════════════╝",
        "",
        f"  Source:      {s.source}",
        f"  Mode:        {s.scan_mode}",
        f"  Duration:    {s.duration_seconds:.1f}s",
        f"  Files:       {s.files_scanned} scanned, {s.files_skipped} skipped",
        f"  Languages:   {', '.join(s.languages_detected) or 'N/A'}",
        "",
        "── FINDINGS OVERVIEW ──────────────────────────────────────────",
        f"  Total:       {s.total_findings}",
        f"  Critical:    {s.critical_count}",
        f"  High:        {s.high_count}",
        f"  Medium:      {s.medium_count}",
        f"  Low:         {s.low_count}",
        f"  Info:        {s.info_count}",
        "",
        "── CATEGORY BREAKDOWN ────────────────────────────────────────",
        f"  Secrets:     {s.secrets_count} ({s.secrets_critical} critical)",
        f"  OWASP Vulns: {s.vuln_count}",
        f"  Recon Intel: {s.recon_count}",
        f"  Crypto:      {s.total_findings - s.secrets_count - s.vuln_count - s.recon_count}",
        f"  PQC Ready:   {s.pqc_ready_count}",
    ]

    if s.vuln_by_category:
        lines.append("")
        lines.append("── OWASP VULNERABILITY CATEGORIES ─────────────────────────────")
        for cat, cnt in s.vuln_by_category.items():
            lines.append(f"  {cat}: {cnt}")

    if s.owasp_coverage:
        lines.append("")
        lines.append("── OWASP TOP 10:2025 COVERAGE ─────────────────────────────────")
        for cat, cnt in s.owasp_coverage.items():
            bar = "█" * min(cnt, 30)
            lines.append(f"  {cat}: {cnt} {bar}")

    lines.extend([
        "",
        "── SECURITY SCORES ────────────────────────────────────────────",
        f"  Overall Security:     {s.overall_security_score:.0f}/100 {'🟢' if s.overall_security_score >= 80 else '🟡' if s.overall_security_score >= 50 else '🔴'}",
        f"  Quantum Risk:         {s.quantum_risk_score:.0f}/100",
        f"  Secrets Exposure:     {s.secrets_exposure_score:.0f}/100",
        f"  Vulnerability Risk:   {s.vuln_risk_score:.0f}/100",
        f"  Crypto Agility:       {s.crypto_agility_score:.0f}/100",
    ])

    if s.compliance_summary:
        lines.append("")
        lines.append("── COMPLIANCE VIOLATIONS ───────────────────────────────────────")
        for fw, cnt in list(s.compliance_summary.items())[:10]:
            lines.append(f"  {fw}: {cnt}")

    if s.errors:
        lines.append("")
        lines.append(f"── ERRORS ({len(s.errors)}) ─────────────────────────────────")
        for e in s.errors[:5]:
            lines.append(f"  ⚠ {e}")

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
