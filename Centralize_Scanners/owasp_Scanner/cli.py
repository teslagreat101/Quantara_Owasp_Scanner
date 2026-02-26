#!/usr/bin/env python3
"""
Quantum Protocol v3.5 — CLI Entry Point

Usage:
  quantum-scanner scan <path> [options]
  quantum-scanner repo <url> [options]
  quantum-scanner archive <file> [options]

Scan Modes:
  --mode full        All crypto + all secrets (default)
  --mode secrets     Secrets & credentials only
  --mode quantum     Only quantum-vulnerable crypto
  --mode quick       High-confidence patterns only
  --mode compliance  Map to compliance frameworks
"""

from __future__ import annotations
import argparse, json, logging, sys
from pathlib import Path
from quantum_protocol import __version__
from quantum_protocol.models.enums import RiskLevel, ScanMode
from quantum_protocol.core.engine import (
    scan_local_directory, scan_repository, scan_uploaded_archive,
)
from quantum_protocol.reporters.formatters import (
    export_json, export_sarif, export_csv, export_summary, export_html_dashboard,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quantum-scanner",
        description=f"Quantum Protocol v{__version__} — Crypto + Secrets Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  quantum-scanner scan ./my-project --format html --output report.html\n"
            "  quantum-scanner scan . --mode secrets           # secrets-only scan\n"
            "  quantum-scanner repo https://github.com/org/repo --token $GH_TOKEN\n"
            "  quantum-scanner scan . --mode quantum --min-conf 0.8\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="Scan a local directory")
    scan_cmd.add_argument("path", help="Directory to scan")
    _add_common_args(scan_cmd)

    repo_cmd = sub.add_parser("repo", help="Scan a Git repository")
    repo_cmd.add_argument("url", help="Repository HTTPS URL")
    repo_cmd.add_argument("--token", default=None)
    repo_cmd.add_argument("--branch", default="main")
    _add_common_args(repo_cmd)

    archive_cmd = sub.add_parser("archive", help="Scan a .zip or .tar.gz archive")
    archive_cmd.add_argument("file", help="Archive path")
    _add_common_args(archive_cmd)
    return parser


def _add_common_args(p):
    p.add_argument("--format", "-f", choices=["json","sarif","csv","html","summary"], default="summary")
    p.add_argument("--output", "-o", help="Output file path")
    p.add_argument("--mode", "-m", choices=["full","quick","quantum","secrets","compliance"], default="full")
    p.add_argument("--min-conf", type=float, default=0.0)
    p.add_argument("--risk-level", choices=["critical","high","medium","low","info"], default="info")
    p.add_argument("--secrets-only", action="store_true", help="Alias for --mode secrets")
    p.add_argument("--quiet", "-q", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")


def main():
    parser = build_parser()
    args = parser.parse_args()
    log_level = logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", stream=sys.stderr)

    scan_mode = ScanMode.SECRETS if args.secrets_only else ScanMode(args.mode)

    def progress(fname, cur, total):
        if not args.quiet:
            print(f"\r  [{cur:>5}/{total}] {fname[:60]:<60}", end="", file=sys.stderr)

    try:
        if args.command == "scan":
            result = scan_local_directory(args.path, scan_mode, progress)
        elif args.command == "repo":
            result = scan_repository(args.url, args.token, args.branch, scan_mode, progress)
        elif args.command == "archive":
            result = scan_uploaded_archive(args.file, scan_mode, progress)
        else:
            parser.print_help(); sys.exit(1)
    except Exception as exc:
        print(f"\n  Error: {exc}", file=sys.stderr)
        if args.verbose: import traceback; traceback.print_exc(file=sys.stderr)
        sys.exit(2)

    if not args.quiet: print(file=sys.stderr)

    # Post-filters
    risk_order = ["info","low","medium","high","critical"]
    min_idx = risk_order.index(args.risk_level)
    min_risks = set(RiskLevel(r.capitalize()) for r in risk_order[min_idx:])
    result.findings = [f for f in result.findings if f.confidence >= args.min_conf and f.risk in min_risks]
    result.total_findings = len(result.findings)

    exporters = {"json": export_json, "sarif": export_sarif, "csv": export_csv,
                 "html": export_html_dashboard, "summary": export_summary}
    output = exporters[args.format](result)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"  Output written to {args.output}", file=sys.stderr)
    else:
        print(output)

    sys.exit(1 if result.critical_count > 0 else 0)


if __name__ == "__main__":
    main()
