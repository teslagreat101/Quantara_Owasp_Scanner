"""
Quantum Protocol v5.0 — Report Generation Module
PDF, HTML, and JSON report generation for scan results.

Phase 8.4: PDF/HTML Report Generation
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


class ReportGenerator:
    """Generate scan reports in multiple formats."""

    @staticmethod
    def generate_json_report(scan_data: Dict[str, Any]) -> str:
        """Generate JSON report."""
        return json.dumps(scan_data, indent=2, default=str)

    @staticmethod
    def generate_html_report(scan_data: Dict[str, Any]) -> str:
        """Generate HTML report."""
        findings = scan_data.get("findings", [])
        summary = scan_data.get("summary", {})
        owasp_coverage = scan_data.get("owasp_coverage", {})
        top_files = scan_data.get("top_files", [])

        severity_colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#22c55e",
            "info": "#6b7280",
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_data.get('target', 'Unknown')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', -apple-system, sans-serif; 
            background: #0B0F0C; 
            color: #A5B3AD; 
            line-height: 1.6;
            padding: 40px 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00FF88; font-size: 2.5rem; margin-bottom: 8px; }}
        h2 {{ color: #fff; font-size: 1.5rem; margin: 32px 0 16px; border-bottom: 2px solid rgba(0,255,136,0.2); padding-bottom: 8px; }}
        .header-info {{ display: flex; gap: 24px; flex-wrap: wrap; margin: 16px 0; }}
        .header-info span {{ color: #6B7F77; }}
        .header-info strong {{ color: #fff; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 24px 0; }}
        .stat {{ 
            background: #111716; 
            border: 1px solid rgba(0,255,136,0.15); 
            border-radius: 12px; 
            padding: 20px;
            text-align: center;
        }}
        .stat-value {{ font-size: 2.5rem; font-weight: 700; }}
        .stat-label {{ font-size: 0.875rem; color: #6B7F77; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
        th {{ 
            background: rgba(0,255,136,0.08); 
            color: #00FF88; 
            text-align: left; 
            padding: 14px; 
            font-size: 0.75rem; 
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{ padding: 14px; border-bottom: 1px solid rgba(0,255,136,0.06); font-size: 0.9rem; }}
        tr:hover {{ background: rgba(0,255,136,0.02); }}
        .sev {{ 
            display: inline-block; 
            padding: 4px 12px; 
            border-radius: 20px; 
            font-size: 0.75rem; 
            font-weight: 600;
            text-transform: uppercase;
        }}
        .file-path {{ color: #00FF88; font-family: monospace; font-size: 0.8rem; }}
        .cwe {{ color: #6B7F77; font-size: 0.8rem; }}
        .remediation {{ 
            background: rgba(0,255,136,0.03); 
            border-left: 3px solid #00FF88;
            padding: 12px;
            margin-top: 8px;
            border-radius: 0 8px 8px 0;
        }}
        .footer {{ 
            text-align: center; 
            margin-top: 60px; 
            padding-top: 20px;
            border-top: 1px solid rgba(0,255,136,0.1);
            color: #3D4F48; 
            font-size: 0.75rem; 
        }}
        .risk-score {{ 
            display: inline-block;
            padding: 8px 24px;
            border-radius: 30px;
            font-size: 1.5rem;
            font-weight: bold;
            color: #000;
            background: linear-gradient(135deg, #00FF88, #00C853);
        }}
        .owasp-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 16px 0; }}
        .owasp-item {{ 
            background: #111716; 
            border: 1px solid rgba(0,255,136,0.1);
            border-radius: 8px;
            padding: 12px 16px;
        }}
        .owasp-name {{ color: #fff; font-size: 0.9rem; }}
        .owasp-count {{ color: #00FF88; font-size: 0.8rem; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 OWASP Security Scan Report</h1>
        <div class="header-info">
            <span>Target: <strong>{scan_data.get('target', 'Unknown')}</strong></span>
            <span>Status: <strong>{scan_data.get('status', 'Unknown')}</strong></span>
            <span>Duration: <strong>{scan_data.get('duration', 0)}s</strong></span>
            <span>Risk Score: <span class="risk-score">{scan_data.get('risk_score', 0)}/100</span></span>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            {''.join(f'''
            <div class="stat">
                <div class="stat-value" style="color: {severity_colors.get(sev, '#6b7280')}">{count}</div>
                <div class="stat-label">{sev.title()} Severity</div>
            </div>
            ''' for sev, count in summary.items() if count > 0)}
            <div class="stat">
                <div class="stat-value" style="color: #00FF88">{len(findings)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>

        <h2>OWASP Coverage</h2>
        <div class="owasp-grid">
            {''.join(f'''
            <div class="owasp-item">
                <div class="owasp-name">{owasp}</div>
                <div class="owasp-count">{data.get('count', 0)} findings</div>
            </div>
            ''' for owasp, data in owasp_coverage.items()) if owasp_coverage else '<p style="color: #6B7F77;">No OWASP categories detected</p>'}
        </div>

        <h2>Top Vulnerable Files</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Finding Count</th>
                </tr>
            </thead>
            <tbody>
                {''.join(f'''
                <tr>
                    <td class="file-path">{file.get('file', 'Unknown')}</td>
                    <td>{file.get('count', 0)}</td>
                </tr>
                ''' for file in top_files[:10]) if top_files else '<tr><td colspan="2" style="color: #6B7F77;">No vulnerable files detected</td></tr>'}
            </tbody>
        </table>

        <h2>Findings Detail ({len(findings)} total)</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Location</th>
                    <th>CWE</th>
                </tr>
            </thead>
            <tbody>
                {''.join(f'''
                <tr>
                    <td>
                        <span class="sev" style="background: {severity_colors.get(f.get('severity', 'info').lower(), '#6b7280')}20; color: {severity_colors.get(f.get('severity', 'info').lower(), '#6b7280')}">
                            {f.get('severity', 'Info').upper()}
                        </span>
                    </td>
                    <td style="color: #fff; font-weight: 500;">{f.get('title', 'Unknown')}</td>
                    <td class="file-path">{f.get('file', 'Unknown')}:{f.get('line_number', 0)}</td>
                    <td class="cwe">{f.get('cwe', 'N/A')}</td>
                </tr>
                <tr>
                    <td colspan="4" style="padding-top: 0; border-bottom: 2px solid rgba(0,255,136,0.1);">
                        <p style="color: #A5B3AD; margin-bottom: 8px;">{f.get('description', 'No description')}</p>
                        <div class="remediation">
                            <strong style="color: #00FF88;">Remediation:</strong>
                            <p style="margin-top: 4px; color: #A5B3AD;">{f.get('remediation', 'No remediation provided')}</p>
                        </div>
                    </td>
                </tr>
                ''' for f in findings) if findings else '<tr><td colspan="4" style="text-align: center; color: #6B7F77; padding: 40px;">No findings detected</td></tr>'}
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by Quantum Protocol v5.0 OWASP Scanner</p>
            <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
</body>
</html>"""
        return html

    @staticmethod
    def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
        """Generate PDF report from HTML."""
        if not WEASYPRINT_AVAILABLE:
            # Return placeholder if weasyprint not installed
            raise ImportError("weasyprint not installed. Run: pip install weasyprint")
        
        html_content = ReportGenerator.generate_html_report(scan_data)
        html = HTML(string=html_content)
        return html.write_pdf()

    @staticmethod
    def save_report(scan_data: Dict[str, Any], format: str, output_path: str) -> str:
        """Save report to file."""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == "json":
            content = ReportGenerator.generate_json_report(scan_data)
            with open(output_path, "w") as f:
                f.write(content)
        
        elif format.lower() == "html":
            content = ReportGenerator.generate_html_report(scan_data)
            with open(output_path, "w") as f:
                f.write(content)
        
        elif format.lower() == "pdf":
            content = ReportGenerator.generate_pdf_report(scan_data)
            with open(output_path, "wb") as f:
                f.write(content)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        return output_path


# Singleton instance
report_generator = ReportGenerator()
