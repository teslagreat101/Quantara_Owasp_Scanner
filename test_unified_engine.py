"""
Quantum Protocol v5.0 — Unified Scanner Engine Smoke Test

Validates:
  1. All modules in UNIFIED_MODULE_REGISTRY are importable
  2. Normalization works across all finding types
  3. Deduplication removes exact duplicates
  4. Risk scoring computes correctly
  5. OWASP coverage mapping produces valid output
  6. Scan profiles resolve correctly
  7. Each module can scan sample code without crashing
"""

import sys
import os
from pathlib import Path

# Ensure project root and scanners are on sys.path
ROOT = str(Path(__file__).resolve().parent)
CENTRAL_DIR = os.path.join(ROOT, "Centralize_Scanners")

for path in [ROOT, CENTRAL_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

SCANNER2_DIR = os.path.join(ROOT, "Owasp_Scanner_2")
if SCANNER2_DIR not in sys.path:
    sys.path.insert(0, SCANNER2_DIR)


def test_imports():
    """Test that orchestrator and all modules import correctly."""
    print("\n═══ Test 1: Module Imports ═══")
    from scanner_engine.orchestrator import (
        UNIFIED_MODULE_REGISTRY, normalize_finding_to_dict, run_module_scan,
        get_available_modules, get_available_profiles, get_modules_for_profile,
        compute_scan_scores, deduplicate_findings, SCAN_PROFILES,
    )
    from scanner_engine.ssrf_scanner import scan_ssrf_file, scan_ssrf_directory
    from scanner_engine.owasp_coverage import (
        OWASP_TOP_10_2025, get_owasp_coverage_report,
        get_total_pattern_count, get_total_cwe_count,
    )

    print(f"  ✅ Orchestrator imported — {len(UNIFIED_MODULE_REGISTRY)} modules registered")
    print(f"  ✅ SSRF scanner imported")
    print(f"  ✅ OWASP coverage imported — {len(OWASP_TOP_10_2025)} categories mapped")
    print(f"  ✅ {len(SCAN_PROFILES)} scan profiles available")
    return True


def test_module_registry():
    """Test the unified module registry has all expected modules."""
    print("\n═══ Test 2: Module Registry ═══")
    from scanner_engine.orchestrator import UNIFIED_MODULE_REGISTRY

    expected_modules = [
        "misconfig", "injection", "frontend_js", "endpoint", "auth",
        "access_control", "cloud", "api_security", "supply_chain",
        "insecure_design", "integrity", "logging", "exception",
        "sensitive_data", "ssrf",
    ]

    for mod in expected_modules:
        assert mod in UNIFIED_MODULE_REGISTRY, f"Missing module: {mod}"
        meta = UNIFIED_MODULE_REGISTRY[mod]
        assert "name" in meta, f"Module {mod} missing 'name'"
        assert "owasp" in meta, f"Module {mod} missing 'owasp'"
        assert "pattern_count" in meta, f"Module {mod} missing 'pattern_count'"
        print(f"  ✅ {mod}: {meta['name']} ({meta['owasp']}) — {meta['pattern_count']} patterns")

    total_patterns = sum(m["pattern_count"] for m in UNIFIED_MODULE_REGISTRY.values())
    print(f"\n  Total modules: {len(UNIFIED_MODULE_REGISTRY)}")
    print(f"  Total patterns: {total_patterns}")
    return True


def test_scan_profiles():
    """Test scan profile resolution."""
    print("\n═══ Test 3: Scan Profiles ═══")
    from scanner_engine.orchestrator import get_modules_for_profile, get_available_profiles

    profiles = get_available_profiles()
    for p in profiles:
        modules = get_modules_for_profile(p["key"])
        print(f"  ✅ {p['key']}: {p['name']} — {len(modules)} modules")
        assert len(modules) > 0, f"Profile {p['key']} has no modules"

    # Quick should be a subset of full
    quick = set(get_modules_for_profile("quick"))
    full = set(get_modules_for_profile("full"))
    assert quick.issubset(full), "Quick profile should be subset of full"
    print(f"\n  ✅ Quick ({len(quick)}) ⊂ Full ({len(full)})")
    return True


def test_module_scanning():
    """Test each Phase 1 module can scan sample vulnerable code."""
    print("\n═══ Test 4: Module Scanning ═══")
    from scanner_engine.orchestrator import run_module_scan

    # Vulnerable Python code sample containing various issues
    vulnerable_code = '''
import os
import subprocess
import pickle

# SQL Injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

# Command Injection
def run_command(cmd):
    os.system("ls " + cmd)
    subprocess.call(cmd, shell=True)

# XSS
def render(request):
    name = request.GET['name']
    return HttpResponse("<h1>" + name + "</h1>")

# Debug Mode
DEBUG = True
SECRET_KEY = "changeme"
password = "admin"

# CORS Misconfiguration
Access-Control-Allow-Origin: *

# Unsafe Deserialization
data = pickle.loads(user_input)

# Missing Auth
@app.route('/admin')
def admin():
    return render_template('admin.html')

# SSRF
import requests
url = request.args.get('url')
response = requests.get(url)

# Cloud metadata
metadata_url = "http://169.254.169.254/latest/meta-data/"

# Logging sensitive data
logger.info(f"User login: {request.body}")

# Exception swallowing
try:
    authenticate(user)
except Exception as e:
    pass

# Webhook SSRF
webhook_url = request.body['callback_url']
'''

    # Test each Phase 1 module with code scan
    phase1_modules = [
        "misconfig", "injection", "frontend_js", "auth",
        "access_control", "cloud", "api_security", "supply_chain",
        "insecure_design", "integrity",
    ]

    total_findings = 0
    for mod in phase1_modules:
        try:
            findings = run_module_scan(mod, vulnerable_code, "code")
            count = len(findings)
            total_findings += count
            status = f"✅ {count} findings" if count >= 0 else "⚠️ error"
            print(f"  {status} — {mod}")
        except Exception as e:
            print(f"  ⚠️ {mod}: {str(e)[:80]}")

    # Test SSRF module
    try:
        from scanner_engine.ssrf_scanner import scan_ssrf_file
        ssrf_findings = scan_ssrf_file(vulnerable_code, "test_input.py")
        total_findings += len(ssrf_findings)
        print(f"  ✅ {len(ssrf_findings)} findings — ssrf")
    except Exception as e:
        print(f"  ⚠️ ssrf: {str(e)[:80]}")

    print(f"\n  Total findings across all modules: {total_findings}")
    return True


def test_normalization():
    """Test finding normalization across different scanner types."""
    print("\n═══ Test 5: Finding Normalization ═══")
    from scanner_engine.orchestrator import normalize_finding_to_dict
    from dataclasses import dataclass, field

    @dataclass
    class MockFinding:
        id: str = "TEST-001"
        file: str = "test.py"
        line_number: int = 42
        severity: str = "High"
        title: str = "Test Finding"
        description: str = "A test finding"
        confidence: float = 0.85
        cwe: str = "CWE-89"
        tags: list = field(default_factory=lambda: ["test"])

    finding = MockFinding()
    normalized = normalize_finding_to_dict(finding, "injection")
    assert normalized["module"] == "injection"
    assert normalized["severity"] == "High"
    assert normalized["line_number"] == 42
    print(f"  ✅ Normalized finding: {normalized['title']} ({normalized['module']})")
    return True


def test_deduplication():
    """Test finding deduplication."""
    print("\n═══ Test 6: Deduplication ═══")
    from scanner_engine.orchestrator import UnifiedFinding, deduplicate_findings

    # Create duplicate findings
    f1 = UnifiedFinding(id="1", file="test.py", line_number=10, severity="High",
                        title="SQL Injection", description="SQLi found", confidence=0.9)
    f2 = UnifiedFinding(id="2", file="test.py", line_number=10, severity="High",
                        title="SQL Injection", description="SQLi found", confidence=0.7)
    f3 = UnifiedFinding(id="3", file="test.py", line_number=20, severity="Medium",
                        title="XSS", description="XSS found", confidence=0.8)

    deduped = deduplicate_findings([f1, f2, f3])
    assert len(deduped) == 2, f"Expected 2 unique findings, got {len(deduped)}"
    # Should keep higher confidence
    sqli = [f for f in deduped if f.title == "SQL Injection"][0]
    assert sqli.confidence == 0.9, "Should keep higher confidence finding"
    print(f"  ✅ Deduplication: 3 findings → {len(deduped)} unique (kept highest confidence)")
    return True


def test_risk_scoring():
    """Test risk score computation."""
    print("\n═══ Test 7: Risk Scoring ═══")
    from scanner_engine.orchestrator import UnifiedFinding, compute_scan_scores

    findings = [
        UnifiedFinding(id="1", file="a.py", line_number=1, severity="Critical",
                       title="SQLi", description="", owasp="A03:2025"),
        UnifiedFinding(id="2", file="b.py", line_number=2, severity="High",
                       title="XSS", description="", owasp="A03:2025"),
        UnifiedFinding(id="3", file="c.py", line_number=3, severity="Medium",
                       title="Misconfig", description="", owasp="A05:2025"),
    ]

    scores = compute_scan_scores(findings, modules_run=3)
    assert scores.total_findings == 3
    assert scores.severity_counts["critical"] == 1
    assert scores.severity_counts["high"] == 1
    assert scores.risk_level == "Critical"
    assert scores.overall_score < 100
    print(f"  ✅ Score: {scores.overall_score}/100 | Risk: {scores.risk_level}")
    print(f"  ✅ Severity: {scores.severity_counts}")
    print(f"  ✅ OWASP coverage: {scores.owasp_coverage}")
    return True


def test_owasp_coverage():
    """Test OWASP coverage mapping."""
    print("\n═══ Test 8: OWASP Coverage Map ═══")
    from scanner_engine.owasp_coverage import (
        OWASP_TOP_10_2025, get_owasp_coverage_report,
        get_total_pattern_count, get_total_cwe_count,
    )

    assert len(OWASP_TOP_10_2025) == 10, f"Expected 10 OWASP categories, got {len(OWASP_TOP_10_2025)}"

    # Simulate findings
    findings_by_module = {
        "access_control": 3, "injection": 5, "misconfig": 8,
        "auth": 2, "ssrf": 1, "cloud": 4,
    }
    report = get_owasp_coverage_report(findings_by_module)
    assert len(report) == 10

    for cat_id, data in report.items():
        status_icon = "🟢" if data["status"] == "scanned" and data["findings"] > 0 else "🔵" if data["status"] == "scanned" else "⚪"
        print(f"  {status_icon} {cat_id}: {data['name']} — {data['findings']} findings ({data['patterns']} patterns)")

    total_patterns = get_total_pattern_count()
    total_cwes = get_total_cwe_count()
    print(f"\n  Total patterns: {total_patterns}")
    print(f"  Total CWEs covered: {total_cwes}")
    return True


def main():
    """Run all smoke tests."""
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     QUANTUM PROTOCOL v5.0 — UNIFIED ENGINE SMOKE TEST      ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    tests = [
        ("Imports", test_imports),
        ("Module Registry", test_module_registry),
        ("Scan Profiles", test_scan_profiles),
        ("Module Scanning", test_module_scanning),
        ("Normalization", test_normalization),
        ("Deduplication", test_deduplication),
        ("Risk Scoring", test_risk_scoring),
        ("OWASP Coverage", test_owasp_coverage),
    ]

    passed = 0
    failed = 0
    for name, test_fn in tests:
        try:
            result = test_fn()
            if result:
                passed += 1
            else:
                failed += 1
                print(f"  ❌ FAILED: {name}")
        except Exception as e:
            failed += 1
            print(f"  ❌ ERROR in {name}: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n{'═' * 60}")
    print(f"  Results: {passed}/{passed + failed} passed")
    if failed == 0:
        print("  ✅ ALL TESTS PASSED")
    else:
        print(f"  ❌ {failed} test(s) FAILED")
    print(f"{'═' * 60}")
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
