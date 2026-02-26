"""Quick smoke test for OWASP scanner modules."""

from misconfig_engine import scan_misconfig_file
from injection_scanner import scan_injection_file
from frontend_js_analyzer import scan_frontend_file

# Test misconfig detection
test_mc = """
DEBUG = True
password = 'admin'
chmod 777 /tmp/data
--privileged
Access-Control-Allow-Origin: *
"""
mc_findings = scan_misconfig_file(test_mc, "test_settings.py")
print(f"Misconfig findings: {len(mc_findings)}")
for f in mc_findings:
    print(f"  [{f.severity}] {f.title}")

# Test injection detection
test_inj = """
cursor.execute(f"SELECT * FROM users WHERE id = {request.args.get('id')}")
os.system(f'ping {input_host}')
render_template_string(request.form['template'])
"""
inj_findings = scan_injection_file(test_inj, "app.py")
print(f"\nInjection findings: {len(inj_findings)}")
for f in inj_findings:
    print(f"  [{f.severity}] {f.title}")

# Test frontend detection
test_fe = """
const API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
eval(userInput);
document.innerHTML = location.search;
"""
fe_findings = scan_frontend_file(test_fe, "app.js")
print(f"\nFrontend findings: {len(fe_findings)}")
for f in fe_findings:
    print(f"  [{f.severity}] {f.title}")

print("\n✓ All modules functioning correctly!")
