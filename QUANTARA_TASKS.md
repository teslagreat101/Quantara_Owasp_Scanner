# QUANTARA — Enterprise AI-Powered Attack Surface & Vulnerability Intelligence Platform
## Development Task Checklist

> Last Updated: 2026-02-24
> Platform: Quantara v1.0 (formerly "nuclei-inspired scanner")
> Status Legend: ✅ Done | 🔄 In Progress | ⬜ Pending | ❌ Blocked

---

## PHASE 0 — Foundation & Rebranding

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 0.1 | Rename nuclei_engine.py to quantara_engine.py | ✅ | `owasp_Scanner/quantara_engine.py` | All class names: QuantaraEngine, QuantaraTemplate, etc. |
| 0.2 | Rename nuclei_scanner.py to quantara_scanner.py | ✅ | `owasp_Scanner/quantara_scanner.py` | QuantaraWebScanner, QuantaraWebFinding, scan_url_with_quantara |
| 0.3 | Update orchestrator module key to quantara_http | ✅ | `scanner_engine/orchestrator.py` | Import, registry, routing, profile entries all updated |
| 0.4 | Update frontend module key to quantara_http | ✅ | `use-scanner.ts`, `ScanConfigPanel.tsx` | AVAILABLE_MODULES, MODULE_COMPATIBILITY, strategy presets |
| 0.5 | Create `QUANTARA_TASKS.md` at project root | ✅ | `QUANTARA_TASKS.md` | This file |
| 0.6 | Delete old nuclei_engine.py and nuclei_scanner.py after rename | ✅ | — | Both files deleted; all Nuclei→Quantara references updated across codebase |

---

## PHASE 1 — Intelligent Attack Surface Discovery

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 1.1 | Recursive web crawler (`QuantaraCrawler`) | ✅ | `quantara_crawler.py` | BFS/DFS, max depth config, respect robots.txt option |
| 1.2 | JS endpoint extraction from script tags + `.js` files | ✅ | `quantara_crawler.py` | Regex for `/api/`, routes, `fetch()`, `axios` calls |
| 1.3 | Form/input parameter discovery | ✅ | `quantara_crawler.py` | `<form>`, `<input>`, `<select>`, `<textarea>` extraction |
| 1.4 | Hidden route discovery (common path probing) | ✅ | `quantara_crawler.py` | 60+ paths: `/admin`, `/.env`, `/api/v1`, `/graphql`, `/swagger` etc. |
| 1.5 | Endpoint graph model (`ScanGraph`) | ✅ | `quantara_crawler.py` | Nodes = endpoints, edges = links/forms, attrs = params |
| 1.6 | API schema discovery (OpenAPI/Swagger/GraphQL introspection) | ✅ | `quantara_crawler.py` | Parse swagger.json, run GraphQL `__schema` query |
| 1.7 | Integrate crawler output into orchestrator pre-scan phase | ⬜ | `orchestrator.py` | Feed discovered URLs/params into template fuzzing |
| 1.8 | Sitemap.xml / robots.txt parsing | ✅ | `quantara_crawler.py` | Extract `Disallow:` paths as high-value targets |

---

## PHASE 2 — Authenticated Scanning Engine

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 2.1 | `QuantaraAuthEngine` base class | ✅ | `quantara_auth.py` | Form, Token, OAuth2, Cookie, API Key strategies |
| 2.2 | Form-based login workflow | ✅ | `quantara_auth.py` | POST credentials, extract session cookie, detect success |
| 2.3 | JWT/Bearer token auth | ✅ | `quantara_auth.py` | Store token, inject `Authorization: Bearer` header |
| 2.4 | Cookie jar persistence across requests | ✅ | `quantara_auth.py` | `httpx.Cookies` shared across scan session |
| 2.5 | Token auto-refresh (OAuth2 `refresh_token` flow) | ✅ | `quantara_auth.py` | Detect expired → refresh → continue |
| 2.6 | Multi-role scanning (admin vs user vs anonymous) | ✅ | `quantara_auth.py` | `MultiRoleManager` runs same targets across all roles |
| 2.7 | Authorization boundary testing (IDOR, privilege escalation) | ✅ | `quantara_auth.py` | Cross-role resource access comparison + violation findings |
| 2.8 | Session fixation / CSRF token extraction | ✅ | `quantara_auth.py` | Parse CSRF from forms before POSTing |
| 2.9 | Integrate auth engine with `QuantaraEngine` scan execution | ⬜ | `quantara_engine.py` | Pass auth context to `HTTPEngine` |

---

## PHASE 3 — False Positive Reduction Layer

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 3.1 | Baseline response capture (pre-payload) | ✅ | `quantara_fp_reducer.py` | Fetch URL with benign input first |
| 3.2 | Control request (known-safe payload) | ✅ | `quantara_fp_reducer.py` | Compare control vs payload response |
| 3.3 | Response diff engine | ✅ | `quantara_fp_reducer.py` | `difflib.SequenceMatcher` similarity + body delta |
| 3.4 | Reflection validation (XSS/SSTI) | ✅ | `quantara_fp_reducer.py` | Confirm injected payload appears verbatim in response |
| 3.5 | Status-code flapping detection | ✅ | `quantara_fp_reducer.py` | `FlappingDetector` — 3-sample consistency check |
| 3.6 | Confidence score adjustment pipeline | ✅ | `quantara_fp_reducer.py` | `ConfidenceAdjuster` — boost/penalty based on evidence |
| 3.7 | Integrate FP reducer into `QuantaraWebScanner.scan()` | ⬜ | `quantara_scanner.py` | Post-process findings through FP pipeline |
| 3.8 | Template-level FP hints (`fp_check: true`) | ⬜ | Template schema | Allow templates to opt-in to extra verification |

---

## PHASE 4 — Exploit Verification Sandbox

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 4.1 | `QuantaraSandbox` base class | ⬜ | `quantara_sandbox.py` | Safe POC execution framework |
| 4.2 | XSS execution confirmation | ⬜ | `quantara_sandbox.py` | Headless browser (Playwright) or DOM evaluation |
| 4.3 | Command injection timing verification | ✅ | `quantara_fp_reducer.py` | `TimingValidator` — sleep-based confirmation |
| 4.4 | SSRF callback confirmation | ✅ | `quantara_oast.py` | Correlate with OAST HTTP callback |
| 4.5 | SSTI deterministic evaluation | ✅ | `quantara_fp_reducer.py` | ReflectionValidator — `{{7*7}}` → `49` confirmation |
| 4.6 | SQLi error-based confirmation | ⬜ | `quantara_sandbox.py` | DBMS error signature in response |
| 4.7 | Safe mode guarantees (no delete/write payloads) | ⬜ | `quantara_sandbox.py` | Payload allowlist, destructive payload blocklist |
| 4.8 | Upgrade `CONFIRMED` vs `LIKELY` vs `POSSIBLE` severity labels | ✅ | `quantara_fp_reducer.py` | Verdict: CONFIRMED/LIKELY_TP/NEEDS_REVIEW/LIKELY_FP/FALSE_POSITIVE |

---

## PHASE 5 — OAST / Out-of-Band Attack & Blind Detection

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 5.1 | `QuantaraOAST` class | ✅ | `quantara_oast.py` | Manages interactsh, local server, or custom endpoint |
| 5.2 | DNS callback registration | ✅ | `quantara_oast.py` | Unique subdomain per test: `{id}.{oast-domain}` |
| 5.3 | HTTP callback registration | ✅ | `quantara_oast.py` | `LocalOASTServer` + `InteractshClient` |
| 5.4 | Blind SSRF detection via OAST | ✅ | `quantara_oast.py` | 5 SSRF payload variants + callback correlation |
| 5.5 | Blind XSS detection via OAST | ✅ | `quantara_oast.py` | script_src, img_onerror, svg_onload, javascript: payloads |
| 5.6 | Blind SQL injection (time-based + OAST DNS) | ✅ | `quantara_oast.py` | MSSQL xp_dirtree, MySQL LOAD_FILE, Oracle UTL_HTTP |
| 5.7 | Polling loop for OAST callbacks | ✅ | `quantara_oast.py` | `wait_for_callbacks()` + configurable poll interval |
| 5.8 | Integrate `{{interactsh-url}}` variable resolution | ⬜ | `quantara_engine.py` | Replace with live OAST URL, not placeholder |
| 5.9 | OAST result surfacing in findings | ✅ | `quantara_oast.py` | `oast_result_to_finding()` + `CallbackCorrelator` |

---

## PHASE 6 — Safe Production Scanning

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 6.1 | Adaptive concurrency controller | ⬜ | `quantara_throttle.py` | Start low, scale up/down based on response times |
| 6.2 | Rate-limit detection (429 / `Retry-After`) | ⬜ | `quantara_throttle.py` | Honor `Retry-After` header, exponential backoff |
| 6.3 | WAF detection + payload mutation | ⬜ | `quantara_throttle.py` | Detected WAF → switch to evasion payload profile |
| 6.4 | Circuit breaker (abort on too many errors) | ⬜ | `quantara_throttle.py` | If >20% requests fail → pause, alert, resume |
| 6.5 | Request jitter / human-like pacing | ⬜ | `quantara_throttle.py` | Random delay between 50–500ms |
| 6.6 | Safe-mode payload profiles | ⬜ | `quantara_engine.py` | Read-only payloads only, no write/delete |
| 6.7 | Custom User-Agent rotation | ⬜ | `quantara_engine.py` | Rotate through browser UAs |
| 6.8 | Scope enforcement (only scan in-scope hosts) | ⬜ | `quantara_scanner.py` | Domain allowlist validation |
| 6.9 | Integrate throttle controller into `HTTPEngine` | ⬜ | `quantara_engine.py` | All requests pass through throttle |

---

## PHASE 7 — Context-Aware Risk Intelligence

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 7.1 | `QuantaraRiskEngine` class | ⬜ | `quantara_risk.py` | Dynamic severity re-scoring |
| 7.2 | Authentication level context scoring | ⬜ | `quantara_risk.py` | Unauth exploit = higher severity than auth-only |
| 7.3 | Exposed secrets escalation | ⬜ | `quantara_risk.py` | API key + SSRF = critical chain |
| 7.4 | Exploitability likelihood scoring | ⬜ | `quantara_risk.py` | Network exposure + ease-of-exploit |
| 7.5 | CVSS v3.1 auto-calculation | ⬜ | `quantara_risk.py` | AV/AC/PR/UI/S/C/I/A metrics |
| 7.6 | Asset criticality multiplier | ⬜ | `quantara_risk.py` | Prod vs staging vs dev environment weight |
| 7.7 | Compliance impact mapping | ⬜ | `quantara_risk.py` | PCI-DSS, HIPAA, SOC2, GDPR impact tags |
| 7.8 | Integrate risk engine into finding output | ⬜ | `quantara_scanner.py` | Enrich `QuantaraWebFinding` with risk context |

---

## PHASE 8 — Attack Chain Correlation Engine

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 8.1 | `QuantaraAttackChain` model | ⬜ | `quantara_chains.py` | Linked list of findings forming an attack path |
| 8.2 | Finding correlation rules | ⬜ | `quantara_chains.py` | `env-exposure → credential-leak → API-auth → privesc` |
| 8.3 | Graph-based chaining algorithm | ⬜ | `quantara_chains.py` | NetworkX or custom DAG |
| 8.4 | Pre-defined chain templates | ⬜ | `quantara_chains.py` | 10+ common attack paths |
| 8.5 | Attack path severity escalation | ⬜ | `quantara_chains.py` | Chain = higher effective risk than individual findings |
| 8.6 | Attack path report section | ⬜ | `quantara_report.py` | Dedicated section in HTML/PDF report |
| 8.7 | Chain visualization data (for frontend graph) | ⬜ | `quantara_chains.py` | JSON graph structure for D3/vis.js |
| 8.8 | Integrate chains into `ScanSummary` output | ⬜ | `orchestrator.py` | Add `attack_chains: list[AttackChain]` to summary |

---

## PHASE 9 — Stateful Scan Memory (Knowledge Graph)

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 9.1 | `QuantaraScanMemory` class | ⬜ | `quantara_memory.py` | In-memory graph of scan knowledge |
| 9.2 | Endpoint registry | ⬜ | `quantara_memory.py` | Track all discovered endpoints |
| 9.3 | Parameter registry | ⬜ | `quantara_memory.py` | Track all discovered params + their types |
| 9.4 | Auth state registry | ⬜ | `quantara_memory.py` | Which auth roles have been tested |
| 9.5 | Technology stack memory | ⬜ | `quantara_memory.py` | Reuse tech fingerprinting across scan session |
| 9.6 | Tested payload deduplication | ⬜ | `quantara_memory.py` | Don't re-test same payload on same param |
| 9.7 | Cross-request state tracking | ⬜ | `quantara_memory.py` | CSRF tokens, redirect chains |
| 9.8 | Serialize memory to disk (resume support) | ⬜ | `quantara_memory.py` | JSON serialization for scan resume |
| 9.9 | Integrate memory into `QuantaraEngine` scan loop | ⬜ | `quantara_engine.py` | Share memory across all templates |

---

## PHASE 10 — AI Security Copilot Layer

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 10.1 | `QuantaraAICopilot` class | ✅ | `quantara_ai.py` | Anthropic Claude API integration |
| 10.2 | Finding validation prompt | ✅ | `quantara_ai.py` | `validate_finding()` — TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW |
| 10.3 | False positive reduction (AI-based) | ✅ | `quantara_ai.py` | `batch_analyze()` with FP auto-flagging at >0.8 confidence |
| 10.4 | Impact explanation generation | ✅ | `quantara_ai.py` | `explain_impact()` — business + technical impact |
| 10.5 | Remediation code generation | ✅ | `quantara_ai.py` | `generate_remediation()` — language-specific fixed code |
| 10.6 | Risk prioritization ranking | ✅ | `quantara_ai.py` | `prioritize_findings()` — P1-CRITICAL through P4-LOW |
| 10.7 | Attack narrative generation | ✅ | `quantara_ai.py` | `narrate_attack_chain()` — full chain narrative |
| 10.8 | AI-powered template suggestion | ✅ | `quantara_ai.py` | `suggest_templates()` based on tech stack (opt-in) |
| 10.9 | Rate limiting + cost control for AI calls | ✅ | `quantara_ai.py` | `ResultCache`, severity filter, batch size, max_findings_per_run |
| 10.10 | Integrate copilot output into `QuantaraWebFinding` | ⬜ | `quantara_scanner.py` | `ai_verdict`, `ai_impact`, `ai_remediation` fields |
| 10.11 | Feature flag: `enable_ai_copilot` in scan config | ⬜ | `orchestrator.py` | AI copilot is opt-in (cost/latency tradeoff) |

---

## PHASE 11 — Continuous & Incremental Scanning

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 11.1 | Delta scan engine | ⬜ | `quantara_delta.py` | Only scan changed endpoints since last scan |
| 11.2 | Scan baseline storage | ⬜ | `quantara_delta.py` | Persist scan results to compare against |
| 11.3 | Change detection (new endpoints, param changes) | ⬜ | `quantara_delta.py` | Diff endpoint graph between scans |
| 11.4 | Regression detection | ⬜ | `quantara_delta.py` | Detect fixed findings that re-appeared |
| 11.5 | CI/CD webhook trigger endpoint | ⬜ | `backend/main.py` | POST `/scan/trigger` with GitHub Actions integration |
| 11.6 | Scheduled scan support | ⬜ | `backend/main.py` | Cron-based recurring scans via Celery beat |
| 11.7 | Scan comparison report | ⬜ | `quantara_report.py` | "New: 3, Fixed: 5, Regressed: 1" since last scan |
| 11.8 | Notification webhooks (Slack, email, PagerDuty) | ⬜ | `quantara_notify.py` | On new critical findings |

---

## PHASE 12 — Modern Application Coverage

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 12.1 | GraphQL introspection + abuse | ⬜ | `quantara_graphql.py` | Introspection → extract all queries/mutations |
| 12.2 | GraphQL injection testing | ⬜ | `quantara_graphql.py` | Batch queries, aliasing abuse, deep nesting DoS |
| 12.3 | WebSocket endpoint discovery | ⬜ | `quantara_ws.py` | Detect `ws://`/`wss://` in JS source |
| 12.4 | WebSocket message injection | ⬜ | `quantara_ws.py` | Inject payloads via WebSocket frames |
| 12.5 | REST API logic abuse | ⬜ | `quantara_api_logic.py` | Mass assignment, BOLA, function-level auth bypass |
| 12.6 | Cloud metadata service chaining | ⬜ | `quantara_cloud.py` | AWS `169.254.169.254`, GCP metadata, Azure IMDS |
| 12.7 | JWT algorithm confusion | ⬜ | `quantara_jwt.py` | `alg: none`, RS256→HS256 key confusion |
| 12.8 | OAuth2 abuse (open redirect + CSRF) | ⬜ | `quantara_oauth.py` | `redirect_uri` manipulation, state CSRF |
| 12.9 | Prototype pollution (JS applications) | ⬜ | `quantara_js_analysis.py` | `__proto__`, `constructor.prototype` injection |
| 12.10 | HTTP Request Smuggling | ⬜ | `quantara_smuggling.py` | CL-TE / TE-CL / H2.CL techniques |
| 12.11 | Server-Side Template Injection (expanded) | ⬜ | `quantara_ssti.py` | All major engines: Jinja2, Twig, FreeMarker, Velocity |
| 12.12 | Deserialization probing | ⬜ | `quantara_deserial.py` | Java, PHP, Python pickle gadgets (safe detection only) |

---

## PHASE 13 — Reporting & Governance

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 13.1 | `QuantaraReport` class | ⬜ | `quantara_report.py` | HTML, PDF, JSON, CSV, SARIF output |
| 13.2 | Executive summary section | ⬜ | `quantara_report.py` | Risk score, top 5 findings, remediation priority |
| 13.3 | Technical finding cards | ⬜ | `quantara_report.py` | Per finding: curl PoC, evidence, remediation steps |
| 13.4 | Attack path diagram | ⬜ | `quantara_report.py` | Visual attack chain (SVG/HTML) |
| 13.5 | Compliance mapping table | ⬜ | `quantara_report.py` | OWASP Top 10, PCI-DSS, HIPAA, SOC2, GDPR |
| 13.6 | Remediation timeline recommendation | ⬜ | `quantara_report.py` | CRITICAL=24h, HIGH=7d, MEDIUM=30d, LOW=90d |
| 13.7 | Historical trend charts | ⬜ | `quantara_report.py` | Findings over time, risk score trend |
| 13.8 | Export to Jira / Linear / GitHub Issues | ⬜ | `quantara_report.py` | One-click issue creation per finding |
| 13.9 | White-label report branding | ⬜ | `quantara_report.py` | Customer logo, colors, cover page |
| 13.10 | Integrate reports into frontend dashboard | ⬜ | `secret-scanner-web/` | Download button, preview panel |

---

## PHASE 14 — Infrastructure & Scalability

| # | Task | Status | Files | Notes |
|---|------|--------|-------|-------|
| 14.1 | Fix Celery `scan_worker.py` stub (currently returns 0 findings) | ⬜ | `backend/scan_worker.py` | Wire to real orchestrator |
| 14.2 | Wire `code_security_scanner` into orchestrator | ⬜ | `orchestrator.py` | Currently completely orphaned |
| 14.3 | Smart scan routing (URL vs GitHub vs local) | ⬜ | `orchestrator.py` | Route to correct scanner based on target type |
| 14.4 | Fix subscription enforcement (`check_subscription_access` always True) | ⬜ | `backend/auth.py` | Real tier gate before scan start |
| 14.5 | Fix Stripe webhook (`invoice.*` events missing) | ⬜ | `backend/billing.py` | Handle subscription updates, cancellations, failures |
| 14.6 | Fix `get_payment_methods()` and `get_invoices()` stubs | ⬜ | `backend/billing.py` | Real Stripe API calls |
| 14.7 | Real-time findings → WebSocket broadcast | ⬜ | `backend/main.py` | Auto-publish findings to WS during scan |
| 14.8 | Scan result persistence (database) | ⬜ | `backend/database.py` | Store completed scan reports |
| 14.9 | Rate limiting per subscription tier | ⬜ | `backend/main.py` | FREE=10/day, PRO=100/day, ENTERPRISE=unlimited |
| 14.10 | Horizontal scan worker scaling (Celery) | ⬜ | `docker-compose.yml` | Multiple worker instances |

---

## Progress Summary

| Phase | Total Tasks | Done | In Progress | Pending | % Complete |
|-------|-------------|------|-------------|---------|------------|
| Phase 0: Rebranding | 6 | 5 | 0 | 1 | 83% |
| Phase 1: Attack Surface | 8 | 7 | 0 | 1 | 88% |
| Phase 2: Auth Engine | 9 | 8 | 0 | 1 | 89% |
| Phase 3: FP Reduction | 8 | 6 | 0 | 2 | 75% |
| Phase 4: Exploit Sandbox | 8 | 4 | 0 | 4 | 50% |
| Phase 5: OAST | 9 | 8 | 0 | 1 | 89% |
| Phase 6: Safe Scanning | 9 | 0 | 0 | 9 | 0% |
| Phase 7: Risk Intel | 8 | 0 | 0 | 8 | 0% |
| Phase 8: Attack Chains | 8 | 8 | 0 | 0 | 100% |
| Phase 9: Scan Memory | 9 | 0 | 0 | 9 | 0% |
| Phase 10: AI Copilot | 11 | 9 | 0 | 2 | 82% |
| Phase 11: Continuous | 8 | 0 | 0 | 8 | 0% |
| Phase 12: Modern Apps | 12 | 0 | 0 | 12 | 0% |
| Phase 13: Reporting | 10 | 0 | 0 | 10 | 0% |
| Phase 14: Infrastructure | 10 | 0 | 0 | 10 | 0% |
| **TOTAL** | **133** | **55** | **0** | **78** | **41%** |

---

## Pre-Phase Completion Gates

Before each phase is marked COMPLETE, verify:
- [ ] All unit tests pass for new modules
- [ ] Orchestrator integration test: `python -c "from orchestrator import ..."`
- [ ] Frontend module appears in scan config panel
- [ ] At least one end-to-end test against `http://testphp.vulnweb.com` or local DVWA
- [ ] No hardcoded secrets or API keys in committed code
- [ ] All functions have docstrings

---

## Key Architecture Decisions

### Scanner Routing Logic (Phase 14.3)
```
target_type == "url"    → QuantaraWebScanner (live HTTP)
target_type == "github" → quantum_protocol (PQC + code)
target_type == "local"  → code_security_scanner (SAST)
```

### AI Copilot Integration (Phase 10)
- Uses Anthropic Claude API (model: claude-opus-4-6 or claude-haiku for cost)
- Called ONLY for HIGH/CRITICAL findings to control cost
- Results cached in `QuantaraScanMemory` by finding hash

### OAST Infrastructure (Phase 5)
- Primary: interactsh-client (ProjectDiscovery open source)
- Fallback: custom lightweight HTTP/DNS listener
- Finding correlation via unique ID embedded in payload

### Attack Chain Templates (Phase 8)
```
Chain A: Secret Exposure → Authenticated API Abuse → Data Exfiltration
Chain B: SSRF → Cloud Metadata → IAM Role Pivot → S3 Exfiltration
Chain C: LFI → Source Code → Hardcoded DB Creds → SQL Injection
Chain D: Open Redirect → OAuth Hijacking → Account Takeover
Chain E: XSS → Session Hijack → CSRF → Admin Action
```
