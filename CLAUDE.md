# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Quantum Protocol v5.0** — an enterprise-grade OWASP security scanner platform. FastAPI backend + Next.js 16 frontend with real-time scanning via SSE/WebSocket, AI-powered remediation, subscription billing (Stripe), and 11+ scanner modules.

---

## Development Commands

### Backend (FastAPI)

```bash
# From project root — activate venv first
source .venv/Scripts/activate   # Windows: .venv\Scripts\activate

# Run dev server
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Run tests
pytest backend/tests/

# Run a single test file
pytest backend/tests/test_api.py -v

# Run a single test function
pytest backend/tests/test_api.py::test_function_name -v
```

### Frontend (Next.js)

```bash
cd secret-scanner-web

npm run dev      # Start dev server on http://localhost:3000
npm run build    # Production build
npm run lint     # ESLint check
```

### Docker (Full Stack)

```bash
docker-compose up -d         # Start all services
docker-compose logs -f       # Tail logs
docker-compose down          # Stop all services
docker-compose up -d --build # Rebuild and restart
```

---

## Architecture

### Backend (`backend/`)

- **`main.py`** — Primary FastAPI app. Contains all REST endpoints, SSE streaming (`/api/v1/scan/{id}/stream`), WebSocket handlers, CORS config, and startup logic (seeds super admin, initializes DB).
- **`app.py`** — Alternate simplified FastAPI entry; use `main.py` for the full platform.
- **`database.py`** — SQLAlchemy ORM with models: `User`, `Scan`, `Finding`, `ScanLog`, `SubscriptionTier`. Supports PostgreSQL (production) and SQLite (dev fallback).
- **`auth.py`** — JWT token creation/validation, Firebase integration, email verification, super admin seeding.
- **`billing.py`** — Stripe subscription management, tier enforcement, webhook handling.
- **`scan_worker.py`** — Celery worker that executes scan jobs asynchronously. Queues: `scan_jobs`, `default`.
- **`ai_remediation.py`** — Google Generative AI (Gemini) integration for security fix suggestions.
- **`websocket_manager.py`** — Manages active WebSocket connections for live scan updates.
- **`redis_client.py`** — Scan state management and pub/sub via Redis.
- **`rate_limiter.py`** — Request rate limiting and WAF middleware.

### Scanner Engines (`Centralize_Scanners/`)

- **`scanner_engine/orchestrator.py`** — Coordinates all scanner modules; maps results to OWASP Top 10 categories.
- **`scanner_engine/owasp_coverage.py`** — OWASP Top 10 mapping and coverage tracking.
- **`quantum_protocol/`** — Advanced scanner with plugins, rules engine, analyzers, and reporters.
- Registered modules: `misconfig`, `injection`, `frontend_js`, `endpoint`, `ssrf`, and others.

### Frontend (`secret-scanner-web/src/`)

Uses **Next.js App Router** (`src/app/`):
- `app/page.tsx` — Landing/homepage
- `app/dashboard/` — User dashboard with scan history, findings, charts
- `app/dashboard/scanner/` — Live scanner interface with SSE stream consumption
- `app/billing/` — Subscription management (Stripe)
- `app/admin/` — Admin panel (users, billing, security, settings)
- `app/login/` — Firebase auth flow

Key components:
- `components/real-time-findings-panel.tsx` — SSE consumer for live scan results
- `components/auth-dialog.tsx` — Auth modal (login/register/reset)
- `components/dashboard/scanner/ai-copilot/` — AI remediation UI panel
- `components/sidebar.tsx` — Navigation sidebar

State/services: Firebase Authentication (frontend auth), JWT tokens passed to API, no Redux — React context only.

### Infrastructure

- **PostgreSQL** (port 5432) — Primary data store
- **Redis** (port 6379) — Scan state, Celery broker, pub/sub
- **Celery** — Async background scan job processing (4 workers)
- **Firebase** — Frontend auth + hosting
- **Stripe** — Subscription billing

---

## Key Conventions

- **API prefix:** All backend routes are under `/api/v1/`
- **Real-time:** Scan results stream via SSE at `/api/v1/scan/{scan_id}/stream`; WebSocket at `/ws/{scan_id}`
- **Auth flow:** Firebase token (frontend) → exchanged for JWT → passed as `Authorization: Bearer` header to backend
- **Subscription tiers:** Free / Pro / Enterprise — enforced in `billing.py` and checked per endpoint in `main.py`
- **TypeScript paths:** `@/*` resolves to `secret-scanner-web/src/*`
- **UI library:** shadcn/ui (new-york style) + Radix UI primitives + Lucide icons

## Environment Variables

Copy `.env.template` to `.env`. Required keys:
- `DATABASE_URL` — PostgreSQL connection string (or leave blank for SQLite dev mode)
- `REDIS_URL` — Redis connection string
- `FIREBASE_PROJECT_ID`, `FIREBASE_PRIVATE_KEY`, `FIREBASE_CLIENT_EMAIL` — Firebase service account
- `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY` — Stripe billing
- `SUPER_ADMIN_EMAIL` — Seeded on first backend startup
- `GOOGLE_API_KEY` — Gemini AI for remediation suggestions
- `DEVELOPMENT=true` — Enables `localhost:*` CORS in development

---

## Frontend Design Rules

### Always Do First
- **Invoke the `frontend-design` skill** before writing any frontend code, every session, no exceptions.

### Brand
- Logo: `OWASP_SCANNER_LOGO1.png` at project root. Use it — don't use placeholders where the real logo exists.
- Primary brand color: neon green `#00FF88` on dark background `#0B0F0C`
- Typography: "Outfit" for headings — do not substitute.

### Anti-Generic Guardrails
- **Colors:** Never use default Tailwind palette (indigo-500, blue-600, etc.)
- **Shadows:** Use layered, color-tinted shadows with low opacity — not flat `shadow-md`
- **Typography:** Pair display/serif with clean sans. Tight tracking (`-0.03em`) on large headings, generous line-height (`1.7`) on body
- **Animations:** Only animate `transform` and `opacity`. Never `transition-all`. Spring-style easing.
- **Interactive states:** Every clickable element needs hover, focus-visible, and active states
- **Depth:** Base → elevated → floating surface system

### Hard Rules
- Do not use `transition-all`
- Do not use default Tailwind blue/indigo as primary color
- Mobile-first responsive

### Screenshot Validation
- Always serve on localhost — never screenshot a `file:///` URL
- Dev server: `node serve.mjs` → `http://localhost:3000` (project root)
- Screenshot: `node screenshot.mjs http://localhost:3000` → saves to `./temporary screenshots/`
- Do at least 2 comparison rounds after any UI change

## MCP (Model Context Protocol)
- **Invoke the `mcp-builder` skill** when building MCP servers to integrate external APIs
- Use TypeScript with Streamable HTTP transport for remote servers, stdio for local
- Location: `SKILLS/mcp-builder/SKILL.md`
