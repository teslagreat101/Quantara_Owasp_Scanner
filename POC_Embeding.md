Plan: Embed Hetty + mitmweb into POC Verification Lab

Context:

The existing "Proof of Concept Verification" section at /dashboard/scanner is a Quick Repeater (POCConsole) + secrets viewer + AI advisor. The goal is to add Hetty and mitmweb as professional proxy tabs alongside the existing console — like Burp Repeater + Proxy — without touching any other part of the scanner page.

Architecture fit:

No existing nginx — we add it as a new docker-compose service
Network is scanner-net (not scanner-internal as in the spec)
Backend is FastAPI/Python (not Node.js)
Frontend uses Next.js App Router + next.config.ts
The iframe proxy chain: browser → Next.js /poc/hetty/ rewrite → nginx → hetty:8080
Implementation Order:

STEP 1 — Docker Compose (docker-compose.yml)

Add three new services + two new volumes:


  # ─── Hetty — Modern HTTP proxy / repeater ───────────────────────
  hetty:
    image: ghcr.io/dstotijn/hetty:latest
    container_name: owasp-scanner-hetty
    restart: unless-stopped
    ports:
      - "127.0.0.1:8082:8080"
    volumes:
      - hetty-data:/root/.hetty
    networks:
      - scanner-net

  # ─── mitmweb — Classic interactive proxy ─────────────────────────
  mitmweb:
    image: mitmproxy/mitmproxy:latest
    container_name: owasp-scanner-mitmweb
    restart: unless-stopped
    command: mitmweb --web-host 0.0.0.0 --web-port 8081 --listen-host 0.0.0.0 -p 8080 --set web_open_browser=false --set confdir=/root/.mitmproxy
    ports:
      - "127.0.0.1:8083:8081"   # mitmweb UI
      - "127.0.0.1:8084:8080"   # proxy port
    volumes:
      - mitmproxy-data:/root/.mitmproxy
    networks:
      - scanner-net

  # ─── Nginx — Strips X-Frame-Options; proxies /poc/* ──────────────
  poc-proxy:
    image: nginx:alpine
    container_name: owasp-poc-proxy
    restart: unless-stopped
    volumes:
      - ./nginx/poc-proxy.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - hetty
      - mitmweb
    networks:
      - scanner-net
Add to volumes::


  hetty-data:
    driver: local
  mitmproxy-data:
    driver: local


STEP 2 — Nginx Config (nginx/poc-proxy.conf) — NEW FILE

server {
    listen 80;

    # Strip X-Frame-Options so Next.js iframe can embed the UIs
    proxy_hide_header X-Frame-Options;
    proxy_hide_header Content-Security-Policy;
    add_header X-Frame-Options "";

    location /poc/hetty/ {
        proxy_pass http://hetty:8080/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    location /poc/mitmweb/ {
        proxy_pass http://mitmweb:8081/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
STEP 3 — Next.js Rewrites (secret-scanner-web/next.config.ts)


Add async rewrites() so the browser iframe uses same-origin /poc/hetty/ URL, while the Next.js server proxies internally to the nginx pod on poc-proxy:80:


async rewrites() {
  return [
    {
      source: '/poc/hetty/:path*',
      destination: `${process.env.POC_PROXY_URL || 'http://poc-proxy'}/poc/hetty/:path*`,
    },
    {
      source: '/poc/mitmweb/:path*',
      destination: `${process.env.POC_PROXY_URL || 'http://poc-proxy'}/poc/mitmweb/:path*`,
    },
  ];
},
Also add POC_PROXY_URL=http://poc-proxy to .env.docker.
For local dev (outside Docker), expose dev fallback env: POC_PROXY_URL=http://localhost:8085 (poc-proxy maps 127.0.0.1:8085:80). Add that port mapping to the docker-compose poc-proxy service.

STEP 4 — Backend FastAPI Endpoints (backend/main.py)

Add four endpoints near the existing /api/poc/* block:


# Lab Tool status — pings health of hetty/mitmweb
GET  /api/lab/status
# Returns: { hetty: { running: bool, url: str }, mitmweb: { running: bool, url: str } }

# CA certificate downloads
GET  /api/lab/ca/hetty      → FileResponse from hetty-data volume
GET  /api/lab/ca/mitmproxy  → FileResponse from mitmproxy-data volume
Auth: require valid JWT (same get_current_firebase_user dependency)
status endpoint does an async httpx.get health probe to http://hetty:8080 and http://mitmweb:8081 with 3s timeout; returns running: True/False
CA endpoints: check if file exists at known docker paths (/root/.hetty/ca.crt, /root/.mitmproxy/mitmproxy-ca-cert.pem); if backend runs in Docker these paths are reachable via volume mounts — add the volumes to the backend service in docker-compose
start-tool and stop-tool are skipped (tools always managed by docker-compose); the frontend "Start" button just navigates to the tab and verifies connectivity
Backend docker-compose additions (mount CA volumes into backend):


  backend:
    volumes:
      - scan_targets:/scan_targets
      - scan_results:/scan_results
      - hetty-data:/root/.hetty:ro        # for CA download
      - mitmproxy-data:/root/.mitmproxy:ro  # for CA download

STEP 5 — Env Files

.env.template — append:


HETTY_URL=http://127.0.0.1:8082
MITMWEB_URL=http://127.0.0.1:8083
POC_PROXY_URL=http://poc-proxy
.env.docker — append:


POC_PROXY_URL=http://poc-proxy

STEP 6 — Hook: use-lab-tools.ts — NEW FILE

secret-scanner-web/src/hooks/use-lab-tools.ts


// Polls GET /api/lab/status every 5s when active
// Returns: { hetty: LabToolStatus, mitmweb: LabToolStatus }
// LabToolStatus: { running: boolean; url: string; loading: boolean }
// Provides: downloadCA(tool: 'hetty' | 'mitmproxy') — triggers browser download

STEP 7 — Component: AdvancedProxyLab.tsx — NEW FILE

secret-scanner-web/src/components/dashboard/scanner/poc/AdvancedProxyLab.tsx

Layout:


┌─────────────────────────────────────────────────────────┐
│ [Status: ● Running]  [Download CA ↓]  [Proxy Settings ⚙]│
├─────────────────────────────────────────────────────────┤
│ ▼ Setup Instructions (collapsible)                       │
│   "Set browser proxy to 127.0.0.1:8084 (mitmweb) or    │
│    configure Hetty's built-in proxy"                     │
│   [Copy Proxy Settings]  [CA Install Guide]              │
├─────────────────────────────────────────────────────────┤
│                                                          │
│              <iframe src="/poc/hetty/">                   │
│              (calc(100vh - 280px) height)                │
│                                                          │
└─────────────────────────────────────────────────────────┘
Key behaviors:

Uses use-lab-tools hook; polls every 5s when isActive prop is true
Shows "Tool Not Running" overlay with retry button when running: false
Auto-refreshes iframe key when tool transitions to running
"Download CA" calls /api/lab/ca/hetty or /api/lab/ca/mitmproxy with JWT Bearer header; uses URL.createObjectURL for download
"Copy Proxy Settings" copies 127.0.0.1:8084 (mitmweb) or 127.0.0.1:8082 (hetty) to clipboard
CA Install Guide: collapsible <details> panel with step-by-step text instructions
Keyboard shortcut Ctrl+Shift+H: handled at document level in useEffect, switches to Hetty tab
No transitions on .iframe-container scale/opacity (just opacity + transform per design rules)

STEP 8 — Modify: POCSection.tsx

Minimal change — add a 3-tab bar just above the existing content area, inside the AnimatePresence / motion.div:


[Quick Repeater]  [Hetty ●]  [mitmweb ●]
activeLabTab state: 'repeater' | 'hetty' | 'mitmweb'
activeLabTab === 'repeater': render existing findings selector + grid (zero changes)
activeLabTab === 'hetty': render <AdvancedProxyLab tool="hetty" isActive={true} />
activeLabTab === 'mitmweb': render <AdvancedProxyLab tool="mitmweb" isActive={true} />
Status dot (●) next to Hetty/mitmweb tab pulled from use-lab-tools hook
The "Standby" state only shows on repeater tab when no findings; Hetty/mitmweb tabs always accessible

Files to Create/Modify

File	Action

docker-compose.yml	Modify — add hetty, mitmweb, poc-proxy services + volumes
nginx/poc-proxy.conf	CREATE — nginx reverse proxy config
backend/main.py	Modify — add 3 /api/lab/ endpoints
secret-scanner-web/next.config.ts	Modify — add /poc/* rewrites
.env.template	Modify — add POC env vars
.env.docker	Modify — add POC_PROXY_URL
secret-scanner-web/src/hooks/use-lab-tools.ts	CREATE
secret-scanner-web/src/components/dashboard/scanner/poc/AdvancedProxyLab.tsx	CREATE
secret-scanner-web/src/components/dashboard/scanner/poc/POCSection.tsx	Modify — add 3-tab bar
Verification

docker-compose up -d — verify hetty, mitmweb, poc-proxy containers start

curl http://127.0.0.1:8082 — confirm hetty UI responds
curl http://127.0.0.1:8083 — confirm mitmweb UI responds
curl http://127.0.0.1:8085/poc/hetty/ — confirm nginx strips X-Frame-Options
Open browser → http://localhost:3000/dashboard/scanner → verification tab
Click "Hetty" tab → iframe loads with status ● Running
Click "mitmweb" tab → iframe loads
Click "Download CA" → file download triggers
Keyboard Ctrl+Shift+H → Hetty tab auto-activates
Verify "Quick Repeater" tab still shows existing POC console unchanged
User approved the plan
Update Todos

Step 1: Add hetty, mitmweb, poc-proxy services to docker-compose.yml

Step 2: Create nginx/poc-proxy.conf

Step 3: Add rewrites to next.config.ts

Step 4: Add /api/lab/* endpoints to backend/main.py

Step 5: Update .env.template and .env.docker

Step 6: Create use-lab-tools.ts hook

Step 7: Create AdvancedProxyLab.tsx component

Step 8: Add 3-tab bar to POCSection.tsx
Update Todos

Step 1: Add hetty, mitmweb, poc-proxy services to docker-compose.yml

Step 2: Create nginx/poc-proxy.conf

Step 3: Add rewrites to next.config.ts

Step 4: Add /api/lab/* endpoints to backend/main.py

Step 5: Update .env.template and .env.docker

Step 6: Create use-lab-tools.ts hook

Step 7: Create AdvancedProxyLab.tsx component

Step 8: Add 3-tab bar to POCSection.tsx

Step 1 — Docker Compose

Edit c:\Users\HP\Music\AGI-Full_Stack\Owasp_Scanner_Final\docker-compose.yml
Added 50 lines
Now add the CA volumes to the backend service and the new volumes at the bottom:

Edit c:\Users\HP\Music\AGI-Full_Stack\Owasp_Scanner_Final\docker-compose.yml
Added 2 lines
Edit c:\Users\HP\Music\AGI-Full_Stack\Owasp_Scanner_Final\docker-compose.yml

Added 4 lines

Update Todos: 

Step 1: Add hetty, mitmweb, poc-proxy services to docker-compose.yml

Step 2: Create nginx/poc-proxy.conf

Step 3: Add rewrites to next.config.ts

Step 4: Add /api/lab/* endpoints to backend/main.py

Step 5: Update .env.template and .env.docker

Step 6: Create use-lab-tools.ts hook

Step 7: Create AdvancedProxyLab.tsx component

Step 8: Add 3-tab bar to POCSection.tsx

Step 2 — Create nginx config
Bash Create nginx directory
IN
mkdir -p "c:/Users/HP/Music/AGI-Full_Stack/Owasp_Scanner_Final/nginx"

OUT
0
Write c:\Users\HP\Music\AGI-Full_Stack\Owasp_Scanner_Final\nginx\poc-proxy.conf
48 lines
server {
    listen 80;
    server_name _;

    # ── Strip restrictive embedding headers from proxied UIs ──────────
    proxy_hide_header X-Frame-Options;
    proxy_hide_header Content-Security-Policy;
    proxy_hide_header X-Content-Type-Options;
    add_header X-Frame-Options "";

    # ── Common proxy settings ─────────────────────────────────────────
    proxy_set_header Host               $host;
    proxy_set_header X-Real-IP          $remote_addr;
    proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto  $scheme;
    proxy_http_version 1.1;

    # ── Hetty — Modern HTTP Repeater / Proxy ──────────────────────────
    # Accessible via: /poc/hetty/
    location /poc/hetty/ {
        proxy_pass http://hetty:8080/;

        # WebSocket support (Hetty uses WS for live interception)
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout          86400;
        proxy_send_timeout          86400;
    }

    # ── mitmweb — Classic Interactive MITM Proxy ──────────────────────
    # Accessible via: /poc/mitmweb/
    location /poc/mitmweb/ {
        proxy_pass http://mitmweb:8081/;

        # WebSocket support (mitmweb uses WS for live flow updates)
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout          86400;
        proxy_send_timeout          86400;
    }

    # ── Health check ──────────────────────────────────────────────────
    location /healthz {
        return 200 "ok\n";
        add_header Content-Type text/plain;
    }
}
Update Todos

Step 1: Add hetty, mitmweb, poc-proxy services to docker-compose.yml

Step 2: Create nginx/poc-proxy.conf

Step 3: Add rewrites to next.config.ts

Step 4: Add /api/lab/* endpoints to backend/main.py

Step 5: Update .env.template and .env.docker

Step 6: Create use-lab-tools.ts hook

Step 7: Create AdvancedProxyLab.tsx component

Step 8: Add 3-tab bar to POCSection.tsx