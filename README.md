# Quantara_Quantum Protocol v5.0 — Local Development Setup

## Prerequisites

- Python 3.11+
- Node.js 20+
- PostgreSQL (optional, for persistence)
- Redis (optional, for real-time state)

## Quick Start (Without Docker)

### 1. Backend Setup

```powershell
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
venv\Scripts\Activate.ps1

# Or on Windows CMD
venv\Scripts\activate.bat

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Backend will be available at: http://localhost:8000

API documentation at: http://localhost:8000/docs

### 2. Frontend Setup

In a new terminal:

```powershell
# Navigate to frontend directory
cd secret-scanner-web

# Install dependencies (if not already done)
npm install

# Run the Next.js dev server
npm run dev
```

Frontend will be available at: http://localhost:3000

## Optional: Database Setup

### PostgreSQL (Windows)

1. Download and install PostgreSQL: https://www.postgresql.org/download/windows/
2. Create a database named `secretscanner`
3. Set environment variable:
   ```powershell
   $env:DATABASE_URL="postgresql://postgres:yourpassword@localhost:5432/secretscanner"
   ```

### Redis (Windows)

1. Download Redis for Windows: https://github.com/microsoftarchive/redis/releases
2. Or use Memurai (Redis-compatible): https://www.memurai.com/
3. Start Redis server on default port 6379

Without PostgreSQL/Redis, the system will work with in-memory storage.

## Environment Variables

Create a `.env` file in the `backend` directory:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/secretscanner
REDIS_URL=redis://localhost:6379/0
```

## Testing the API

Once the backend is running:

```powershell
# Health check
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/health" -Method GET

# List modules
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/modules" -Method GET

# Start a scan
$body = @{
    target = "C:\path\to\your\code"
    scan_type = "directory"
    modules = @("misconfig", "injection")
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scan/start" -Method POST -Body $body -ContentType "application/json"
```

## Architecture Overview

```
┌─────────────────┐      HTTP/WebSocket      ┌─────────────────┐
│   Next.js       │  ───────────────────────►  │   FastAPI       │
│   (Port 3000)   │                          │   (Port 8000)   │
└─────────────────┘                          └────────┬────────┘
                                                      │
                           ┌─────────────────────────┼─────────────────────────┐
                           │                         │                         │
                           ▼                         ▼                         ▼
                    ┌─────────────┐          ┌─────────────┐          ┌─────────────────┐
                    │  PostgreSQL │          │    Redis    │          │ Scanner Engines │
                    │  (Optional) │          │  (Optional) │          │  (11 modules)   │
                    └─────────────┘          └─────────────┘          └─────────────────┘
```

## Troubleshooting

### Module Import Errors

If you see import errors for scanner modules, ensure the parent directory is in Python path:

```python
import sys
sys.path.insert(0, r"C:\Users\HP\Music\AGI-Full_Stack\Claude_Github_Secret_Scanner")
```

### Port Conflicts

If ports 3000 or 8000 are in use:

- Frontend: `npm run dev -- --port 3001`
- Backend: `uvicorn main:app --port 8001`

### CORS Errors

The backend is configured to accept requests from `localhost:3000` and `localhost:3001`. If your frontend runs on a different port, update `main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:YOUR_PORT"],
    ...
)
```
