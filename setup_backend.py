#!/usr/bin/env python3
"""
Setup script to install all backend dependencies
Run: python setup_backend.py
"""

import subprocess
import sys

def install_packages():
    """Install all required packages."""
    packages = [
        # Core
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.27.0",
        "pydantic>=2.5.0",
        "python-multipart>=0.0.9",
        "sse-starlette>=1.8.0",
        "starlette>=0.36.0",
        "aiofiles>=23.2.1",
        
        # Database
        "sqlalchemy>=2.0.0",
        "psycopg2-binary>=2.9.9",
        "redis>=5.0.0",
        "alembic>=1.13.0",
        
        # Celery
        "celery>=5.3.0",
        "flower>=2.0.0",
        "django-celery-beat>=2.5.0",
        
        # HTTP
        "requests>=2.31.0",
        "httpx>=0.27.0",
        "aiohttp>=3.9.0",
        
        # Auth
        "python-jose[cryptography]>=3.3.0",
        "passlib[bcrypt]>=1.7.4",
        "bcrypt>=4.1.0",
        "cryptography>=42.0.0",
        
        # Billing
        "stripe>=8.0.0",
        
        # Storage
        "boto3>=1.34.0",
        "minio>=7.2.0",
        
        # Monitoring
        "prometheus-client>=0.19.0",
        "structlog>=24.1.0",
        
        # Rate limiting
        "slowapi>=0.1.9",
        "limits>=3.8.0",
        
        # Utils
        "email-validator>=2.1.0",
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0.0",
        "gitpython>=3.1.40",
    ]
    
    print("Installing backend dependencies...")
    print("=" * 50)
    
    for pkg in packages:
        print(f"Installing {pkg}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            print(f"✓ {pkg} installed")
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to install {pkg}: {e}")
            return False
    
    print("=" * 50)
    print("All dependencies installed successfully!")
    print("\nYou can now start the backend with:")
    print("  python -m backend.main")
    return True

if __name__ == "__main__":
    install_packages()
