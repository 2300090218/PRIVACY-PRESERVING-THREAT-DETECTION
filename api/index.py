"""
Vercel Serverless Function Gateway - Privacy-Preserving Threat Detection Platform
Unified entry point for @vercel/python runtime connecting Next.js frontend with FastAPI backend.
"""

import os
import sys
import tempfile
import asyncio

# Ensure project root and all internal packages are accessible in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

PRIVACY_GATEWAY_DIR = os.path.join(ROOT_DIR, "privacy_gateway")
if PRIVACY_GATEWAY_DIR not in sys.path:
    sys.path.insert(0, PRIVACY_GATEWAY_DIR)

ML_DIR = os.path.join(ROOT_DIR, "ml")
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

# Handle Vercel serverless read-only filesystem by redirecting SQLite, models, and datasets to writable /tmp
if os.environ.get("VERCEL"):
    import shutil
    tmp_dir = "/tmp" if os.path.exists("/tmp") else tempfile.gettempdir()

    current_db_url = os.environ.get("DATABASE_URL", "")
    if not current_db_url or "sqlite" in current_db_url:
        tmp_db_path = os.path.join(tmp_dir, "threat_detection.db").replace("\\", "/")
        root_db_path = os.path.join(ROOT_DIR, "threat_detection.db")
        if os.path.exists(root_db_path) and not os.path.exists(tmp_db_path):
            try:
                shutil.copyfile(root_db_path, tmp_db_path)
            except Exception:
                pass
        os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{tmp_db_path}"

    tmp_models = os.path.join(tmp_dir, "models").replace("\\", "/")
    root_models = os.path.join(ROOT_DIR, "ml", "models")
    if os.path.exists(root_models) and not os.path.exists(tmp_models):
        try:
            shutil.copytree(root_models, tmp_models, dirs_exist_ok=True)
        except Exception:
            pass
    if os.path.exists(tmp_models):
        os.environ["MODEL_DIR"] = tmp_models

    tmp_datasets = os.path.join(tmp_dir, "datasets").replace("\\", "/")
    root_datasets = os.path.join(ROOT_DIR, "ml", "datasets")
    if os.path.exists(root_datasets) and not os.path.exists(tmp_datasets):
        try:
            shutil.copytree(root_datasets, tmp_datasets, dirs_exist_ok=True)
        except Exception:
            pass
    if os.path.exists(tmp_datasets):
        os.environ["DATASET_DIR"] = tmp_datasets

# Import main FastAPI application instance from backend
from backend.app.main import app, initialize_platform

# Cold-start initialization guard for Vercel serverless functions
_init_lock = None
_platform_initialized = False

async def _ensure_serverless_initialized():
    """Ensures database tables and baseline seeds are created on cold start."""
    global _init_lock, _platform_initialized
    if not _platform_initialized:
        if _init_lock is None:
            _init_lock = asyncio.Lock()
        async with _init_lock:
            if not _platform_initialized:
                try:
                    await initialize_platform()
                except Exception as e:
                    print(f"[Vercel Gateway] Auto-init notice: {e}")
                _platform_initialized = True

# Normalizer & Cold-Start Middleware for Vercel Serverless Routing
@app.middleware("http")
async def vercel_gateway_middleware(request, call_next):
    # Ensure database schema is ready even if ASGI lifespan was bypassed
    await _ensure_serverless_initialized()

    # Normalize incoming URL paths across Vercel route dispatch modes
    path = request.scope.get("path", "")
    if path == "/api/docs":
        request.scope["path"] = "/docs"
    elif path == "/api/openapi.json":
        request.scope["path"] = "/openapi.json"
    elif path == "/api/redoc":
        request.scope["path"] = "/redoc"
    elif path in ("/api", "/api/"):
        request.scope["path"] = "/"
    elif path and not path.startswith("/api") and path not in ("/docs", "/openapi.json", "/redoc", "/"):
        # Prepend /api if route was invoked with stripped prefix by reverse proxy
        request.scope["path"] = f"/api{path}"

    response = await call_next(request)
    return response

# Export app for Vercel Python runtime
__all__ = ["app"]
