"""
ReTool v2 — FastAPI Application
2-container architecture: App (UI + API) + Worker (RE tools)
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db
from .api.upload import router as upload_router
from .api.analysis import router as analysis_router
from .api.stats import router as stats_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Create required directories
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    os.makedirs(settings.WORKER_INPUT, exist_ok=True)
    os.makedirs(settings.WORKER_OUTPUT, exist_ok=True)

    # Ensure DB directory exists
    db_dir = os.path.dirname(settings.DATABASE_URL.replace("sqlite:///", ""))
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    # Initialize database
    init_db()

    print(f"[ReTool] App started on port 3010")
    print(f"[ReTool] Upload dir: {settings.UPLOAD_DIR}")
    print(f"[ReTool] Reports dir: {settings.REPORTS_DIR}")
    print(f"[ReTool] Worker input: {settings.WORKER_INPUT}")
    print(f"[ReTool] Worker output: {settings.WORKER_OUTPUT}")

    yield

    print("[ReTool] App shutting down")


app = FastAPI(
    title="ReTool v2",
    description="Reverse Engineering Analysis Platform — 2-container architecture",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(stats_router)

# Serve frontend if templates exist
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")

# Mount static files if directory exists
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def index():
    """Serve the main UI page."""
    index_path = os.path.join(templates_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return {
        "name": "ReTool v2",
        "version": "2.0.0",
        "description": "Reverse Engineering Analysis Platform",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "2.0.0"}
