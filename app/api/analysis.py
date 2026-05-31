"""
CRUD endpoints for analysis records.
"""

import json
import os
import uuid
import threading
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app.models import Analysis
from app.engines.static_engine import run_local_analysis
from app.engines.report_engine import generate_report

router = APIRouter(prefix="/api", tags=["analyses"])


@router.get("/analyses")
def list_analyses(
    status: str = Query(None, description="Filter by status"),
    file_type: str = Query(None, description="Filter by file type"),
    search: str = Query(None, description="Search filename or hash"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List analyses with optional filters."""
    query = db.query(Analysis)

    if status:
        query = query.filter(Analysis.status == status)
    if file_type:
        query = query.filter(Analysis.file_type.ilike(f"%{file_type}%"))
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Analysis.filename.ilike(search_pattern),
                Analysis.md5.ilike(search_pattern),
                Analysis.sha256.ilike(search_pattern),
                Analysis.sha1.ilike(search_pattern),
            )
        )

    total = query.count()
    analyses = query.order_by(Analysis.created_at.desc()).offset(offset).limit(limit).all()

    results = []
    for a in analyses:
        results.append({
            "id": a.id,
            "filename": a.filename,
            "file_type": a.file_type,
            "platform": a.platform,
            "file_size": a.file_size,
            "status": a.status,
            "md5": a.md5,
            "sha256": a.sha256,
            "analysis_profile": a.analysis_profile,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "completed_at": a.completed_at.isoformat() if a.completed_at else None,
            "error_message": a.error_message,
        })

    return {"total": total, "offset": offset, "limit": limit, "analyses": results}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str, db: Session = Depends(get_db)):
    """Get full analysis details by ID."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    def _safe_json(text):
        if not text:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "filepath": analysis.filepath,
        "file_type": analysis.file_type,
        "platform": analysis.platform,
        "file_size": analysis.file_size,
        "status": analysis.status,
        "analysis_profile": analysis.analysis_profile,
        "md5": analysis.md5,
        "sha1": analysis.sha1,
        "sha256": analysis.sha256,
        "tech_stack": _safe_json(analysis.tech_stack),
        "architecture": _safe_json(analysis.architecture),
        "features": _safe_json(analysis.features),
        "api_endpoints": _safe_json(analysis.api_endpoints),
        "dependencies": _safe_json(analysis.dependencies),
        "data_models": _safe_json(analysis.data_models),
        "network_activity": _safe_json(analysis.network_activity),
        "decompiled_code": _safe_json(analysis.decompiled_code),
        "config_values": _safe_json(analysis.config_values),
        "ai_summary": analysis.ai_summary,
        "worker_results": _safe_json(analysis.worker_results),
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
        "error_message": analysis.error_message,
    }


@router.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id: str, db: Session = Depends(get_db)):
    """Delete an analysis and its files."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Remove uploaded file
    if analysis.filepath and os.path.exists(analysis.filepath):
        try:
            os.remove(analysis.filepath)
        except Exception:
            pass

    # Remove report directory
    from app.config import settings
    report_dir = os.path.join(settings.REPORTS_DIR, analysis_id)
    if os.path.exists(report_dir):
        try:
            import shutil
            shutil.rmtree(report_dir)
        except Exception:
            pass

    db.delete(analysis)
    db.commit()

    return {"message": "Analysis deleted", "id": analysis_id}


@router.post("/analyses/{analysis_id}/reanalyze")
def reanalyze(analysis_id: str, db: Session = Depends(get_db)):
    """Re-run analysis on an existing file."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    if not analysis.filepath or not os.path.exists(analysis.filepath):
        raise HTTPException(status_code=400, detail="Original file no longer exists")

    # Reset status
    analysis.status = "queued"
    analysis.error_message = None
    analysis.completed_at = None
    analysis.worker_results = "{}"
    db.commit()

    # Re-run local analysis
    try:
        run_local_analysis(analysis, db)
    except Exception as e:
        analysis.status = "failed"
        analysis.error_message = f"Re-analysis failed: {str(e)}"
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))

    # Re-send to worker
    from app.api.upload import _start_worker_poll
    _start_worker_poll(
        analysis_id=analysis_id,
        filepath=analysis.filepath,
        profile=analysis.analysis_profile or "quick_scan",
        file_type=analysis.file_type or "Unknown",
    )

    db.refresh(analysis)

    return {
        "id": analysis.id,
        "status": analysis.status,
        "message": "Re-analysis started",
    }