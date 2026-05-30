"""
Dashboard statistics endpoint.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..database import get_db
from ..models import Analysis

router = APIRouter(prefix="/api", tags=["stats"])


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics."""
    total = db.query(func.count(Analysis.id)).scalar() or 0
    completed = db.query(func.count(Analysis.id)).filter(Analysis.status == "completed").scalar() or 0
    analyzing = db.query(func.count(Analysis.id)).filter(Analysis.status.in_(["queued", "analyzing"])).scalar() or 0
    failed = db.query(func.count(Analysis.id)).filter(Analysis.status == "failed").scalar() or 0

    # Platform distribution
    platform_rows = (
        db.query(Analysis.platform, func.count(Analysis.id))
        .group_by(Analysis.platform)
        .all()
    )
    platform_dist = {row[0] or "Unknown": row[1] for row in platform_rows}

    # File type distribution
    type_rows = (
        db.query(Analysis.file_type, func.count(Analysis.id))
        .group_by(Analysis.file_type)
        .all()
    )
    type_dist = {row[0] or "Unknown": row[1] for row in type_rows}

    # Total file size analyzed
    total_size = db.query(func.sum(Analysis.file_size)).scalar() or 0

    # Recent analyses
    recent = (
        db.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(5)
        .all()
    )
    recent_list = [
        {
            "id": a.id,
            "filename": a.filename,
            "file_type": a.file_type,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in recent
    ]

    return {
        "total": total,
        "completed": completed,
        "analyzing": analyzing,
        "failed": failed,
        "total_size": total_size,
        "platform_distribution": platform_dist,
        "type_distribution": type_dist,
        "recent_analyses": recent_list,
    }
