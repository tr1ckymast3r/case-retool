"""
Upload endpoint — handles file upload, local analysis,
worker task dispatch, and background polling for results.
"""

import os
import uuid
import json
import time
import shutil
import threading
from datetime import datetime

from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import Analysis
from app.engines.static_engine import run_local_analysis, merge_worker_results, mark_completed

router = APIRouter(prefix="/api", tags=["upload"])


def _save_upload(file: UploadFile) -> tuple:
    """Save uploaded file to uploads directory. Returns (filepath, file_size)."""
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)

    # Generate unique filename to avoid collisions
    ext = os.path.splitext(file.filename)[1] if file.filename else ""
    saved_name = f"{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(settings.UPLOAD_DIR, saved_name)

    file_size = 0
    with open(filepath, "wb") as f:
        while True:
            chunk = file.file.read(8192)
            if not chunk:
                break
            f.write(chunk)
            file_size += len(chunk)

    return filepath, file_size


def _start_worker_poll(analysis_id: str, filepath: str, profile: str, file_type: str):
    """Write task to worker input and start background polling thread."""

    os.makedirs(settings.WORKER_INPUT, exist_ok=True)
    os.makedirs(settings.WORKER_OUTPUT, exist_ok=True)

    print(f"[ReTool] Dispatching to worker: id={analysis_id}, type={file_type}, profile={profile}", flush=True)
    print(f"[ReTool]   Source: {filepath}", flush=True)
    print(f"[ReTool]   Worker input: {settings.WORKER_INPUT}", flush=True)

    # Copy file to shared volume so worker can access it
    shared_input = os.path.join(settings.WORKER_INPUT, f"{analysis_id}_{os.path.basename(filepath)}")
    try:
        shutil.copy2(filepath, shared_input)
        worker_filepath = shared_input
        print(f"[ReTool]   Copied to: {shared_input} ({os.path.getsize(shared_input)} bytes)", flush=True)
    except Exception as e:
        print(f"[WARN] Could not copy to shared volume: {e}", flush=True)
        mark_completed(analysis_id, None)
        return

    # Write task JSON for worker
    task = {
        "id": analysis_id,
        "filepath": worker_filepath,
        "profile": profile,
        "file_type": file_type,
        "timestamp": datetime.utcnow().isoformat(),
    }
    task_path = os.path.join(settings.WORKER_INPUT, f"{analysis_id}.json")
    try:
        with open(task_path, "w") as f:
            json.dump(task, f)
        print(f"[ReTool]   Task written: {task_path}", flush=True)
        # Verify it was written
        if os.path.exists(task_path):
            print(f"[ReTool]   Task verified: {os.path.getsize(task_path)} bytes", flush=True)
        else:
            print(f"[ERROR]   Task file NOT found after write!", flush=True)
    except Exception as e:
        # If we can't write to worker input, just mark completed with local results
        print(f"[WARN] Could not write worker task: {e}", flush=True)
        mark_completed(analysis_id, None)
        return

    # Background thread polls for worker result
    def poll_worker():
        result_path = os.path.join(settings.WORKER_OUTPUT, f"{analysis_id}.json")
        print(f"[ReTool]   Polling for: {result_path}", flush=True)
        for i in range(300):  # 10 minutes max (2s * 300)
            time.sleep(2)
            if os.path.exists(result_path):
                try:
                    # Small delay to ensure file is fully written
                    time.sleep(0.5)
                    with open(result_path) as f:
                        worker_result = json.load(f)
                    print(f"[ReTool]   Worker result received for {analysis_id}", flush=True)
                    merge_worker_results(analysis_id, worker_result, None)
                    # Clean up task and result files
                    try:
                        os.remove(task_path)
                    except Exception:
                        pass
                    try:
                        os.remove(result_path)
                    except Exception:
                        pass
                except Exception as e:
                    print(f"[ERROR] Failed to process worker result: {e}", flush=True)
                    mark_completed(analysis_id, None)
                return
            if i % 30 == 29:  # Log every 60 seconds
                print(f"[ReTool]   Still waiting for worker result ({analysis_id})... {(i+1)*2}s", flush=True)
        else:
            # Timeout — mark as completed with local results only
            print(f"[WARN] Worker timeout for analysis {analysis_id}", flush=True)
            mark_completed(analysis_id, None)
            # Clean up task file
            try:
                os.remove(task_path)
            except Exception:
                pass

    thread = threading.Thread(target=poll_worker, daemon=True)
    thread.start()


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    profile: str = Form("quick_scan"),
    db: Session = Depends(get_db),
):
    """Upload a file for reverse engineering analysis."""

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Save file
    try:
        filepath, file_size = _save_upload(file)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {str(e)}")

    # Create analysis record
    analysis_id = uuid.uuid4().hex
    analysis = Analysis(
        id=analysis_id,
        filename=file.filename,
        filepath=filepath,
        file_size=file_size,
        status="queued",
        analysis_profile=profile,
        created_at=datetime.utcnow(),
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # Run local quick analysis (fast, synchronous)
    try:
        run_local_analysis(analysis, db)
    except Exception as e:
        analysis.status = "failed"
        analysis.error_message = f"Local analysis error: {str(e)}"
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))

    # Start background worker polling
    _start_worker_poll(
        analysis_id=analysis_id,
        filepath=filepath,
        profile=profile,
        file_type=analysis.file_type or "Unknown",
    )

    # Refresh from DB to get updated fields
    db.refresh(analysis)

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "file_type": analysis.file_type,
        "platform": analysis.platform,
        "status": analysis.status,
        "file_size": analysis.file_size,
        "md5": analysis.md5,
        "sha256": analysis.sha256,
        "message": "File uploaded. Local analysis complete. Deep analysis in progress.",
    }