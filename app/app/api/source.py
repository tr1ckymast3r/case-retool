"""
Source code browser API — serve extracted files from analysis output.
"""
import os
import json
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse

router = APIRouter()

OUTPUT_DIR = "/data/output"


@router.get("/api/source/{analysis_id}/tree")
async def get_source_tree(analysis_id: str, path: str = Query("", alias="path")):
    """Get directory tree for an analysis's extracted files."""
    extract_dir = os.path.join(OUTPUT_DIR, analysis_id, "extracted")
    if not os.path.exists(extract_dir):
        # Try the main output dir itself
        extract_dir = os.path.join(OUTPUT_DIR, analysis_id)

    target_dir = os.path.join(extract_dir, path) if path else extract_dir
    if not os.path.exists(target_dir):
        raise HTTPException(404, "Directory not found")

    entries = []
    try:
        for name in sorted(os.listdir(target_dir)):
            full_path = os.path.join(target_dir, name)
            rel_path = os.path.join(path, name) if path else name
            is_dir = os.path.isdir(full_path)
            entry = {
                "name": name,
                "path": rel_path,
                "is_dir": is_dir,
            }
            if not is_dir:
                try:
                    entry["size"] = os.path.getsize(full_path)
                except:
                    entry["size"] = 0
                entry["ext"] = os.path.splitext(name)[1].lower()
            entries.append(entry)
    except PermissionError:
        raise HTTPException(403, "Permission denied")

    return {"analysis_id": analysis_id, "path": path, "entries": entries}


@router.get("/api/source/{analysis_id}/file")
async def get_source_file(analysis_id: str, path: str = Query(..., alias="path")):
    """Get file content for a specific file in the analysis."""
    extract_dir = os.path.join(OUTPUT_DIR, analysis_id, "extracted")
    if not os.path.exists(extract_dir):
        extract_dir = os.path.join(OUTPUT_DIR, analysis_id)

    file_path = os.path.join(extract_dir, path)
    if not os.path.exists(file_path):
        raise HTTPException(404, "File not found")
    if os.path.isdir(file_path):
        raise HTTPException(400, "Is a directory, not a file")

    # Check file size - limit to 2MB for text display
    fsize = os.path.getsize(file_path)
    if fsize > 2 * 1024 * 1024:
        raise HTTPException(413, f"File too large ({fsize} bytes). Max 2MB.")

    # Try to read as text
    try:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
        return {
            "path": path,
            "size": fsize,
            "content": content,
            "lines": content.count("\n") + 1,
            "binary": False,
        }
    except Exception:
        # Binary file
        return {
            "path": path,
            "size": fsize,
            "content": None,
            "binary": True,
            "error": "Binary file — cannot display as text",
        }


@router.get("/api/source/{analysis_id}/functions")
async def get_source_functions(analysis_id: str, path: str = Query(..., alias="path")):
    """Get JS functions for a specific file (from cached analysis results)."""
    import sqlite3
    db_path = "/app/data/retool.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT worker_results FROM analyses WHERE id = ?", (analysis_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(404, "Analysis not found")

    wr = json.loads(row[0])
    children = wr.get("children", [])

    # Find matching child by filename
    fname = os.path.basename(path)
    for child in children:
        if child.get("filename") == fname:
            js = child.get("results", {}).get("js_analysis", {})
            if js:
                return js

    # Not found in children — try to analyze on the fly
    extract_dir = os.path.join(OUTPUT_DIR, analysis_id, "extracted")
    file_path = os.path.join(extract_dir, path)
    if os.path.exists(file_path) and file_path.endswith(".js"):
        try:
            import sys
            sys.path.insert(0, "/opt/retool/scripts")
            from js_analyzer import analyze_js_deep
            return analyze_js_deep(file_path)
        except Exception as e:
            return {"error": str(e)}

    return {"error": "No JS analysis available for this file"}
