from __future__ import annotations
from pathlib import Path
from fastapi import BackgroundTasks, FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import hashlib, json
from typing import Any, Dict, Optional
from datetime import datetime

# === Import your real detector ===
# Make sure your script file is at server/detector/hardened.py
# and it defines: detect_signatures_and_headers(path: Path) -> dict
from detector.hardened import detect_signatures_and_headers
from detector.pdf_full import analyze_pdf_full
from detector.office_full import analyze_office_full
from detector.pe_full import analyze_pe_full
from cape_integration import (
    create_dynamic_state,
    html_report_path_for_sha,
    html_report_path_for_task,
    load_cape_json_for_sha,
    load_dynamic_state,
    lookup_cape_analysis,
    post_analysis_callback,
    run_dynamic_analysis,
)

# Try to import enhanced PDF analysis
try:
    from detector.pdf_enhanced import analyze_pdf_enhanced, get_available_libraries
    PDF_ENHANCED_AVAILABLE = True
    PDF_LIBRARIES_STATUS = get_available_libraries()
    print("Enhanced PDF analysis available:", PDF_LIBRARIES_STATUS)
except ImportError as e:
    PDF_ENHANCED_AVAILABLE = False
    PDF_LIBRARIES_STATUS = {}
    analyze_pdf_enhanced = None
    print("Enhanced PDF analysis not available:", e)

# Try to import enhanced Office analysis
try:
    from detector.office_enhanced import analyze_office_enhanced, get_available_libraries as get_office_libraries
    OFFICE_ENHANCED_AVAILABLE = True
    OFFICE_LIBRARIES_STATUS = get_office_libraries()
    print("Enhanced Office analysis available:", OFFICE_LIBRARIES_STATUS)
except ImportError as e:
    OFFICE_ENHANCED_AVAILABLE = False
    OFFICE_LIBRARIES_STATUS = {}
    analyze_office_enhanced = None
    print("Enhanced Office analysis not available:", e)
try:
    from report_generator import generate_pdf_report
    REPORT_GENERATION_AVAILABLE = True
except ImportError:
    REPORT_GENERATION_AVAILABLE = False
    print("Warning: reportlab not installed. PDF report generation disabled.")

BASE = Path(__file__).parent
QUAR = BASE / "quarantine"
OUT  = BASE / "out"
QUAR.mkdir(exist_ok=True)
OUT.mkdir(exist_ok=True)

MAX_BYTES = 64 * 1024 * 1024  # 64 MB

app = FastAPI(title="Fathom API")

# CORS for Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def route_suggestion(final_type: str) -> str:
    if final_type in ("pe", "dll"):
        return "static_pe"
    if final_type == "pdf":
        return "static_pdf"
    if final_type in ("office_ooxml", "office_ole"):
        return "static_office"
    return "none"

@app.post("/api/upload")
async def upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    callback_url: Optional[str] = Form(default=None),
):
    # Read into memory (fine for dev; switch to streamed-save if you need >64MB)
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    # Save to quarantine with a safe name
    import re
    safe_name = file.filename or "unknown_file"
    # Remove or replace problematic characters
    safe_name = re.sub(r'[<>:"|?*\\\/]', '_', safe_name)
    # Remove any remaining non-ASCII characters that might cause issues
    safe_name = re.sub(r'[^\w\-_\.]', '_', safe_name)
    # Ensure it's not empty and has reasonable length
    if not safe_name or safe_name.startswith('.'):
        safe_name = "uploaded_file"
    if len(safe_name) > 100:
        name_part, ext_part = safe_name.rsplit('.', 1) if '.' in safe_name else (safe_name, '')
        safe_name = name_part[:90] + ('.' + ext_part if ext_part else '')
    
    dest = QUAR / safe_name
    try:
        dest.write_bytes(content)
    except OSError as e:
        # If we still have path issues, use SHA256 as filename
        sha_fallback = hashlib.sha256(content).hexdigest()[:16]
        dest = QUAR / f"file_{sha_fallback}.bin"
        dest.write_bytes(content)

    # Run your detector
    try:
        record = detect_signatures_and_headers(dest)  # <-- your function
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detector error: {e}")

    # Enrich with a route suggestion (optional)
    final_type = (record.get("final_guess") or {}).get("type", "unknown")
    record["route"] = route_suggestion(final_type)
    
    # If it's a PDF, automatically run enhanced analysis and merge results
    if final_type == "pdf":
        try:
            if PDF_ENHANCED_AVAILABLE:
                enhanced_result = analyze_pdf_enhanced(str(dest))
                # Merge enhanced results into the main record
                if "static" not in record:
                    record["static"] = {}
                record["static"]["pdf"] = enhanced_result.get("static", {}).get("pdf", {})
                
                # Merge counts
                if "counts" not in record:
                    record["counts"] = {}
                enhanced_counts = enhanced_result.get("counts", {})
                record["counts"].update(enhanced_counts)
                
                # Merge errors
                enhanced_errors = enhanced_result.get("errors", [])
                if enhanced_errors:
                    if "errors" not in record:
                        record["errors"] = []
                    record["errors"].extend(enhanced_errors)
                    
        except Exception as e:
            # Don't fail the whole upload if enhanced analysis fails
            if "errors" not in record:
                record["errors"] = []
            record["errors"].append(f"enhanced_pdf_analysis_error:{e}")

    # If it's an Office document, automatically run enhanced analysis and merge results
    if final_type in ["office_ooxml", "office_ole"] or "office" in final_type.lower():
        try:
            if OFFICE_ENHANCED_AVAILABLE:
                enhanced_result = analyze_office_enhanced(str(dest))
                # Merge enhanced results into the main record
                if "static" not in record:
                    record["static"] = {}
                record["static"]["office"] = enhanced_result.get("static", {}).get("office", {})
                
                # Merge counts
                if "counts" not in record:
                    record["counts"] = {}
                enhanced_counts = enhanced_result.get("counts", {})
                record["counts"].update(enhanced_counts)
                
                # Merge errors
                enhanced_errors = enhanced_result.get("errors", [])
                if enhanced_errors:
                    if "errors" not in record:
                        record["errors"] = []
                    record["errors"].extend(enhanced_errors)
                    
        except Exception as e:
            # Don't fail the whole upload if enhanced analysis fails
            if "errors" not in record:
                record["errors"] = []
            record["errors"].append(f"enhanced_office_analysis_error:{e}")

    # Persist JSON by sha256 (fallback if your dict somehow lacks it)
    sha = record.get("sha256") or hashlib.sha256(content).hexdigest()

    try:
        dynamic_state = create_dynamic_state(sha, dest, file.filename, callback_url)
        background_tasks.add_task(run_dynamic_analysis, sha, str(dest), file.filename)
        record["dynamic"] = {
            "enabled": True,
            "status": dynamic_state.get("status"),
            "cape_task_id": dynamic_state.get("cape_task_id"),
            "status_url": f"/api/dynamic/{sha}",
        }
    except Exception as e:
        record["dynamic"] = {
            "enabled": False,
            "status": "failed",
            "error": f"dynamic_start_error:{e}",
        }

    (OUT / f"{sha}.json").write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    if callback_url:
        callback_payload = {
            "record": record,
            "report_url": f"/api/report/{sha}",
            "dynamic_status_url": f"/api/dynamic/{sha}",
            "dynamic_report_json_url": f"/api/dynamic/{sha}/report-json",
            "dynamic_report_html_url": f"/api/dynamic/{sha}/report-html",
        }
        background_tasks.add_task(post_analysis_callback, callback_url, "static_completed", sha, callback_payload)

    return record

@app.get("/api/report/{sha256}")
async def get_report(sha256: str):
    p = OUT / f"{sha256}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return json.loads(p.read_text(encoding="utf-8"))


@app.get("/api/dynamic/lookup")
async def lookup_dynamic_report(q: str):
    try:
        return lookup_cape_analysis(q)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dynamic_lookup_error:{e}")


@app.get("/api/dynamic/task/{task_id}/report-html")
async def get_dynamic_task_report_html(task_id: int):
    try:
        path = html_report_path_for_task(task_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dynamic_task_report_html_error:{e}")
    return FileResponse(path=str(path), filename=path.name, media_type="text/html")


@app.get("/api/dynamic/{sha256}")
async def get_dynamic_status(sha256: str):
    return load_dynamic_state(sha256)


@app.get("/api/dynamic/{sha256}/report-json")
async def get_dynamic_report_json(sha256: str):
    try:
        return load_cape_json_for_sha(sha256)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dynamic_report_read_error:{e}")


@app.get("/api/dynamic/{sha256}/report-html")
async def get_dynamic_report_html(sha256: str):
    try:
        path = html_report_path_for_sha(sha256)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"dynamic_report_html_error:{e}")
    return FileResponse(path=str(path), filename=path.name, media_type="text/html")

# =========================
# Static PDF routes
# =========================
@app.post("/api/static/pdf/analyze")
async def analyze_pdf(file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    # Save to quarantine under sha-based filename
    sha = hashlib.sha256(content).hexdigest()
    safe_name = f"{sha}.pdf"
    dest = QUAR / safe_name
    try:
        dest.write_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"write_error:{e}")

    try:
        # Use enhanced PDF analysis if available, otherwise fallback to basic
        if PDF_ENHANCED_AVAILABLE:
            res = analyze_pdf_enhanced(str(dest))
        else:
            res = analyze_pdf_full(str(dest))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pdf_analyze_error:{e}")

    # Optionally persist merged view into out/<sha>.json if exists, else write a minimal record
    out_path = OUT / f"{sha}.json"
    try:
        if out_path.exists():
            record: Dict[str, Any] = json.loads(out_path.read_text(encoding="utf-8"))
            # merge static/counts/errors
            record.setdefault("static", {})
            record["static"]["pdf"] = (res.get("static") or {}).get("pdf")
            record.setdefault("counts", {})
            for k, v in (res.get("counts") or {}).items():
                if k not in record["counts"]:
                    record["counts"][k] = v
            if res.get("errors"):
                record.setdefault("errors", []).extend(res["errors"]) 
        else:
            record = {
                "filename": file.filename,
                "sha256": sha,
                "static": res.get("static"),
                "counts": res.get("counts"),
                "errors": res.get("errors"),
            }
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        # non-fatal
        pass

    return {"sha256": sha, **res}


@app.get("/api/static/pdf/{sha}")
async def get_pdf_static(sha: str):
    p = OUT / f"{sha}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        record = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"read_error:{e}")
    return {
        "static": record.get("static"),
        "counts": record.get("counts"),
        "errors": record.get("errors") or [],
    }


# =========================
# Static PE routes
# =========================
@app.post("/api/static/pe/analyze")
async def analyze_pe(file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    sha = hashlib.sha256(content).hexdigest()
    # Safely extract extension, limiting to alphanumeric characters
    import re
    filename = file.filename or ""
    if "." in filename:
        ext = filename.rsplit(".", 1)[-1].lower()
        # Only allow safe extensions (alphanumeric + common safe chars)
        ext = re.sub(r'[^a-z0-9]', '', ext)[:10]  # limit length too
        if not ext:
            ext = "pe"
    else:
        ext = "pe"
    safe_name = f"{sha}.{ext}"
    dest = QUAR / safe_name
    try:
        dest.write_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"write_error:{e}")

    try:
        res = analyze_pe_full(str(dest))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pe_analyze_error:{e}")

    out_path = OUT / f"{sha}.json"
    try:
        if out_path.exists():
            record: Dict[str, Any] = json.loads(out_path.read_text(encoding="utf-8"))
            record.setdefault("static", {})
            record["static"]["pe"] = (res.get("static") or {}).get("pe")
            record.setdefault("counts", {})
            for k, v in (res.get("counts") or {}).items():
                if k not in record["counts"]:
                    record["counts"][k] = v
            if res.get("errors"):
                record.setdefault("errors", []).extend(res["errors"])
        else:
            record = {
                "filename": file.filename,
                "sha256": sha,
                "static": res.get("static"),
                "counts": res.get("counts"),
                "errors": res.get("errors"),
            }
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

    return {"sha256": sha, **res}


@app.get("/api/static/pe/{sha}")
async def get_pe_static(sha: str):
    p = OUT / f"{sha}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        record = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"read_error:{e}")
    return {
        "static": record.get("static"),
        "counts": record.get("counts"),
        "errors": record.get("errors") or [],
    }

# =========================
# Static Office routes
# =========================
@app.post("/api/static/office/analyze")
async def analyze_office(file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    sha = hashlib.sha256(content).hexdigest()
    # Safely extract extension, limiting to alphanumeric characters
    import re
    filename = file.filename or ""
    if "." in filename:
        ext = filename.rsplit(".", 1)[-1].lower()
        # Only allow safe extensions (alphanumeric + common safe chars)
        ext = re.sub(r'[^a-z0-9]', '', ext)[:10]  # limit length too
        if not ext:
            ext = "office"
    else:
        ext = "office"
    safe_name = f"{sha}.{ext}"
    dest = QUAR / safe_name
    try:
        dest.write_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"write_error:{e}")

    try:
        res = analyze_office_full(str(dest))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"office_analyze_error:{e}")

    # Merge/persist similar to PDF
    out_path = OUT / f"{sha}.json"
    try:
        if out_path.exists():
            record: Dict[str, Any] = json.loads(out_path.read_text(encoding="utf-8"))
            record.setdefault("static", {})
            record["static"]["office"] = (res.get("static") or {}).get("office")
            record.setdefault("counts", {})
            for k, v in (res.get("counts") or {}).items():
                if k not in record["counts"]:
                    record["counts"][k] = v
            if res.get("errors"):
                record.setdefault("errors", []).extend(res["errors"]) 
        else:
            record = {
                "filename": file.filename,
                "sha256": sha,
                "static": res.get("static"),
                "counts": res.get("counts"),
                "errors": res.get("errors"),
            }
        out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

    return {"sha256": sha, **res}


@app.get("/api/static/office/{sha}")
async def get_office_static(sha: str):
    p = OUT / f"{sha}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        record = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"read_error:{e}")
    return {
        "static": record.get("static"),
        "counts": record.get("counts"),
        "errors": record.get("errors") or [],
    }

# =========================
# PDF Report Generation
# =========================
@app.post("/api/report/generate/{sha}")
async def generate_report(sha: str):
    """Generate a PDF report for the given analysis"""
    if not REPORT_GENERATION_AVAILABLE:
        raise HTTPException(status_code=503, detail="PDF report generation not available. Please install reportlab: pip install reportlab")
    
    report_path = OUT / f"{sha}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Analysis report not found")
    
    try:
        # Load the analysis record
        record = json.loads(report_path.read_text(encoding="utf-8"))
        
        # Generate PDF report
        pdf_path = generate_pdf_report(record, str(OUT))
        
        # Return the PDF file path for download
        return {"pdf_path": pdf_path, "filename": Path(pdf_path).name}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

@app.get("/api/report/download/{filename}")
async def download_report(filename: str):
    """Download a generated PDF report"""
    pdf_path = OUT / filename
    
    if not pdf_path.exists() or not filename.endswith('.pdf'):
        raise HTTPException(status_code=404, detail="Report file not found")
    
    return FileResponse(
        path=str(pdf_path),
        filename=filename,
        media_type='application/pdf'
    )

@app.get("/api/report/list")
async def list_reports():
    """List all available PDF reports"""
    try:
        reports = []
        for pdf_file in OUT.glob("fathom_report_*.pdf"):
            stat = pdf_file.stat()
            reports.append({
                "filename": pdf_file.name,
                "size": stat.st_size,
                "created": stat.st_ctime,
                "modified": stat.st_mtime
            })
        
        # Sort by creation time, newest first
        reports.sort(key=lambda x: x["created"], reverse=True)
        return {"reports": reports}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {e}")

# =========================
# Office Macro Extraction
# =========================
@app.post("/api/extract/office/{sha}")
async def extract_office_macros(sha: str):
    """Extract VBA macros from Office documents"""
    
    # Check if we have the Office file - look for files by SHA and by original filename
    office_path = None
    
    # First, try to find by SHA256 hash (for files saved with hash names)
    for ext in ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt', '.docm', '.xlsm', '.pptm', '.bin', '']:
        test_path = QUAR / f"{sha}{ext}"
        if test_path.exists():
            office_path = test_path
            break
    
    # If not found by hash, search all files in quarantine and match by content hash
    if not office_path:
        for file_path in QUAR.iterdir():
            if file_path.is_file():
                try:
                    # Check if this file's SHA256 matches
                    file_content = file_path.read_bytes()
                    file_sha = hashlib.sha256(file_content).hexdigest()
                    if file_sha == sha:
                        office_path = file_path
                        break
                except Exception:
                    continue
    
    if not office_path:
        raise HTTPException(status_code=404, detail="Office file not found")
    
    try:
        # Import extraction system
        from office_extractor import extract_office_macros
        
        # Extract macros
        extraction_results = extract_office_macros(str(office_path), str(OUT / "macro_extractions"))
        
        return {
            "sha256": sha,
            "extraction_success": extraction_results["extraction_summary"]["extraction_success"],
            "extraction_dir": extraction_results["extraction_dir"],
            "summary": extraction_results["extraction_summary"],
            "extracted_content": extraction_results["extracted_content"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Macro extraction failed: {e}")

@app.get("/api/extract/office/{sha}/download/{file_type}/{filename}")
async def download_extracted_macro(sha: str, file_type: str, filename: str):
    """Download an extracted macro file"""
    
    # Construct the file path
    extraction_dir = OUT / "macro_extractions"
    file_path = extraction_dir / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Extracted file not found")
    
    # Determine media type based on file extension
    media_type = "text/plain"
    if filename.endswith('.vba'):
        media_type = "text/plain"
    elif filename.endswith('.bin'):
        media_type = "application/octet-stream"
    
    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type=media_type
    )

@app.get("/api/extract/office/{sha}/report")
async def get_macro_extraction_report(sha: str):
    """Get detailed macro extraction report"""
    
    try:
        # Look for extraction results
        extraction_dir = OUT / "macro_extractions"
        report_file = extraction_dir / f"{sha}_macro_report.json"
        
        if report_file.exists():
            with open(report_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            return report_data
        else:
            raise HTTPException(status_code=404, detail="Macro extraction report not found")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read macro extraction report: {e}")

@app.delete("/api/extract/office/{sha}")
async def cleanup_macro_extraction(sha: str):
    """Clean up extracted macro files"""
    
    try:
        extraction_dir = OUT / "macro_extractions"
        
        # Remove extracted files for this SHA
        import shutil
        if extraction_dir.exists():
            for item in extraction_dir.iterdir():
                if sha in item.name:
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
        
        return {"message": f"Cleaned up macro extraction files for {sha}"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {e}")

# =========================
# PDF Content Extraction
# =========================
@app.post("/api/extract/pdf/{sha}")
async def extract_pdf_content(sha: str):
    """Extract embedded files and JavaScript from a PDF"""
    
    # Check if we have the PDF file - look for files by SHA and by original filename
    pdf_path = None
    
    # First, try to find by SHA256 hash (for files saved with hash names)
    for ext in ['.pdf', '.bin', '']:
        test_path = QUAR / f"{sha}{ext}"
        if test_path.exists():
            pdf_path = test_path
            break
    
    # If not found by hash, search all files in quarantine and match by content hash
    if not pdf_path:
        for file_path in QUAR.iterdir():
            if file_path.is_file():
                try:
                    # Check if this file's SHA256 matches
                    file_content = file_path.read_bytes()
                    file_sha = hashlib.sha256(file_content).hexdigest()
                    if file_sha == sha:
                        pdf_path = file_path
                        break
                except Exception:
                    continue
    
    if not pdf_path:
        raise HTTPException(status_code=404, detail="PDF file not found")
    
    try:
        # Import extraction system
        from pdf_extractor import extract_pdf_content
        
        # Extract content
        extraction_results = extract_pdf_content(str(pdf_path), str(OUT / "extractions"))
        
        return {
            "sha256": sha,
            "extraction_success": extraction_results["extraction_summary"]["extraction_success"],
            "extraction_dir": extraction_results["extraction_dir"],
            "summary": extraction_results["extraction_summary"],
            "extracted_content": extraction_results["extracted_content"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {e}")

@app.get("/api/extract/pdf/{sha}/download/{file_type}/{filename}")
async def download_extracted_file(sha: str, file_type: str, filename: str):
    """Download an extracted file"""
    
    # Validate file type
    if file_type not in ["embedded_files", "javascript", "images", "fonts"]:
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    # Construct file path
    extraction_dir = OUT / "extractions" / sha[:16]  # Use first 16 chars of hash
    file_path = extraction_dir / file_type / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Extracted file not found")
    
    # Determine media type
    media_type = "application/octet-stream"
    if filename.endswith('.js'):
        media_type = "application/javascript"
    elif filename.endswith('.txt'):
        media_type = "text/plain"
    elif filename.endswith('.png'):
        media_type = "image/png"
    elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
        media_type = "image/jpeg"
    
    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type=media_type
    )

@app.get("/api/extract/pdf/{sha}/report")
async def get_extraction_report(sha: str):
    """Get detailed extraction report"""
    
    extraction_dir = OUT / "extractions" / sha[:16]
    report_path = extraction_dir / "extraction_report.json"
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Extraction report not found")
    
    try:
        import json
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read extraction report: {e}")

@app.delete("/api/extract/pdf/{sha}")
async def cleanup_extraction(sha: str):
    """Clean up extracted files"""
    
    extraction_dir = OUT / "extractions" / sha[:16]
    
    if extraction_dir.exists():
        try:
            import shutil
            shutil.rmtree(extraction_dir)
            return {"message": "Extraction files cleaned up successfully"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Cleanup failed: {e}")
    else:
        raise HTTPException(status_code=404, detail="Extraction directory not found")

# =========================
# System Status and Health Check
# =========================
@app.get("/api/status")
async def get_system_status():
    """Get system status including available libraries and capabilities"""
    
    # Check PDF libraries
    pdf_status = {
        "enhanced_available": PDF_ENHANCED_AVAILABLE,
        "libraries": PDF_LIBRARIES_STATUS,
        "fallback_available": True  # Basic pdf_full is always available
    }
    
    # Check Office libraries
    office_status = {
        "enhanced_available": OFFICE_ENHANCED_AVAILABLE,
        "libraries": OFFICE_LIBRARIES_STATUS,
        "fallback_available": True  # Basic office_full is always available
    }
    
    # Check report generation
    report_status = {
        "available": REPORT_GENERATION_AVAILABLE,
        "error": None if REPORT_GENERATION_AVAILABLE else "reportlab not installed"
    }
    
    # Check other capabilities
    yara_available = True
    try:
        import yara
    except ImportError:
        yara_available = False
    
    # System info
    system_info = {
        "max_file_size": f"{MAX_BYTES // (1024*1024)} MB",
        "quarantine_dir": str(QUAR),
        "output_dir": str(OUT),
        "yara_available": yara_available
    }
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "pdf_analysis": pdf_status,
        "office_analysis": office_status,
        "report_generation": report_status,
        "system": system_info,
        "capabilities": {
            "file_types": ["PE/DLL", "PDF", "Office (OOXML/OLE)"],
            "analysis_types": ["Static Analysis", "YARA Rules", "Behavioral Analysis"],
            "output_formats": ["JSON", "PDF Report"]
        }
    }

@app.get("/api/status/pdf")
async def get_pdf_status():
    """Get detailed PDF analysis capabilities status"""
    
    status = {
        "enhanced_analysis": PDF_ENHANCED_AVAILABLE,
        "libraries": {},
        "recommendations": []
    }
    
    # Detailed library status
    if PDF_ENHANCED_AVAILABLE:
        status["libraries"] = PDF_LIBRARIES_STATUS
        
        # Count available libraries
        available_count = sum(1 for available in PDF_LIBRARIES_STATUS.values() if available)
        total_count = len(PDF_LIBRARIES_STATUS)
        
        status["library_count"] = f"{available_count}/{total_count}"
        
        # Generate recommendations
        if available_count == 0:
            status["recommendations"].append("Install PDF libraries: pip install PyMuPDF peepdf-3 PyPDF4")
        elif available_count < 2:
            status["recommendations"].append("Install additional PDF libraries for better analysis")
        else:
            status["recommendations"].append("PDF analysis capabilities are optimal")
            
    else:
        status["libraries"] = {"basic_pdf_full": True}
        status["library_count"] = "1/4 (basic only)"
        status["recommendations"] = [
            "Install enhanced PDF libraries for better analysis",
            "Run: install_pdf_libs.bat or install_pdf_libs.ps1"
        ]
    
    return status

@app.get("/api/test/pdf")
async def test_pdf_analysis():
    """Test PDF analysis functionality with a simple test"""
    
    try:
        # Create a simple test to verify PDF analysis works
        if PDF_ENHANCED_AVAILABLE:
            # Test enhanced analysis
            from detector.pdf_enhanced import get_available_libraries
            libraries = get_available_libraries()
            
            return {
                "status": "success",
                "message": "Enhanced PDF analysis is working",
                "libraries": libraries,
                "test_type": "enhanced"
            }
        else:
            # Test basic analysis
            from detector.pdf_full import analyze_pdf_full
            
            return {
                "status": "success", 
                "message": "Basic PDF analysis is working",
                "libraries": {"pdf_full": True},
                "test_type": "basic",
                "recommendation": "Install enhanced libraries for better analysis"
            }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"PDF analysis test failed: {e}",
            "recommendation": "Check library installation and restart server"
        }
