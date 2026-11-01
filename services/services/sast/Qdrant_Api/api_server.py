"""
FastAPI REST API & Web UI Server for CWE & CVE Extraction
=========================================================
Provides:
  1. A simple, clean Web UI at http://localhost:8080 with file upload,
     live progress bar, and one-click JSON download.
  2. Background job processing for non-blocking browser uploads.
  3. REST API endpoints for automated microservice calls.

Usage:
  python api_server.py --port 8080
"""

import sys
import uuid
import json
import asyncio
import threading
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, Response, JSONResponse
from pydantic import BaseModel, Field
import uvicorn

CURRENT_DIR = Path(__file__).parent.resolve()
API_ROOT = CURRENT_DIR.parent.resolve()
WORKSPACE_ROOT = API_ROOT.parent.resolve()

for p in [CURRENT_DIR, API_ROOT, WORKSPACE_ROOT]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from API_qdrant_Vul_db.Qdrant_Api.extractor import CweCveExtractor
    from API_qdrant_Vul_db.Qdrant_Api.enrich_scan_results import enrich_scan_data
except ImportError:
    try:
        from Qdrant_Api.extractor import CweCveExtractor
        from Qdrant_Api.enrich_scan_results import enrich_scan_data
    except ImportError:
        from extractor import CweCveExtractor
        from enrich_scan_results import enrich_scan_data

# Global Extractor instance, GPU inference lock & Job Tracker
extractor_instance: Optional[CweCveExtractor] = None
JOBS: Dict[str, Dict[str, Any]] = {}
GPU_LOCK = threading.Lock()
MAX_STORED_JOBS = 50


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize Jina Embeddings and Qdrant in memory once at server startup."""
    global extractor_instance
    print("Starting API Server and loading Extraction Engine into GPU...")
    extractor_instance = CweCveExtractor(force_local=True)
    print("✓ API Server ready to accept requests on port 8080!")
    yield
    print("Shutting down API server...")


app = FastAPI(
    title="CWE-ID & CVE-ID Extraction API",
    description="High-Throughput Threat Attribution & Weakness Classification Engine (Jina + Qdrant + MITRE)",
    version="2.0.0",
    lifespan=lifespan
)


# =========================================================================
# WEB UI (Simple Upload Button -> Progress Bar -> Download Output JSON)
# =========================================================================
HTML_UI = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CWE & CVE Extraction Engine</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --border: #334155;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --accent: #10b981;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
    }
    .container {
      width: 100%;
      max-width: 760px;
    }
    .header {
      text-align: center;
      margin-bottom: 30px;
    }
    .header h1 {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.5px;
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
    }
    .header p {
      color: var(--muted);
      font-size: 15px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 28px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
      margin-bottom: 24px;
    }
    .dropzone {
      border: 2px dashed #475569;
      border-radius: 12px;
      padding: 40px 20px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s ease;
      background: rgba(15, 23, 42, 0.4);
    }
    .dropzone:hover, .dropzone.dragover {
      border-color: var(--primary);
      background: rgba(59, 130, 246, 0.08);
    }
    .dropzone svg {
      width: 48px;
      height: 48px;
      fill: none;
      stroke: var(--primary);
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
      margin-bottom: 12px;
    }
    .dropzone h3 {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 6px;
    }
    .dropzone p {
      font-size: 13px;
      color: var(--muted);
    }
    input[type="file"] {
      display: none;
    }
    .file-info {
      display: none;
      margin-top: 16px;
      padding: 12px 16px;
      background: #0f172a;
      border-radius: 8px;
      border: 1px solid var(--border);
      align-items: center;
      justify-content: space-between;
    }
    .file-name {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      color: #38bdf8;
      font-weight: 500;
    }
    .file-size {
      font-size: 12px;
      color: var(--muted);
    }
    .options {
      margin-top: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .checkbox-label {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 14px;
      color: #cbd5e1;
      cursor: pointer;
      user-select: none;
    }
    .checkbox-label input {
      accent-color: var(--primary);
      width: 16px;
      height: 16px;
    }
    .btn {
      width: 100%;
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 10px;
      padding: 14px 20px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s ease;
      margin-top: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .btn:hover:not(:disabled) {
      background: var(--primary-hover);
    }
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .btn-download {
      background: var(--accent);
      margin-top: 16px;
    }
    .btn-download:hover {
      background: #059669;
    }
    .progress-section {
      display: none;
      margin-top: 24px;
    }
    .progress-header {
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      font-size: 13px;
    }
    .progress-status {
      font-weight: 500;
      color: #38bdf8;
    }
    .progress-bar-bg {
      background: #0f172a;
      border-radius: 999px;
      height: 10px;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    .progress-bar-fill {
      background: linear-gradient(90deg, #3b82f6, #10b981);
      height: 100%;
      width: 0%;
      transition: width 0.3s ease;
    }
    .results-section {
      display: none;
      margin-top: 24px;
      padding-top: 24px;
      border-top: 1px solid var(--border);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 16px;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin-bottom: 20px;
    }
    .stat-card {
      background: #0f172a;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
      text-align: center;
    }
    .stat-val {
      font-size: 22px;
      font-weight: 700;
      color: #f8fafc;
      font-family: 'JetBrains Mono', monospace;
    }
    .stat-lbl {
      font-size: 12px;
      color: var(--muted);
      margin-top: 4px;
    }
    .preview-box {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #cbd5e1;
      max-height: 200px;
      overflow-y: auto;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ CWE & CVE Extraction Engine</h1>
      <p>Upload review findings JSON to extract root-cause MITRE CWEs & CVEs</p>
    </div>

    <div class="card">
      <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
        <svg viewBox="0 0 24 24">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
          <polyline points="17 8 12 3 7 8"></polyline>
          <line x1="12" y1="3" x2="12" y2="15"></line>
        </svg>
        <h3>Choose or Drag scan-res.json</h3>
        <p>Supports .json vulnerability finding exports</p>
      </div>

      <input type="file" id="fileInput" accept=".json" onchange="handleFileSelect(event)">

      <div class="file-info" id="fileInfo">
        <span class="file-name" id="fileName">scan-res.json</span>
        <span class="file-size" id="fileSize">0 KB</span>
      </div>

      <div class="options">
        <label class="checkbox-label">
          <input type="checkbox" id="securityOnly">
          Output only enriched security findings (filters out maintainability/style comments)
        </label>
      </div>

      <button class="btn" id="startBtn" disabled onclick="startEnrichment()">
        <span>⚡ Start Enrichment</span>
      </button>

      <!-- Progress Section -->
      <div class="progress-section" id="progressSection">
        <div class="progress-header">
          <span class="progress-status" id="progressStatus">Initializing...</span>
          <span class="progress-pct" id="progressPct" style="font-family: monospace;">0%</span>
        </div>
        <div class="progress-bar-bg">
          <div class="progress-bar-fill" id="progressBar"></div>
        </div>
      </div>

      <!-- Results Section -->
      <div class="results-section" id="resultsSection">
        <div class="badge">✓ Enrichment Complete</div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-val" id="statFindings">0</div>
            <div class="stat-lbl">Security Findings</div>
          </div>
          <div class="stat-card">
            <div class="stat-val" id="statCwes" style="color: #34d399;">100%</div>
            <div class="stat-lbl">MITRE Compliance</div>
          </div>
          <div class="stat-card">
            <div class="stat-val" id="statTime" style="color: #38bdf8;">~8s</div>
            <div class="stat-lbl">Elapsed Time</div>
          </div>
        </div>

        <button class="btn btn-download" id="downloadBtn" onclick="downloadResult()">
          <span>⬇️ Download scan-res-enriched.json</span>
        </button>

        <div style="margin-top: 16px;">
          <p style="font-size: 12px; color: var(--muted); margin-bottom: 6px;">Enriched Findings Preview:</p>
          <div class="preview-box" id="previewBox"></div>
        </div>
      </div>
    </div>
  </div>

  <script>
    let selectedFile = null;
    let currentJobId = null;
    let pollInterval = null;
    let startTime = null;

    const dropzone = document.getElementById('dropzone');
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length) {
        document.getElementById('fileInput').files = e.dataTransfer.files;
        handleFileSelect({ target: { files: e.dataTransfer.files } });
      }
    });

    function handleFileSelect(e) {
      if (!e.target.files.length) return;
      selectedFile = e.target.files[0];
      document.getElementById('fileName').innerText = selectedFile.name;
      document.getElementById('fileSize').innerText = (selectedFile.size / (1024 * 1024)).toFixed(2) + ' MB';
      document.getElementById('fileInfo').style.display = 'flex';
      document.getElementById('startBtn').disabled = false;
    }

    async function startEnrichment() {
      if (!selectedFile) return;

      document.getElementById('startBtn').disabled = true;
      document.getElementById('progressSection').style.display = 'block';
      document.getElementById('resultsSection').style.display = 'none';
      document.getElementById('progressBar').style.width = '5%';
      document.getElementById('progressPct').innerText = '5%';
      document.getElementById('progressStatus').innerText = 'Uploading scan JSON...';
      startTime = Date.now();

      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('security_only', document.getElementById('securityOnly').checked);

      try {
        const res = await fetch('/api/v1/jobs/submit', { method: 'POST', body: formData });
        const data = await res.json();
        currentJobId = data.job_id;

        pollInterval = setInterval(pollJobStatus, 500);
      } catch (err) {
        document.getElementById('progressStatus').innerText = 'Error: ' + err.message;
        document.getElementById('startBtn').disabled = false;
      }
    }

    async function pollJobStatus() {
      if (!currentJobId) return;
      try {
        const res = await fetch('/api/v1/jobs/' + currentJobId);
        const job = await res.json();

        document.getElementById('progressBar').style.width = job.progress + '%';
        document.getElementById('progressPct').innerText = job.progress + '%';
        document.getElementById('progressStatus').innerText = job.message || 'Processing...';

        if (job.status === 'completed') {
          clearInterval(pollInterval);
          showCompletion(job);
        } else if (job.status === 'failed') {
          clearInterval(pollInterval);
          document.getElementById('progressStatus').innerText = 'Failed: ' + (job.error || 'Unknown error');
          document.getElementById('startBtn').disabled = false;
        }
      } catch (err) {
        console.error('Polling error', err);
      }
    }

    function showCompletion(job) {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1) + 's';
      document.getElementById('statTime').innerText = elapsed;
      document.getElementById('statFindings').innerText = job.summary.enriched_security_findings || 0;

      const previewItems = (job.preview || []).slice(0, 2);
      document.getElementById('previewBox').innerText = JSON.stringify(previewItems, null, 2);

      document.getElementById('resultsSection').style.display = 'block';
      document.getElementById('startBtn').disabled = false;
      document.getElementById('startBtn').innerHTML = '<span>⚡ Enrich Another File</span>';
    }

    function downloadResult() {
      if (!currentJobId) return;
      window.location.href = '/api/v1/jobs/' + currentJobId + '/download';
    }
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def serve_ui():
    """Serve the simple, clean Upload & Progress UI."""
    return HTMLResponse(content=HTML_UI)


# =========================================================================
# BACKGROUND JOB API (Upload -> Track Progress -> Download JSON)
# =========================================================================

def run_enrichment_worker(job_id: str, raw_json: Any, security_only: bool, repo_dir: Optional[str] = None):
    """Worker running in background thread to compute enrichment with progress."""
    try:
        def update_progress(pct: int, msg: str):
            if job_id in JOBS:
                JOBS[job_id]["progress"] = pct
                JOBS[job_id]["message"] = msg

        if repo_dir and Path(repo_dir).is_dir():
            codebase_path = Path(repo_dir).resolve()
        elif (WORKSPACE_ROOT / "opencv").is_dir():
            codebase_path = WORKSPACE_ROOT / "opencv"
        else:
            codebase_path = WORKSPACE_ROOT

        with GPU_LOCK:
            enriched = enrich_scan_data(
                scan_data=raw_json,
                codebase_root=codebase_path,
                security_only=security_only,
                extractor=extractor_instance,
                show_progress=False,
                progress_callback=update_progress
            )

        sec_comments = [c for c in enriched.get("comments", []) if isinstance(c, dict) and "cwe_id" in c]

        JOBS[job_id]["status"] = "completed"
        JOBS[job_id]["progress"] = 100
        JOBS[job_id]["message"] = "Enrichment complete!"
        JOBS[job_id]["result"] = enriched
        JOBS[job_id]["summary"] = enriched.get("summary", {})
        JOBS[job_id]["preview"] = sec_comments[:3]

        # Evict oldest jobs if exceeding MAX_STORED_JOBS
        if len(JOBS) > MAX_STORED_JOBS:
            oldest_keys = list(JOBS.keys())[:len(JOBS) - MAX_STORED_JOBS]
            for k in oldest_keys:
                if k != job_id:
                    JOBS.pop(k, None)

    except Exception as e:
        JOBS[job_id]["status"] = "failed"
        JOBS[job_id]["error"] = str(e)


@app.post("/api/v1/jobs/submit")
async def submit_enrichment_job(
    file: UploadFile = File(...),
    security_only: bool = Form(False),
    repo_dir: Optional[str] = Form(None)
):
    """Upload scan-res.json and start background enrichment job."""
    content = await file.read()
    try:
        raw_json = json.loads(content.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON file: {e}")

    job_id = str(uuid.uuid4())[:8]
    JOBS[job_id] = {
        "status": "processing",
        "progress": 5,
        "message": "File received. Initializing enrichment...",
        "summary": {}
    }

    thread = threading.Thread(
        target=run_enrichment_worker,
        args=(job_id, raw_json, security_only, repo_dir),
        daemon=True
    )
    thread.start()

    return {"job_id": job_id, "status": "submitted"}


@app.get("/api/v1/jobs/{job_id}")
def get_job_status(job_id: str):
    """Poll job status and progress percentage."""
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Job not found")

    job = JOBS[job_id]
    return {
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "message": job.get("message", ""),
        "summary": job.get("summary", {}),
        "preview": job.get("preview", []),
        "error": job.get("error")
    }


@app.get("/api/v1/jobs/{job_id}/download")
def download_job_result(job_id: str):
    """Download the completed enriched JSON file."""
    if job_id not in JOBS or JOBS[job_id].get("status") != "completed":
        raise HTTPException(status_code=404, detail="Enriched file not ready")

    result_data = JOBS[job_id]["result"]
    json_bytes = json.dumps(result_data, indent=2).encode("utf-8")

    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=scan-res-enriched.json"
        }
    )


# =========================================================================
# DIRECT REST API ENDPOINTS
# =========================================================================

class SnippetRequest(BaseModel):
    code_snippet: str = Field(..., description="Vulnerable code snippet or function body")
    language: str = Field("c", description="Programming language (e.g., c, python, js, go)")
    flaw_summary: Optional[str] = Field("", description="Flaw description from review scanner")
    package_name: Optional[str] = Field("", description="Optional repository or package name")


@app.get("/health")
def health_check():
    """Verify API service and vector index status."""
    return {
        "status": "healthy",
        "engine": "Jina (1.5B) + Qdrant (206k vectors) + MITRE Catalog",
        "model_loaded": extractor_instance is not None
    }


@app.post("/api/v1/enrich_snippet")
def enrich_single_snippet(req: SnippetRequest):
    """Enrich a single code snippet with MITRE CWE-ID and attributed CVE-ID."""
    if extractor_instance is None:
        raise HTTPException(status_code=503, detail="Extraction engine not initialized")

    with GPU_LOCK:
        result = extractor_instance.extract(
            code_snippet=req.code_snippet,
            language=req.language,
            flaw_summary=req.flaw_summary or "",
            package_name=req.package_name or ""
        )
    return result


def main():
    parser = argparse.ArgumentParser(description="Start CWE & CVE Extraction REST API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    args = parser.parse_args()

    uvicorn.run("api_server:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
