"""
FastAPI REST API & Web UI Server for Universal 13-Language Vulnerability Scanner
================================================================================
Provides:
  1. A simple, clean Web UI at http://localhost:8082 with file upload,
     path input, live progress bar, and one-click JSON download.
  2. Background job processing for non-blocking browser uploads and scans.
  3. REST API endpoints for automated microservice calls (SCA pillar of codechecker).

Usage:
  python vul_packages/api_server.py --port 8082 --host 0.0.0.0
"""

import sys
import os
import uuid
import json
import time
import shutil
import zipfile
import tarfile
import tempfile
import threading
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, Response, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

CURRENT_DIR = Path(__file__).parent.resolve()
API_ROOT = CURRENT_DIR.parent.resolve()
WORKSPACE_ROOT = API_ROOT.parent.resolve()

for p in [CURRENT_DIR, API_ROOT, WORKSPACE_ROOT]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    import API_qdrant_Vul_db.vul_packages.scan_repo as scan_repo
except ImportError:
    try:
        import vul_packages.scan_repo as scan_repo
    except ImportError:
        import scan_repo

# Global Job Tracker & Worker Concurrency Lock
JOBS: Dict[str, Dict[str, Any]] = {}
SCAN_LOCK = threading.Lock()
MAX_STORED_JOBS = 50


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize local SQLite OSV Database and verify index on startup."""
    print("=" * 75)
    print("STARTING UNIVERSAL 13-LANGUAGE VULNERABILITY API SERVER (PORT 8082)")
    conn = scan_repo.get_db_conn()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM advisories")
            cnt = cursor.fetchone()[0]
            print(f"✓ Local OSV SQLite Database loaded: {scan_repo.LOCAL_DB_PATH} ({cnt:,} records)")
        except Exception:
            print(f"✓ Local OSV SQLite Database loaded: {scan_repo.LOCAL_DB_PATH}")
    else:
        print("! Warning: Local SQLite DB not found; will use online OSV API fallback.")
    print("✓ Ready to accept requests on port 8082!")
    print("=" * 75)
    yield
    print("Shutting down SCA API server...")


app = FastAPI(
    title="Universal 13-Language SCA Vulnerability API",
    description="Software Composition Analysis (SCA) & Reachability Engine powered by Google OSV. Audits dependencies across 13 ecosystems.",
    version="3.3.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================================
# WEB UI (Simple Upload / Path -> Progress Bar -> Download Output JSON)
# =========================================================================
HTML_UI = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Universal 13-Language SCA Vulnerability Scanner</title>
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
      --danger: #ef4444;
      --warning: #f59e0b;
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
      max-width: 860px;
    }
    .header {
      text-align: center;
      margin-bottom: 24px;
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
    .badge-bar {
      display: flex;
      justify-content: center;
      gap: 8px;
      margin-top: 10px;
      flex-wrap: wrap;
    }
    .pill {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
      padding: 3px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 500;
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 12px;
      justify-content: center;
    }
    .tab-btn {
      background: transparent;
      border: none;
      color: var(--muted);
      font-size: 14px;
      font-weight: 600;
      padding: 8px 18px;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .tab-btn:hover {
      color: var(--text);
      background: rgba(255, 255, 255, 0.05);
    }
    .tab-btn.active {
      color: #fff;
      background: var(--primary);
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
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
      padding: 34px 20px;
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
      width: 44px;
      height: 44px;
      fill: none;
      stroke: var(--primary);
      stroke-width: 2;
      stroke-linecap: round;
      stroke-linejoin: round;
      margin-bottom: 10px;
    }
    .dropzone h3 {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 4px;
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
      margin-top: 14px;
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
    .divider {
      display: flex;
      align-items: center;
      text-align: center;
      margin: 18px 0;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .divider::before, .divider::after {
      content: '';
      flex: 1;
      border-bottom: 1px solid var(--border);
    }
    .divider::before { margin-right: 12px; }
    .divider::after { margin-left: 12px; }
    .input-group {
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-bottom: 14px;
    }
    .input-group label {
      font-size: 13px;
      color: #cbd5e1;
      font-weight: 500;
    }
    .input-control {
      background: #0f172a;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 14px;
      color: #fff;
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s;
    }
    .input-control:focus {
      border-color: var(--primary);
    }
    .options {
      margin-top: 16px;
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
    .select-row {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 13px;
      color: #cbd5e1;
    }
    .select-row select {
      background: #0f172a;
      border: 1px solid var(--border);
      color: #fff;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 13px;
      outline: none;
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
    .badge-vuln {
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin-bottom: 20px;
    }
    .stat-card {
      background: #0f172a;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px;
      text-align: center;
    }
    .stat-val {
      font-size: 20px;
      font-weight: 700;
      color: #f8fafc;
      font-family: 'JetBrains Mono', monospace;
    }
    .stat-lbl {
      font-size: 11px;
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
      max-height: 240px;
      overflow-y: auto;
      white-space: pre-wrap;
    }
    .footer-links {
      text-align: center;
      margin-top: 10px;
      font-size: 13px;
    }
    .footer-links a {
      color: #38bdf8;
      text-decoration: none;
      margin: 0 10px;
    }
    .footer-links a:hover {
      text-decoration: underline;
    }
    .quick-samples {
      display: flex;
      gap: 8px;
      align-items: center;
      margin-top: 8px;
      flex-wrap: wrap;
    }
    .sample-pill {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--border);
      color: #cbd5e1;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-family: 'JetBrains Mono', monospace;
      cursor: pointer;
      transition: all 0.15s;
    }
    .sample-pill:hover {
      background: rgba(59, 130, 246, 0.2);
      border-color: var(--primary);
      color: #fff;
    }
    .result-card {
      background: #0f172a;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px;
      margin-top: 20px;
    }
    .rec-box {
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34d399;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    table.vuln-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-top: 10px;
    }
    table.vuln-table th, table.vuln-table td {
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    table.vuln-table th {
      color: var(--muted);
      text-transform: uppercase;
      font-size: 11px;
    }
    .sev-tag {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }
    .sev-CRITICAL { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
    .sev-HIGH { background: rgba(249, 115, 22, 0.2); color: #f97316; }
    .sev-MEDIUM { background: rgba(234, 179, 8, 0.2); color: #eab308; }
    .sev-LOW { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ Universal 13-Language SCA Vulnerability Scanner</h1>
      <p>Audit dependencies, inspect CVEs, and verify active code reachability</p>
      <div class="badge-bar">
        <span class="pill">Python</span>
        <span class="pill">JS / TS</span>
        <span class="pill">Go</span>
        <span class="pill">Java</span>
        <span class="pill">Kotlin</span>
        <span class="pill">Rust</span>
        <span class="pill">C#</span>
        <span class="pill">PHP</span>
        <span class="pill">Ruby</span>
        <span class="pill">Swift</span>
        <span class="pill">C / C++</span>
      </div>
    </div>

    <!-- Mode Tabs -->
    <div class="tabs">
      <button class="tab-btn active" id="btnTabRepo" onclick="switchTab('repo')">📁 Repository &amp; Archive Scan</button>
      <button class="tab-btn" id="btnTabPkg" onclick="switchTab('pkg')">⚡ Instant Package Tester</button>
      <button class="tab-btn" id="btnTabManifest" onclick="switchTab('manifest')">📝 Raw Manifest Audit</button>
    </div>

    <!-- TAB 1: REPO & ARCHIVE AUDIT (QDRANT STYLE) -->
    <div class="card" id="paneRepo">
      <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
        <svg viewBox="0 0 24 24">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
          <polyline points="17 8 12 3 7 8"></polyline>
          <line x1="12" y1="3" x2="12" y2="15"></line>
        </svg>
        <h3>Choose or Drag Repo Archive or Manifest</h3>
        <p>Supports .zip, .tar.gz, requirements.txt, package.json, go.mod, Cargo.toml...</p>
      </div>

      <input type="file" id="fileInput" accept=".zip,.tar.gz,.tgz,.txt,.json,.toml,.lock" onchange="handleFileSelect(event)">

      <div class="file-info" id="fileInfo">
        <span class="file-name" id="fileName">project.zip</span>
        <span class="file-size" id="fileSize">0 KB</span>
      </div>

      <div class="divider">OR SCAN SERVER DIRECTORY</div>

      <div class="input-group">
        <label for="targetPath">Local Repository or Workspace Collection Path:</label>
        <input type="text" id="targetPath" class="input-control" placeholder="e.g. /home/minakshi.katoch/Desktop/codechecker/mock_data" oninput="handlePathInput()">
      </div>

      <div class="options">
        <label class="checkbox-label">
          <input type="checkbox" id="activeOnly">
          Focus on Actionable Risks only (actively imported in code, eliminate noise)
        </label>

        <div class="select-row">
          <label for="minSeverity">Minimum Severity Threshold:</label>
          <select id="minSeverity">
            <option value="">All Severities (LOW, MEDIUM, HIGH, CRITICAL)</option>
            <option value="MEDIUM">MEDIUM and above</option>
            <option value="HIGH" selected>HIGH and CRITICAL only</option>
            <option value="CRITICAL">CRITICAL only</option>
          </select>
        </div>
      </div>

      <button class="btn" id="startBtn" disabled onclick="startScanJob()">
        <span>⚡ Start Vulnerability Scan</span>
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
        <div class="badge">✓ Vulnerability Scan Complete</div>

        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-val" id="statPkgs">0</div>
            <div class="stat-lbl">Total Packages</div>
          </div>
          <div class="stat-card">
            <div class="stat-val" id="statActive" style="color: #ef4444;">0</div>
            <div class="stat-lbl">Active Risks</div>
          </div>
          <div class="stat-card">
            <div class="stat-val" id="statClean" style="color: #34d399;">0</div>
            <div class="stat-lbl">Clean Packages</div>
          </div>
          <div class="stat-card">
            <div class="stat-val" id="statTime" style="color: #38bdf8;">~0s</div>
            <div class="stat-lbl">Elapsed Time</div>
          </div>
        </div>

        <button class="btn btn-download" id="downloadBtn" onclick="downloadResult()">
          <span>⬇️ Download vulnerability_report.json</span>
        </button>

        <div style="margin-top: 16px;">
          <p style="font-size: 12px; color: var(--muted); margin-bottom: 6px;">Actionable Risks Preview (Active Code Traces):</p>
          <div class="preview-box" id="previewBox"></div>
        </div>
      </div>
    </div>

    <!-- TAB 2: INSTANT PACKAGE TESTER -->
    <div class="card" id="panePkg" style="display: none;">
      <h3 style="margin-bottom: 12px; font-size: 16px;">Test Individual Package</h3>
      <p style="font-size: 13px; color: var(--muted); margin-bottom: 16px;">
        Instantly audit any dependency against the local OSV database and compute the exact recommended upgrade version.
      </p>

      <div style="display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 10px;">
        <div class="input-group">
          <label>Package Name:</label>
          <input type="text" id="pkgName" class="input-control" placeholder="e.g. jinja2, axios, runc" value="jinja2">
        </div>
        <div class="input-group">
          <label>Installed Version:</label>
          <input type="text" id="pkgVer" class="input-control" placeholder="e.g. 2.3" value="2.3">
        </div>
        <div class="input-group">
          <label>Ecosystem:</label>
          <select id="pkgEco" class="input-control" style="height: 38px;">
            <option value="">Auto-detect</option>
            <option value="PyPI">PyPI (Python)</option>
            <option value="npm">npm (JavaScript/TS)</option>
            <option value="Go">Go</option>
            <option value="Maven">Maven (Java/Kotlin)</option>
            <option value="crates.io">crates.io (Rust)</option>
            <option value="Packagist">Packagist (PHP)</option>
            <option value="RubyGems">RubyGems</option>
            <option value="NuGet">NuGet (.NET)</option>
          </select>
        </div>
      </div>

      <div class="quick-samples">
        <span style="font-size: 12px; color: var(--muted);">Quick Presets:</span>
        <span class="sample-pill" onclick="setPkgPreset('jinja2', '2.3', 'PyPI')">jinja2 2.3 (Python)</span>
        <span class="sample-pill" onclick="setPkgPreset('axios', '1.15.2', 'npm')">axios 1.15.2 (npm)</span>
        <span class="sample-pill" onclick="setPkgPreset('github.com/opencontainers/runc', '1.2.7', 'Go')">runc 1.2.7 (Go)</span>
        <span class="sample-pill" onclick="setPkgPreset('urllib3', '1.25.8', 'PyPI')">urllib3 1.25.8</span>
        <span class="sample-pill" onclick="setPkgPreset('lodash', '4.17.20', 'npm')">lodash 4.17.20</span>
      </div>

      <button class="btn" onclick="checkSinglePackageUI()">
        <span>🔍 Check Package Vulnerability</span>
      </button>

      <div id="pkgResultSection" style="display: none;"></div>
    </div>

    <!-- TAB 3: RAW MANIFEST AUDIT -->
    <div class="card" id="paneManifest" style="display: none;">
      <h3 style="margin-bottom: 12px; font-size: 16px;">Direct Manifest Text Audit</h3>
      <p style="font-size: 13px; color: var(--muted); margin-bottom: 16px;">
        Paste manifest contents directly into the editor to audit dependencies in-memory without saving files.
      </p>

      <div class="input-group">
        <label>Manifest Filename:</label>
        <select id="manifestType" class="input-control" style="margin-bottom: 10px;" onchange="updateManifestSample()">
          <option value="requirements.txt">requirements.txt (Python)</option>
          <option value="package.json">package.json (Node/npm)</option>
          <option value="go.mod">go.mod (Go)</option>
          <option value="Cargo.toml">Cargo.toml (Rust)</option>
        </select>
      </div>

      <div class="input-group">
        <label>Manifest Raw Content:</label>
        <textarea id="manifestContent" class="input-control" rows="8" style="font-family: 'JetBrains Mono', monospace; font-size: 12px; line-height: 1.5;">jinja2==2.3
urllib3==1.25.8
requests==2.20.0
pytest==7.4.0</textarea>
      </div>

      <button class="btn" onclick="checkManifestUI()">
        <span>⚡ Audit Manifest Dependencies</span>
      </button>

      <div id="manifestResultSection" style="display: none;"></div>
    </div>

    <div class="footer-links">
      <a href="/docs" target="_blank">📖 Interactive Swagger UI</a>
      <a href="/health" target="_blank">🩺 Health Status</a>
      <a href="/api/v1/master-report" target="_blank">📄 Latest Master Report</a>
    </div>
  </div>

  <script>
    let selectedFile = null;
    let currentJobId = null;
    let pollInterval = null;
    let startTime = null;

    function switchTab(tab) {
      document.getElementById('paneRepo').style.display = tab === 'repo' ? 'block' : 'none';
      document.getElementById('panePkg').style.display = tab === 'pkg' ? 'block' : 'none';
      document.getElementById('paneManifest').style.display = tab === 'manifest' ? 'block' : 'none';

      document.getElementById('btnTabRepo').className = 'tab-btn' + (tab === 'repo' ? ' active' : '');
      document.getElementById('btnTabPkg').className = 'tab-btn' + (tab === 'pkg' ? ' active' : '');
      document.getElementById('btnTabManifest').className = 'tab-btn' + (tab === 'manifest' ? ' active' : '');
    }

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

    function handlePathInput() {
      const p = document.getElementById('targetPath').value.trim();
      if (p.length > 0) {
        document.getElementById('startBtn').disabled = false;
      } else if (!selectedFile) {
        document.getElementById('startBtn').disabled = true;
      }
    }

    async function startScanJob() {
      const targetPath = document.getElementById('targetPath').value.trim();
      if (!selectedFile && !targetPath) return;

      document.getElementById('startBtn').disabled = true;
      document.getElementById('progressSection').style.display = 'block';
      document.getElementById('resultsSection').style.display = 'none';
      document.getElementById('progressBar').style.width = '10%';
      document.getElementById('progressPct').innerText = '10%';
      document.getElementById('progressStatus').innerText = 'Submitting scan request...';
      startTime = Date.now();

      const formData = new FormData();
      if (selectedFile) formData.append('file', selectedFile);
      if (targetPath) formData.append('target_path', targetPath);
      formData.append('active_only', document.getElementById('activeOnly').checked);
      formData.append('min_severity', document.getElementById('minSeverity').value);

      try {
        const res = await fetch('/api/v1/jobs/submit', { method: 'POST', body: formData });
        const data = await res.json();
        currentJobId = data.job_id;
        pollInterval = setInterval(pollJobStatus, 400);
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
        document.getElementById('progressStatus').innerText = job.message || 'Scanning...';

        if (job.status === 'completed') {
          clearInterval(pollInterval);
          showCompletion(job);
        } else if (job.status === 'failed') {
          clearInterval(pollInterval);
          document.getElementById('progressStatus').innerText = 'Failed: ' + (job.error || 'Scan error');
          document.getElementById('startBtn').disabled = false;
        }
      } catch (err) {
        console.error('Polling error', err);
      }
    }

    function showCompletion(job) {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1) + 's';
      document.getElementById('statTime').innerText = elapsed;
      document.getElementById('statPkgs').innerText = job.summary.total_packages || 0;
      document.getElementById('statActive').innerText = job.summary.actionable_active_risks || 0;
      document.getElementById('statClean').innerText = job.summary.clean_packages || 0;

      const previewItems = job.preview || [];
      document.getElementById('previewBox').innerText = previewItems.length ? JSON.stringify(previewItems, null, 2) : "All packages are clean.";

      document.getElementById('resultsSection').style.display = 'block';
      document.getElementById('startBtn').disabled = false;
      document.getElementById('startBtn').innerHTML = '<span>⚡ Scan Another Target</span>';
    }

    function downloadResult() {
      if (!currentJobId) return;
      window.location.href = '/api/v1/jobs/' + currentJobId + '/download';
    }

    function setPkgPreset(pkg, ver, eco) {
      document.getElementById('pkgName').value = pkg;
      document.getElementById('pkgVer').value = ver;
      document.getElementById('pkgEco').value = eco;
    }

    async function checkSinglePackageUI() {
      const pkg = document.getElementById('pkgName').value.trim();
      const ver = document.getElementById('pkgVer').value.trim();
      const eco = document.getElementById('pkgEco').value;
      const resSec = document.getElementById('pkgResultSection');

      if (!pkg || !ver) return;
      resSec.style.display = 'block';
      resSec.innerHTML = '<p style="color: var(--muted); font-size: 13px; padding: 15px 0;">Auditing ' + pkg + ' against OSV database...</p>';

      try {
        const resp = await fetch('/api/v1/check/package', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package: pkg, version: ver, ecosystem: eco || null })
        });
        const data = await resp.json();

        if (!data.is_vulnerable) {
          resSec.innerHTML = `
            <div class="result-card">
              <div class="badge">✓ Clean Package</div>
              <p style="font-size: 14px;"><strong>${data.package}==${data.installed_version}</strong> has <strong>0 known vulnerabilities</strong> in the OSV database.</p>
            </div>
          `;
          return;
        }

        const sev = data.highest_severity || 'UNKNOWN';
        let vulnsHtml = (data.vulnerabilities || []).map(v => `
          <tr>
            <td><strong>${v.cve_id || v.advisory_id}</strong></td>
            <td><span class="sev-tag sev-${v.severity}">${v.severity}</span></td>
            <td>${v.cwe || 'N/A'}</td>
            <td>${v.title || ''}</td>
            <td style="color: #38bdf8;">${v.fixed_in || 'N/A'}</td>
          </tr>
        `).join('');

        resSec.innerHTML = `
          <div class="result-card">
            <div class="badge badge-vuln">⚠️ ${data.total_cves} Vulnerabilities Identified</div>
            <div class="rec-box">
              <span>🎯 Recommended Fix: Upgrade to version <strong>${data.recommended_fix || 'Latest'}</strong></span>
            </div>
            <table class="vuln-table">
              <thead>
                <tr>
                  <th>Vulnerability</th>
                  <th>Severity</th>
                  <th>CWE</th>
                  <th>Title</th>
                  <th>Fixed In</th>
                </tr>
              </thead>
              <tbody>${vulnsHtml}</tbody>
            </table>
          </div>
        `;
      } catch (err) {
        resSec.innerHTML = `<p style="color: var(--danger); font-size: 13px;">Error: ${err.message}</p>`;
      }
    }

    function updateManifestSample() {
      const t = document.getElementById('manifestType').value;
      const c = document.getElementById('manifestContent');
      if (t === 'requirements.txt') {
        c.value = "jinja2==2.3\\nurllib3==1.25.8\\nrequests==2.20.0\\npytest==7.4.0";
      } else if (t === 'package.json') {
        c.value = JSON.stringify({ dependencies: { "axios": "1.15.2", "lodash": "4.17.15", "express": "4.18.2" } }, null, 2);
      } else if (t === 'go.mod') {
        c.value = "module test\\n\\ngo 1.22\\n\\nrequire (\\n\\tgithub.com/opencontainers/runc v1.2.7\\n\\tgithub.com/gin-gonic/gin v1.9.1\\n)";
      } else if (t === 'Cargo.toml') {
        c.value = "[dependencies]\\nserde = \\"1.0.150\\"\\ntokio = \\"1.20.0\\"";
      }
    }

    async function checkManifestUI() {
      const fname = document.getElementById('manifestType').value;
      const content = document.getElementById('manifestContent').value;
      const resSec = document.getElementById('manifestResultSection');

      resSec.style.display = 'block';
      resSec.innerHTML = '<p style="color: var(--muted); font-size: 13px; padding: 15px 0;">Parsing manifest dependencies...</p>';

      try {
        const resp = await fetch('/api/v1/check/manifest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename: fname, content: content })
        });
        const data = await resp.json();

        let rows = (data.findings || []).map(f => `
          <tr>
            <td><strong>${f.package}</strong></td>
            <td>${f.installed_version}</td>
            <td><span class="sev-tag sev-${f.highest_severity}">${f.highest_severity}</span></td>
            <td>${f.cve_summary.length} CVEs (${f.cve_summary.slice(0, 3).join(', ')})</td>
            <td style="color: #34d399; font-weight: 600;">${f.recommended_fix || 'N/A'}</td>
          </tr>
        `).join('');

        resSec.innerHTML = `
          <div class="result-card">
            <div class="stats-grid" style="margin-bottom: 15px;">
              <div class="stat-card">
                <div class="stat-val">${data.parsed_packages}</div>
                <div class="stat-lbl">Parsed Packages</div>
              </div>
              <div class="stat-card">
                <div class="stat-val" style="color: #ef4444;">${data.vulnerable_packages}</div>
                <div class="stat-lbl">Vulnerable Packages</div>
              </div>
              <div class="stat-card">
                <div class="stat-val" style="color: #34d399;">${data.clean_packages}</div>
                <div class="stat-lbl">Clean Packages</div>
              </div>
            </div>
            <table class="vuln-table">
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Installed</th>
                  <th>Highest Severity</th>
                  <th>Vulnerabilities</th>
                  <th>Recommended Fix</th>
                </tr>
              </thead>
              <tbody>${rows || '<tr><td colspan="5" style="text-align: center; color: var(--accent);">✓ All dependencies in this manifest are verified secure!</td></tr>'}</tbody>
            </table>
          </div>
        `;
      } catch (err) {
        resSec.innerHTML = `<p style="color: var(--danger); font-size: 13px;">Error: ${err.message}</p>`;
      }
    }
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
def serve_ui():
    """Serve the simple, clean Upload & Progress UI."""
    return HTMLResponse(content=HTML_UI)


# =========================================================================
# BACKGROUND JOB API (Upload / Path -> Track Progress -> Download JSON)
# =========================================================================

def run_scan_worker(job_id: str, file_bytes: Optional[bytes], filename: Optional[str], target_path: Optional[str], active_only: bool, min_severity: Optional[str]):
    """Worker running in background thread to compute vulnerability scan with live progress."""
    try:
        def update_progress(pct: int, msg: str):
            if job_id in JOBS:
                JOBS[job_id]["progress"] = pct
                JOBS[job_id]["message"] = msg

        update_progress(15, "Initializing dependency parsers...")
        min_sev_score = scan_repo.SEVERITY_LEVELS.get(min_severity, 0) if min_severity else 0

        # Scenario A: In-memory / Uploaded File
        if file_bytes and filename:
            fname_lower = filename.lower()
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)

                if fname_lower.endswith(".zip") or fname_lower.endswith(".tar.gz") or fname_lower.endswith(".tgz"):
                    update_progress(30, "Unpacking repository archive...")
                    archive_path = tmp_path / filename
                    with open(archive_path, "wb") as f:
                        f.write(file_bytes)

                    extract_dir = tmp_path / "repo"
                    extract_dir.mkdir(parents=True, exist_ok=True)

                    if fname_lower.endswith(".zip"):
                        with zipfile.ZipFile(archive_path, "r") as z:
                            for m in z.namelist():
                                tm = (extract_dir / m).resolve()
                                if not str(tm).startswith(str(extract_dir.resolve())):
                                    raise ValueError("Directory traversal attempt in zip archive")
                            z.extractall(extract_dir)
                    else:
                        with tarfile.open(archive_path, "r:*") as t:
                            for m in t.getmembers():
                                tm = (extract_dir / m.name).resolve()
                                if not str(tm).startswith(str(extract_dir.resolve())):
                                    raise ValueError("Directory traversal attempt in tar archive")
                            t.extractall(extract_dir)

                    update_progress(55, "Auditing dependencies across 13 ecosystems...")
                    with SCAN_LOCK:
                        rep = scan_repo.audit_single_repo(extract_dir, min_sev_score=min_sev_score, active_only=active_only)
                    rep["repo_name"] = Path(filename).stem
                    result = rep

                else:
                    # Manifest file (requirements.txt, package.json, etc.)
                    update_progress(40, f"Parsing {filename}...")
                    m_file = tmp_path / filename
                    with open(m_file, "wb") as f:
                        f.write(file_bytes)

                    pkgs = scan_repo.extract_manifest_packages(m_file)
                    vulnerable_findings = []
                    clean_cnt = 0

                    update_progress(60, "Querying OSV vulnerability database...")
                    for p in pkgs:
                        vulns = scan_repo.lookup_package_vulnerabilities(p["name"], p.get("version"), p.get("ecosystem"))
                        if min_sev_score > 0:
                            vulns = [v for v in vulns if scan_repo.SEVERITY_LEVELS.get(v.get("severity", "UNKNOWN"), 0) >= min_sev_score]
                        if vulns:
                            vulnerable_findings.append(scan_repo.format_package_finding(p, vulns, [], tmp_path))
                        else:
                            clean_cnt += 1

                    vulnerable_findings.sort(key=lambda x: scan_repo.SEVERITY_LEVELS.get(x["highest_severity"], 0), reverse=True)
                    result = {
                        "repo_name": Path(filename).stem,
                        "repo_path": filename,
                        "summary": {
                            "total_packages": len(pkgs),
                            "clean_packages": clean_cnt,
                            "vulnerable_packages": len(vulnerable_findings),
                            "actionable_active_risks": len(vulnerable_findings),
                            "dormant_manifest_risks": 0,
                            "severity_breakdown": {
                                k: sum(1 for f in vulnerable_findings if f["highest_severity"] == k)
                                for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                                if any(f["highest_severity"] == k for f in vulnerable_findings)
                            }
                        },
                        "manifest_files": {filename: len(pkgs)},
                        "actionable_risks": vulnerable_findings,
                        "dormant_risks": []
                    }

        # Scenario B: Target Path on Server Disk
        elif target_path:
            p = Path(target_path).resolve()
            if not p.exists():
                raise ValueError(f"Target path does not exist on server: {target_path}")

            update_progress(35, "Discovering repository stacks...")
            repos = scan_repo.discover_repositories(p)
            is_multi = len(repos) > 1

            update_progress(50, f"Scanning {len(repos)} repository stack(s)...")
            repo_reports = []
            for idx, r in enumerate(repos, 1):
                pct = 50 + int((idx / len(repos)) * 40)
                update_progress(pct, f"Scanning [{idx}/{len(repos)}] {r.name}...")
                with SCAN_LOCK:
                    rep = scan_repo.audit_single_repo(r, min_sev_score=min_sev_score, active_only=active_only)
                repo_reports.append(rep)

            if is_multi:
                ov_tot = sum(r["summary"]["total_packages"] for r in repo_reports)
                ov_clean = sum(r["summary"]["clean_packages"] for r in repo_reports)
                ov_vuln = sum(r["summary"]["vulnerable_packages"] for r in repo_reports)
                ov_act = sum(r["summary"]["actionable_active_risks"] for r in repo_reports)
                ov_dorm = sum(r["summary"]["dormant_manifest_risks"] for r in repo_reports)
                sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
                for r in repo_reports:
                    for sk, sv in r["summary"]["severity_breakdown"].items():
                        sev_counts[sk] = sev_counts.get(sk, 0) + sv

                result = {
                    "scan_metadata": {
                        "target": str(p),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "scanner": "Universal 13-Language Vulnerability Scanner v3.3"
                    },
                    "overall_summary": {
                        "total_repositories": len(repos),
                        "repositories_with_vulnerabilities": sum(1 for r in repo_reports if r["summary"]["vulnerable_packages"] > 0),
                        "total_packages": ov_tot,
                        "clean_packages": ov_clean,
                        "vulnerable_packages": ov_vuln,
                        "actionable_active_risks": ov_act,
                        "dormant_manifest_risks": ov_dorm,
                        "severity_breakdown": {k: v for k, v in sev_counts.items() if v > 0}
                    },
                    "repositories": repo_reports
                }
            else:
                result = repo_reports[0] if repo_reports else {}

        else:
            raise ValueError("No file or target_path provided to scan.")

        update_progress(95, "Compiling report and code traces...")

        # Extract summary and preview for UI
        if "overall_summary" in result:
            summary = result["overall_summary"]
            all_active = []
            for r in result.get("repositories", []):
                all_active.extend(r.get("actionable_risks", []))
            preview = all_active[:3]
        else:
            summary = result.get("summary", {})
            preview = result.get("actionable_risks", [])[:3]

        JOBS[job_id]["status"] = "completed"
        JOBS[job_id]["progress"] = 100
        JOBS[job_id]["message"] = "Vulnerability scan complete!"
        JOBS[job_id]["result"] = result
        JOBS[job_id]["summary"] = summary
        JOBS[job_id]["preview"] = preview

        if len(JOBS) > MAX_STORED_JOBS:
            oldest_keys = list(JOBS.keys())[:len(JOBS) - MAX_STORED_JOBS]
            for k in oldest_keys:
                if k != job_id:
                    JOBS.pop(k, None)

    except Exception as e:
        JOBS[job_id]["status"] = "failed"
        JOBS[job_id]["error"] = str(e)


@app.post("/api/v1/jobs/submit", tags=["Jobs"])
async def submit_scan_job(
    file: Optional[UploadFile] = File(None),
    target_path: Optional[str] = Form(None),
    active_only: bool = Form(False),
    min_severity: Optional[str] = Form(None)
):
    """Submit a repository archive, manifest file, or server path to run a background scan."""
    file_bytes = None
    filename = None
    if file and file.filename:
        file_bytes = await file.read()
        filename = file.filename

    if not file_bytes and not target_path:
        raise HTTPException(status_code=400, detail="Must provide either a file upload or target_path")

    job_id = str(uuid.uuid4())[:8]
    JOBS[job_id] = {
        "status": "processing",
        "progress": 5,
        "message": "Job received. Initializing vulnerability audit...",
        "summary": {}
    }

    thread = threading.Thread(
        target=run_scan_worker,
        args=(job_id, file_bytes, filename, target_path, active_only, min_severity),
        daemon=True
    )
    thread.start()

    return {"job_id": job_id, "status": "submitted"}


@app.get("/api/v1/jobs/{job_id}", tags=["Jobs"])
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


@app.get("/api/v1/jobs/{job_id}/download", tags=["Jobs"])
def download_job_result(job_id: str):
    """Download the completed vulnerability_report.json file."""
    if job_id not in JOBS or JOBS[job_id].get("status") != "completed":
        raise HTTPException(status_code=404, detail="Scan report not ready")

    result_data = JOBS[job_id]["result"]
    json_bytes = json.dumps(result_data, indent=2).encode("utf-8")

    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=vulnerability_report.json"
        }
    )


# =========================================================================
# DIRECT REST API ENDPOINTS
# =========================================================================

class DirectScanRequest(BaseModel):
    target_path: str = Field(..., description="Path to repository or collection", json_schema_extra={"example": "/home/minakshi.katoch/Desktop/codechecker/mock_data"})
    active_only: bool = Field(False, description="Filter for active imported packages only")
    min_severity: Optional[str] = Field("HIGH", description="LOW, MEDIUM, HIGH, CRITICAL")


class PackageRequest(BaseModel):
    package: str = Field(..., description="Package name", json_schema_extra={"example": "jinja2"})
    version: str = Field(..., description="Package version", json_schema_extra={"example": "2.3"})
    ecosystem: Optional[str] = Field(None, description="PyPI, npm, Go, Maven, crates.io, NuGet, Packagist, RubyGems", json_schema_extra={"example": "PyPI"})


class ManifestRequest(BaseModel):
    filename: str = Field(..., description="Manifest filename", json_schema_extra={"example": "requirements.txt"})
    content: str = Field(..., description="Raw text of manifest", json_schema_extra={"example": "jinja2==2.3\nurllib3==1.25.8\nflask==0.12"})
    min_severity: Optional[str] = Field(None, description="Minimum severity threshold")


@app.get("/health", tags=["System"])
def health_check():
    """Verify SCA service and OSV database status."""
    db_conn = scan_repo.get_db_conn()
    total_records = 0
    if db_conn:
        try:
            cursor = db_conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM advisories")
            total_records = cursor.fetchone()[0]
        except Exception:
            pass

    return {
        "status": "healthy",
        "service": "Universal 13-Language SCA Vulnerability API",
        "port": 8082,
        "database": {
            "mode": "Local SQLite (Sub-millisecond)" if scan_repo.LOCAL_DB_PATH.exists() else "Online OSV Fallback",
            "total_vulnerability_records": total_records
        },
        "supported_languages": [
            "python", "javascript", "typescript", "go", "java", 
            "kotlin", "rust", "csharp", "php", "ruby", "swift", "c", "cpp"
        ]
    }


@app.post("/api/v1/scan", tags=["Scanning"])
def direct_scan(req: DirectScanRequest):
    """Synchronous direct scan endpoint for microservice / pipeline calls."""
    target = Path(req.target_path).resolve()
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Target path not found: {req.target_path}")

    min_sev_score = scan_repo.SEVERITY_LEVELS.get(req.min_severity, 0) if req.min_severity else 0
    repos = scan_repo.discover_repositories(target)

    if len(repos) == 1:
        with SCAN_LOCK:
            rep = scan_repo.audit_single_repo(repos[0], min_sev_score=min_sev_score, active_only=req.active_only)
        return rep

    repo_reports = []
    for r in repos:
        with SCAN_LOCK:
            repo_reports.append(scan_repo.audit_single_repo(r, min_sev_score=min_sev_score, active_only=req.active_only))

    return {
        "scan_metadata": {
            "target": str(target),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner": "Universal 13-Language Vulnerability Scanner v3.3"
        },
        "overall_summary": {
            "total_repositories": len(repos),
            "total_packages": sum(r["summary"]["total_packages"] for r in repo_reports),
            "actionable_active_risks": sum(r["summary"]["actionable_active_risks"] for r in repo_reports),
            "clean_packages": sum(r["summary"]["clean_packages"] for r in repo_reports)
        },
        "repositories": repo_reports
    }


@app.post("/api/v1/check_package", tags=["Lookup"])
@app.post("/api/v1/check/package", tags=["Lookup"], include_in_schema=False)
def check_single_package(req: PackageRequest):
    """Instant single package vulnerability lookup with recommended fix."""
    vulns = scan_repo.lookup_package_vulnerabilities(req.package, req.version, req.ecosystem)
    if not vulns:
        return {
            "package": req.package,
            "installed_version": req.version,
            "ecosystem": req.ecosystem or "Auto-detected",
            "is_vulnerable": False,
            "total_cves": 0
        }

    pkg_mock = {
        "name": req.package,
        "version": req.version,
        "ecosystem": req.ecosystem or (vulns[0].get("ecosystem") if vulns else "Unknown"),
        "file": "API Query"
    }

    formatted = scan_repo.format_package_finding(pkg_mock, vulns, [], Path("/"))
    formatted["is_vulnerable"] = True
    formatted["total_cves"] = len(formatted.get("cve_summary", []))
    return formatted


@app.post("/api/v1/check_manifest", tags=["Lookup"])
@app.post("/api/v1/check/manifest", tags=["Lookup"], include_in_schema=False)
def check_manifest_content(req: ManifestRequest):
    """Directly audit raw manifest text in-memory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_file = Path(tmp_dir) / req.filename
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(req.content)

        packages = scan_repo.extract_manifest_packages(temp_file)
        min_sev_score = scan_repo.SEVERITY_LEVELS.get(req.min_severity, 0) if req.min_severity else 0
        vulnerable_findings = []
        clean_count = 0

        for pkg in packages:
            vulns = scan_repo.lookup_package_vulnerabilities(pkg["name"], pkg.get("version"), pkg.get("ecosystem"))
            if min_sev_score > 0:
                vulns = [v for v in vulns if scan_repo.SEVERITY_LEVELS.get(v.get("severity", "UNKNOWN"), 0) >= min_sev_score]
            if vulns:
                vulnerable_findings.append(scan_repo.format_package_finding(pkg, vulns, [], Path(tmp_dir)))
            else:
                clean_count += 1

        vulnerable_findings.sort(key=lambda x: scan_repo.SEVERITY_LEVELS.get(x["highest_severity"], 0), reverse=True)

        return {
            "filename": req.filename,
            "parsed_packages": len(packages),
            "clean_packages": clean_count,
            "vulnerable_packages": len(vulnerable_findings),
            "findings": vulnerable_findings
        }


@app.get("/api/v1/master-report", tags=["Reports"])
def get_master_report():
    """Retrieve the latest master aggregated vulnerability_report.json."""
    if not scan_repo.DEFAULT_OUTPUT_PATH.exists():
        raise HTTPException(status_code=404, detail="Master vulnerability report has not been generated yet.")
    return FileResponse(scan_repo.DEFAULT_OUTPUT_PATH, media_type="application/json", filename="vulnerability_report.json")


def main():
    parser = argparse.ArgumentParser(description="Start 13-Language SCA Vulnerability REST API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8082, help="Port (default: 8082)")
    args = parser.parse_args()

    uvicorn.run("api_server:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
