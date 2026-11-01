import express from 'express';
import cors from 'cors';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import { exec, spawnSync } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { config, saveConfig } from '../core/config.js';
import { runScan, runReview } from '../core/ocr-runner.js';
import { applyFixWithOpenCode } from '../core/opencode-runner.js';
import { streamChatWithVllm } from '../core/vllm-client.js';
import { enrichFindings, enrichFinding } from '../core/cve-enricher.js';
import { normalizeFinding } from '../core/types.js';
import { synthesizeAllPatches, synthesizePatchForFinding, isConcretePatch } from '../core/patch-synthesizer.js';
import { ScanCache } from '../core/scan-cache.js';
import { SessionManager, getOcrSessionFilePath } from '../core/session-manager.js';
import { analyzeExemptions, analyzeSuperFastExemptions, saveExemptions, loadExemptions } from '../core/scan-exemptions.js';
import { scanEstimator } from '../core/scan-estimator.js';
import { getModelStatus, switchModel } from '../core/vllm-manager.js';
import { ScanJobRegistry } from './scan-job-registry.js';
import { generateFindingsCsv, groupFindingsByRepository } from '../core/csv-exporter.js';

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const webDir = path.join(__dirname, '..', '..', 'ui', 'dist');

// In-memory cache of latest findings
let currentFindings = [];

// Determine active vLLM log path (dynamically checking running process and known paths)
function getVllmLogPath() {
  // 1. Try detecting from active vLLM process stdout/stderr file descriptor
  try {
    const { execSync } = require('node:child_process');
    const pids = execSync('pgrep -f "vllm serve" 2>/dev/null || true').toString().trim().split('\n');
    for (const pid of pids) {
      if (!pid) continue;
      for (const fd of ['1', '2']) {
        try {
          const target = fs.readlinkSync(`/proc/${pid.trim()}/fd/${fd}`);
          if (target && fs.existsSync(target) && (target.endsWith('.log') || target.includes('vllm'))) {
            return target;
          }
        } catch {}
      }
    }
  } catch {}

  // 2. Check standard temporary and configured log paths
  const candidatePaths = [
    '/tmp/vllm-qwen3.log',
    '/tmp/vllm.log',
    '/tmp/vllm-14b.log',
    path.join(os.homedir(), '.opencodereview', 'logs', 'vllm.log'),
    path.join(os.homedir(), '.qbit', 'logs', 'vllm.log')
  ];

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) return p;
  }

  return null;
}

export function createApp() {
  const app = express();

  app.use(cors());
  app.use(express.json());
  app.use(express.static(webDir));

  // Health and engine status
  app.get('/api/status', async (req, res) => {
    let vllmHealthy = false;
    let detectedModel = config.model;

    try {
      const vllmRes = await fetch(`${config.vllmUrl.replace('/v1', '')}/health`, {
        signal: AbortSignal.timeout(2000)
      });
      vllmHealthy = vllmRes.ok;

      // Auto-detect currently served model from vLLM
      if (vllmHealthy) {
        const modelsRes = await fetch(`${config.vllmUrl}/models`, {
          headers: { 'Authorization': `Bearer ${config.apiKey}` },
          signal: AbortSignal.timeout(2000)
        });
        if (modelsRes.ok) {
          const modelsData = await modelsRes.json();
          if (Array.isArray(modelsData?.data) && modelsData.data[0]?.id) {
            detectedModel = modelsData.data[0].id;
            config.model = detectedModel;
          }
        }
      }
    } catch {}

    res.json({
      status: 'ready',
      vllm: {
        url: config.vllmUrl,
        model: detectedModel,
        healthy: vllmHealthy
      },
      ocr: {
        path: config.ocrPath,
        available: true
      },
      opencode: {
        path: config.opencodePath,
        available: true
      },
      workspace: process.cwd()
    });
  });

  // vLLM Model Management endpoints
  app.get('/api/vllm/models', async (req, res) => {
    try {
      const status = await getModelStatus();
      res.json(status);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/vllm/switch', async (req, res) => {
    const { variant } = req.body;
    if (!variant) {
      return res.status(400).json({ error: 'Missing model variant (7b, 14b or 30b)' });
    }
    try {
      const result = await switchModel(variant);
      // Re-trigger scan estimator indexing with new model efficiency factor
      scanEstimator.startIndexing(process.cwd());
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get current findings (synced with active scan job, ScanCache, and ocr_output.json in workspace)
  app.get('/api/findings', async (req, res) => {
    const { pathFilter, includeFixed } = req.query;
    const cache = new ScanCache(process.cwd());
    const cachedList = cache.getFindings(pathFilter || '', includeFixed === 'true');
    const activeJob = scanRegistry.getActiveJob();

    if (activeJob && Array.isArray(activeJob.findings) && activeJob.findings.length > 0) {
      currentFindings = activeJob.findings;
    } else if (cachedList.length > 0) {
      currentFindings = cachedList;
    } else {
      const ocrFile = path.join(process.cwd(), 'ocr_output.json');
      if (fs.existsSync(ocrFile)) {
        try {
          const rawContent = fs.readFileSync(ocrFile, 'utf8');
          const parsed = JSON.parse(rawContent);
          const comments = Array.isArray(parsed) ? parsed : (parsed.comments || []);
          if (comments.length > 0) {
            currentFindings = comments.map((c, i) => normalizeFinding(c, i + 1));
          }
        } catch {}
      }
    }

    res.json({
      findings: currentFindings,
      total: currentFindings.length
    });

    // Asynchronously enrich missing CWE/CVE in background and persist results to cache
    const needsEnrichment = currentFindings.filter(f => 
      !f.cwe_id || f.cwe_id === 'N/A' || f.cwe_id === 'NONE' ||
      !f.cve_id || f.cve_id === 'N/A'
    );
    if (needsEnrichment.length > 0) {
      (async () => {
        try {
          await enrichFindings(needsEnrichment.slice(0, 50), { timeoutMs: 8000, concurrency: 4 });
          for (const f of needsEnrichment) {
            if (cache.data.findings[f.id]) {
              cache.data.findings[f.id].cwe_id = f.cwe_id;
              cache.data.findings[f.id].cwe_title = f.cwe_title;
              cache.data.findings[f.id].cve_id = f.cve_id;
              cache.data.findings[f.id].ref_cve_id = f.ref_cve_id;
              cache.data.findings[f.id].ref_cwe_id = f.ref_cwe_id;
              cache.data.findings[f.id].nvd_severity = f.nvd_severity;
            }
          }
          cache.save();
        } catch {}
      })().catch(() => {});
    }
  });

  // Real-time Hardware Metrics (GPU & CPU)
  app.get('/api/metrics', async (req, res) => {
    let gpu = {
      name: 'NVIDIA GPU',
      utilization: 0,
      memoryUsedMb: 0,
      memoryTotalMb: 0,
      temperatureC: 0
    };

    try {
      const { stdout } = await execAsync(
        'nvidia-smi --query-gpu=name,memory.total,memory.used,utilization.gpu,temperature.gpu --format=csv,noheader,nounits',
        { timeout: 1500 }
      );
      const parts = stdout.trim().split(',').map(s => s.trim());
      if (parts.length >= 5) {
        gpu = {
          name: parts[0],
          memoryTotalMb: parseInt(parts[1], 10) || 0,
          memoryUsedMb: parseInt(parts[2], 10) || 0,
          utilization: parseInt(parts[3], 10) || 0,
          temperatureC: parseInt(parts[4], 10) || 0
        };
      }
    } catch {}

    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const load = os.loadavg();

    res.json({
      timestamp: Date.now(),
      gpu,
      cpu: {
        cores: os.cpus().length,
        load1m: load[0],
        memoryUsedMb: Math.round((totalMem - freeMem) / (1024 * 1024)),
        memoryTotalMb: Math.round(totalMem / (1024 * 1024)),
        memoryPercent: Math.round(((totalMem - freeMem) / totalMem) * 100)
      }
    });
  });

  // Live vLLM Engine Log Tail Stream
  app.get('/api/vllm/logs', (req, res) => {
    const logPath = getVllmLogPath();
    if (!logPath || !fs.existsSync(logPath)) {
      return res.json({ lines: ['[vLLM] No active vLLM log file located at ~/.opencodereview/logs/vllm.log'] });
    }

    try {
      const stats = fs.statSync(logPath);
      const readBytes = Math.min(stats.size, 16384);
      const buffer = Buffer.alloc(readBytes);
      const fd = fs.openSync(logPath, 'r');
      fs.readSync(fd, buffer, 0, readBytes, stats.size - readBytes);
      fs.closeSync(fd);

      const content = buffer.toString('utf-8');
      const lines = content.split('\n').filter(Boolean).slice(-40);
      res.json({ lines });
    } catch (err) {
      res.json({ lines: [`[vLLM Log Error] ${err.message}`] });
    }
  });

  // SCA Vulnerability Package Scanner (via port 8082 Universal SCA API)
  app.post('/api/sca/scan', async (req, res) => {
    try {
      const scaBaseUrl = (process.env.SCA_URL || 'http://localhost:8082').replace(/\/+$/, '');
      let targetPath = req.body.target_path || process.cwd();
      const minSeverity = req.body.min_severity || 'LOW';
      const activeOnly = req.body.active_only !== undefined ? req.body.active_only : false;

      // If targetPath is relative, resolve against current working directory
      if (!path.isAbsolute(targetPath)) {
        targetPath = path.resolve(process.cwd(), targetPath);
      }

      // Check if targetPath exists on host filesystem
      if (fs.existsSync(targetPath)) {
        const stat = fs.statSync(targetPath);
        const zipPath = path.join(os.tmpdir(), `sca_${Date.now()}_${Math.random().toString(36).slice(2)}.zip`);

        try {
          const pyScript = `
import zipfile, os, sys

target = sys.argv[1]
zip_path = sys.argv[2]

if os.path.isfile(target):
    filename = os.path.basename(target)
    with zipfile.ZipFile(zip_path, 'w') as z:
        z.write(target, f"requirements/{filename}")
        z.write(target, filename)
else:
    excluded = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
    allowed_exts = {'.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.java', '.rb', '.php', '.rs', '.cs', '.txt', '.in', '.toml', '.json', '.xml', '.gradle', '.mod'}
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in excluded]
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, target)
                ext = os.path.splitext(f)[1].lower()
                if ext in allowed_exts:
                    z.write(full, rel)
`;
          const packResult = spawnSync('python3', ['-c', pyScript, targetPath, zipPath]);
          if (packResult.status === 0 && fs.existsSync(zipPath)) {
            const form = new FormData();
            const fileBytes = fs.readFileSync(zipPath);
            form.append('file', new Blob([fileBytes]), 'repo.zip');
            if (minSeverity) form.append('min_severity', minSeverity);
            form.append('active_only', activeOnly ? 'true' : 'false');

            const submitRes = await fetch(`${scaBaseUrl}/api/v1/jobs/submit`, {
              method: 'POST',
              body: form,
              signal: AbortSignal.timeout(30000)
            });

            if (submitRes.ok) {
              const submitData = await submitRes.json();
              const jobId = submitData?.job_id;
              if (jobId) {
                let attempts = 0;
                while (attempts < 60) {
                  await new Promise(resolve => setTimeout(resolve, 800));
                  const pollRes = await fetch(`${scaBaseUrl}/api/v1/jobs/${jobId}`, {
                    signal: AbortSignal.timeout(5000)
                  });
                  if (pollRes.ok) {
                    const pollData = await pollRes.json();
                    if (pollData.status === 'completed') {
                      const dlRes = await fetch(`${scaBaseUrl}/api/v1/jobs/${jobId}/download`, {
                        signal: AbortSignal.timeout(10000)
                      });
                      if (dlRes.ok) {
                        const dlData = await dlRes.json();
                        return res.json(dlData);
                      }
                      return res.json(pollData);
                    }
                    if (pollData.status === 'failed') {
                      return res.status(400).json({ error: pollData.error || 'SCA background scan job failed' });
                    }
                  }
                  attempts++;
                }
              }
            }
          }
        } finally {
          if (fs.existsSync(zipPath)) {
            try { fs.unlinkSync(zipPath); } catch {}
          }
        }
      }

      // Fallback to direct scan endpoint if packaging was skipped or direct container access is available
      const scaResponse = await fetch(`${scaBaseUrl}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_path: targetPath,
          min_severity: minSeverity,
          active_only: activeOnly
        }),
        signal: AbortSignal.timeout(30000)
      });

      if (!scaResponse.ok) {
        const errText = await scaResponse.text();
        return res.status(scaResponse.status).json({
          error: `SCA Scanner returned ${scaResponse.status}: ${errText}`
        });
      }

      const data = await scaResponse.json();
      res.json(data);
    } catch (err) {
      res.status(502).json({
        error: `Failed to connect to SCA scanner on ${scaBaseUrl}: ${err.message}`
      });
    }
  });

  // Directory and File tree / search endpoint for the workspace
  app.get('/api/files', (req, res) => {
    const workspaceRoot = process.cwd();
    const query = (req.query.q || '').toString().trim().toLowerCase();
    const targetDir = (req.query.dir || '').toString().trim();

    // If query is provided, do a fast relative path search
    if (query) {
      const results = [];
      const ignoreDirs = new Set(['.git', 'node_modules', '.gemini', 'dist', 'build', '.cache']);

      function searchDir(currentDir, relDir, depth) {
        if (depth > 6 || results.length >= 35) return;
        let entries = [];
        try {
          entries = fs.readdirSync(currentDir, { withFileTypes: true });
        } catch {
          return;
        }

        for (const entry of entries) {
          if (ignoreDirs.has(entry.name)) continue;
          const entryRel = relDir ? `${relDir}/${entry.name}` : entry.name;
          const isDir = entry.isDirectory();

          if (entryRel.toLowerCase().includes(query)) {
            results.push({
              name: entry.name,
              path: entryRel,
              type: isDir ? 'directory' : 'file'
            });
          }

          if (results.length >= 35) return;

          if (isDir) {
            searchDir(path.join(currentDir, entry.name), entryRel, depth + 1);
          }
        }
      }

      searchDir(workspaceRoot, '', 0);
      return res.json({ results });
    }

    // Otherwise, list contents of targetDir (defaulting to workspace root)
    try {
      const safeDir = path.resolve(workspaceRoot, targetDir);
      if (!safeDir.startsWith(workspaceRoot)) {
        return res.status(400).json({ error: 'Access denied: outside workspace' });
      }

      if (!fs.existsSync(safeDir)) {
        return res.status(404).json({ error: 'Path not found' });
      }

      const stat = fs.statSync(safeDir);
      if (!stat.isDirectory()) {
        return res.json({ items: [] });
      }

      const entries = fs.readdirSync(safeDir, { withFileTypes: true });
      const items = entries
        .filter(e => !['.git', 'node_modules', '.gemini', 'dist', 'build'].includes(e.name))
        .map(e => {
          const itemRel = targetDir ? `${targetDir}/${e.name}` : e.name;
          const estimate = scanEstimator.getEstimatesForPath(itemRel);
          return {
            name: e.name,
            path: itemRel,
            type: e.isDirectory() ? 'directory' : 'file',
            fastEta: estimate?.fastEtaFormatted || '',
            fullEta: estimate?.fullEtaFormatted || '',
            fastDurationSec: estimate?.fastDurationSec || 0,
            fullDurationSec: estimate?.fullDurationSec || 0
          };
        })
        .sort((a, b) => {
          if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
          return a.name.localeCompare(b.name);
        });

      res.json({ currentDir: targetDir, items });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Precomputed Scan Estimation API
  app.get('/api/estimates', (req, res) => {
    const target = (req.query.path || '').toString();
    const estimates = scanEstimator.getEstimatesForPath(target);
    res.json(estimates);
  });

  // FastScan Exemption Discovery API
  const scanRegistry = new ScanJobRegistry(process.cwd());

  app.get('/api/fastscan', (req, res) => {
    const target = (req.query.path || process.cwd()).toString();
    const saved = loadExemptions(target);
    if (saved) {
      return res.json(saved);
    }
    const analysis = analyzeExemptions(target);
    saveExemptions(target, analysis);
    res.json(analysis);
  });

  app.post('/api/fastscan', (req, res) => {
    const target = (req.body?.path || process.cwd()).toString();
    const analysis = analyzeExemptions(target);
    saveExemptions(target, analysis);
    res.json(analysis);
  });

  // SuperFast Scan API: Analyzes & auto-prunes heavy modules if exceeding 5-hour ceiling
  app.post('/api/superfastscan', (req, res) => {
    const target = (req.body?.path || process.cwd()).toString();
    const maxHours = parseFloat(req.body?.maxHours) || 5.0;
    const analysis = analyzeSuperFastExemptions(target, maxHours);
    saveExemptions(target, analysis);
    res.json(analysis);
  });

  // Background Scan Job API (Survives SSH disconnection)
  app.get('/api/scan/active', (req, res) => {
    const job = scanRegistry.getActiveJob();
    if (!job) {
      return res.json({ active: false });
    }
    res.json({
      active: true,
      jobId: job.id,
      status: job.status,
      startTime: job.startTime,
      filesTotal: job.filesTotal,
      filesReviewed: job.filesReviewed,
      sessionId: job.sessionId,
      findingsCount: job.findings.length
    });
  });

  app.get('/api/scan/jobs/:jobId', (req, res) => {
    const job = scanRegistry.getJob(req.params.jobId);
    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    res.json({
      id: job.id,
      status: job.status,
      startTime: job.startTime,
      completedAt: job.completedAt,
      filesTotal: job.filesTotal,
      filesReviewed: job.filesReviewed,
      sessionId: job.sessionId,
      findingsCount: Array.isArray(job.findings) ? job.findings.length : (job.findingsCount || 0),
      summary: job.summary
    });
  });

  app.get('/api/scan/stream/:jobId', (req, res) => {
    scanRegistry.attachSSE(req.params.jobId, res, req);
  });

  app.get('/api/scan/stream', (req, res) => {
    const job = scanRegistry.getActiveJob();
    if (!job) {
      return res.status(404).json({ error: 'No active scan job' });
    }
    scanRegistry.attachSSE(job.id, res, req);
  });

  // CSV Export API (Single and Multi-Repository support)
  app.get('/api/export/csv', (req, res) => {
    const { repo, includePatches = 'true' } = req.query;
    const cache = new ScanCache(process.cwd());
    let list = currentFindings.length > 0 ? currentFindings : cache.getFindings();

    // If specific repo requested
    if (repo) {
      const groups = groupFindingsByRepository(list, process.cwd());
      list = groups.get(repo) || [];
    }

    const csvContent = generateFindingsCsv(list, {
      includePatches: includePatches !== 'false',
      repoName: repo || ''
    });

    const filename = repo ? `vulnerabilities_${repo}.csv` : 'vulnerabilities_consolidated.csv';
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
  });

  // Multi-repository listing and counts
  app.get('/api/export/repos', (req, res) => {
    const cache = new ScanCache(process.cwd());
    const list = currentFindings.length > 0 ? currentFindings : cache.getFindings();
    const groups = groupFindingsByRepository(list, process.cwd());
    const result = [];
    for (const [repoName, repoFindings] of groups.entries()) {
      result.push({
        repo: repoName,
        findingsCount: repoFindings.length
      });
    }
    res.json({ repositories: result });
  });

  // Run or attach to full repository vulnerability scan (Streaming logs via SSE)
  app.post('/api/scan', async (req, res) => {
    const { pathFilter, exclude: requestedExclude, fastMode, minSeverity = 'high' } = req.body || {};

    let exclude = requestedExclude || '';
    if (!exclude && fastMode !== false) {
      const saved = loadExemptions(process.cwd());
      if (saved && saved.excludeArgsString) {
        exclude = saved.excludeArgsString;
      }
    }

    // Check if an existing background job is already running
    let job = scanRegistry.getActiveJob();
    if (!job || job.status !== 'running') {
      job = scanRegistry.createJob({
        pathFilter,
        exclude,
        minSeverity,
        fastMode,
        targetDir: process.cwd()
      });
      // Start background scan execution independently of HTTP connection
      scanRegistry.startJob(job.id).catch(err => {
        console.error('Scan job error:', err);
      });
    }

    // Attach SSE stream to the client (if client disconnects, scan continues running)
    scanRegistry.attachSSE(job.id, res, req);
  });

  // Run git diff review (Streaming logs via SSE)
  app.post('/api/review', async (req, res) => {
    const { staged, from, to } = req.body || {};

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (event, data) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent('start', { staged });

    try {
      const result = await runReview({
        staged,
        from,
        to,
        onProgress: (chunk) => {
          const lines = chunk.split('\n').map(l => l.trim()).filter(Boolean);
          for (const line of lines) {
            sendEvent('log', { message: line });
          }
        }
      });

      if (result.status === 'error') {
        sendEvent('error', { error: result.error });
      } else {
        currentFindings = result.findings || [];
        sendEvent('complete', {
          findings: currentFindings,
          summary: result.summary
        });
      }
    } catch (err) {
      sendEvent('error', { error: err.message });
    } finally {
      res.end();
    }
  });

  // Apply fix with OpenCode (Streaming logs via SSE)
  app.post('/api/fix', async (req, res) => {
    const { findingId, customInstruction } = req.body || {};
    const finding = currentFindings.find(f => f.id === findingId) || currentFindings[0];

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (event, data) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent('start', { findingId: finding.id, path: finding.path });

    try {
      finding.status = 'fixing';
      const result = await applyFixWithOpenCode({
        finding,
        customInstruction,
        onLog: (msg) => {
          sendEvent('log', { message: msg });
        }
      });

      if (result.success) {
        finding.status = 'fixed';
        try {
          const cache = new ScanCache(process.cwd());
          cache.markFixed(finding.id);
        } catch {}
        try {
          const ocrFile = path.join(process.cwd(), 'ocr_output.json');
          if (fs.existsSync(ocrFile)) {
            const raw = JSON.parse(fs.readFileSync(ocrFile, 'utf8'));
            if (raw.comments) {
              const idx = currentFindings.findIndex(f => f.id === finding.id);
              if (idx !== -1 && raw.comments[idx]) {
                raw.comments[idx].status = 'fixed';
                fs.writeFileSync(ocrFile, JSON.stringify(raw, null, 2), 'utf8');
              }
            }
          }
        } catch {}
        sendEvent('complete', {
          success: true,
          findingId: finding.id,
          mode: result.mode
        });
      } else {
        finding.status = 'open';
        sendEvent('error', {
          success: false,
          error: result.output
        });
      }
    } catch (err) {
      finding.status = 'open';
      sendEvent('error', { error: err.message });
    } finally {
      res.end();
    }
  });

  // Batch synthesize missing concrete patches using QbitCode / vLLM (Streaming SSE)
  app.post('/api/patches/synthesize', async (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (event, data) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    try {
      const ocrFile = path.join(process.cwd(), 'ocr_output.json');
      if (fs.existsSync(ocrFile) && currentFindings.length === 0) {
        try {
          const parsed = JSON.parse(fs.readFileSync(ocrFile, 'utf8'));
          const comments = Array.isArray(parsed) ? parsed : (parsed.comments || []);
          currentFindings = comments.map((c, i) => normalizeFinding(c, i + 1));
        } catch {}
      }

      if (currentFindings.length === 0) {
        sendEvent('complete', { status: 'success', findings: [], synthesizedCount: 0, total: 0 });
        return res.end();
      }

      const missingCount = currentFindings.filter(f => !isConcretePatch(f.suggestion_code)).length;
      sendEvent('start', { total: currentFindings.length, missingCount });

      const result = await synthesizeAllPatches(
        currentFindings,
        process.cwd(),
        (current, total, finding, isDone, needed) => {
          sendEvent('progress', {
            current,
            total,
            percent: Math.round((current / total) * 100),
            path: finding.path,
            line: finding.start_line,
            category: finding.category || 'Vulnerability',
            findingId: finding.id,
            isDone,
            needed
          });
        }
      );
      currentFindings = result.findings;

      sendEvent('complete', {
        status: 'success',
        findings: currentFindings,
        synthesizedCount: result.synthesizedCount,
        total: currentFindings.length
      });
    } catch (err) {
      console.error('[API Error] Patch synthesis failed:', err.message);
      sendEvent('error', { error: err.message, findings: currentFindings });
    } finally {
      res.end();
    }
  });

  // Interactive Chat Stream (vLLM via SSE) - Strict Read-Only Vulnerability Advisor
  app.post('/api/chat', async (req, res) => {
    const { messages, findingContext } = req.body || {};

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const systemPrompt = `You are Qbit AI, an elite security analysis and vulnerability explainer copilot powered by local vLLM. 
The Web UI operates strictly in READ-ONLY AUDIT MODE: you explain flaws, technical risks, CWE classifications, and security concepts. You do NOT make write changes to files on disk.
When a user asks to inspect or discuss a vulnerability or code finding:
1. Clearly explain the root cause and technical vulnerability risk in this specific code context.
2. Detail the Common Weakness Enumeration (CWE) or CVE classification, severity, and attack vectors.
3. Provide an educational explanation of how to remediate the defect with a safe, idiomatic replacement code snippet.
4. If the developer wants to apply fixes to their repository files, instruct them to use the interactive QbitCode CLI / TUI: \`qbitcode\` or \`/fix <id>\`.
Be concise, technical, authoritative, and direct.`;

    let enrichedMessages = [...(messages || [])];
    if (findingContext && enrichedMessages.length > 0) {
      // Find the first user message or append context
      const userIdx = enrichedMessages.findIndex(m => m.role === 'user');
      if (userIdx !== -1) {
        const existing = enrichedMessages[userIdx];
        enrichedMessages[userIdx] = {
          ...existing,
          content: `[Target Code Finding]\nFile: ${findingContext.path} (Lines ${findingContext.start_line}-${findingContext.end_line})\nCategory: ${findingContext.category} | Severity: ${findingContext.severity}\nIdentified Issue: ${findingContext.content}\n${findingContext.existing_code ? `Current Code:\n\`\`\`\n${findingContext.existing_code}\n\`\`\`\n` : ''}${findingContext.suggestion_code ? `Suggested Resolution:\n\`\`\`\n${findingContext.suggestion_code}\n\`\`\`\n` : ''}\nDeveloper Request: ${existing.content}`
        };
      }
    }

    try {
      for await (const chunk of streamChatWithVllm({ messages: enrichedMessages, systemPrompt })) {
        res.write(`data: ${JSON.stringify({ token: chunk })}\n\n`);
      }
      res.write(`data: [DONE]\n\n`);
    } catch (err) {
      res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    } finally {
      res.end();
    }
  });

  // Save Settings
  app.post('/api/config', (req, res) => {
    const saved = saveConfig(req.body);
    res.json({ success: saved, config });
  });

  // Fallback to SPA index.html
  app.use((req, res) => {
    res.sendFile(path.join(webDir, 'index.html'));
  });

  return app;
}

export function startServer(port = config.port) {
  // Start upfront background filesystem & scan duration precomputing
  try {
    scanEstimator.startIndexing(process.cwd());
  } catch (err) {
    console.warn('⚠️ ScanEstimator precomputing notice:', err.message);
  }

  const app = createApp();
  const server = app.listen(port, () => {
    // server running
  });
  return server;
}
