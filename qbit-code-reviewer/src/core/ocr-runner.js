import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { config } from './config.js';
import { normalizeFinding, summarizeFindings } from './types.js';
import { SessionManager } from './session-manager.js';
import { ScanCache } from './scan-cache.js';
import { enrichFindings } from './cve-enricher.js';

/**
 * Executes OCR command and returns parsed JSON findings.
 * Captures session ID from output stream, records active session,
 * and recovers partial findings on crash or non-zero exit.
 */
export async function runOcrCommand(subcommand, args = [], cwd = process.cwd(), timeoutMs = 0, onProgress = null) {
  // Fast check if vLLM is reachable when using vllm provider
  let vllmOnline = false;
  try {
    const healthUrl = `${config.vllmUrl.replace('/v1', '')}/health`;
    const res = await fetch(healthUrl, { signal: AbortSignal.timeout(2000) });
    vllmOnline = res.ok;
  } catch {}

  if (!vllmOnline && !process.env.FORCE_OCR) {
    return {
      status: 'error',
      error: `vLLM server is offline (${config.vllmUrl}). Please ensure vLLM is running.`,
      summary: summarizeFindings([]),
      findings: []
    };
  }

  const tmpFile = path.join(os.tmpdir(), `qbit-ocr-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const fullArgs = [subcommand, ...args, '--format', 'json', '--output', tmpFile];

  // Check if an explicit --resume flag was passed in args
  let currentSessionId = null;
  const resumeIdx = args.indexOf('--resume');
  if (resumeIdx !== -1 && args[resumeIdx + 1]) {
    currentSessionId = args[resumeIdx + 1];
  }

  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const proc = spawn(config.ocrPath, fullArgs, {
      cwd,
      env: {
        ...process.env,
        PATH: `${path.dirname(config.ocrPath)}:${process.env.PATH || ''}`
      }
    });

    let timer = null;
    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        try { proc.kill('SIGTERM'); } catch {}
      }, timeoutMs);
    }

    const checkSessionMatch = (text) => {
      if (!currentSessionId) {
        const m = text.match(/\[ocr\] Session:\s+([a-f0-9\-]+)/i);
        if (m && m[1]) {
          currentSessionId = m[1];
          SessionManager.saveActiveSession(cwd, {
            sessionId: currentSessionId,
            subcommand,
            status: 'in_progress',
            startTime: Date.now()
          });
        }
      }
    };

    proc.stdout.on('data', (d) => {
      const text = d.toString();
      stdout += text;
      checkSessionMatch(text);
      if (typeof onProgress === 'function') {
        onProgress(text, tmpFile);
      }
    });

    proc.stderr.on('data', (d) => {
      const text = d.toString();
      stderr += text;
      checkSessionMatch(text);
      if (typeof onProgress === 'function') {
        onProgress(text, tmpFile);
      }
      // Stream live progress lines from engine only if no custom onProgress handler
      if (process.stdout.isTTY && !onProgress) {
        process.stderr.write(text);
      }
    });

    proc.on('error', (err) => {
      if (timer) clearTimeout(timer);
      try { if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile); } catch {}
      reject(new Error(`Failed to launch OCR binary (${config.ocrPath}): ${err.message}`));
    });

    proc.on('close', async (code) => {
      if (timer) clearTimeout(timer);
      let rawJson = null;

      // 1. Check if output file was created
      if (fs.existsSync(tmpFile)) {
        try {
          const content = fs.readFileSync(tmpFile, 'utf-8');
          rawJson = JSON.parse(content);
        } catch (err) {
          // Ignore parse error here and fallback to stdout
        }
        try { fs.unlinkSync(tmpFile); } catch {}
      }

      // 2. If not in file, try parsing stdout
      if (!rawJson && stdout.trim()) {
        try {
          rawJson = JSON.parse(stdout);
        } catch {}
      }

      if (rawJson && code === 0) {
        SessionManager.markCompleted(cwd);
        const rawComments = rawJson.comments || [];
        const findings = rawComments.map((c, i) => normalizeFinding(c, i + 1));
        const summary = summarizeFindings(findings);
        return resolve({
          status: 'success',
          sessionId: currentSessionId,
          summary,
          findings,
          raw: rawJson
        });
      }

      // If OCR exited with non-zero code or no final JSON produced (e.g. crash, abort, SIGINT)
      const sid = currentSessionId || SessionManager.getActiveSession(cwd)?.sessionId;
      let partialFindings = [];
      let completedFiles = [];

      if (sid) {
        try {
          partialFindings = await SessionManager.getSessionFindings(cwd, sid);
          completedFiles = await SessionManager.getSessionCompletedFiles(cwd, sid);
        } catch {}
      }

      // If we recovered completed files from the session before crash
      if (completedFiles.length > 0) {
        SessionManager.saveActiveSession(cwd, {
          sessionId: sid,
          subcommand,
          status: 'interrupted',
          completedFiles,
          findingCount: partialFindings.length
        });

        return resolve({
          status: 'interrupted',
          sessionId: sid,
          completedFiles,
          findings: partialFindings,
          summary: summarizeFindings(partialFindings),
          error: stderr || stdout || `OCR exited with code ${code}`,
          resumable: true
        });
      }

      // If OCR exited with error and no completed files could be recovered
      if (code !== 0) {
        return resolve({
          status: 'error',
          sessionId: sid,
          error: stderr || stdout || `OCR exited with code ${code}`,
          summary: summarizeFindings([]),
          findings: []
        });
      }

      // Empty result with code 0
      SessionManager.markCompleted(cwd);
      return resolve({
        status: 'success',
        sessionId: currentSessionId,
        summary: summarizeFindings([]),
        findings: []
      });
    });
  });
}

/**
 * Runs a full repository or directory vulnerability scan with caching and session crash continuation
 */
export async function runScan({ targetDir = process.cwd(), pathFilter = '', exclude = '', minSeverity = 'high', concurrency = null, onProgress = null, noCache = false, noResume = false } = {}) {
  const cache = new ScanCache(targetDir);

  if (!noCache) {
    const { unchangedFiles, modifiedFiles, deletedFiles, contentReusedFiles = [] } = cache.partitionFiles(pathFilter);

    // Clean up any deleted files from cache
    if (deletedFiles.length > 0) {
      cache.removeDeletedFiles(deletedFiles);
    }

    if (contentReusedFiles.length > 0 && typeof onProgress === 'function') {
      onProgress(`⚡ [CONTENT HASH REUSE] Reused cached findings for ${contentReusedFiles.length} identical file(s) across version folders.\n`);
    }

    // If there are no modified files and we have already cached entries, return immediately
    if (modifiedFiles.length === 0 && unchangedFiles.length > 0) {
      if (typeof onProgress === 'function') {
        onProgress(`⚡ [CACHE HIT] All ${unchangedFiles.length} files in scope are up-to-date. Loaded from cache.\n`);
      }
      let cachedFindings = cache.getFindings(pathFilter);
      if (minSeverity === 'high' || minSeverity === 'critical') {
        cachedFindings = cachedFindings.filter(f => f.severity === 'critical' || f.severity === 'high');
      }
      return {
        status: 'success',
        summary: summarizeFindings(cachedFindings),
        findings: cachedFindings,
        cached: true,
        stats: { unchanged: unchangedFiles.length, modified: 0, contentReused: contentReusedFiles.length }
      };
    }
  }

  // Crash continuation check: find previous interrupted session if available
  let resumeSessionId = null;
  if (!noResume) {
    const resumable = await SessionManager.findResumableSession(targetDir, 'scan', pathFilter);
    if (resumable && resumable.sessionId) {
      resumeSessionId = resumable.sessionId;
      if (typeof onProgress === 'function') {
        onProgress(`⚡ [CRASH CONTINUATION] Found previous scan session ${resumeSessionId} (${resumable.completedFiles.length} file(s) already reviewed). Resuming scan from checkpoint...\n`);
      }
    }
  }

  // Dynamically resolve concurrency and model from active profile or config
  const activeConcurrency = String(concurrency || config.concurrency || (config.model && config.model.includes('14b') ? 8 : 4));
  const activeModel = config.model || (parseInt(activeConcurrency, 10) >= 8 ? 'qwen2.5-coder-14b-instruct' : 'qwen3-coder-30b-a3b-instruct');

  const args = ['--concurrency', activeConcurrency, '--no-plan', '--max-tools', '8'];
  if (activeModel) {
    args.push('--model', activeModel);
  }
  if (minSeverity === 'high' || minSeverity === 'critical') {
    args.push('--background', 'Strict Audit Directive: Identify and report ONLY vulnerabilities with CRITICAL or HIGH severity (e.g. Remote Code Execution, Memory Corruption, Authentication Bypass, Injection, Privilege Escalation). Completely ignore medium, low, informational, and style issues.');
  }
  if (resumeSessionId) {
    args.push('--resume', resumeSessionId);
  }
  if (pathFilter) {
    args.push('--path', pathFilter);
  }
  if (exclude) {
    args.push('--exclude', exclude);
  }

  let res = await runOcrCommand('scan', args, targetDir, 0, onProgress);

  // If resume failed due to scope mismatch or stale session, fallback to fresh scan without --resume
  if (res.status === 'failed' && resumeSessionId && (res.rawOutput || '').includes('does not match current scope')) {
    if (typeof onProgress === 'function') {
      onProgress(`⚠️ Previous session scope did not match current scan. Starting fresh scan without checkpoint...\n`);
    }
    const cleanArgs = ['--concurrency', activeConcurrency, '--no-plan', '--max-tools', '8'];
    if (activeModel) {
      cleanArgs.push('--model', activeModel);
    }
    if (minSeverity === 'high' || minSeverity === 'critical') {
      cleanArgs.push('--background', 'Strict Audit Directive: Identify and report ONLY vulnerabilities with CRITICAL or HIGH severity (e.g. Remote Code Execution, Memory Corruption, Authentication Bypass, Injection, Privilege Escalation). Completely ignore medium, low, informational, and style issues.');
    }
    if (pathFilter) {
      cleanArgs.push('--path', pathFilter);
    }
    if (exclude) {
      cleanArgs.push('--exclude', exclude);
    }
    res = await runOcrCommand('scan', cleanArgs, targetDir, 0, onProgress);
  }

  // If scan was interrupted/crashed but has partial completed files
  if (res.status === 'interrupted') {
    if (res.completedFiles && res.completedFiles.length > 0 && !noCache) {
      cache.updateScanResults(res.findings || [], res.completedFiles);
      const allFindings = cache.getFindings(pathFilter);
      res.findings = allFindings;
      res.summary = summarizeFindings(allFindings);
    }

    // Persist rescued findings to ocr_output.json in targetDir
    try {
      const ocrFile = path.join(targetDir, 'ocr_output.json');
      fs.writeFileSync(ocrFile, JSON.stringify({
        status: 'interrupted',
        sessionId: res.sessionId,
        completedFiles: res.completedFiles || [],
        summary: res.summary,
        comments: res.findings || []
      }, null, 2), 'utf8');
    } catch {}

    return res;
  }

  // If scan completed cleanly
  if (res.status === 'success') {
    SessionManager.markCompleted(targetDir);

    // Automatically enrich findings with MITRE CWE and CVE from localhost:8080
    if (res.findings && res.findings.length > 0) {
      if (typeof onProgress === 'function') {
        onProgress(`⚡ [ENRICHMENT] Querying localhost:8080 MITRE CWE & CVE catalog for ${res.findings.length} findings...\n`);
      }
      await enrichFindings(res.findings);
    }

    if (!noCache) {
      const { unchangedFiles, modifiedFiles } = cache.partitionFiles(pathFilter);
      const scannedList = modifiedFiles.length > 0 ? modifiedFiles : (res.findings || []).map(f => f.path);
      cache.updateScanResults(res.findings || [], scannedList);
      const allFindings = cache.getFindings(pathFilter);
      res.findings = allFindings;
      res.summary = summarizeFindings(allFindings);
    }

    // Persist final findings to ocr_output.json in targetDir
    try {
      const ocrFile = path.join(targetDir, 'ocr_output.json');
      fs.writeFileSync(ocrFile, JSON.stringify({
        status: 'success',
        sessionId: res.sessionId,
        summary: res.summary,
        comments: res.findings || []
      }, null, 2), 'utf8');
    } catch {}
  }

  return res;
}

/**
 * Runs a git diff review on uncommitted or range changes
 */
export async function runReview({ from, to, staged = false, commit, targetDir = process.cwd(), onProgress = null } = {}) {
  const args = [];
  if (staged) {
    args.push('--staged');
  } else if (from && to) {
    args.push('--from', from, '--to', to);
  } else if (commit) {
    args.push('--commit', commit);
  }
  return runOcrCommand('review', args, targetDir, 300000, onProgress);
}
