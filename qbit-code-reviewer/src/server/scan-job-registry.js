import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { runScan } from '../core/ocr-runner.js';
import { runSubrepoBatchScan, discoverSubRepositories } from '../core/subrepo-runner.js';
import { SessionManager, getOcrSessionFilePath } from '../core/session-manager.js';
import { enrichFindings, enrichFinding } from '../core/cve-enricher.js';
import { normalizeFinding } from '../core/types.js';
import { ProgressEstimator } from '../core/progress-estimator.js';

/**
 * ScanJobRegistry manages asynchronous, background scan jobs.
 * 
 * Features:
 * - Decouples scan execution from active HTTP / SSH connections.
 * - Buffers logs and intermediate findings in memory and on disk.
 * - Allows multiple clients or reconnected SSH sessions to reattach to an ongoing scan.
 * - Persists job state to `.qbit/jobs/<jobId>.json` so status survives network drops.
 */
export class ScanJobRegistry extends EventEmitter {
  constructor(workspaceDir = process.cwd()) {
    super();
    this.workspaceDir = path.resolve(workspaceDir);
    this.jobsDir = path.join(this.workspaceDir, '.qbit', 'jobs');
    this.jobs = new Map(); // jobId -> Job State
    this.activeJobId = null;

    if (!fs.existsSync(this.jobsDir)) {
      try {
        fs.mkdirSync(this.jobsDir, { recursive: true });
      } catch {}
    }

    this.recoverJobsFromDisk();
  }

  recoverJobsFromDisk() {
    try {
      if (!fs.existsSync(this.jobsDir)) return;
      const files = fs.readdirSync(this.jobsDir);
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        const filePath = path.join(this.jobsDir, file);
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (data && data.id) {
          // If a job was left in "running" state when the server died, mark it interrupted
          if (data.status === 'running') {
            data.status = 'interrupted';
            data.completedAt = Date.now();
            try {
              fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
            } catch {}
          }
          this.jobs.set(data.id, data);
        }
      }
    } catch (e) {
      console.warn('⚠️ Could not recover past scan jobs from disk:', e.message);
    }
  }

  getActiveJob() {
    if (!this.activeJobId) return null;
    return this.jobs.get(this.activeJobId) || null;
  }

  getJob(jobId) {
    return this.jobs.get(jobId) || null;
  }

  persistJob(job) {
    try {
      if (!fs.existsSync(this.jobsDir)) {
        fs.mkdirSync(this.jobsDir, { recursive: true });
      }
      const filePath = path.join(this.jobsDir, `${job.id}.json`);
      const tmp = `${filePath}.${Date.now()}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({
        id: job.id,
        targetDir: job.targetDir,
        pathFilter: job.pathFilter,
        exclude: job.exclude,
        fastMode: job.fastMode,
        status: job.status,
        startTime: job.startTime,
        completedAt: job.completedAt,
        filesTotal: job.filesTotal,
        filesReviewed: job.filesReviewed,
        findingsCount: job.findings.length,
        sessionId: job.sessionId,
        error: job.error,
        summary: job.summary
      }, null, 2), 'utf8');
      fs.renameSync(tmp, filePath);
    } catch (e) {
      console.warn(`⚠️ Failed to persist job ${job.id}:`, e.message);
    }
  }

  createJob({ pathFilter = '', exclude = '', minSeverity = 'high', fastMode = true, targetDir = this.workspaceDir } = {}) {
    const existing = this.getActiveJob();
    if (existing && existing.status === 'running') {
      return existing; // Return running job instead of launching duplicate
    }

    const id = `scan_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const job = {
      id,
      targetDir: path.resolve(targetDir),
      pathFilter,
      exclude,
      minSeverity,
      fastMode,
      status: 'pending', // pending | running | completed | failed | interrupted
      startTime: Date.now(),
      completedAt: null,
      filesTotal: 0,
      filesReviewed: 0,
      filesSkipped: 0,
      etaSeconds: 0,
      etaFormatted: '',
      percent: 0,
      logs: [],
      findings: [],
      sessionId: null,
      error: null,
      summary: null,
      sseListeners: new Set()
    };

    this.jobs.set(id, job);
    this.activeJobId = id;
    this.persistJob(job);
    return job;
  }

  emitToJob(job, event, data) {
    const payload = { event, data, timestamp: Date.now() };

    if (event === 'log' && data.message) {
      job.logs.push(data.message);
      if (job.logs.length > 2000) job.logs.shift(); // Keep buffer bounded
    }

    for (const listener of job.sseListeners) {
      try {
        listener(event, data);
      } catch {}
    }
    this.emit('job_event', { jobId: job.id, event, data });
  }

  async startJob(jobId) {
    const job = this.jobs.get(jobId);
    if (!job || job.status === 'running') return;

    job.status = 'running';
    this.activeJobId = job.id;
    this.persistJob(job);
    this.emitToJob(job, 'start', {
      jobId: job.id,
      pathFilter: job.pathFilter || 'all',
      excludeActive: !!job.exclude
    });

    if (job.exclude) {
      this.emitToJob(job, 'log', {
        message: `⚡ [FASTSCAN] Active scan exemptions applied. Non-code, dependency, and artifact files are skipped.`
      });
    }

    const estimator = new ProgressEstimator();
    estimator.start(job.filesTotal || 0);

    let sentFindingsCount = 0;
    const reviewedFilesSet = new Set();
    let lastProgressEmit = Date.now();

    // Check if target workspace has multi-stack sub-repositories (only when no specific path filter was requested)
    const subrepos = (!job.pathFilter || job.pathFilter.trim() === '') ? discoverSubRepositories(job.targetDir) : [];

    try {
      let result;
      if (subrepos.length > 1) {
        this.emitToJob(job, 'log', {
          message: `🚀 [MULTI-REPO MODE] Discovered ${subrepos.length} sub-repositories. Executing sequential sub-repo scans with single shared .qbit/ cache...`
        });

        result = await runSubrepoBatchScan({
          workspaceRoot: job.targetDir,
          exclude: job.exclude,
          minSeverity: job.minSeverity || 'high',
          onProgress: (chunk, tmpFile) => {
            const lines = chunk.split('\n').map(l => l.trim()).filter(Boolean);
            for (const line of lines) {
              this.emitToJob(job, 'log', { message: line });

              // Extract session id
              if (!job.sessionId) {
                const m = line.match(/\[ocr\] Session:\s+([a-f0-9\-]+)/i);
                if (m && m[1]) {
                  job.sessionId = m[1];
                  this.persistJob(job);
                }
              }

              // Extract total discovered files and active reviewable files
              const reviewMatch = line.match(/reviewing (\d+) in/) || line.match(/(\d+) file\(s\) discovered/);
              if (reviewMatch) {
                const parsedTotal = parseInt(reviewMatch[1], 10);
                job.filesTotal = Math.max(job.filesTotal, parsedTotal);
                estimator.setTotalFiles(job.filesTotal);
                this.persistJob(job);
              }

              // Parse reused/cached file announcements
              const reuseMatch = line.match(/reusing (\d+) file\(s\)/i) || line.match(/Reused cached findings for (\d+) identical file/i);
              if (reuseMatch) {
                const reusedCount = parseInt(reuseMatch[1], 10);
                job.filesSkipped += reusedCount;
                estimator.recordSkipped(reusedCount);
              }
              // Per-file completion notifications from scanner
              if (
                line.includes('✔ code_comment') ||
                line.includes('✔ task_done') ||
                line.includes('[ocr] reviewed') ||
                line.includes('review_item_done')
              ) {
                estimator.recordFileScanned();
                job.filesReviewed++;
              }
            }

            // Check active OCR session file for completed subtasks and comments
            if (job.sessionId && Date.now() - lastProgressEmit > 1000) {
              lastProgressEmit = Date.now();
              try {
                const sessionPath = getOcrSessionFilePath(job.targetDir, job.sessionId);
                if (sessionPath && fs.existsSync(sessionPath)) {
                  const content = fs.readFileSync(sessionPath, 'utf8');
                  const sLines = content.split('\n');
                  let completedCount = 0;
                  for (const sl of sLines) {
                    if (!sl) continue;
                    // Count completed review items accurately
                    if (sl.includes('"type":"review_item_done"') || sl.includes('"type":"review_item_reused"')) {
                      completedCount++;
                    }
                    if (sl.includes('"tool_name":"code_comment"') || sl.includes('"name":"code_comment"') || sl.includes('"type":"review_item_done"')) {
                      try {
                        const rec = JSON.parse(sl);
                        if (Array.isArray(rec.comments) && rec.comments.length > 0) {
                          for (const c of rec.comments) {
                            const norm = normalizeFinding(c, job.findings.length + 1);
                            if (!job.findings.some(f => f.path === norm.path && f.start_line === norm.start_line && f.content === norm.content)) {
                              job.findings.push(norm);
                              this.emitToJob(job, 'finding', { finding: norm });
                            }
                          }
                        } else if (rec.arguments) {
                          const parsedArgs = JSON.parse(rec.arguments);
                          if (Array.isArray(parsedArgs.comments)) {
                            for (const c of parsedArgs.comments) {
                              const norm = normalizeFinding(c, job.findings.length + 1);
                              if (!job.findings.some(f => f.path === norm.path && f.start_line === norm.start_line && f.content === norm.content)) {
                                job.findings.push(norm);
                                this.emitToJob(job, 'finding', { finding: norm });
                              }
                            }
                          }
                        }
                      } catch {}
                    }
                  }
                  if (completedCount > job.filesReviewed) {
                    job.filesReviewed = completedCount;
                    estimator.scannedFiles = completedCount;
                  }
                }
              } catch {}

              const state = estimator.getState();
              job.percent = state.percent;
              job.etaSeconds = state.etaSeconds;
              job.etaFormatted = state.etaFormatted;

              // Compute realistic overall workspace ETA accounting for upfront deduplication
              let overallEtaFormatted = job.etaFormatted;
              if (job.totalSubrepos && job.totalSubrepos > 1) {
                const completed = job.completedSubrepos || 0;
                const remaining = Math.max(0, job.totalSubrepos - completed);
                const currentUnitSec = state.etaSeconds || 60;
                // Stacks 2, 3, 4 reuse Stack 1 hash cache and take ~2-5s per unit.
                // Realistic total remaining is: (Current active sub-unit) + (Remaining sub-units * ~45s average)
                const estimatedRemainingSec = Math.round(currentUnitSec + (remaining * 40));
                const remMin = Math.round(estimatedRemainingSec / 60);
                overallEtaFormatted = remMin >= 60 ? `${Math.floor(remMin / 60)}h ${remMin % 60}m` : `${remMin}m`;
              }
              job.overallEtaFormatted = overallEtaFormatted;

              // Ensure reviewedFiles never displays higher than totalFiles
              const displayReviewed = job.filesTotal > 0 ? Math.min(job.filesTotal, job.filesReviewed) : job.filesReviewed;

              this.emitToJob(job, 'progress', {
                reviewedFiles: displayReviewed,
                skippedFiles: job.filesSkipped,
                totalFiles: job.filesTotal,
                percent: job.percent,
                etaSeconds: job.etaSeconds,
                etaFormatted: job.etaFormatted,
                overallEtaFormatted: job.overallEtaFormatted,
                currentSubrepo: job.currentSubrepo,
                completedSubrepos: job.completedSubrepos || 0,
                totalSubrepos: job.totalSubrepos || 1
              });
              this.persistJob(job);
            }
          },
          onSubrepoStart: ({ subrepo, index, total }) => {
            job.currentSubrepo = subrepo;
            job.currentSubrepoIndex = index;
            job.totalSubrepos = total;
            // Reset per-subrepo file counters so audited doesn't exceed total files
            job.filesReviewed = 0;
            job.filesTotal = 0;
            estimator.start(0);
            this.emitToJob(job, 'progress', {
              currentSubrepo: subrepo,
              subrepoIndex: index,
              totalSubrepos: total,
              completedSubrepos: index - 1,
              percent: Math.round(((index - 1) / total) * 100),
              reviewedFiles: 0,
              skippedFiles: job.filesSkipped,
              totalFiles: 0,
              subrepoEtaFormatted: '~1m'
            });
            this.persistJob(job);
          },
          onSubrepoComplete: ({ subrepo, index, total, findingsCount }) => {
            job.completedSubrepos = index;
            job.totalSubrepos = total;
            this.emitToJob(job, 'progress', {
              subrepo,
              currentSubrepo: subrepo,
              completedSubrepos: index,
              subrepoIndex: index,
              totalSubrepos: total,
              percent: Math.round((index / total) * 100),
              reviewedFiles: job.filesReviewed,
              skippedFiles: job.filesSkipped,
              totalFiles: job.filesTotal
            });
            this.persistJob(job);
          }
        });

      } else {
        result = await runScan({
          targetDir: job.targetDir,
          pathFilter: job.pathFilter,
          exclude: job.exclude,
          minSeverity: job.minSeverity || 'high',
          onProgress: (chunk, tmpFile) => {
          const lines = chunk.split('\n').map(l => l.trim()).filter(Boolean);
          for (const line of lines) {
            this.emitToJob(job, 'log', { message: line });

            // Extract session id
            if (!job.sessionId) {
              const m = line.match(/\[ocr\] Session:\s+([a-f0-9\-]+)/i);
              if (m && m[1]) {
                job.sessionId = m[1];
                this.persistJob(job);
              }
            }

            // Extract total discovered files and active reviewable files
            const reviewMatch = line.match(/reviewing (\d+) in/) || line.match(/(\d+) file\(s\) discovered/);
            if (reviewMatch) {
              const parsedTotal = parseInt(reviewMatch[1], 10);
              job.filesTotal = Math.max(job.filesTotal, parsedTotal);
              estimator.setTotalFiles(job.filesTotal);
              this.persistJob(job);
            }

            // Parse reused/cached file announcements
            const reuseMatch = line.match(/reusing (\d+) file\(s\)/i);
            if (reuseMatch) {
              const reusedCount = parseInt(reuseMatch[1], 10);
              job.filesSkipped = reusedCount;
              estimator.recordSkipped(reusedCount);
            }

            // Per-file completion notifications from scanner
            if (
              line.includes('✔ code_comment') ||
              line.includes('✔ task_done') ||
              line.includes('[ocr] reviewed') ||
              line.includes('review_item_done')
            ) {
              estimator.recordFileScanned();
              job.filesReviewed++;
            }
          }

          // Check completed files and intermediate findings from active OCR session JSONL periodically
          if (job.sessionId && Date.now() - lastProgressEmit > 1000) {
            lastProgressEmit = Date.now();

            try {
              const sessionPath = getOcrSessionFilePath(job.targetDir, job.sessionId);
              
              if (sessionPath && fs.existsSync(sessionPath)) {
                const content = fs.readFileSync(sessionPath, 'utf8');
                const sLines = content.split('\n');
                let completedCount = 0;
                for (const sl of sLines) {
                  if (!sl) continue;
                  if (sl.includes('"type":"review_item_done"') || sl.includes('"type":"review_item_reused"')) {
                    completedCount++;
                  }
                  // Extract findings emitted in this item
                  if (sl.includes('"tool_name":"code_comment"') || sl.includes('"name":"code_comment"') || sl.includes('"type":"review_item_done"')) {
                    try {
                      const rec = JSON.parse(sl);
                      if (Array.isArray(rec.comments) && rec.comments.length > 0) {
                        for (const rawComment of rec.comments) {
                          const normalized = normalizeFinding(rawComment, job.findings.length + 1);
                          if (!job.findings.some(f => f.path === normalized.path && f.start_line === normalized.start_line && f.content === normalized.content)) {
                            job.findings.push(normalized);
                            this.emitToJob(job, 'finding', { finding: normalized });
                          }
                        }
                      } else if (rec.arguments) {
                        const parsedArgs = JSON.parse(rec.arguments);
                        if (Array.isArray(parsedArgs.comments)) {
                          for (const c of parsedArgs.comments) {
                            const norm = normalizeFinding(c, job.findings.length + 1);
                            if (!job.findings.some(f => f.path === norm.path && f.start_line === norm.start_line && f.content === norm.content)) {
                              job.findings.push(norm);
                              this.emitToJob(job, 'finding', { finding: norm });
                            }
                          }
                        }
                      }
                    } catch {}
                  }
                }
                if (completedCount > job.filesReviewed) {
                  job.filesReviewed = completedCount;
                  estimator.scannedFiles = completedCount;
                }
              }
            } catch {}

            const state = estimator.getState();
            job.percent = state.percent;
            job.etaSeconds = state.etaSeconds;
            job.etaFormatted = state.etaFormatted;

            this.emitToJob(job, 'progress', {
              reviewedFiles: job.filesReviewed,
              skippedFiles: job.filesSkipped,
              totalFiles: job.filesTotal,
              percent: job.percent,
              etaSeconds: job.etaSeconds,
              etaFormatted: job.etaFormatted
            });
            this.persistJob(job);
          }
        }
      });
      }

      if (result.status === 'error') {
        job.status = 'failed';
        job.error = result.error;
        job.completedAt = Date.now();
        this.emitToJob(job, 'error', { error: result.error });
      } else if (result.status === 'interrupted') {
        job.status = 'interrupted';
        job.sessionId = result.sessionId || job.sessionId;
        job.findings = result.findings || [];
        job.summary = result.summary;
        job.completedAt = Date.now();
        this.emitToJob(job, 'interrupted', {
          jobId: job.id,
          sessionId: job.sessionId,
          findings: job.findings,
          summary: job.summary
        });
      } else {
        job.status = 'completed';
        job.sessionId = result.sessionId || job.sessionId;
        job.findings = result.findings || [];
        job.summary = result.summary;
        job.completedAt = Date.now();
        this.emitToJob(job, 'complete', {
          jobId: job.id,
          sessionId: job.sessionId,
          findings: job.findings,
          summary: job.summary
        });
      }
    } catch (err) {
      job.status = 'failed';
      job.error = err.message;
      job.completedAt = Date.now();
      this.emitToJob(job, 'error', { error: err.message });
    } finally {
      if (this.activeJobId === job.id) {
        this.activeJobId = null;
      }
      this.persistJob(job);
    }
  }

  attachSSE(jobId, res, req) {
    const job = this.jobs.get(jobId);
    if (!job) {
      res.status(404).json({ error: 'Scan job not found' });
      return;
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const sendEvent = (event, data) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    // Replay initial status and buffered logs to the newly connected/reconnected client
    sendEvent('status', {
      jobId: job.id,
      status: job.status,
      startTime: job.startTime,
      filesTotal: job.filesTotal,
      filesReviewed: job.filesReviewed,
      sessionId: job.sessionId,
      findingsCount: job.findings.length
    });

    for (const msg of job.logs) {
      sendEvent('log', { message: msg });
    }

    for (const finding of job.findings) {
      sendEvent('finding', { finding });
    }

    if (job.status === 'completed') {
      sendEvent('complete', {
        jobId: job.id,
        sessionId: job.sessionId,
        findings: job.findings,
        summary: job.summary
      });
      res.end();
      return;
    }

    if (job.status === 'failed') {
      sendEvent('error', { error: job.error });
      res.end();
      return;
    }

    // Register active listener
    const listener = (event, data) => {
      sendEvent(event, data);
      if (event === 'complete' || event === 'error' || event === 'interrupted') {
        res.end();
      }
    };

    job.sseListeners.add(listener);

    req.on('close', () => {
      job.sseListeners.delete(listener);
    });
  }
}
