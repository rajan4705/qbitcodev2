import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from './config.js';

const EXEMPT_EXTS = new Set([
  '.json', '.md', '.txt', '.svg', '.png', '.jpg', '.pdf', '.yml', '.yaml',
  '.lock', '.ico', '.woff', '.woff2', '.mp3', '.mp4', '.map', '.eot', '.ttf',
  '.git', '.csv', '.tsv', '.log'
]);

const EXEMPT_DIRS = new Set([
  'node_modules', '.git', '.qbit', 'dist', 'build', '.cache',
  'tests', 'test', 'testdata', 'docs', 'doc', 'mocks', 'fixtures', 'benchmarks', 'examples'
]);

/**
 * In-memory tree index of directory and file scan estimates.
 */
class ScanEstimatorService {
  constructor() {
    this.workspaceRoot = '';
    this.dirStats = new Map(); // relPath -> { codeCount, fastCount, uniqueFastCount, totalFiles, fastDurationSec, fullDurationSec, fastEtaFormatted, fullEtaFormatted }
    this.fileStats = new Map(); // relPath -> { codeLines, durationSec, etaFormatted }
    this.isIndexing = false;
    this.lastIndexedAt = 0;
    this.workspaceSummary = null;
  }

  getEfficiencyFactor() {
    // 14b model runs with 8 workers and ~2x token generation speed (~3x overall speedup)
    // 30b model runs with 4 workers
    const is14b = config.model && config.model.includes('14b');
    return is14b ? 0.35 : 1.0;
  }

  formatDuration(seconds) {
    if (seconds < 2) return '< 2s';
    if (seconds < 60) return `~${Math.round(seconds)}s`;
    const mins = Math.round(seconds / 60);
    if (mins < 60) return `~${mins}m`;
    const hours = Math.floor(mins / 60);
    const remMins = mins % 60;
    return remMins > 0 ? `~${hours}h ${remMins}m` : `~${hours}h`;
  }

  startIndexing(workspaceRoot) {
    if (!workspaceRoot || this.isIndexing) return;
    this.workspaceRoot = path.resolve(workspaceRoot);
    this.isIndexing = true;

    // Run indexing asynchronously in background without blocking event loop
    setImmediate(() => {
      try {
        const t0 = Date.now();
        const hashMap = new Map();
        const newDirStats = new Map();
        const newFileStats = new Map();

        const walk = (dir, rel) => {
          let stats = {
            codeCount: 0,
            fastCount: 0,
            uniqueFastCount: 0,
            totalFiles: 0,
            fastDurationSec: 0,
            fullDurationSec: 0,
            fastEtaFormatted: '',
            fullEtaFormatted: ''
          };

          let entries = [];
          try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
          } catch {
            return stats;
          }

          for (const e of entries) {
            if (e.isDirectory()) {
              if (!e.name.startsWith('.') && e.name !== 'node_modules') {
                const subRel = rel ? `${rel}/${e.name}` : e.name;
                const subStats = walk(path.join(dir, e.name), subRel);
                stats.codeCount += subStats.codeCount;
                stats.fastCount += subStats.fastCount;
                stats.uniqueFastCount += subStats.uniqueFastCount;
                stats.totalFiles += subStats.totalFiles;
              }
            } else if (e.isFile()) {
              stats.totalFiles++;
              const ext = path.extname(e.name).toLowerCase();
              const isNonCode = EXEMPT_EXTS.has(ext);

              if (!isNonCode) {
                stats.codeCount++;
                const lowerName = e.name.toLowerCase();
                const isTestOrDoc = lowerName.includes('test') || lowerName.includes('spec') || lowerName.includes('mock');

                // Quick line estimate for individual file
                const fileRel = rel ? `${rel}/${e.name}` : e.name;
                const fileSec = 1.6; // Average per-file LLM AST inspection time with 4 workers
                newFileStats.set(fileRel, {
                  durationSec: fileSec,
                  etaFormatted: this.formatDuration(fileSec),
                  isFastScanCandidate: !isTestOrDoc
                });

                if (!isTestOrDoc) {
                  stats.fastCount++;
                  try {
                    const buf = fs.readFileSync(path.join(dir, e.name));
                    const h = crypto.createHash('sha256').update(buf.slice(0, 16384)).digest('hex');
                    if (!hashMap.has(h)) {
                      hashMap.set(h, true);
                      stats.uniqueFastCount++;
                    }
                  } catch {}
                }
              }
            }
          }

          // Compute duration in seconds based on active model efficiency and concurrency
          const factor = this.getEfficiencyFactor();
          const cachedFiles = Math.max(0, stats.fastCount - stats.uniqueFastCount);
          stats.fastDurationSec = Math.round(((stats.uniqueFastCount * 0.42) + (cachedFiles * 0.01)) * factor);
          stats.fullDurationSec = Math.round(stats.codeCount * 0.45 * factor);

          stats.fastEtaFormatted = this.formatDuration(stats.fastDurationSec);
          stats.fullEtaFormatted = this.formatDuration(stats.fullDurationSec);

          newDirStats.set(rel, stats);
          return stats;
        };

        const rootStats = walk(this.workspaceRoot, '');
        this.dirStats = newDirStats;
        this.fileStats = newFileStats;
        this.lastIndexedAt = Date.now();
        this.workspaceSummary = {
          totalFiles: rootStats.totalFiles,
          codeCount: rootStats.codeCount,
          fastCount: rootStats.fastCount,
          uniqueFastCount: rootStats.uniqueFastCount,
          duplicatesEliminated: rootStats.fastCount - rootStats.uniqueFastCount,
          fastDurationSec: rootStats.fastDurationSec,
          fullDurationSec: rootStats.fullDurationSec,
          fastEtaFormatted: rootStats.fastEtaFormatted,
          fullEtaFormatted: rootStats.fullEtaFormatted,
          indexedInMs: Date.now() - t0
        };
      } catch (err) {
        console.error('[ScanEstimator] Indexing error:', err.message);
      } finally {
        this.isIndexing = false;
      }
    });
  }

  getEstimatesForPath(targetRelPath = '') {
    const norm = (targetRelPath || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    
    // Check if it's a directory
    if (this.dirStats.has(norm)) {
      const stats = this.dirStats.get(norm);
      return {
        isDir: true,
        path: norm,
        codeCount: stats.codeCount,
        fastCount: stats.fastCount,
        uniqueFastCount: stats.uniqueFastCount,
        fastDurationSec: stats.fastDurationSec,
        fullDurationSec: stats.fullDurationSec,
        fastEtaFormatted: stats.fastEtaFormatted,
        fullEtaFormatted: stats.fullEtaFormatted,
        workspaceSummary: this.workspaceSummary
      };
    }

    // Check if it's a file
    if (this.fileStats.has(norm)) {
      const f = this.fileStats.get(norm);
      return {
        isDir: false,
        path: norm,
        fastDurationSec: f.durationSec,
        fullDurationSec: f.durationSec,
        fastEtaFormatted: f.etaFormatted,
        fullEtaFormatted: f.etaFormatted,
        workspaceSummary: this.workspaceSummary
      };
    }

    // Default / loading fallback
    return {
      isDir: true,
      path: norm,
      fastDurationSec: 0,
      fullDurationSec: 0,
      fastEtaFormatted: this.isIndexing ? 'Calculating...' : '~1m',
      fullEtaFormatted: this.isIndexing ? 'Calculating...' : '~3m',
      workspaceSummary: this.workspaceSummary
    };
  }
}

export const scanEstimator = new ScanEstimatorService();

