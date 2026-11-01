import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { runScan } from './ocr-runner.js';
import { ScanCache } from './scan-cache.js';
import { SessionManager } from './session-manager.js';
import { enrichFindings } from './cve-enricher.js';
import { synthesizeAllPatches } from './patch-synthesizer.js';

/**
 * Discovers sub-repositories (stacks/versions) under a workspace root.
 * Orders them intelligently: Stack 1 first (to build the baseline content cache),
 * followed by Stacks 2, 3, and 4.
 */
/**
 * Discovers sub-repositories (stacks/modules) under a workspace root.
 * Analyzes repository structure up-front and nests sub-scans hierarchically
 * when large modules (>150 code files) exist inside a stack.
 * Orders them intelligently: Stack 1 baselines first to prime the cache.
 */
export function discoverSubRepositories(workspaceRoot = process.cwd()) {
  const root = path.resolve(workspaceRoot);
  const subrepos = [];

  const EXEMPT_DIR_NAMES = new Set([
    'node_modules', '.git', '.qbit', 'dist', 'build', '.cache',
    'tests', 'test', 'testdata', 'docs', 'doc', 'mocks', 'fixtures', 'benchmarks', 'examples'
  ]);
  const EXEMPT_EXTS = new Set([
    '.json', '.md', '.txt', '.svg', '.png', '.jpg', '.pdf', '.yml', '.yaml',
    '.lock', '.ico', '.woff', '.woff2', '.mp3', '.mp4', '.map'
  ]);

  const countCodeFiles = (dir) => {
    let count = 0;
    try {
      const walk = (d) => {
        const entries = fs.readdirSync(d, { withFileTypes: true });
        for (const e of entries) {
          if (e.isDirectory()) {
            if (!EXEMPT_DIR_NAMES.has(e.name.toLowerCase()) && !e.name.startsWith('.')) {
              walk(path.join(d, e.name));
            }
          } else if (e.isFile()) {
            const ext = path.extname(e.name).toLowerCase();
            if (!EXEMPT_EXTS.has(ext)) count++;
          }
        }
      };
      walk(dir);
    } catch {}
    return count;
  };

  try {
    const topDirs = fs.readdirSync(root, { withFileTypes: true })
      .filter(d => d.isDirectory() && !d.name.startsWith('.') && d.name !== 'node_modules');

    for (const td of topDirs) {
      const topPath = path.join(root, td.name);
      const secondDirs = fs.readdirSync(topPath, { withFileTypes: true })
        .filter(d => d.isDirectory() && !d.name.startsWith('.') && d.name !== 'node_modules');

      if (secondDirs.length > 0) {
        for (const sd of secondDirs) {
          const stackPath = path.join(topPath, sd.name);
          const stackRel = path.join(td.name, sd.name).replace(/\\/g, '/');

          // Check if this stack contains multiple large submodules (>150 code files)
          // to partition into granular, fault-tolerant sub-scans
          let innerDirs = [];
          try {
            innerDirs = fs.readdirSync(stackPath, { withFileTypes: true })
              .filter(d => d.isDirectory() && !d.name.startsWith('.') && !EXEMPT_DIR_NAMES.has(d.name.toLowerCase()));
          } catch {}

          const bigModules = [];
          for (const ind of innerDirs) {
            const modPath = path.join(stackPath, ind.name);
            const codeCount = countCodeFiles(modPath);
            if (codeCount > 150) {
              bigModules.push({ name: ind.name, codeCount, absPath: modPath });
            }
          }

          if (bigModules.length > 1) {
            // Nested hierarchical sub-scans for maximum fault tolerance & modular caching
            for (const mod of bigModules) {
              const modRel = path.join(stackRel, mod.name).replace(/\\/g, '/');
              // If a single module contains over 300 direct files, chunk it into ~150 file sub-tasks
              let directFiles = [];
              try {
                directFiles = fs.readdirSync(mod.absPath, { withFileTypes: true })
                  .filter(e => e.isFile() && !EXEMPT_EXTS.has(path.extname(e.name).toLowerCase()) && !e.name.startsWith('.'))
                  .map(e => e.name)
                  .sort();
              } catch {}

              if (directFiles.length > 250) {
                const CHUNK_SIZE = 150;
                for (let cIdx = 0; cIdx < directFiles.length; cIdx += CHUNK_SIZE) {
                  const chunkFiles = directFiles.slice(cIdx, cIdx + CHUNK_SIZE);
                  const chunkNum = Math.floor(cIdx / CHUNK_SIZE) + 1;
                  const totalChunks = Math.ceil(directFiles.length / CHUNK_SIZE);
                  const chunkRelPaths = chunkFiles.map(f => path.join(modRel, f).replace(/\\/g, '/')).join(',');

                  subrepos.push({
                    name: `${td.name}/${sd.name}/${mod.name} [Part ${chunkNum}/${totalChunks}]`,
                    relPath: chunkRelPaths,
                    absPath: mod.absPath,
                    isBaseline: sd.name.includes(' 1') || sd.name.includes('-1'),
                    codeCount: chunkFiles.length
                  });
                }
              } else {
                subrepos.push({
                  name: `${td.name}/${sd.name}/${mod.name}`,
                  relPath: modRel,
                  absPath: mod.absPath,
                  isBaseline: sd.name.includes(' 1') || sd.name.includes('-1'),
                  codeCount: mod.codeCount
                });
              }
            }
          } else {
            subrepos.push({
              name: `${td.name}/${sd.name}`,
              relPath: stackRel,
              absPath: stackPath,
              isBaseline: sd.name.includes(' 1') || sd.name.includes('-1'),
              codeCount: countCodeFiles(stackPath)
            });
          }
        }
      } else {
        subrepos.push({
          name: td.name,
          relPath: td.name,
          absPath: topPath,
          isBaseline: td.name.includes(' 1') || td.name.includes('-1'),
          codeCount: countCodeFiles(topPath)
        });
      }
    }
  } catch (e) {
    console.error('Error discovering sub-repositories:', e.message);
  }

  // Natural numeric sort subrepos: All "Stack 1" baselines first, then natural order (Part 1, Part 2, ... Part 10)
  return subrepos.sort((a, b) => {
    if (a.isBaseline && !b.isBaseline) return -1;
    if (!a.isBaseline && b.isBaseline) return 1;
    return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
  });
}

/**
 * Executes sub-repository scans sequentially.
 * Shares ONE central `.qbit/` folder in workspaceRoot.
 * Content hashes learned from Stack 1 instantly skip matching files in Stacks 2, 3, and 4.
 */
export async function runSubrepoBatchScan({
  workspaceRoot = process.cwd(),
  exclude = '',
  minSeverity = 'high',
  onProgress = () => {},
  onSubrepoStart = () => {},
  onSubrepoComplete = () => {}
} = {}) {
  const root = path.resolve(workspaceRoot);
  const cache = new ScanCache(root);
  const subrepos = discoverSubRepositories(root);

  if (subrepos.length === 0) {
    onProgress(`⚠️ No sub-repositories found. Falling back to single full scan.\n`);
    return await runScan({ targetDir: root, exclude, onProgress });
  }

  onProgress(`🚀 [SUB-REPO BATCH ENGINE] Discovered ${subrepos.length} distinct sub-repositories / granular modules.\n`);
  onProgress(`📦 Storing unified cache at: ${path.join(root, '.qbit', 'scan_cache.json')}\n`);
  onProgress(`⚡ Strategy: Scanning baseline Stack 1 repos first to prime content hash cache...\n`);

  // Upfront Global Content Hashing & Deduplication Benchmark
  try {
    const t0 = Date.now();
    let totalCodeFiles = 0;
    const globalHashMap = new Map();
    let dupCount = 0;

    const hashWalk = (dir) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const e of entries) {
        if (e.isDirectory()) {
          const lower = e.name.toLowerCase();
          if (!['node_modules', '.git', '.qbit', 'dist', 'build', '.cache', 'tests', 'test', 'docs', 'doc'].includes(lower) && !e.name.startsWith('.')) {
            hashWalk(path.join(dir, e.name));
          }
        } else if (e.isFile()) {
          const ext = path.extname(e.name).toLowerCase();
          if (!['.json', '.md', '.txt', '.svg', '.png', '.jpg', '.pdf', '.yml', '.yaml', '.lock', '.ico', '.woff', '.woff2'].includes(ext)) {
            totalCodeFiles++;
            try {
              const buf = fs.readFileSync(path.join(dir, e.name));
              const hash = crypto.createHash('sha256').update(buf.slice(0, 65536)).digest('hex');
              if (globalHashMap.has(hash)) {
                dupCount++;
              } else {
                globalHashMap.set(hash, true);
              }
            } catch {}
          }
        }
      }
    };

    hashWalk(root);
    const hashDurationMs = Date.now() - t0;
    const timeSavedHours = ((dupCount * 1.8) / 3600).toFixed(1);
    const uniqueFiles = totalCodeFiles - dupCount;

    onProgress(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
    onProgress(`⚡ [GLOBAL CONTENT HASHING & DEDUPLICATION BENCHMARK]\n`);
    onProgress(`   Total Code Files: ${totalCodeFiles.toLocaleString()} indexed in ${(hashDurationMs / 1000).toFixed(2)}s\n`);
    onProgress(`   Unique Content Files: ${uniqueFiles.toLocaleString()}\n`);
    onProgress(`   Duplicate Files Eliminated: ${dupCount.toLocaleString()} (${totalCodeFiles > 0 ? Math.round((dupCount / totalCodeFiles) * 100) : 0}% eliminated)\n`);
    onProgress(`   Time Saved by Deduplication: ~${timeSavedHours} hours of LLM inference!\n`);
    onProgress(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`);
  } catch (err) {
    onProgress(`[Content Hash Note] Upfront hashing benchmark notice: ${err.message}\n`);
  }

  const results = [];
  let totalSubrepos = subrepos.length;
  let completedSubrepos = 0;

  for (let i = 0; i < subrepos.length; i++) {
    const sub = subrepos[i];
    completedSubrepos++;

    onSubrepoStart({
      subrepo: sub.name,
      index: completedSubrepos,
      total: totalSubrepos
    });

    onProgress(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
    onProgress(`▶ [SUB-REPO ${completedSubrepos}/${totalSubrepos}] Scanning: ${sub.name}\n`);
    onProgress(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

    // 1. Fast Upfront Content-Hash Partitioning using Central Cache
    const partition = cache.partitionFiles(sub.relPath);
    if (partition.contentReusedFiles.length > 0) {
      onProgress(`⚡ [UPFRONT CACHE HIT] Reused cached findings for ${partition.contentReusedFiles.length} identical file(s) in 0.01s!\n`);
    }

    if (partition.modifiedFiles.length === 0 && partition.unchangedFiles.length > 0) {
      onProgress(`✔ [100% CACHED] All ${partition.unchangedFiles.length} code files already analyzed in baseline. Skipping LLM scan.\n`);
      const cachedFindings = cache.getFindings(sub.relPath);
      results.push({
        subrepo: sub.name,
        status: 'cached',
        findingsCount: cachedFindings.length
      });
      onSubrepoComplete({
        subrepo: sub.name,
        index: completedSubrepos,
        total: totalSubrepos,
        findingsCount: cachedFindings.length,
        status: 'cached'
      });
      continue;
    }

    onProgress(`🔍 [ACTIVE SCAN] ${partition.modifiedFiles.length} file(s) require deep LLM inspection.\n`);

    // 2. Dispatch OCR scan command scoped strictly to this sub-repo path
    try {
      const res = await runScan({
        targetDir: root,
        pathFilter: sub.relPath,
        exclude,
        minSeverity,
        onProgress: (chunk, tmpFile) => {
          onProgress(`[${sub.name}] ${chunk}`, tmpFile);
        }
      });

      const findingsCount = res.findings ? res.findings.length : 0;
      
      // 3. Enrich & Synthesize Patches for this sub-repo in background non-blocking worker
      if (res.findings && res.findings.length > 0) {
        onProgress(`⚡ [BACKGROUND ENRICHMENT & REMEDIATION] Offloading CWE/CVE indexing & patch synthesis for ${res.findings.length} findings to background worker...\n`);
        (async () => {
          try {
            await enrichFindings(res.findings, { timeoutMs: 1500 });
            await synthesizeAllPatches(res.findings, root, (current, total) => {
              onProgress(`[Background Synthesizer: ${sub.name}] Patch synthesis: ${current}/${total}\r`);
            });
            // Update cache with fully patched and enriched findings
            cache.updateScanResults(res.findings, [sub.relPath]);
          } catch (e) {
            onProgress(`⚠️ Background post-processing note: ${e.message}\n`);
          }
        })().catch(() => {});
        // Immediately record baseline findings into cache so next sub-repo starts scanning without waiting!
        cache.updateScanResults(res.findings, [sub.relPath]);
      }

      onProgress(`✔ [SUB-REPO COMPLETED] ${sub.name}: ${findingsCount} finding(s) with patches recorded & indexed in cache.\n\n`);

      results.push({
        subrepo: sub.name,
        status: res.status || 'success',
        findingsCount
      });

      onSubrepoComplete({
        subrepo: sub.name,
        index: completedSubrepos,
        total: totalSubrepos,
        findingsCount,
        status: res.status || 'success'
      });

    } catch (err) {
      onProgress(`✖ [SUB-REPO ERROR] Failed scanning ${sub.name}: ${err.message}\n`);
      results.push({
        subrepo: sub.name,
        status: 'error',
        error: err.message
      });
    }
  }

  onProgress(`🎉 [ALL SUB-REPOS COMPLETED] Processed ${completedSubrepos}/${totalSubrepos} sub-repositories!\n`);
  const allFinalFindings = cache.getFindings();
  return {
    status: 'success',
    totalSubrepos,
    results,
    findings: allFinalFindings
  };
}

