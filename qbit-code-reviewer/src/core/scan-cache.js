import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * ScanCache manages deterministic caching of scan results across both CLI and Web UI.
 * Stored at `.qbit/scan_cache.json` relative to target repository/workspace.
 */
export class ScanCache {
  constructor(workspaceDir = process.cwd()) {
    this.workspaceDir = workspaceDir;
    this.cacheDir = path.join(this.workspaceDir, '.qbit');
    this.cacheFile = path.join(this.cacheDir, 'scan_cache.json');
    this.data = {
      version: 1,
      engine: 'ocr',
      lastUpdated: 0,
      files: {},         // relativePath -> { hash, size, mtimeMs, scannedAt }
      contentHashes: {}, // sha256 -> Array of normalized findings (path-independent templates)
      dirHashes: {},     // relativeDir -> compositeHash
      findings: {}       // findingId -> normalizedFinding
    };
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.cacheFile)) {
        const raw = fs.readFileSync(this.cacheFile, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && parsed.version === 1) {
          this.data = {
            ...this.data,
            ...parsed,
            files: parsed.files || {},
            contentHashes: parsed.contentHashes || {},
            dirHashes: parsed.dirHashes || {},
            findings: parsed.findings || {}
          };
        }
      }
    } catch (e) {
      // If corrupted, fallback to clean state
    }
  }

  save() {
    try {
      if (!fs.existsSync(this.cacheDir)) {
        fs.mkdirSync(this.cacheDir, { recursive: true });
      }
      this.data.lastUpdated = Date.now();
      const tmp = `${this.cacheFile}.${Date.now()}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2), 'utf8');
      fs.renameSync(tmp, this.cacheFile);
    } catch (e) {
      // Graceful degradation if filesystem is read-only
    }
  }

  /**
   * Calculates sha256 hash of a file
   */
  getFileHash(filePath) {
    try {
      const buf = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(buf).digest('hex');
    } catch {
      return null;
    }
  }

  static computeFindingId(relPath, finding) {
    const rawKey = `${relPath}:${finding.start_line || 0}:${finding.cwe_id || finding.category || ''}:${(finding.content || '').slice(0, 100)}`;
    return `QBIT-${crypto.createHash('md5').update(rawKey).digest('hex').slice(0, 10)}`;
  }
  normalizeRelPath(targetPath) {
    let rel = path.isAbsolute(targetPath)
      ? path.relative(this.workspaceDir, targetPath)
      : targetPath;
    rel = rel.replace(/\\/g, '/');
    if (rel.startsWith('./')) rel = rel.slice(2);
    return rel;
  }

  /**
   * Fast check using mtime and file size before hashing
   */
  isUpToDate(relPath, absPath) {
    const cached = this.data.files[relPath];
    if (!cached) return false;

    try {
      const stat = fs.statSync(absPath);
      // Fast path: file size and mtime are identical
      if (stat.size === cached.size && Math.floor(stat.mtimeMs) === Math.floor(cached.mtimeMs)) {
        return true;
      }
      // Secondary check: if mtime touched but content identical
      const currentHash = this.getFileHash(absPath);
      if (currentHash && currentHash === cached.hash) {
        // Update mtime so fast-path works next time
        cached.mtimeMs = stat.mtimeMs;
        cached.size = stat.size;
        return true;
      }
    } catch {
      return false;
    }
    return false;
  }

  /**
   * Evaluates directory or target files to partition into unchanged vs modified
   * @param {string} targetScope Directory or file path filter
   * @returns {{ unchangedFiles: string[], modifiedFiles: string[], deletedFiles: string[] }}
   */
  partitionFiles(targetScope = '') {
    const normalizedScope = this.normalizeRelPath(targetScope);
    const scopeDir = path.resolve(this.workspaceDir, normalizedScope || '.');

    const discoveredFiles = [];
    const walk = (dir) => {
      if (!fs.existsSync(dir)) return;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        const rel = this.normalizeRelPath(full);

        // Skip ignored directories
        if (
          entry.isDirectory() &&
          ['node_modules', '.git', '.qbit', 'dist', 'build', '.cache'].includes(entry.name)
        ) {
          continue;
        }

        if (entry.isDirectory()) {
          walk(full);
        } else if (entry.isFile()) {
          discoveredFiles.push({ rel, full });
        }
      }
    };

    if (fs.existsSync(scopeDir)) {
      const stat = fs.statSync(scopeDir);
      if (stat.isFile()) {
        discoveredFiles.push({
          rel: this.normalizeRelPath(scopeDir),
          full: scopeDir
        });
      } else {
        walk(scopeDir);
      }
    }

    const unchangedFiles = [];
    const modifiedFiles = [];
    const contentReusedFiles = [];
    const discoveredRelSet = new Set(discoveredFiles.map(d => d.rel));

    for (const { rel, full } of discoveredFiles) {
      if (this.isUpToDate(rel, full)) {
        unchangedFiles.push(rel);
      } else {
        // Check if file content hash is already known from any other folder/version
        const fileHash = this.getFileHash(full);
        if (fileHash && this.data.contentHashes[fileHash] !== undefined) {
          // Content hash match! Adopt the findings for this new path
          this.adoptFindingsFromContentHash(rel, full, fileHash);
          unchangedFiles.push(rel);
          contentReusedFiles.push(rel);
        } else {
          modifiedFiles.push(rel);
        }
      }
    }

    if (contentReusedFiles.length > 0) {
      this.save();
    }

    // Check for deleted files within scope
    const deletedFiles = [];
    for (const cachedRel of Object.keys(this.data.files)) {
      if (
        (!normalizedScope || cachedRel === normalizedScope || cachedRel.startsWith(normalizedScope + '/')) &&
        !discoveredRelSet.has(cachedRel)
      ) {
        deletedFiles.push(cachedRel);
      }
    }

    return { unchangedFiles, modifiedFiles, deletedFiles, contentReusedFiles };
  }

  /**
   * Clones findings previously discovered for an identical content hash to a new path
   */
  adoptFindingsFromContentHash(relPath, absPath, fileHash) {
    try {
      const stat = fs.statSync(absPath);
      this.data.files[relPath] = {
        hash: fileHash,
        size: stat.size,
        mtimeMs: stat.mtimeMs,
        scannedAt: Date.now()
      };

      const templates = this.data.contentHashes[fileHash] || [];
      for (const t of templates) {
        const id = ScanCache.computeFindingId(relPath, t);
        this.data.findings[id] = {
          ...t,
          id,
          path: relPath,
          status: 'open'
        };
      }
    } catch {}
  }

  /**
   * Gets cached findings, optionally filtered by scope and status
   */
  getFindings(targetScope = '', includeResolved = false) {
    const normalizedScope = this.normalizeRelPath(targetScope);
    const results = [];

    for (const f of Object.values(this.data.findings)) {
      const fPath = this.normalizeRelPath(f.path || '');
      if (normalizedScope && fPath !== normalizedScope && !fPath.startsWith(normalizedScope + '/')) {
        continue;
      }
      if (!includeResolved && f.status === 'fixed') {
        continue;
      }
      results.push(f);
    }
    return results;
  }

  /**
   * Record scan findings and update cached state for scanned files
   * @param {Array} newFindings Findings returned from the scanner
   * @param {string[]} scannedFiles List of relative paths scanned
   */
  updateScanResults(newFindings = [], scannedFiles = []) {
    const scannedSet = new Set(scannedFiles.map(p => this.normalizeRelPath(p)));

    // 1. For each scanned file, update file hash & metadata
    for (const rel of scannedSet) {
      const absPath = path.resolve(this.workspaceDir, rel);
      if (fs.existsSync(absPath)) {
        const stat = fs.statSync(absPath);
        this.data.files[rel] = {
          hash: this.getFileHash(absPath),
          size: stat.size,
          mtimeMs: stat.mtimeMs,
          scannedAt: Date.now()
        };
      } else {
        delete this.data.files[rel];
      }

      // Mark old findings for this file as fixed if they are no longer in newFindings
      for (const [id, finding] of Object.entries(this.data.findings)) {
        if (this.normalizeRelPath(finding.path) === rel) {
          // If not in newFindings, mark resolved
          const stillPresent = newFindings.some(nf => 
            this.normalizeRelPath(nf.path) === rel &&
            (nf.id === id || (nf.cwe_id === finding.cwe_id && nf.category === finding.category))
          );
          if (!stillPresent) {
            finding.status = 'fixed';
            finding.fixedAt = Date.now();
          }
        }
      }
    }

    // 2. Insert or update new findings and group by contentHash
    for (const nf of newFindings) {
      const rel = this.normalizeRelPath(nf.path);
      const id = ScanCache.computeFindingId(rel, nf);
      this.data.findings[id] = {
        ...nf,
        id,
        path: rel,
        status: nf.status || 'open'
      };
    }

    // 3. Populate contentHashes map for cross-directory/version deduplication
    for (const rel of scannedSet) {
      const fileEntry = this.data.files[rel];
      if (fileEntry && fileEntry.hash) {
        // Collect all findings belonging to this file as path-relative templates
        const fileFindings = Object.values(this.data.findings)
          .filter(f => this.normalizeRelPath(f.path) === rel && f.status !== 'fixed')
          .map(f => ({
            severity: f.severity,
            category: f.category,
            start_line: f.start_line,
            end_line: f.end_line,
            content: f.content,
            cwe_id: f.cwe_id,
            cwe_title: f.cwe_title,
            cve_id: f.cve_id,
            cve_severity: f.cve_severity,
            ref_cwe_id: f.ref_cwe_id,
            ref_cve_id: f.ref_cve_id,
            suggestion: f.suggestion,
            suggestion_code: f.suggestion_code,
            patch_description: f.patch_description,
            existing_code: f.existing_code
          }));

        this.data.contentHashes[fileEntry.hash] = fileFindings;
      }
    }

    this.save();
  }

  /**
   * Purge deleted files and their findings
   */
  removeDeletedFiles(deletedFiles = []) {
    if (!deletedFiles.length) return;
    for (const rel of deletedFiles) {
      delete this.data.files[rel];
      for (const [id, finding] of Object.entries(this.data.findings)) {
        if (this.normalizeRelPath(finding.path) === rel) {
          delete this.data.findings[id];
        }
      }
    }
    this.save();
  }

  /**
   * Explicitly mark a finding as fixed (e.g. after patch application)
   */
  markFixed(findingId) {
    if (this.data.findings[findingId]) {
      this.data.findings[findingId].status = 'fixed';
      this.data.findings[findingId].fixedAt = Date.now();
      this.save();
      return true;
    }
    return false;
  }
}
