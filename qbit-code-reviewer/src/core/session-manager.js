import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { config } from './config.js';
import { normalizeFinding } from './types.js';

const execFileAsync = promisify(execFile);

/**
 * Encodes repository path to match OpenCodeReview convention:
 * e.g., /home/user/repo -> home-user-repo
 */
export function encodeRepoPath(repoDir) {
  let p = path.resolve(repoDir);
  p = p.replace(/^[a-zA-Z]:/, ''); // Strip Windows drive letter
  p = p.replace(/^[\\/]+/, '');   // Strip leading slashes
  return p.replace(/[\\/]/g, '-');
}

/**
 * Gets path to the raw OCR session JSONL file if it exists.
 */
export function getOcrSessionFilePath(repoDir, sessionId) {
  if (!sessionId) return null;
  const home = os.homedir();
  const encoded = encodeRepoPath(repoDir);
  return path.join(home, '.opencodereview', 'sessions', encoded, `${sessionId}.jsonl`);
}

export class SessionManager {
  static getSessionDir(targetDir) {
    return path.join(path.resolve(targetDir), '.qbit');
  }

  static getSessionFile(targetDir) {
    return path.join(this.getSessionDir(targetDir), 'active_session.json');
  }

  /**
   * Retrieves active/interrupted session record from workspace
   */
  static getActiveSession(targetDir = process.cwd()) {
    try {
      const file = this.getSessionFile(targetDir);
      if (fs.existsSync(file)) {
        const raw = fs.readFileSync(file, 'utf8');
        return JSON.parse(raw);
      }
    } catch {}
    return null;
  }

  /**
   * Saves or updates active session record in workspace
   */
  static saveActiveSession(targetDir = process.cwd(), data = {}) {
    try {
      const dir = this.getSessionDir(targetDir);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const existing = this.getActiveSession(targetDir) || {};
      const updated = {
        ...existing,
        ...data,
        targetDir: path.resolve(targetDir),
        lastUpdated: Date.now()
      };
      const tmp = `${this.getSessionFile(targetDir)}.${Date.now()}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(updated, null, 2), 'utf8');
      fs.renameSync(tmp, this.getSessionFile(targetDir));
      return updated;
    } catch {
      return null;
    }
  }

  /**
   * Marks active session as completed
   */
  static markCompleted(targetDir = process.cwd()) {
    try {
      const session = this.getActiveSession(targetDir);
      if (session) {
        session.status = 'completed';
        session.completedAt = Date.now();
        const file = this.getSessionFile(targetDir);
        const tmp = `${file}.${Date.now()}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(session, null, 2), 'utf8');
        fs.renameSync(tmp, file);
      }
    } catch {}
  }

  /**
   * Fetches findings recorded in a session via `ocr session comments` with JSONL fallback
   */
  static async getSessionFindings(targetDir = process.cwd(), sessionId) {
    if (!sessionId) return [];

    // 1. Try OCR binary `ocr session comments <sessionId> --json --repo <targetDir>`
    try {
      const { stdout } = await execFileAsync(config.ocrPath, [
        'session',
        'comments',
        sessionId,
        '--json',
        '--repo',
        path.resolve(targetDir)
      ], { timeout: 10000 });

      if (stdout.trim()) {
        const raw = JSON.parse(stdout);
        if (Array.isArray(raw)) {
          return raw.map((c, i) => normalizeFinding(c, i + 1));
        }
      }
    } catch {}

    // 2. Fallback: Parse the session JSONL file directly
    try {
      const jsonlPath = getOcrSessionFilePath(targetDir, sessionId);
      if (jsonlPath && fs.existsSync(jsonlPath)) {
        const lines = fs.readFileSync(jsonlPath, 'utf8').split('\n');
        const commentsByFingerprint = new Map();

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const rec = JSON.parse(line);
            if (rec.type === 'review_item_done' || rec.type === 'review_item_reused') {
              const file = rec.filePath || rec.newPath || '';
              const comms = Array.isArray(rec.comments) ? rec.comments : [];
              for (const c of comms) {
                if (!c.path) c.path = file;
              }
              const fp = rec.fingerprint || file;
              commentsByFingerprint.set(fp, comms);
            } else if (rec.type === 'review_item_failed') {
              const fp = rec.fingerprint || rec.filePath || '';
              if (fp) commentsByFingerprint.delete(fp);
            }
          } catch {}
        }

        const flattened = [];
        for (const comms of commentsByFingerprint.values()) {
          flattened.push(...comms);
        }
        return flattened.map((c, i) => normalizeFinding(c, i + 1));
      }
    } catch {}

    return [];
  }

  /**
   * Inspects completed files in a session via `ocr session show` with JSONL fallback
   */
  static async getSessionCompletedFiles(targetDir = process.cwd(), sessionId) {
    if (!sessionId) return [];

    // 1. Try OCR binary `ocr session show <sessionId> --json --repo <targetDir>`
    try {
      const { stdout } = await execFileAsync(config.ocrPath, [
        'session',
        'show',
        sessionId,
        '--json',
        '--repo',
        path.resolve(targetDir)
      ], { timeout: 10000 });

      if (stdout.trim()) {
        const parsed = JSON.parse(stdout);
        if (parsed && Array.isArray(parsed.items)) {
          const files = parsed.items
            .filter(item => item.type === 'review_item_done' || item.type === 'review_item_reused')
            .map(item => item.file_path || item.new_path)
            .filter(Boolean);
          if (files.length > 0) return [...new Set(files)];
        }
      }
    } catch {}

    // 2. Fallback: Parse the session JSONL file directly
    try {
      const jsonlPath = getOcrSessionFilePath(targetDir, sessionId);
      if (jsonlPath && fs.existsSync(jsonlPath)) {
        const lines = fs.readFileSync(jsonlPath, 'utf8').split('\n');
        const completed = new Set();

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const rec = JSON.parse(line);
            if (rec.type === 'review_item_done' || rec.type === 'review_item_reused') {
              const f = rec.filePath || rec.newPath;
              if (f) completed.add(f);
            } else if (rec.type === 'review_item_failed') {
              const f = rec.filePath || rec.newPath;
              if (f) completed.delete(f);
            }
          } catch {}
        }
        return Array.from(completed);
      }
    } catch {}

    return [];
  }

  /**
   * Reads scanPaths scope from the session's first JSONL entry or active record
   */
  static getSessionScanScope(targetDir, sessionId) {
    try {
      const active = this.getActiveSession(targetDir);
      if (active && active.sessionId === sessionId && active.pathFilter !== undefined) {
        return active.pathFilter || '';
      }
      const jsonlPath = getOcrSessionFilePath(targetDir, sessionId);
      if (jsonlPath && fs.existsSync(jsonlPath)) {
        const firstLine = fs.readFileSync(jsonlPath, 'utf8').split('\n')[0];
        if (firstLine && firstLine.trim()) {
          const parsed = JSON.parse(firstLine);
          if (Array.isArray(parsed.scanPaths)) {
            return parsed.scanPaths.filter(Boolean).join(',');
          }
        }
      }
    } catch {}
    return null;
  }

  /**
   * Finds a session that can be resumed for this repository and subcommand.
   * Returns { sessionId, completedFiles, fromActiveRecord } or null if none available.
   */
  static async findResumableSession(targetDir = process.cwd(), subcommand = 'scan', pathFilter = '') {
    const absDir = path.resolve(targetDir);
    const normalizedTargetScope = (pathFilter || '').trim().replace(/^\.\/?/, '');

    // 1. Check workspace active_session.json
    const active = this.getActiveSession(absDir);
    if (active && active.sessionId && active.status !== 'completed') {
      const sessionScope = this.getSessionScanScope(absDir, active.sessionId);
      const isScopeMatch = sessionScope === null || 
                           sessionScope === normalizedTargetScope ||
                           (sessionScope === '' && normalizedTargetScope === '') ||
                           (sessionScope === '.' && normalizedTargetScope === '') ||
                           (sessionScope === '' && normalizedTargetScope === '.');

      if (isScopeMatch) {
        const completedFiles = await this.getSessionCompletedFiles(absDir, active.sessionId);
        if (completedFiles.length > 0) {
          return {
            sessionId: active.sessionId,
            completedFiles,
            fromActiveRecord: true
          };
        }
      }
    }

    // 2. Fallback to `ocr session list --json --repo <targetDir>`
    try {
      const { stdout } = await execFileAsync(config.ocrPath, [
        'session',
        'list',
        '--json',
        '--repo',
        absDir,
        '--limit',
        '10'
      ], { timeout: 10000 });

      if (stdout.trim()) {
        const sessions = JSON.parse(stdout);
        if (Array.isArray(sessions)) {
          for (const s of sessions) {
            // Find an aborted session with completed files matching the mode
            if (s.aborted && s.completed_files > 0) {
              const mode = subcommand === 'scan' ? 'full_scan' : subcommand;
              if (!s.review_mode || s.review_mode === mode) {
                const sessionScope = this.getSessionScanScope(absDir, s.session_id);
                const isScopeMatch = sessionScope === null || 
                                     sessionScope === normalizedTargetScope ||
                                     (sessionScope === '' && normalizedTargetScope === '') ||
                                     (sessionScope === '.' && normalizedTargetScope === '') ||
                                     (sessionScope === '' && normalizedTargetScope === '.');
                if (!isScopeMatch) continue;

                const completedFiles = await this.getSessionCompletedFiles(absDir, s.session_id);
                if (completedFiles.length > 0) {
                  return {
                    sessionId: s.session_id,
                    completedFiles,
                    fromActiveRecord: false
                  };
                }
              }
            }
          }
        }
      }
    } catch {}

    return null;
  }
}
