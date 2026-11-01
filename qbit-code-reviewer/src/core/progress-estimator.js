/**
 * ProgressEstimator calculates smoothed scan completion rates and ETAs.
 * 
 * Key Principles:
 * 1. Distinguishes between scanned (active LLM review), skipped (cached/ignored), and pending files.
 * 2. Uses Exponential Moving Average (EMA) exclusively on active files to prevent skipped files
 *    from causing artificial drops to 0 seconds.
 * 3. Handles startup discovery overhead and caps rate outliers.
 */
export class ProgressEstimator {
  constructor(options = {}) {
    this.alpha = options.alpha || 0.25; // EMA smoothing factor (0 < alpha <= 1)
    this.defaultMsPerFile = options.defaultMsPerFile || 2400; // default ~2.4s per file with 4 workers
    this.minSamplesForEma = options.minSamplesForEma || 3;
    
    this.reset();
  }

  reset() {
    this.totalFiles = 0;
    this.scannedFiles = 0;
    this.skippedFiles = 0;
    this.startTime = null;
    this.lastFileTimestamp = null;
    this.emaMsPerFile = this.defaultMsPerFile;
    this.activeSamplesCount = 0;
  }

  start(totalFiles = 0) {
    this.reset();
    this.totalFiles = totalFiles;
    this.startTime = Date.now();
    this.lastFileTimestamp = this.startTime;
  }

  setTotalFiles(total) {
    if (total > this.totalFiles) {
      this.totalFiles = total;
    }
  }

  recordSkipped(count = 1) {
    this.skippedFiles += count;
  }

  recordFileScanned() {
    const now = Date.now();
    this.scannedFiles++;

    if (this.lastFileTimestamp) {
      const deltaMs = now - this.lastFileTimestamp;
      // Filter out instant/cached returns (< 250ms) from active LLM processing rate
      if (deltaMs >= 250 && deltaMs <= 60000) {
        this.activeSamplesCount++;
        if (this.activeSamplesCount === 1) {
          this.emaMsPerFile = deltaMs;
        } else {
          this.emaMsPerFile = (this.alpha * deltaMs) + ((1 - this.alpha) * this.emaMsPerFile);
        }
      }
    }
    this.lastFileTimestamp = now;
  }

  getPendingFiles() {
    return Math.max(0, this.totalFiles - (this.scannedFiles + this.skippedFiles));
  }

  getPercent() {
    if (this.totalFiles <= 0) return 0;
    const processed = this.scannedFiles + this.skippedFiles;
    return Math.min(100, Math.round((processed / this.totalFiles) * 100));
  }

  getEtaSeconds() {
    const pending = this.getPendingFiles();
    if (pending === 0) return 0;

    const msPerFile = this.activeSamplesCount >= this.minSamplesForEma
      ? this.emaMsPerFile
      : this.defaultMsPerFile;

    const totalMs = pending * msPerFile;
    return Math.max(1, Math.round(totalMs / 1000));
  }

  formatEta() {
    const sec = this.getEtaSeconds();
    if (sec <= 0) return '0s';
    if (sec < 60) return `${sec}s`;
    
    const totalMin = Math.round(sec / 60);
    if (totalMin < 60) return `${totalMin}m`;

    const hrs = Math.floor(totalMin / 60);
    const mins = totalMin % 60;
    return `${hrs}h ${mins}m`;
  }

  getState() {
    return {
      totalFiles: this.totalFiles,
      scannedFiles: this.scannedFiles,
      skippedFiles: this.skippedFiles,
      pendingFiles: this.getPendingFiles(),
      percent: this.getPercent(),
      etaSeconds: this.getEtaSeconds(),
      etaFormatted: this.formatEta(),
      rateMsPerFile: Math.round(this.emaMsPerFile)
    };
  }
}

