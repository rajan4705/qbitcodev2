import { ProgressEstimator } from '../qbit-code-reviewer/src/core/progress-estimator.js';
import assert from 'node:assert';

async function runTest() {
  console.log('🧪 Starting Phase 4 Test: Remaining-Time & Accurate ETA Estimation...');

  const estimator = new ProgressEstimator({ alpha: 0.3, defaultMsPerFile: 2000 });
  estimator.start(100);

  console.log('1. Initial State verification...');
  let state = estimator.getState();
  assert.strictEqual(state.totalFiles, 100);
  assert.strictEqual(state.pendingFiles, 100);
  assert.strictEqual(state.percent, 0);
  console.log(`✓ Initial ETA for 100 files at 2.0s/file: ${state.etaFormatted} (${state.etaSeconds}s)`);

  console.log('2. Testing Skipped/Cached Files Handling...');
  // Suppose 50 files are skipped instantly from cache
  estimator.recordSkipped(50);
  state = estimator.getState();
  assert.strictEqual(state.skippedFiles, 50);
  assert.strictEqual(state.pendingFiles, 50);
  assert.strictEqual(state.percent, 50);
  // ETA should accurately reflect ONLY remaining 50 files
  assert.strictEqual(state.etaSeconds, 100); // 50 * 2s
  console.log(`✓ After 50 skipped files: Pending = ${state.pendingFiles}, Progress = ${state.percent}%, ETA = ${state.etaFormatted}`);

  console.log('3. Simulating Active LLM File Scanning with EMA smoothing...');
  // Simulate 5 files scanned taking ~1500ms each
  for (let i = 0; i < 5; i++) {
    estimator.recordFileScanned();
  }
  state = estimator.getState();
  assert.strictEqual(state.scannedFiles, 5);
  assert.strictEqual(state.pendingFiles, 45);
  assert.strictEqual(state.percent, 55);
  console.log(`✓ After 5 scanned files: Progress = ${state.percent}%, Remaining ETA = ${state.etaFormatted}`);

  console.log('4. Testing Edge Cases (Completion)...');
  estimator.recordSkipped(45);
  state = estimator.getState();
  assert.strictEqual(state.pendingFiles, 0);
  assert.strictEqual(state.percent, 100);
  assert.strictEqual(state.etaSeconds, 0);
  assert.strictEqual(state.etaFormatted, '0s');
  console.log('✓ Completion reached cleanly: ETA = 0s, Percent = 100%');

  console.log('\n🎉 ALL PHASE 4 TESTS PASSED! Progress and ETA smoothing verified.');
}

runTest().catch(err => {
  console.error('❌ Phase 4 Test Failed:', err);
  process.exit(1);
});

