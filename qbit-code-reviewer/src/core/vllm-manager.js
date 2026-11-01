import fs from 'node:fs';
import path from 'node:path';
import { spawn, execSync } from 'node:child_process';
import { config, saveConfig } from './config.js';

const SCRIPT_DIR = path.dirname(new URL(import.meta.url).pathname);
const WORKSPACE_ROOT = path.resolve(SCRIPT_DIR, '../../../');
const MODELS_BASE = process.env.MODELS_DIR || (
  fs.existsSync(path.join(WORKSPACE_ROOT, 'models'))
    ? path.join(WORKSPACE_ROOT, 'models')
    : path.resolve(process.cwd(), 'models')
);
const PORT = parseInt(process.env.VLLM_PORT || '8000', 10);

const standard7bPath = path.join(MODELS_BASE, 'qwen2.5-coder-7b-instruct');
const awq7bPath = path.join(MODELS_BASE, 'qwen2.5-coder-7b-instruct-awq');
const resolved7bPath = fs.existsSync(standard7bPath) ? standard7bPath : awq7bPath;

export const MODEL_PROFILES = {
  '7b': {
    id: '7b',
    name: 'Qwen2.5-Coder-7B-Instruct',
    servedModelName: 'qwen2.5-coder-7b-instruct',
    path: resolved7bPath,
    toolCallParser: 'hermes',
    maxModelLen: 32768,
    gpuMemoryUtilization: 0.85,
    kvCacheDtype: 'auto',
    recommendedConcurrency: 8,
    badge: 'LIGHTWEIGHT RUNNER (8x)',
    description: 'Fast, efficient unquantized 7B coder model with full 32k context.'
  },
  '14b': {
    id: '14b',
    name: 'Qwen2.5-Coder-14B-Instruct',
    servedModelName: 'qwen2.5-coder-14b-instruct',
    path: path.join(MODELS_BASE, 'qwen2.5-coder-14b-instruct'),
    toolCallParser: 'hermes',
    maxModelLen: 32768,
    gpuMemoryUtilization: 0.85,
    kvCacheDtype: 'auto',
    recommendedConcurrency: 8,
    badge: 'FAST BUG HUNTER (8x)',
    description: 'Ultra-low latency, 2x token throughput, 8 concurrent scan workers for fast repository sweeps.'
  },
  '30b': {
    id: '30b',
    name: 'Qwen3-Coder-30B-A3B-Instruct',
    servedModelName: 'qwen3-coder-30b-a3b-instruct',
    path: path.join(MODELS_BASE, 'qwen3-coder-30b-a3b-instruct'),
    toolCallParser: 'qwen3_coder',
    maxModelLen: 32768,
    gpuMemoryUtilization: 0.82,
    kvCacheDtype: 'fp8',
    recommendedConcurrency: 4,
    badge: 'DEEP FIXER & ARCHITECT (4x)',
    description: 'High-reasoning MoE model, optimal for AST-aware patch synthesis and inline code refactoring.'
  }
};

/**
 * Returns available local models and their installation status
 */
export async function getModelStatus() {
  const models = [];
  let activeServedModel = null;
  let isHealthy = false;

  const vllmBase = (process.env.VLLM_URL || config.vllmUrl || `http://127.0.0.1:${PORT}/v1`).replace(/\/v1\/?$/, '');

  try {
    const res = await fetch(`${vllmBase}/v1/models`, { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      const data = await res.json();
      if (data && data.data && data.data.length > 0) {
        activeServedModel = data.data[0].id;
      }
    }
    const healthRes = await fetch(`${vllmBase}/health`, { signal: AbortSignal.timeout(1500) });
    isHealthy = healthRes.ok;
  } catch {}

  for (const [key, profile] of Object.entries(MODEL_PROFILES)) {
    const isDownloaded = fs.existsSync(profile.path) && (
      fs.existsSync(path.join(profile.path, 'config.json')) ||
      fs.existsSync(path.join(profile.path, 'model.safetensors.index.json'))
    );

    const isActive = isHealthy && (
      activeServedModel === profile.servedModelName ||
      (activeServedModel && activeServedModel.includes(key))
    );

    models.push({
      ...profile,
      isDownloaded,
      isActive
    });
  }

  const activeProfile = models.find(m => m.isActive) || models.find(m => m.isDownloaded) || MODEL_PROFILES['7b'];

  return {
    isHealthy,
    activeModelId: activeProfile.id,
    activeServedModel: activeServedModel || activeProfile.servedModelName,
    recommendedConcurrency: activeProfile.recommendedConcurrency,
    models
  };
}

/**
 * Switch vLLM server to the target model variant ('14b' or '30b')
 */
export async function switchModel(variant, onLog = console.log) {
  const profile = MODEL_PROFILES[variant];
  if (!profile) {
    throw new Error(`Unknown model variant: "${variant}". Available variants: 7b, 14b, 30b`);
  }

  if (!fs.existsSync(profile.path)) {
    throw new Error(`Model weights not found at ${profile.path}. Please verify model files.`);
  }

  onLog(`🛑 Stopping active vLLM process on port ${PORT}...`);

  // Kill port 8000 and any lingering vllm server processes
  try {
    execSync(`fuser -k -9 ${PORT}/tcp 2>/dev/null || true`);
    execSync(`pkill -9 -f "vllm serve" 2>/dev/null || true`);
    execSync(`pkill -9 -f "EngineCoreProc" 2>/dev/null || true`);
  } catch {}

  // Allow OS to release sockets and GPU memory
  await new Promise(r => setTimeout(r, 4000));

  onLog(`🚀 Launching vLLM with ${profile.name}...`);
  onLog(`   Weights: ${profile.path}`);
  onLog(`   Served Model: ${profile.servedModelName}`);
  onLog(`   Parser: ${profile.toolCallParser} | Max Len: ${profile.maxModelLen} | KV: ${profile.kvCacheDtype}`);
  onLog(`   Scanner Concurrency: ${profile.recommendedConcurrency} workers`);

  // Launch via clean_and_switch wrapper in screen session
  const logFile = `/tmp/vllm-${variant}.log`;
  const cleanSwitchScript = path.join(WORKSPACE_ROOT, 'scripts', 'clean_and_switch.sh');
  execSync(`screen -dmS vllm_server ${cleanSwitchScript} ${variant}`);

  onLog(`⏳ Waiting for vLLM health check on http://127.0.0.1:${PORT}/health (Log: ${logFile})...`);

  let ready = false;
  for (let i = 1; i <= 50; i++) {
    await new Promise(r => setTimeout(r, 2000));
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/health`, { signal: AbortSignal.timeout(1500) });
      if (res.ok) {
        ready = true;
        break;
      }
    } catch {}
    if (i % 5 === 0) {
      onLog(`   ... still warming up (${i * 2}s elapsed)`);
    }
  }

  if (!ready) {
    throw new Error(`vLLM did not report ready within 100 seconds. Check logs in ${logFile}`);
  }

  // Update persistent qbit config
  saveConfig({
    model: profile.servedModelName,
    activeModelId: profile.id,
    concurrency: profile.recommendedConcurrency
  });

  onLog(`✨ Successfully switched to ${profile.name}! Server is online on port ${PORT}.`);
  return {
    success: true,
    activeModelId: profile.id,
    servedModelName: profile.servedModelName,
    concurrency: profile.recommendedConcurrency
  };
}

