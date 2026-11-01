import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import dotenv from 'dotenv';

// Load .env if present
dotenv.config();

const homeDir = os.homedir();
const configDir = path.join(homeDir, '.qbit');
const configFile = path.join(configDir, 'config.json');

function findBinary(name, searchPaths = []) {
  // Check PATH first
  const envPath = process.env.PATH || '';
  const pathDirs = envPath.split(path.delimiter);
  const allDirs = [...searchPaths, ...pathDirs];

  for (const dir of allDirs) {
    if (!dir) continue;
    const fullPath = path.join(dir, name);
    try {
      if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
        fs.accessSync(fullPath, fs.constants.X_OK);
        return fullPath;
      }
    } catch {}
  }
  return name; // fallback to binary name
}

function loadSavedConfig() {
  try {
    if (fs.existsSync(configFile)) {
      return JSON.parse(fs.readFileSync(configFile, 'utf-8'));
    }
  } catch {}
  return {};
}

const saved = loadSavedConfig();

export const config = {
  vllmUrl: process.env.VLLM_URL || saved.vllmUrl || 'http://127.0.0.1:8000/v1',
  model: process.env.VLLM_MODEL || saved.model || 'qwen2.5-coder-14b-instruct',
  apiKey: process.env.VLLM_API_KEY || saved.apiKey || 'token',
  ocrPath: process.env.OCR_PATH || saved.ocrPath || findBinary('ocr', [
    path.join(homeDir, '.local', 'bin'),
    '/usr/local/bin',
    path.join(homeDir, 'bin')
  ]),
  opencodePath: process.env.OPENCODE_PATH || saved.opencodePath || findBinary('opencode', [
    path.join(homeDir, '.opencode', 'bin'),
    path.join(homeDir, '.local', 'bin'),
    '/usr/local/bin'
  ]),
  port: parseInt(process.env.PORT || saved.port || '5432', 10),
  workspaceRoot: process.cwd()
};

export function saveConfig(newConfig) {
  try {
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    const merged = { ...saved, ...newConfig };
    fs.writeFileSync(configFile, JSON.stringify(merged, null, 2), 'utf-8');
    Object.assign(config, merged);
    return true;
  } catch (err) {
    console.error('Failed to save config:', err.message);
    return false;
  }
}
