import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';
import { generateCompletionWithVllm } from './vllm-client.js';

/**
 * Builds the remediation prompt for OpenCode
 */
export function buildRemediationPrompt(finding, customInstruction = '') {
  return `You are fixing a verified code defect.
Target File: ${finding.path}
Lines Affected: ${finding.start_line}-${finding.end_line}
Severity: ${finding.severity.toUpperCase()}
Category: ${finding.category}
Issue: ${finding.content}

Existing Code:
\`\`\`
${finding.existing_code}
\`\`\`

Recommended Solution:
\`\`\`
${finding.suggestion_code}
\`\`\`

${customInstruction ? `User Instructions: ${customInstruction}\n` : ''}
Please update ${finding.path} to apply this fix properly. Ensure code formatting, proper imports, and no regressions.`;
}

/**
 * Invokes OpenCode to fix a specific finding
 */
/**
 * Invokes remediation: tries direct match first, then OpenCode, and falls back to vLLM-guided patch
 */
export async function applyFixWithOpenCode({
  finding,
  customInstruction = '',
  targetDir = process.cwd(),
  onLog = () => {}
}) {
  const fullPath = path.isAbsolute(finding.path) ? finding.path : path.join(targetDir, finding.path);

  // 1. Fast Path: If suggestion_code exists and matches or fuzzy matches existing_code, patch directly!
  if (finding.suggestion_code && fs.existsSync(fullPath)) {
    onLog(`[Remediation] Checking direct code match in ${path.basename(fullPath)}...`);
    const directRes = applyDirectPatchFallback(fullPath, finding, onLog);
    if (directRes.success) {
      return {
        success: true,
        mode: 'direct_ast',
        output: directRes.message,
        findingId: finding.id
      };
    }
  }

  // 2. Secondary Path: If QbitCode is installed and accessible, run qbitcode with a clean prompt
  const prompt = buildRemediationPrompt(finding, customInstruction);
  onLog(`[Remediation] Dispatching remediation prompt for ${finding.path} (Severity: ${finding.severity})...`);

  let opencodeSuccess = false;
  let opencodeOutput = '';

  try {
    const env = {
      ...process.env,
      PATH: `${path.dirname(config.opencodePath)}:${process.env.PATH || ''}`
    };

    const runResult = await new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      const proc = spawn(config.opencodePath, ['run', '--auto', prompt], {
        cwd: targetDir,
        env
      });

      const timer = setTimeout(() => {
        timedOut = true;
        onLog('[Remediation] QbitCode execution window reached (15s). Synthesizing patch with local vLLM...');
        try { proc.kill('SIGTERM'); } catch {}
      }, 15000);

      proc.stdout.on('data', (d) => {
        const text = d.toString();
        stdout += text;
        onLog(text);
      });

      proc.stderr.on('data', (d) => {
        const text = d.toString();
        stderr += text;
        onLog(`[err] ${text}`);
      });

      proc.on('error', (err) => {
        clearTimeout(timer);
        resolve({ success: false, output: err.message });
      });

      proc.on('close', (code) => {
        clearTimeout(timer);
        resolve({
          success: code === 0 && !timedOut,
          output: stdout || stderr
        });
      });
    });

    opencodeSuccess = runResult.success;
    opencodeOutput = runResult.output;
  } catch (err) {
    onLog(`[Remediation] QbitCode runner error: ${err.message}`);
  }

  if (opencodeSuccess) {
    onLog(`[Remediation] Successfully patched ${finding.path}`);
    return {
      success: true,
      mode: 'qbitcode',
      output: opencodeOutput,
      findingId: finding.id
    };
  }

  // 3. Fallback: If OpenCode failed or timed out and no verified replacement snippet was provided, report clean failure
  onLog(`[Remediation] Remediation agent could not synthesize a verifiable patch for ${finding.path}.`);
  return {
    success: false,
    mode: 'failed',
    output: opencodeOutput || 'Remediation failed: OpenCode timed out or could not produce a verified patch. Source file untouched.',
    findingId: finding.id
  };
}

/**
 * Direct patch fallback: Safely applies suggestion_code to file with exact or whitespace-normalized matching
 */
function applyDirectPatchFallback(fullPath, finding, onLog) {
  try {
    if (!fs.existsSync(fullPath)) {
      onLog(`[Patch] Target file not found at ${fullPath}`);
      return { success: false, message: `File not found: ${fullPath}` };
    }

    if (!finding.existing_code || !finding.suggestion_code) {
      return { success: false, message: 'No concrete code replacement provided.' };
    }

    const content = fs.readFileSync(fullPath, 'utf-8');

    // 1. Direct match
    if (content.includes(finding.existing_code)) {
      const updated = content.replace(finding.existing_code, finding.suggestion_code);
      fs.writeFileSync(fullPath, updated, 'utf-8');
      onLog(`[Patch] Successfully replaced target code block in ${path.basename(fullPath)}`);
      return { success: true, message: 'Direct patch applied successfully.' };
    }

    // 2. Line-trimmed match
    const existingLines = finding.existing_code.split('\n').map(l => l.trim()).filter(Boolean);
    const fileLines = content.split('\n');

    if (existingLines.length > 0) {
      for (let i = 0; i < fileLines.length; i++) {
        if (fileLines[i].trim() === existingLines[0]) {
          let match = true;
          for (let j = 1; j < existingLines.length; j++) {
            if (!fileLines[i + j] || fileLines[i + j].trim() !== existingLines[j]) {
              match = false;
              break;
            }
          }
          if (match) {
            // Replace lines i through i + existingLines.length
            fileLines.splice(i, existingLines.length, finding.suggestion_code);
            fs.writeFileSync(fullPath, fileLines.join('\n'), 'utf-8');
            onLog(`[Patch] Successfully replaced target code block via line alignment in ${path.basename(fullPath)}`);
            return { success: true, message: 'Patch applied via line alignment.' };
          }
        }
      }
    }

    return {
      success: false,
      message: 'Existing code block did not match file content directly.'
    };
  } catch (err) {
    onLog(`[Patch Error] ${err.message}`);
    return { success: false, message: err.message };
  }
}
