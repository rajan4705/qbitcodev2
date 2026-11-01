import fs from 'node:fs';
import path from 'node:path';
import { generateCompletionWithVllm } from './vllm-client.js';
import { config } from './config.js';

/**
 * Checks if a code snippet is a genuine, concrete code patch rather than empty or a comment.
 */
export function isConcretePatch(code) {
  if (!code || typeof code !== 'string') return false;
  const trimmed = code.trim();
  if (trimmed.length < 5) return false;

  // Check if it's purely a single-line or multi-line comment or placeholder
  const withoutComments = trimmed
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*/g, '')
    .replace(/#.*/g, '')
    .trim();

  if (withoutComments.length < 4) return false;

  // Must contain code punctuation (braces, parens, semicolons, operators, assignments)
  const hasCodeMarkers = /[;{}()=+\-*/<>\[\]]/.test(withoutComments);
  return hasCodeMarkers;
}

/**
 * Synthesizes a concrete code patch for a single finding using QbitCode / vLLM.
 */
export async function synthesizePatchForFinding(finding, targetDir = process.cwd()) {
  // If finding already has a verified concrete patch, return early
  if (isConcretePatch(finding.suggestion_code)) {
    return {
      success: true,
      patch: finding.suggestion_code,
      patch_description: finding.patch_description || `Remediation for ${finding.category || 'defect'}: ${(finding.content || '').slice(0, 150)}`
    };
  }

  // Ensure existing_code is loaded from disk if empty
  let existingCode = finding.existing_code || '';
  if (!existingCode && finding.path) {
    try {
      const fullPath = path.isAbsolute(finding.path) ? finding.path : path.join(targetDir, finding.path);
      if (fs.existsSync(fullPath)) {
        const fileContent = fs.readFileSync(fullPath, 'utf8');
        const lines = fileContent.split('\n');
        const start = Math.max(0, (finding.start_line || 1) - 1);
        const end = Math.min(lines.length, (finding.end_line || finding.start_line || 1) + 2);
        existingCode = lines.slice(start, end).join('\n');
        finding.existing_code = existingCode;
      }
    } catch {}
  }

  const prompt = `Target File: ${finding.path}
Line Numbers: ${finding.start_line}-${finding.end_line}
Vulnerability Description: ${finding.content}
Vulnerable Code Block:
\`\`\`
${existingCode || '// Vulnerable section at line ' + finding.start_line}
\`\`\`

Generate the exact corrected replacement code for this block to fix the vulnerability.
Rules:
1. Output valid, complete code that replaces the vulnerable block.
2. DO NOT output conversational chatter or markdown explanations outside the JSON.
3. DO NOT just write comments like "// fix here" or "// add checks". Write the actual code logic.
4. Ensure proper bounds checking, memory management, or error handling.

Respond in this exact JSON structure:
{
  "patch": "<exact replacement code>",
  "patch_description": "<1-2 sentence explanation of the patch>"
}`;

  try {
    const rawResponse = await generateCompletionWithVllm({
      messages: [
        {
          role: 'system',
          content: 'You are QbitCode, an elite autonomous code remediation engine. You output production-ready code patches strictly in valid JSON format.'
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0.1,
      maxTokens: 1024
    });

    // Parse JSON from response (handling optional ```json fences)
    let cleaned = rawResponse.trim();
    if (cleaned.startsWith('```')) {
      cleaned = cleaned.replace(/^```[a-z]*\s*/i, '').replace(/```\s*$/i, '').trim();
    }

    let parsed = null;
    try {
      parsed = JSON.parse(cleaned);
    } catch {
      const match = cleaned.match(/\{[\s\S]*\}/);
      if (match) {
        try {
          parsed = JSON.parse(match[0]);
        } catch {}
      }
    }

    if (parsed && parsed.patch && isConcretePatch(parsed.patch)) {
      finding.suggestion_code = parsed.patch.trim();
      finding.patch_description = parsed.patch_description || `Remediation for ${finding.category || 'defect'}: ${(finding.content || '').slice(0, 150)}`;
      return {
        success: true,
        patch: finding.suggestion_code,
        patch_description: finding.patch_description
      };
    }

    // Fallback if JSON format failed but returned raw code
    if (isConcretePatch(cleaned)) {
      finding.suggestion_code = cleaned;
      finding.patch_description = `Applied security fix for ${(finding.content || '').slice(0, 150)}`;
      return {
        success: true,
        patch: finding.suggestion_code,
        patch_description: finding.patch_description
      };
    }
  } catch (err) {
    console.error(`[Patch Synthesizer] Error synthesizing patch for ${finding.id}:`, err.message);
  }

  return {
    success: false,
    patch: finding.suggestion_code || '',
    patch_description: finding.patch_description || ''
  };
}

/**
 * Synthesizes patches for all findings that are currently missing a concrete patch.
 * Updates ocr_output.json automatically.
 */
export async function synthesizeAllPatches(findings, targetDir = process.cwd(), onProgress = () => {}) {
  let synthesizedCount = 0;
  const total = findings.length;

  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];
    const needed = !isConcretePatch(finding.suggestion_code);
    onProgress(i + 1, total, finding, false, needed);

    if (needed) {
      const res = await synthesizePatchForFinding(finding, targetDir);
      if (res.success) synthesizedCount++;
      onProgress(i + 1, total, finding, true, needed);
    } else {
      onProgress(i + 1, total, finding, true, false);
    }
  }

  // Persist updated findings to ocr_output.json
  try {
    const ocrFile = path.join(targetDir, 'ocr_output.json');
    const dataToSave = {
      status: 'success',
      comments: findings
    };
    fs.writeFileSync(ocrFile, JSON.stringify(dataToSave, null, 2), 'utf8');
  } catch {}

  return {
    findings,
    synthesizedCount
  };
}
