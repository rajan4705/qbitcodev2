import readline from 'node:readline/promises';
import chalk from 'chalk';
import { runScan } from '../core/ocr-runner.js';
import { streamChatWithVllm } from '../core/vllm-client.js';
import { applyFixWithOpenCode } from '../core/opencode-runner.js';
import { config } from '../core/config.js';

export async function handleChat(options) {
  console.log(chalk.cyan.bold('\n💬 Qbit Interactive Code Reviewer Chat Studio'));
  console.log(chalk.dim(`   Powered by local vLLM (${config.model})`));
  console.log(chalk.dim(`   Commands: 'scan', 'findings', 'fix <#>', 'exit'\n`));

  let findings = [];
  try {
    const res = await runScan({});
    if (res.status === 'success') {
      findings = res.findings || [];
    }
  } catch {}

  // Pre-seed context if user specified a finding ID
  let contextFinding = null;
  if (options.finding) {
    const idx = parseInt(options.finding, 10) - 1;
    contextFinding = findings[idx] || null;
    if (contextFinding) {
      console.log(chalk.yellow.bold(`[Active Context: ${contextFinding.path}:${contextFinding.start_line}]`));
      console.log(chalk.dim(`Issue: ${contextFinding.content}\n`));
    }
  }

  const conversationHistory = [];

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  try {
    while (true) {
      const prompt = await rl.question(chalk.bold.magenta('qbit> '));
      const trimmed = prompt.trim();

      if (!trimmed) continue;
      if (trimmed === 'exit' || trimmed === 'quit') {
        console.log(chalk.dim('Exiting Qbit chat. Happy coding!'));
        break;
      }

      if (trimmed === 'findings' || trimmed === 'scan') {
        findings.forEach((f, i) => {
          console.log(`  [#${i + 1}] ${f.severity.toUpperCase()} ${f.path}:${f.start_line} - ${f.content}`);
        });
        console.log();
        continue;
      }

      if (trimmed.startsWith('fix ')) {
        const idStr = trimmed.replace('fix ', '').trim();
        const idx = parseInt(idStr, 10) - 1;
        const target = findings[idx];
        if (!target) {
          console.log(chalk.red(`Finding #${idStr} not found.`));
          continue;
        }

        console.log(chalk.cyan(`\n⚡ Instructing QbitCode to fix finding #${idStr} (${target.path})...`));
        const res = await applyFixWithOpenCode({
          finding: target,
          onLog: (m) => process.stdout.write(chalk.dim(`  ${m}\n`))
        });
        if (res.success) {
          console.log(chalk.green.bold(`✔ Successfully patched ${target.path}\n`));
        } else {
          console.log(chalk.red.bold(`✖ Failed to apply patch: ${res.output}\n`));
        }
        continue;
      }

      // Add to conversation history
      let userMessageContent = trimmed;
      if (contextFinding && conversationHistory.length === 0) {
        userMessageContent = `Regarding this code review finding in ${contextFinding.path}:${contextFinding.start_line}:\nIssue: ${contextFinding.content}\nExisting Code:\n${contextFinding.existing_code}\nSuggested:\n${contextFinding.suggestion_code}\n\nUser Question: ${trimmed}`;
      }

      conversationHistory.push({ role: 'user', content: userMessageContent });

      process.stdout.write(chalk.bold.cyan('\nQbit: '));

      let assistantResponse = '';
      for await (const chunk of streamChatWithVllm({ messages: conversationHistory })) {
        process.stdout.write(chunk);
        assistantResponse += chunk;
      }
      console.log('\n');

      conversationHistory.push({ role: 'assistant', content: assistantResponse });
    }
  } finally {
    rl.close();
  }
}
