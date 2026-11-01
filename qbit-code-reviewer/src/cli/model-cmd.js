import chalk from 'chalk';
import { getModelStatus, switchModel } from '../core/vllm-manager.js';

export async function handleModelList() {
  console.log(chalk.cyan.bold('\n🧠 Local vLLM AI Models Status\n'));
  try {
    const status = await getModelStatus();
    console.log(`Server Status: ${status.isHealthy ? chalk.green('● ONLINE') : chalk.red('○ OFFLINE (port 8000)')}`);
    console.log(`Active Model:  ${chalk.yellow.bold(status.activeServedModel || 'None')}`);
    console.log(`Concurrency:   ${chalk.green.bold(status.recommendedConcurrency)} workers\n`);

    console.log(chalk.bold('Available Model Profiles:'));
    for (const m of status.models) {
      const activeMark = m.isActive ? chalk.green(' [ACTIVE] ') : '          ';
      const downloadedMark = m.isDownloaded ? chalk.green('✓ downloaded') : chalk.red('✗ not found');
      console.log(`\n  ${chalk.cyan.bold(m.id.padEnd(5))} ${activeMark} ${chalk.bold(m.name)}`);
      console.log(`        Tag:         ${chalk.white(m.servedModelName)}`);
      console.log(`        Status:      ${downloadedMark}`);
      console.log(`        Profile:     ${chalk.magenta(m.badge)}`);
      console.log(`        Details:     ${chalk.dim(m.description)}`);
      console.log(`        Location:    ${chalk.dim(m.path)}`);
    }

    console.log(chalk.dim('\nTo switch models, run:'));
    console.log(chalk.cyan('  qbit vllm switch 14b') + chalk.dim('   # Fast Scan & bug hunting (8 workers)'));
    console.log(chalk.cyan('  qbit vllm switch 30b') + chalk.dim('   # Deep fixing & patch synthesis (4 workers)\n'));
  } catch (err) {
    console.error(chalk.red(`Failed to retrieve model status: ${err.message}`));
  }
}

export async function handleModelSwitch(targetVariant) {
  if (!targetVariant) {
    console.log(chalk.yellow('Please specify model variant: 14b or 30b'));
    console.log(chalk.dim('Example: qbit vllm switch 14b'));
    return;
  }

  const variant = targetVariant.toLowerCase().replace(/[^0-9a-z]/g, '');
  console.log(chalk.cyan.bold(`\n⚡ Initiating vLLM switch to ${variant}...`));

  try {
    await switchModel(variant, (msg) => {
      console.log(chalk.cyan(msg));
    });
    console.log(chalk.green.bold(`\n✓ Ready! vLLM is running ${variant} on port 8000.\n`));
  } catch (err) {
    console.error(chalk.red.bold(`\n❌ Failed to switch model: ${err.message}\n`));
    process.exitCode = 1;
  }
}

