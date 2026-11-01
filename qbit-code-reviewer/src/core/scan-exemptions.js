import fs from 'node:fs';
import path from 'node:path';
import chalk from 'chalk';

export const FOLDER_EXEMPTION_RULES = [
  {
    category: 'DEPENDENCY',
    label: 'Dependencies',
    reason: 'Third-party packages and external dependencies',
    match: (name) => [
      'node_modules', 'vendor', 'bower_components', 'Pods', 'Carthage', 
      '.pnpm-store', '.yarn', 'oh_modules', '.bundle'
    ].includes(name)
  },
  {
    category: 'BUILD',
    label: 'Build Artifacts',
    reason: 'Compiled binaries, bundles, Gradle/Maven/Cargo outputs',
    match: (name) => [
      'dist', 'build', 'out', 'target', 'bin', 'obj', '.gradle', '.cxx',
      '.externalNativeBuild', '.next', '.nuxt', '.svelte-kit', '.astro', 
      '.turbo', '.angular', '.parcel-cache', '.docusaurus', 'coverage', 
      '.output', 'storybook-static', 'DerivedData', '.build', '.swiftpm'
    ].includes(name)
  },
  {
    category: 'VCS',
    label: 'Version Control',
    reason: 'Version control internals and git hooks',
    match: (name) => ['.git', '.svn', '.hg', '.husky'].includes(name)
  },
  {
    category: 'VIRTUALENV_CACHE',
    label: 'Virtualenvs & Caches',
    reason: 'Python virtualenvs, runtime execution caches, and IDE metadata',
    match: (name) => [
      'venv', '.venv', 'env', '__pycache__', '.pytest_cache', '.mypy_cache', 
      '.ruff_cache', '.tox', '.nox', '.cache', '.npm', '.eslintcache', 
      '.stylelintcache', '.phpunit.result.cache', '.sts4-cache', '.kotlin'
    ].includes(name) || name.endsWith('.egg-info')
  },
  {
    category: 'IDE',
    label: 'IDE Configuration',
    reason: 'Editor workspace metadata and local settings',
    match: (name) => ['.vscode', '.idea', '.zed', '.fleet', '.eclipse', '.settings'].includes(name)
  },
  {
    category: 'TEMP_LOGS',
    label: 'Temp & Logs',
    reason: 'Temporary scratch files and system logs',
    match: (name) => ['tmp', 'temp', 'logs', '.temp', 'captures'].includes(name)
  },
  {
    category: 'TEST_SUITES',
    label: 'Tests & Fixtures',
    reason: 'Unit/integration test suites, fixtures, test data, mocks, and screenshot tests',
    match: (name) => {
      const lower = name.toLowerCase();
      return [
        'tests', 'test', 'testsuite', 'language-tests', 'commontest',
        'screenshot-tests', 'screenshottestdebug', 'scaletest', 'niohttp2tests',
        'testdata', 'fixtures', '__snapshots__', 'mocks', 'mock', 'test_fixtures',
        'hpack-test-case', 'benches', 'benchmarks', 'e2e', 'cypress'
      ].includes(lower);
    }
  },
  {
    category: 'DOCS_SAMPLES',
    label: 'Docs & Examples',
    reason: 'Documentation, specs, and example demonstration code',
    match: (name) => {
      const lower = name.toLowerCase();
      return ['docs', 'doc', 'example', 'examples', 'sample', 'samples', 'specs', '.specify'].includes(lower);
    }
  }
];

export const FILE_EXTENSIONS_EXEMPT = {
  MEDIA: {
    label: 'Media Assets',
    reason: 'Non-executable images, videos, and audio assets',
    exts: ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.mp3', '.wav', '.ogg', '.mp4', '.mov', '.avi', '.webm']
  },
  ARCHIVE: {
    label: 'Compressed Archives',
    reason: 'Binary archive containers and zip packages',
    exts: ['.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.iso']
  },
  BINARY_LIB: {
    label: 'Compiled Binaries & Packages',
    reason: 'Pre-compiled machine code, packages, keystores, and shared objects',
    exts: ['.o', '.a', '.so', '.dylib', '.dll', '.exe', '.bin', '.class', '.pyc', '.pyo', '.pyd', '.wasm', '.apk', '.aab', '.dex', '.jks', '.keystore']
  },
  FONT: {
    label: 'Fonts & Typography',
    reason: 'Static font assets',
    exts: ['.ttf', '.otf', '.woff', '.woff2', '.eot']
  },
  DOCUMENT_DATA: {
    label: 'Docs, Queries & Snapshots',
    reason: 'Markdown documentation, golden test files, query scripts, and text files',
    exts: ['.pdf', '.psd', '.ai', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.md', '.golden', '.surql', '.txt']
  },
  DATABASE_MODEL: {
    label: 'Databases & ML Weights',
    reason: 'Database tables and neural network weight binaries',
    exts: ['.db', '.sqlite', '.sqlite3', '.onnx', '.pt', '.safetensors', '.h5', '.ckpt']
  }
};

export const LOCK_FILES = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'bun.lock',
  'bun.lockb',
  'Cargo.lock',
  'poetry.lock',
  'composer.lock',
  'Gemfile.lock',
  'flake.lock',
  'Podfile.lock'
]);

export const SOURCE_CODE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hxx',
  '.go', '.rs', '.py', '.java', '.kt', '.kts', '.scala',
  '.cs', '.php', '.rb', '.swift', '.sh', '.bash', '.zsh',
  '.sql', '.html', '.css', '.vue', '.svelte'
]);

/**
 * Counts total files and size in a directory (shallow or safe bounded).
 */
function inspectFolderStats(dirPath, maxFiles = 500) {
  let fileCount = 0;
  let totalBytes = 0;

  function walk(current) {
    if (fileCount >= maxFiles) return;
    try {
      const entries = fs.readdirSync(current, { withFileTypes: true });
      for (const entry of entries) {
        if (fileCount >= maxFiles) break;
        const fullPath = path.join(current, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
        } else if (entry.isFile()) {
          fileCount++;
          try {
            totalBytes += fs.statSync(fullPath).size;
          } catch {}
        }
      }
    } catch {}
  }

  walk(dirPath);
  return { fileCount, totalBytes };
}

/**
 * Traverses target directory & subdirectories to identify all exemptable folders and files.
 */
export function analyzeExemptions(targetDir = process.cwd()) {
  const resolvedTarget = path.resolve(targetDir);
  const exemptFolders = [];
  const exemptFiles = [];
  let sourceFilesCount = 0;
  let totalFilesScanned = 0;

  function traverse(currentDir, relativePrefix = '') {
    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = relativePrefix ? path.join(relativePrefix, entry.name) : entry.name;

      if (entry.isDirectory()) {
        // Check if directory matches an exemption rule
        const rule = FOLDER_EXEMPTION_RULES.find((r) => r.match(entry.name));
        if (rule) {
          const stats = inspectFolderStats(fullPath);
          exemptFolders.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: rule.category,
            categoryLabel: rule.label,
            reason: rule.reason,
            fileCount: stats.fileCount,
            sizeBytes: stats.totalBytes
          });
          // Do not recurse into exempted directories
          continue;
        }

        // Otherwise recurse into subdirectories
        traverse(fullPath, relPath);
      } else if (entry.isFile() || entry.isSymbolicLink()) {
        totalFilesScanned++;
        const ext = path.extname(entry.name).toLowerCase();
        let statSize = 0;
        try {
          statSize = fs.statSync(fullPath).size;
        } catch {}

        // 1. Check lock files
        if (LOCK_FILES.has(entry.name)) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: 'LOCKFILE',
            categoryLabel: 'Dependency Lockfile',
            reason: 'Generated package manager lockfile',
            sizeBytes: statSize,
            ext
          });
          continue;
        }

        // 2. Check minified/bundled files
        if (/\.min\.(js|css)$/i.test(entry.name) || /\.map$/i.test(entry.name) || /\.bundle\.(js|css)$/i.test(entry.name)) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: 'MINIFIED',
            categoryLabel: 'Minified Asset',
            reason: 'Minified or source-mapped production bundle',
            sizeBytes: statSize,
            ext
          });
          continue;
        }

        // 3. Check generated code stubs, mocks, and test files
        const isTestFilename = /(?:^|\b)(?:test_|_test\b|Test\b|Tests\b|Spec\b|TestCase\b|UITests\b|mock_|_mock\b|Mock\b|fixture\b)/i.test(entry.name);
        if (
          /\.(pb|gen)\.(go|cc|h|ts|js)$/i.test(entry.name) || 
          /\.generated\./i.test(entry.name) || 
          /\.snap$/i.test(entry.name) ||
          isTestFilename
        ) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: isTestFilename ? 'TEST_FILE' : 'GENERATED',
            categoryLabel: isTestFilename ? 'Test/Mock File' : 'Generated Code',
            reason: isTestFilename ? 'Unit test, test case, or mock source file' : 'Compiler-generated code stub or snapshot',
            sizeBytes: statSize,
            ext
          });
          continue;
        }

        // 4. Check known exempt file extensions
        let matchedExtCategory = null;
        for (const [catKey, catDef] of Object.entries(FILE_EXTENSIONS_EXEMPT)) {
          if (catDef.exts.includes(ext)) {
            matchedExtCategory = { key: catKey, label: catDef.label, reason: catDef.reason };
            break;
          }
        }

        if (matchedExtCategory) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: matchedExtCategory.key,
            categoryLabel: matchedExtCategory.label,
            reason: matchedExtCategory.reason,
            sizeBytes: statSize,
            ext
          });
          continue;
        }

        // 5. Check oversized non-source files (> 2 MB)
        if (statSize > 2 * 1024 * 1024 && !SOURCE_CODE_EXTENSIONS.has(ext)) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: 'OVERSIZED',
            categoryLabel: 'Oversized Asset',
            reason: `Large file (${(statSize / (1024 * 1024)).toFixed(1)} MB) exceeding scan threshold`,
            sizeBytes: statSize,
            ext
          });
          continue;
        }

        // If source code, record count
        if (SOURCE_CODE_EXTENSIONS.has(ext)) {
          sourceFilesCount++;
        }
      }
    }
  }

  traverse(resolvedTarget);

  // Derive compact glob patterns for --exclude in ocr/qbit scan
  const excludePatterns = generateExcludePatterns(exemptFolders, exemptFiles);

  const totalExemptItems = exemptFolders.length + exemptFiles.length;
  const speedupPercent = totalFilesScanned > 0
    ? Math.min(95, Math.max(20, Math.round((totalExemptItems / (totalExemptItems + sourceFilesCount || 1)) * 100)))
    : 80;

  return {
    targetDir: resolvedTarget,
    timestamp: new Date().toISOString(),
    summary: {
      exemptFoldersCount: exemptFolders.length,
      exemptFilesCount: exemptFiles.length,
      totalExemptItems,
      sourceFilesCount,
      totalFilesScanned,
      estimatedSpeedup: `${speedupPercent}%`
    },
    excludePatterns,
    excludeArgsString: excludePatterns.join(','),
    exemptFolders,
    exemptFiles
  };
}

/**
 * Generates concise, optimal glob exclude patterns.
 */
export function generateExcludePatterns(exemptFolders, exemptFiles) {
  const patterns = new Set();

  // Folder patterns
  for (const f of exemptFolders) {
    patterns.add(`**/${f.name}/**`);
  }

  // File patterns by extension / category
  const extsSeen = new Set();
  for (const f of exemptFiles) {
    if (f.category === 'LOCKFILE') {
      patterns.add(`**/${f.name}`);
    } else if (f.ext) {
      extsSeen.add(f.ext);
    } else {
      patterns.add(`**/${f.relPath.replace(/\\/g, '/')}`);
    }
  }

  // Standard high-impact test, mock, and generated file patterns across stacks
  const commonGlobs = [
    '**/*_test.go', '**/*_test.rs', '**/*Test.java', '**/*Tests.java', 
    '**/*Test.kt', '**/*Tests.kt', '**/*Spec.kt', '**/*TestCase.java',
    '**/*Tests.swift', '**/*UITests.swift', '**/*_test.py', '**/test_*.py',
    '**/*Test.php', '**/*.test.ts', '**/*.test.tsx', '**/*.test.js',
    '**/*.spec.ts', '**/*.spec.tsx', '**/*.spec.js', '**/*.pb.go',
    '**/*.pb.gw.go', '**/*_mock.go', '**/mock_*.go', '**/*Mock.swift'
  ];
  for (const cg of commonGlobs) {
    patterns.add(cg);
  }

  for (const ext of extsSeen) {
    // Only exclude extensions that are NOT primary programming language source code
    if (!SOURCE_CODE_EXTENSIONS.has(ext)) {
      patterns.add(`**/*${ext}`);
    }
  }

  return Array.from(patterns);
}

/**
 * Persists the exemptions list to .qbit/scan_exemptions.json
 */
export function saveExemptions(targetDir, analysisData) {
  const qbitDir = path.join(targetDir, '.qbit');
  try {
    if (!fs.existsSync(qbitDir)) {
      fs.mkdirSync(qbitDir, { recursive: true });
    }
    const outFile = path.join(qbitDir, 'scan_exemptions.json');
    fs.writeFileSync(outFile, JSON.stringify(analysisData, null, 2), 'utf8');

    // Also write simple .scanignore file for easy reference
    const scanIgnoreFile = path.join(targetDir, '.scanignore');
    const ignoreContent = `# Generated by Qbit FastScan on ${new Date().toISOString()}\n` +
      analysisData.excludePatterns.join('\n') + '\n';
    try {
      fs.writeFileSync(scanIgnoreFile, ignoreContent, 'utf8');
    } catch {}

    return outFile;
  } catch (err) {
    return null;
  }
}

/**
 * Loads saved exemptions from targetDir/.qbit/scan_exemptions.json if available.
 */
export function loadExemptions(targetDir = process.cwd()) {
  const potentialPaths = [
    path.join(targetDir, '.qbit', 'scan_exemptions.json'),
    path.join(targetDir, 'scan_exemptions.json')
  ];

  for (const p of potentialPaths) {
    try {
      if (fs.existsSync(p)) {
        return JSON.parse(fs.readFileSync(p, 'utf8'));
      }
    } catch {}
  }
  return null;
}

/**
 * Format bytes into human-readable string.
 */
export function formatBytes(bytes = 0) {
  if (bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

/**
 * SUPERFAST SCAN: Analyzes workspace, applies standard FastScan exemptions,
 * and if total estimated execution exceeds maxHours (default 5.0h),
 * automatically ranks and trims heavy directories/files in order of time consumption
 * to guarantee scan finishes strictly within the time limit.
 */
export function analyzeSuperFastExemptions(targetDir = process.cwd(), maxHours = 5.0) {
  const analysis = analyzeExemptions(targetDir);
  const resolvedTarget = path.resolve(targetDir);

  // Maximum files allowable under maxHours with concurrency=4 (~1.8s/file)
  const maxSeconds = maxHours * 3600;
  const maxFiles = Math.floor(maxSeconds / 1.8);

  let currentSourceCount = analysis.summary.sourceFilesCount;

  if (currentSourceCount <= maxFiles) {
    analysis.summary.superFastApplied = false;
    analysis.summary.targetHoursBudget = maxHours;
    return analysis;
  }

  // Need to prune heavy modules/folders to fit under 5 hours
  // Discover all folders and count code files & byte size to rank by time consumption
  const folderLoads = [];
  const walkFolderLoad = (dir, rel) => {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      let codeFiles = 0;
      let totalBytes = 0;
      for (const e of entries) {
        if (e.isDirectory()) {
          if (!['node_modules', '.git', '.qbit', 'dist', 'build', '.cache'].includes(e.name)) {
            walkFolderLoad(path.join(dir, e.name), rel ? path.join(rel, e.name) : e.name);
          }
        } else if (e.isFile()) {
          const ext = path.extname(e.name).toLowerCase();
          if (!['.json', '.md', '.txt', '.svg', '.png', '.jpg', '.pdf', '.yml', '.yaml', '.lock', '.ico', '.woff', '.woff2'].includes(ext)) {
            codeFiles++;
            try { totalBytes += fs.statSync(path.join(dir, e.name)).size; } catch {}
          }
        }
      }
      if (codeFiles > 80 && rel) {
        folderLoads.push({
          relPath: rel.replace(/\\/g, '/'),
          codeFiles,
          totalBytes,
          timeConsumptionSec: codeFiles * 1.8
        });
      }
    } catch {}
  };

  walkFolderLoad(resolvedTarget, '');

  // Sort by time consumption descending (prune heaviest folders first)
  folderLoads.sort((a, b) => b.timeConsumptionSec - a.timeConsumptionSec);

  const prunedFolders = [];
  let filesPruned = 0;

  for (const item of folderLoads) {
    if (currentSourceCount - filesPruned <= maxFiles) break;

    // Avoid pruning top-level project root
    if (item.relPath.split('/').length <= 1) continue;

    prunedFolders.push({
      relPath: item.relPath,
      reason: `Auto-pruned by SuperFast Scan (takes ${(item.timeConsumptionSec / 60).toFixed(0)}m)`,
      category: 'SUPERFAST_PRUNED',
      categoryLabel: 'Heavy Module Pruned',
      fileCount: item.codeFiles,
      sizeBytes: item.totalBytes
    });

    filesPruned += item.codeFiles;
    analysis.exemptFolders.push({
      name: path.basename(item.relPath),
      path: path.join(resolvedTarget, item.relPath),
      relPath: item.relPath,
      category: 'SUPERFAST_PRUNED',
      categoryLabel: 'Heavy Module Pruned',
      reason: `Auto-pruned by SuperFast Scan to guarantee under ${maxHours}h`,
      fileCount: item.codeFiles,
      sizeBytes: item.totalBytes
    });
    analysis.excludePatterns.push(`**/${item.relPath}/**`);
  }

  analysis.summary.superFastApplied = true;
  analysis.summary.targetHoursBudget = maxHours;
  analysis.summary.prunedHeavyModulesCount = prunedFolders.length;
  analysis.summary.filesPrunedCount = filesPruned;
  analysis.summary.sourceFilesCount = Math.max(0, currentSourceCount - filesPruned);
  analysis.summary.estimatedScanHours = ((analysis.summary.sourceFilesCount * 1.8) / 3600).toFixed(2);

  return analysis;
}

/**
 * Formats a high-contrast colored report for terminal / chat display.
 */
export function formatExemptionsReport(analysis) {
  const lines = [];
  const divider = chalk.dim('━'.repeat(68));

  lines.push('');
  lines.push(chalk.cyan.bold('⚡ QBIT FASTSCAN: Workspace Exemption Analysis'));
  lines.push(divider);
  lines.push(chalk.dim(`   Target: ${analysis.targetDir}`));
  lines.push(
    `   📁 ${chalk.bold('Exempted Folders:')} ${chalk.yellow.bold(analysis.summary.exemptFoldersCount)} | ` +
    `📄 ${chalk.bold('Exempted Files:')} ${chalk.yellow.bold(analysis.summary.exemptFilesCount)} | ` +
    `🛡️  ${chalk.bold('Code in Scope:')} ${chalk.green.bold(analysis.summary.sourceFilesCount)} files`
  );
  lines.push(`   ⚡ ${chalk.bold('Estimated Speedup:')} ${chalk.green.bold(analysis.summary.estimatedSpeedup)} faster scan execution`);
  lines.push(divider);

  if (analysis.exemptFolders.length > 0) {
    lines.push(chalk.bold.yellow('📁 EXEMPTED FOLDERS:'));
    for (const f of analysis.exemptFolders.slice(0, 15)) {
      const tag = chalk.bgHex('#334155').white.bold(` [${f.category}] `);
      const count = f.fileCount ? chalk.dim(` (${f.fileCount} items)`) : '';
      lines.push(`  ${chalk.cyan('•')} ${tag} ${chalk.bold.white(f.relPath + '/')}${count} - ${chalk.dim(f.reason)}`);
    }
    if (analysis.exemptFolders.length > 15) {
      lines.push(chalk.dim(`  ... and ${analysis.exemptFolders.length - 15} more folders.`));
    }
    lines.push('');
  }

  if (analysis.exemptFiles.length > 0) {
    lines.push(chalk.bold.yellow('📄 EXEMPTED FILES & ASSETS:'));
    for (const f of analysis.exemptFiles.slice(0, 15)) {
      const tag = chalk.bgHex('#1e293b').hex('#94a3b8').bold(` [${f.category}] `);
      const sizeStr = f.sizeBytes ? chalk.dim(` (${formatBytes(f.sizeBytes)})`) : '';
      lines.push(`  ${chalk.cyan('•')} ${tag} ${chalk.white(f.relPath)}${sizeStr} - ${chalk.dim(f.reason)}`);
    }
    if (analysis.exemptFiles.length > 15) {
      lines.push(chalk.dim(`  ... and ${analysis.exemptFiles.length - 15} more files.`));
    }
    lines.push('');
  }

  lines.push(chalk.dim('🎯 SCAN COMMAND UPDATED:'));
  lines.push(`  ${chalk.green.bold('✔')} The ${chalk.cyan.bold('/scan')} command is now configured with ${chalk.bold(analysis.excludePatterns.length)} exclusion rules.`);
  lines.push(chalk.dim(`     Exemptions saved to: .qbit/scan_exemptions.json and .scanignore`));
  lines.push(chalk.dim(`     Subsequent scans will skip these folders & files automatically.`));
  lines.push(divider);
  lines.push('');

  return lines.join('\n');
}
