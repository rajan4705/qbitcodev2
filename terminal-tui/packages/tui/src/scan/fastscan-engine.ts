import fs from "node:fs"
import path from "node:path"

export interface ExemptFolder {
  name: string
  path: string
  relPath: string
  category: string
  categoryLabel: string
  reason: string
  fileCount?: number
  sizeBytes?: number
}

export interface ExemptFile {
  name: string
  path: string
  relPath: string
  category: string
  categoryLabel: string
  reason: string
  sizeBytes?: number
  ext?: string
}

export interface FastScanSummary {
  exemptFoldersCount: number
  exemptFilesCount: number
  totalExemptItems: number
  sourceFilesCount: number
  totalFilesScanned: number
  estimatedSpeedup: string
}

export interface FastScanResult {
  targetDir: string
  timestamp: string
  summary: FastScanSummary
  excludePatterns: string[]
  excludeArgsString: string
  exemptFolders: ExemptFolder[]
  exemptFiles: ExemptFile[]
}

export const FOLDER_RULES = [
  {
    category: "DEPENDENCY",
    label: "Dependencies",
    reason: "Third-party packages and external dependencies",
    match: (name: string) =>
      ["node_modules", "vendor", "bower_components", "Pods", "Carthage", ".pnpm-store", ".yarn", "oh_modules"].includes(name),
  },
  {
    category: "BUILD",
    label: "Build Output",
    reason: "Compiled binaries, bundles, and distribution artifacts",
    match: (name: string) =>
      [
        "dist",
        "build",
        "out",
        "target",
        "bin",
        "obj",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".astro",
        ".turbo",
        ".angular",
        ".parcel-cache",
        ".docusaurus",
        "coverage",
        ".output",
        "storybook-static",
      ].includes(name),
  },
  {
    category: "VCS",
    label: "Version Control",
    reason: "Version control metadata and internal hooks",
    match: (name: string) => [".git", ".svn", ".hg", ".husky"].includes(name),
  },
  {
    category: "VIRTUALENV_CACHE",
    label: "Virtualenvs & Caches",
    reason: "Python virtualenvs and runtime execution caches",
    match: (name: string) =>
      ["venv", ".venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".cache"].includes(name) ||
      name.endsWith(".egg-info"),
  },
  {
    category: "IDE",
    label: "IDE Configuration",
    reason: "Editor workspace metadata and local settings",
    match: (name: string) => [".vscode", ".idea", ".zed", ".fleet", ".eclipse"].includes(name),
  },
  {
    category: "TEMP_LOGS",
    label: "Temp & Logs",
    reason: "Temporary scratch files and system logs",
    match: (name: string) => ["tmp", "temp", "logs", ".temp"].includes(name),
  },
  {
    category: "TEST_FIXTURES",
    label: "Test Fixtures",
    reason: "Static test fixtures, mock archives, and snapshot assets",
    match: (name: string) => ["testdata", "fixtures", "__snapshots__", "mocks", "test_fixtures"].includes(name),
  },
]

export const FILE_EXTENSIONS_EXEMPT: Record<string, { label: string; reason: string; exts: string[] }> = {
  MEDIA: {
    label: "Media Assets",
    reason: "Non-executable images, videos, and audio assets",
    exts: [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff", ".mp3", ".wav", ".ogg", ".mp4", ".mov", ".avi", ".webm"],
  },
  ARCHIVE: {
    label: "Compressed Archives",
    reason: "Binary archive containers and zip packages",
    exts: [".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".iso"],
  },
  BINARY_LIB: {
    label: "Compiled Binaries",
    reason: "Pre-compiled machine code and shared objects",
    exts: [".o", ".a", ".so", ".dylib", ".dll", ".exe", ".bin", ".class", ".pyc", ".pyo", ".wasm"],
  },
  FONT: {
    label: "Fonts & Typography",
    reason: "Static font assets",
    exts: [".ttf", ".otf", ".woff", ".woff2", ".eot"],
  },
  DOCUMENT: {
    label: "Office & PDF Docs",
    reason: "Non-code documentation and design files",
    exts: [".pdf", ".psd", ".ai", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"],
  },
  DATABASE_MODEL: {
    label: "Databases & ML Weights",
    reason: "Database tables and neural network weight binaries",
    exts: [".db", ".sqlite", ".sqlite3", ".onnx", ".pt", ".safetensors", ".h5", ".ckpt"],
  },
}

export const LOCK_FILES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
  "Cargo.lock",
  "poetry.lock",
  "composer.lock",
  "Gemfile.lock",
  "flake.lock",
  "Podfile.lock",
])

export const SOURCE_CODE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx",
  ".go", ".rs", ".py", ".java", ".kt", ".kts", ".scala",
  ".cs", ".php", ".rb", ".swift", ".sh", ".bash", ".zsh",
  ".sql", ".html", ".css", ".vue", ".svelte",
])

function inspectFolderStats(dirPath: string, maxFiles = 500) {
  let fileCount = 0
  let totalBytes = 0

  function walk(current: string) {
    if (fileCount >= maxFiles) return
    try {
      const entries = fs.readdirSync(current, { withFileTypes: true })
      for (const entry of entries) {
        if (fileCount >= maxFiles) break
        const fullPath = path.join(current, entry.name)
        if (entry.isDirectory()) {
          walk(fullPath)
        } else if (entry.isFile()) {
          fileCount++
          try {
            totalBytes += fs.statSync(fullPath).size
          } catch {}
        }
      }
    } catch {}
  }

  walk(dirPath)
  return { fileCount, totalBytes }
}

/**
 * Traverses target directory & subdirectories to identify all exemptable folders and files.
 */
export function analyzeExemptions(targetDir: string = process.cwd()): FastScanResult {
  const resolvedTarget = path.resolve(targetDir)
  const exemptFolders: ExemptFolder[] = []
  const exemptFiles: ExemptFile[] = []
  let sourceFilesCount = 0
  let totalFilesScanned = 0

  function traverse(currentDir: string, relativePrefix = "") {
    let entries: fs.Dirent[] = []
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name)
      const relPath = relativePrefix ? path.join(relativePrefix, entry.name) : entry.name

      if (entry.isDirectory()) {
        const rule = FOLDER_RULES.find((r) => r.match(entry.name))
        if (rule) {
          const stats = inspectFolderStats(fullPath)
          exemptFolders.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: rule.category,
            categoryLabel: rule.label,
            reason: rule.reason,
            fileCount: stats.fileCount,
            sizeBytes: stats.totalBytes,
          })
          // Do not recurse into exempted directories
          continue
        }

        traverse(fullPath, relPath)
      } else if (entry.isFile() || entry.isSymbolicLink()) {
        totalFilesScanned++
        const ext = path.extname(entry.name).toLowerCase()
        let statSize = 0
        try {
          statSize = fs.statSync(fullPath).size
        } catch {}

        if (LOCK_FILES.has(entry.name)) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: "LOCKFILE",
            categoryLabel: "Dependency Lockfile",
            reason: "Generated package manager lockfile",
            sizeBytes: statSize,
            ext,
          })
          continue
        }

        if (
          /\.min\.(js|css)$/i.test(entry.name) ||
          /\.map$/i.test(entry.name) ||
          /\.bundle\.(js|css)$/i.test(entry.name)
        ) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: "MINIFIED",
            categoryLabel: "Minified Asset",
            reason: "Minified or source-mapped production bundle",
            sizeBytes: statSize,
            ext,
          })
          continue
        }

        if (
          /\.(pb|gen)\.(go|cc|h|ts|js)$/i.test(entry.name) ||
          /\.generated\./i.test(entry.name) ||
          /\.snap$/i.test(entry.name)
        ) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: "GENERATED",
            categoryLabel: "Generated Code",
            reason: "Compiler-generated code stub or snapshot",
            sizeBytes: statSize,
            ext,
          })
          continue
        }

        let matchedExtCategory: { key: string; label: string; reason: string } | null = null
        for (const [catKey, catDef] of Object.entries(FILE_EXTENSIONS_EXEMPT)) {
          if (catDef.exts.includes(ext)) {
            matchedExtCategory = { key: catKey, label: catDef.label, reason: catDef.reason }
            break
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
            ext,
          })
          continue
        }

        if (statSize > 2 * 1024 * 1024 && !SOURCE_CODE_EXTENSIONS.has(ext)) {
          exemptFiles.push({
            name: entry.name,
            path: fullPath,
            relPath,
            category: "OVERSIZED",
            categoryLabel: "Oversized Asset",
            reason: `Large file (${(statSize / (1024 * 1024)).toFixed(1)} MB) exceeding scan threshold`,
            sizeBytes: statSize,
            ext,
          })
          continue
        }

        if (SOURCE_CODE_EXTENSIONS.has(ext)) {
          sourceFilesCount++
        }
      }
    }
  }

  traverse(resolvedTarget)

  const excludePatterns = generateExcludePatterns(exemptFolders, exemptFiles)
  const totalExemptItems = exemptFolders.length + exemptFiles.length
  const speedupPercent =
    totalFilesScanned > 0
      ? Math.min(95, Math.max(20, Math.round((totalExemptItems / (totalExemptItems + sourceFilesCount || 1)) * 100)))
      : 80

  return {
    targetDir: resolvedTarget,
    timestamp: new Date().toISOString(),
    summary: {
      exemptFoldersCount: exemptFolders.length,
      exemptFilesCount: exemptFiles.length,
      totalExemptItems,
      sourceFilesCount,
      totalFilesScanned,
      estimatedSpeedup: `${speedupPercent}%`,
    },
    excludePatterns,
    excludeArgsString: excludePatterns.join(","),
    exemptFolders,
    exemptFiles,
  }
}

export function generateExcludePatterns(exemptFolders: ExemptFolder[], exemptFiles: ExemptFile[]): string[] {
  const patterns = new Set<string>()

  for (const f of exemptFolders) {
    patterns.add(`**/${f.name}/**`)
  }

  const extsSeen = new Set<string>()
  for (const f of exemptFiles) {
    if (f.category === "LOCKFILE") {
      patterns.add(`**/${f.name}`)
    } else if (f.ext) {
      extsSeen.add(f.ext)
    } else {
      patterns.add(`**/${f.relPath.replace(/\\/g, "/")}`)
    }
  }

  for (const ext of extsSeen) {
    patterns.add(`**/*${ext}`)
  }

  return Array.from(patterns)
}

export function saveExemptions(targetDir: string, analysisData: FastScanResult): string | null {
  const qbitDir = path.join(targetDir, ".qbit")
  try {
    if (!fs.existsSync(qbitDir)) {
      fs.mkdirSync(qbitDir, { recursive: true })
    }
    const outFile = path.join(qbitDir, "scan_exemptions.json")
    fs.writeFileSync(outFile, JSON.stringify(analysisData, null, 2), "utf8")

    const scanIgnoreFile = path.join(targetDir, ".scanignore")
    const ignoreContent =
      `# Generated by Qbit FastScan on ${new Date().toISOString()}\n` +
      analysisData.excludePatterns.join("\n") +
      "\n"
    try {
      fs.writeFileSync(scanIgnoreFile, ignoreContent, "utf8")
    } catch {}

    return outFile
  } catch {
    return null
  }
}

export function loadExemptions(targetDir: string = process.cwd()): FastScanResult | null {
  const potentialPaths = [
    path.join(targetDir, ".qbit", "scan_exemptions.json"),
    path.join(targetDir, "scan_exemptions.json"),
  ]

  for (const p of potentialPaths) {
    try {
      if (fs.existsSync(p)) {
        return JSON.parse(fs.readFileSync(p, "utf8"))
      }
    } catch {}
  }
  return null
}

export function formatBytes(bytes = 0): string {
  if (bytes <= 0) return "0 B"
  const units = ["B", "KB", "MB", "GB"]
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)))
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`
}
