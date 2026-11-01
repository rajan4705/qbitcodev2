import { useDialog } from "../ui/dialog"
import { DialogSelect, type DialogSelectOption } from "../ui/dialog-select"
import { createMemo, createSignal, onMount, onCleanup } from "solid-js"
import { useLocation } from "../context/location"
import { useTuiPaths } from "../context/runtime"
import { usePromptRef } from "../context/prompt"
import { emptyPrompt } from "../prompt/history"
import { useToast } from "../ui/toast"
import path from "node:path"
import fs from "node:fs"

export interface FindingItem {
  id: string
  severity: string
  path: string
  start_line: number
  end_line?: number
  category?: string
  cwe_id?: string
  cwe_title?: string
  cve_id?: string
  content: string
  suggestion?: string
  existing_code?: string
  suggestion_code?: string
  status?: string
}

export function DialogFindings(props: {
  onSelect?: (finding: FindingItem) => void
  sessionID?: string
  scanPath?: string
}) {
  const dialog = useDialog()
  const location = useLocation()
  const paths = useTuiPaths()
  const toast = useToast()

  // Fullscreen interactive cockpit dialog
  dialog.setSize("fullscreen")
  dialog.setCentered(true)

  const [findings, setFindings] = createSignal<FindingItem[]>([])
  const [selectedFinding, setSelectedFinding] = createSignal<FindingItem | null>(null)

  const loadFindings = () => {
    const dir = location.current?.directory ?? paths.cwd

    // Search across current dir, paths.cwd, process.cwd(), and props.scanPath
    const candidateDirs = new Set<string>()
    if (dir) candidateDirs.add(dir)
    if (paths.cwd) candidateDirs.add(paths.cwd)
    if (props.scanPath && path.isAbsolute(props.scanPath)) candidateDirs.add(props.scanPath)
    candidateDirs.add(process.cwd())

    const potentialFiles: string[] = []
    for (const d of candidateDirs) {
      potentialFiles.push(
        path.join(d, "ocr_output.json"),
        path.join(d, ".qbit", "scan_cache.json"),
        path.join(d, "results.json"),
        path.join(d, "qbit_output.json")
      )
    }

    // Sort existing candidate files by mtime descending so the newest scan results are always preferred
    const existingCandidates: { file: string; mtime: number }[] = []
    for (const f of potentialFiles) {
      try {
        if (fs.existsSync(f)) {
          const stat = fs.statSync(f)
          if (stat.size > 2) {
            existingCandidates.push({ file: f, mtime: stat.mtimeMs })
          }
        }
      } catch {}
    }

    existingCandidates.sort((a, b) => b.mtime - a.mtime)

    for (const { file } of existingCandidates) {
      try {
        const raw = JSON.parse(fs.readFileSync(file, "utf8"))
        let list: any[] = []

        if (Array.isArray(raw)) {
          list = raw
        } else if (raw.comments && Array.isArray(raw.comments)) {
          list = raw.comments
        } else if (raw.findings && typeof raw.findings === "object") {
          // .qbit/scan_cache.json stores findings as a map: { [id]: finding }
          list = Array.isArray(raw.findings) ? raw.findings : Object.values(raw.findings)
        }

        // If a specific scanPath filter was used, filter by relative path prefix
        if (props.scanPath && props.scanPath.trim()) {
          const rawFilter = props.scanPath.trim()
          if (rawFilter !== "." && rawFilter !== "./" && rawFilter !== dir) {
            const relFilter = path.isAbsolute(rawFilter)
              ? path.relative(dir, rawFilter).replace(/\\/g, "/")
              : rawFilter.replace(/\\/g, "/").replace(/^\.\//, "")

            if (relFilter && relFilter !== "." && relFilter !== "") {
              const filtered = list.filter((c: any) => {
                const p = (c.path || "").replace(/\\/g, "/").replace(/^\.\//, "")
                return p === relFilter || p.startsWith(relFilter + "/")
              })
              if (filtered.length > 0) {
                list = filtered
              }
            }
          }
        }

        if (list.length > 0) {
          const mapped = list.map((c: any, idx: number) => ({
            id: c.id || `QBIT-${idx + 1}`,
            severity: (c.severity || "medium").toUpperCase(),
            path: c.path || "unknown",
            start_line: c.start_line || 1,
            end_line: c.end_line || c.start_line || 1,
            category: c.category || "security",
            cwe_id: c.cwe_id && c.cwe_id !== "NONE" && c.cwe_id !== "N/A" ? c.cwe_id : undefined,
            cwe_title: c.cwe_title,
            cve_id: c.cve_id && c.cve_id !== "N/A" ? c.cve_id : undefined,
            content: c.content || c.description || "Security vulnerability detected.",
            suggestion: c.suggestion_code || c.suggestion || c.remediation || c.patch_description,
            existing_code: c.existing_code || undefined,
            suggestion_code: c.suggestion_code || undefined,
            status: c.status || "open"
          }))
          setFindings(mapped)
          if (!selectedFinding() && mapped.length > 0) {
            setSelectedFinding(mapped[0])
          }
          break
        }
      } catch {}
    }
  }

  onMount(() => {
    loadFindings()
    // Poll every 1.5s so findings pop in dynamically as the scan progresses or completes
    const timer = setInterval(() => {
      loadFindings()
    }, 1500)
    onCleanup(() => clearInterval(timer))
  })

  const promptRef = usePromptRef()

  const executeFix = (finding: FindingItem) => {
    dialog.clear()

    // Derive a clean, descriptive slug for the branch name (e.g. fix/page-dimensions-validation or fix/buffer-overflow)
    const topicSlug = (finding.cwe_title || finding.content || finding.cwe_id || "vulnerability")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 35)
      .replace(/-+$/, "")
    const branchName = `fix/${topicSlug || finding.id.toLowerCase()}`

    // Build the rich, customizable remediation prompt for the current session agent
    const promptText = `Fix vulnerability [${finding.id}] in \`${finding.path}:${finding.start_line}\`.
Issue: ${finding.content}
${finding.cwe_id ? `CWE: ${finding.cwe_id} (${finding.cwe_title || ""})\n` : ""}${finding.existing_code ? `Target existing code: \`${finding.existing_code}\`\n` : ""}${finding.suggestion ? `Suggested fix: ${finding.suggestion}\n` : ""}
EXECUTION INSTRUCTIONS:
Execute the remediation immediately using your available tools:
1. Create a new git branch named after the problem being fixed: \`git checkout -b ${branchName}\`
2. Apply the patch to \`${finding.path}\` directly.
${finding.existing_code ? `   - If using the edit tool, match the exact code \`${finding.existing_code}\` as oldString, or read the surrounding lines first.\n` : ""}3. Stage and commit: \`git add ${finding.path} && git commit -m "fix(${topicSlug}): resolve ${finding.cwe_id || "issue"} in ${path.basename(finding.path)}"\`
4. Respond with a concise, human-readable summary of the fix. Do not dump raw tool call JSON in your response text.`

    if (promptRef.current) {
      promptRef.current.set({
        ...emptyPrompt(),
        text: promptText,
      })
      promptRef.current.focus()
    }

    toast.show({
      title: `${finding.id} Loaded in Prompt`,
      message: `Prompt ready in your session. Edit or press Enter to run!`,
      variant: "info"
    })
  }

  const executeFixAll = () => {
    dialog.clear()

    const allFindingsText = findings().map(f =>
      `- [${f.id}] ${f.path}:${f.start_line} (${f.cwe_id || f.severity}): ${f.content}${f.existing_code ? ` (Code: \`${f.existing_code}\`)` : ""}`
    ).join('\n')

    const promptText = `Autonomously fix all ${findings().length} detected vulnerabilities sequentially:
${allFindingsText}

EXECUTION INSTRUCTIONS:
For EACH vulnerability:
1. Create a new git branch named after the issue (e.g. \`git checkout -b fix/<topic-name>\`)
2. Apply the safe patch to the target file directly using exact target code or reading surrounding lines.
3. Stage and commit: \`git add <file> && git commit -m "fix(<topic>): patch vulnerability"\`
4. Provide a clear, clean human-readable summary of the actions taken.`

    if (promptRef.current) {
      promptRef.current.set({
        ...emptyPrompt(),
        text: promptText,
      })
      promptRef.current.focus()
    }

    toast.show({
      title: "Batch Remediation Prompt Loaded",
      message: `Review or customize the prompt, then press Enter to execute!`,
      variant: "info"
    })
  }

  const options = createMemo((): DialogSelectOption<FindingItem>[] => {
    if (findings().length === 0) {
      return [
        {
          title: "⏳ FastScan in progress: analyzing codebase...",
          description: "Scanning files with active exclusions. Vulnerabilities will appear here live.",
          details: [
            "⚡ FastScan engine active: non-code files, dependencies, and build artifacts excluded.",
            "Findings refresh automatically, or press Ctrl+R to reload manually.",
            "Press Esc to return to session or inspect real-time progress in the terminal."
          ],
          value: {
            id: "SCANNING",
            severity: "LOW",
            path: "in-progress",
            start_line: 1,
            content: "Vulnerability scan is currently executing..."
          },
          footer: "[Ctrl+R: Refresh] • [Esc: Exit to Chat]"
        }
      ]
    }

    return findings().map((f) => {
      const icon = f.severity === "CRITICAL" ? "🔴" : f.severity === "HIGH" ? "🟠" : f.severity === "MEDIUM" ? "🟡" : "🔵"
      const cwe = f.cwe_id ? `[${f.cwe_id}] ` : ""
      const cve = f.cve_id ? `[${f.cve_id}] ` : ""
      const statusBadge = f.status === "fixed" ? "  ✔ FIXED" : ""

      const detailsList = [
        `📁 File: ${f.path} (Line ${f.start_line}${f.end_line && f.end_line !== f.start_line ? `-${f.end_line}` : ""})`,
        `⚠️ Defect: ${f.content.replace(/\s+/g, " ").trim()}`
      ]
      if (f.suggestion) {
        detailsList.push(`💡 Remediation: ${f.suggestion.replace(/\s+/g, " ").trim()}`)
      }

      return {
        title: `${icon} ${f.id} [${f.severity}] ${cwe}${cve}▶ ${f.path}:${f.start_line}${statusBadge}`,
        description: f.content.replace(/\s+/g, " ").trim(),
        details: detailsList,
        value: f,
        footer: `[Enter: FIX THIS] • [Ctrl+A: Fix All (${findings().length})] • [Esc: Exit]`
      }
    })
  })

  return (
    <DialogSelect
      title={`🛡️ QBIT CODE AUDIT: ${findings().length} VULNERABILITIES IDENTIFIED`}
      placeholder="Type to filter vulnerabilities by CWE, path, or description... [Enter = Fix Single, F = Fix All]"
      options={options()}
      onMove={(opt) => setSelectedFinding(opt.value)}
      onSelect={(opt) => {
        if (opt.value.id === "SCANNING") {
          loadFindings()
          return
        }
        executeFix(opt.value)
      }}
      onCancel={() => dialog.clear()}
      actions={[
        {
          command: "qbit.findings.fix_all",
          title: `Fix All (${findings().length})`,
          bind: "ctrl+a",
          selection: "none",
          onTrigger: () => executeFixAll(),
        },
        {
          command: "qbit.findings.reload",
          title: "Reload",
          bind: "ctrl+r",
          selection: "none",
          onTrigger: () => loadFindings(),
        }
      ]}
      footerHints={[
        { title: "Enter", label: "Fix Selected (creates branch & commit)" },
        { title: "Ctrl+A", label: "Fix All Vulnerabilities" },
        { title: "Esc", label: "Return to Chat" }
      ]}
    />
  )
}
