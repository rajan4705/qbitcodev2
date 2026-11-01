import { useDialog } from "../ui/dialog"
import { DialogSelect, type DialogSelectOption } from "../ui/dialog-select"
import { createMemo, createSignal, onMount } from "solid-js"
import { useLocation } from "../context/location"
import { useTuiPaths } from "../context/runtime"
import { useToast } from "../ui/toast"
import { useClient } from "../context/client"
import {
  analyzeExemptions,
  loadExemptions,
  saveExemptions,
  formatBytes,
  type FastScanResult,
  type ExemptFolder,
  type ExemptFile,
} from "../scan/fastscan-engine"
import { DialogFindings } from "./dialog-findings"

type FastScanItem =
  | { type: "action"; id: string; label: string }
  | { type: "folder"; item: ExemptFolder }
  | { type: "file"; item: ExemptFile }

export function DialogFastScan(props: {
  sessionID?: string
  targetDir?: string
  onRunScan?: () => void
}) {
  const dialog = useDialog()
  const location = useLocation()
  const paths = useTuiPaths()
  const toast = useToast()
  const client = useClient()

  dialog.setSize("fullscreen")
  dialog.setCentered(true)

  const [result, setResult] = createSignal<FastScanResult | null>(null)

  const loadData = () => {
    const dir = props.targetDir || location.current?.directory || paths.cwd
    let existing = loadExemptions(dir)
    if (!existing) {
      existing = analyzeExemptions(dir)
      saveExemptions(dir, existing)
    }
    setResult(existing)
  }

  onMount(() => {
    loadData()
  })

  const runAcceleratedScan = async () => {
    dialog.clear()
    const cur = result()
    const targetSessionID = props.sessionID
    const dir = props.targetDir || location.current?.directory || paths.cwd
    const excludes = cur?.excludeArgsString || ""

    const cmd = excludes
      ? `qbit scan --exclude "${excludes}"`
      : `qbit scan`

    toast.show({
      title: "FastScan Accelerated Scan Started",
      message: `Running scan with ${cur?.summary.totalExemptItems || 0} active exemptions skipped`,
      variant: "info",
    })

    if (targetSessionID) {
      try {
        await client.api.session.shell({
          sessionID: targetSessionID,
          command: cmd,
        })
        setTimeout(() => {
          dialog.replace(() => <DialogFindings sessionID={targetSessionID} scanPath={dir} />)
        }, 500)
      } catch (err) {
        toast.show({
          title: "Scan failed",
          message: String(err),
          variant: "error",
        })
      }
    }
  }

  const options = createMemo((): DialogSelectOption<FastScanItem>[] => {
    const data = result()
    if (!data) return []

    const list: DialogSelectOption<FastScanItem>[] = []

    // 1. Primary Action Item: Run Scan Now
    list.push({
      title: `⚡ RUN ACCELERATED SCAN NOW (${data.summary.estimatedSpeedup} faster)`,
      description: `Immediately execute vulnerability scan with all ${data.summary.totalExemptItems} exemptions applied`,
      details: [
        `🎯 Target: ${data.targetDir}`,
        `📁 Folders Exempted: ${data.summary.exemptFoldersCount} | 📄 Files Exempted: ${data.summary.exemptFilesCount}`,
        `🛡️ Source Code in Scope: ${data.summary.sourceFilesCount} files`,
        `⚡ Estimated Speedup: ${data.summary.estimatedSpeedup}`,
      ],
      value: { type: "action", id: "run_scan", label: "Run Scan" },
      footer: "[Enter: Run Fast Scan Now] • [Esc: Keep Exemptions & Return]",
    })

    // 2. Folder Exemptions
    for (const f of data.exemptFolders) {
      const count = f.fileCount ? ` (${f.fileCount} items)` : ""
      const size = f.sizeBytes ? ` • ${formatBytes(f.sizeBytes)}` : ""
      list.push({
        title: `📁 [${f.category}] ${f.relPath}/${count}${size}`,
        description: `${f.categoryLabel}: ${f.reason}`,
        details: [
          `📂 Folder: ${f.relPath}/`,
          `🏷️  Category: ${f.categoryLabel} (${f.category})`,
          `ℹ️  Reason: ${f.reason}`,
          `📊 Size: ${formatBytes(f.sizeBytes || 0)} (${f.fileCount || 0} files skipped)`,
        ],
        value: { type: "folder", item: f },
        footer: "[Enter: Run Fast Scan] • [Esc: Return to Chat]",
      })
    }

    // 3. File Exemptions
    for (const file of data.exemptFiles) {
      const size = file.sizeBytes ? ` (${formatBytes(file.sizeBytes)})` : ""
      list.push({
        title: `📄 [${file.category}] ${file.relPath}${size}`,
        description: `${file.categoryLabel}: ${file.reason}`,
        details: [
          `📄 File: ${file.relPath}`,
          `🏷️  Category: ${file.categoryLabel}`,
          `ℹ️  Reason: ${file.reason}`,
          `📊 Size: ${formatBytes(file.sizeBytes || 0)}`,
        ],
        value: { type: "file", item: file },
        footer: "[Enter: Run Fast Scan] • [Esc: Return to Chat]",
      })
    }

    return list
  })

  return (
    <DialogSelect
      title={`⚡ FASTSCAN EXEMPTIONS: ${result()?.summary.totalExemptItems || 0} ITEMS EXEMPTED (${result()?.summary.estimatedSpeedup || "80%"} SPEEDUP)`}
      placeholder="Search exempted folders and files... [Enter = Run Accelerated Scan, Esc = Return to Chat]"
      options={options()}
      onSelect={(opt) => {
        if (opt.value.type === "action" || opt.value.type === "folder" || opt.value.type === "file") {
          runAcceleratedScan()
        }
      }}
      onCancel={() => {
        dialog.clear()
        toast.show({
          title: "Scan Command Updated",
          message: `/scan command updated with ${result()?.summary.totalExemptItems || 0} exemptions.`,
          variant: "success",
        })
      }}
      actions={[
        {
          command: "fastscan.run_scan",
          title: "Run Fast Scan",
          bind: "ctrl+s",
          selection: "none",
          onTrigger: () => runAcceleratedScan(),
        },
        {
          command: "fastscan.refresh",
          title: "Re-analyze Directory",
          bind: "ctrl+r",
          selection: "none",
          onTrigger: () => {
            const dir = props.targetDir || location.current?.directory || paths.cwd
            const updated = analyzeExemptions(dir)
            saveExemptions(dir, updated)
            setResult(updated)
            toast.show({
              title: "Exemptions Refreshed",
              message: `Re-analyzed workspace: ${updated.summary.totalExemptItems} items exempted.`,
              variant: "info",
            })
          },
        },
      ]}
      footerHints={[
        { title: "Enter", label: "Run Fast Scan Now" },
        { title: "Ctrl+R", label: "Re-analyze Directory" },
        { title: "Esc", label: "Confirm Exemptions & Return (/scan updated)" },
      ]}
    />
  )
}
