# Comprehensive Plan: Interactive CLI Vulnerability Workflow & CWE/CVE API Integration

## Executive Summary

This plan details the architecture and implementation steps to achieve two primary objectives:
1. **Interactive & Colored CLI Vulnerability Management:** Transform the CLI scan output from static text into an interactive, color-coded interface where vulnerabilities can be selected and immediately prompted for autonomous remediation directly from the terminal.
2. **Automated MITRE CWE & Reference CVE Enrichment (`localhost:8080`):** Wire the Qdrant-backed vector enrichment service running on `http://localhost:8080/api/v1/enrich_snippet` into both the CLI scanner and the Cyberpunk Web Cockpit.

---

## 1. System Architecture & Flow

```mermaid
flowchart TD
    subgraph SCAN_PHASE [1. Code Scanning Phase]
        A["qbit scan [target]"] --> B["AST & OCR Engine"]
        B --> C["Raw Flaws Detected"]
    end

    subgraph ENRICH_PHASE [2. Enrichment Engine (localhost:8080)]
        C --> D["cve-enricher client"]
        D -->|POST /api/v1/enrich_snippet| E["Vector Search on localhost:8080"]
        E -->|CWE-ID, CWE-Title, CVE-ID, NVD Severity| D
        D --> F["Enriched Findings (ocr_output.json)"]
    end

    subgraph CLI_SURFACE [3. CLI Interface (qbitcode)]
        F --> G["Color-Coded Terminal Output (CWE/CVE Badges)"]
        F --> H["Interactive Terminal Selector: Prompt-to-Fix"]
        F --> I["Interactive TUI /fix Autocomplete Dropdown"]
        F --> J["TUI Modal Dialog: /findings"]
    end

    subgraph WEB_SURFACE [4. Web Cockpit (localhost:5432)]
        F --> K["GET /api/findings"]
        K --> L["Vulnerability Cards with Clickable CWE & CVE Chips"]
        K --> M["MITRE CWE Category Distribution Graph"]
    end
```

---

## 2. Part 1: Interactive & Colored CLI Vulnerability List

### Current State
* `qbit scan` prints a basic ASCII table with minimal styling.
* To fix a finding, the user must remember the finding ID or copy/paste file paths into a separate prompt.

### Target State
* **High-Contrast Colored Badges:**
  * `CRITICAL`: Bright red background with bold white font (`bgRed.white.bold`).
  * `HIGH`: Fire-orange bold text (`hex('#FF5500')`).
  * `MEDIUM`: Amber yellow bold text (`hex('#FFB800')`).
  * `LOW`: Electric cyan text (`hex('#00D9FF')`).
  * `CWE Badge`: Slate purple badge (`bgHex('#4B0082').white.bold`).
  * `CVE Badge`: Gold badge (`bgHex('#B8860B').white.bold`).
  * `Code Link`: Clickable terminal hyperlink `path:line`.

### Interactive Remediation Options

#### Option A: Post-Scan Terminal Prompt (CLI Shell Mode)
Right after the `tqdm` progress bar finishes and the findings table prints:
```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ ⚡ Action Required: 3 security vulnerabilities identified                  │
│ [1] QBIT-1: CWE-120 Buffer Overflow in calibPipeline.cpp:45 (CRITICAL)     │
│ [2] QBIT-2: CWE-401 Memory Leak in main.cpp:112 (HIGH)                      │
│ [3] QBIT-3: CWE-476 Null Pointer Dereference in utils.cpp:28 (MEDIUM)       │
└─────────────────────────────────────────────────────────────────────────────┘
? Select finding to remediate (1-3, 'all', or press Enter to skip): 1
? Custom prompt (press Enter for autonomous remediation): Replace sprintf with snprintf and check bounds
🚀 Remediating QBIT-1...
```

#### Option B: Real-Time `/fix` Autocomplete Dropdown (TUI Mode)
In `packages/tui/src/component/prompt/index.tsx` & `autocomplete.tsx`:
* Typing `/fix ` reads `ocr_output.json` dynamically and displays a rich autocomplete dropdown:
  * Shows `[QBIT-1] [CRITICAL] [CWE-120] Buffer Overflow in calibPipeline.cpp:45`
  * Tab/Enter autocompletes the ID into the composer: `/fix QBIT-1 `.
  * User can append prompt instructions directly: `/fix QBIT-1 ensure boundary checks`.

#### Option C: Native TUI Interactive Dialog (`/findings`)
* Register `/findings` as a keymap/slash command opening a `DialogSelect` modal.
* Provides full arrow-key (`↑ / ↓`) navigation across findings with syntax-highlighted preview of `existing_code` and `suggestion_code`.
* Pressing **Enter** stages the fix into the chat session.

---

## 3. Part 2: Integration with CWE & CVE Extraction API (`localhost:8080`)

### API Contract Analysis (`http://localhost:8080`)
Verified via live testing against the running FastAPI service:
* **Endpoint:** `POST /api/v1/enrich_snippet`
* **Request Schema:**
  ```json
  {
    "code_snippet": "char buf[10]; sprintf(buf, \"%s\", input);",
    "language": "c",
    "flaw_summary": "Buffer overflow using sprintf",
    "package_name": "opencv"
  }
  ```
* **Response Schema:**
  ```json
  {
    "cwe_id": "CWE-120",
    "cwe_title": "CWE-120 (Buffer Copy without Checking Size of Input ('Classic Buffer Overflow'))",
    "cve_id": "N/A",
    "is_known_library_cve": false,
    "top_similarity": 0.5571,
    "nvd_severity": "HIGH",
    "language": "c",
    "closest_reference_cve": "CVE-2018-10528",
    "candidate_matches": [ ... ]
  }
  ```
* **Response Latency:** ~450ms per snippet.

### Implementation Blueprint

#### 1. Core Enrichment Module (`qbit-code-reviewer/src/core/cve-enricher.js`)
* Create a dedicated module `enrichFinding(finding, options)`:
  1. Checks if `http://localhost:8080/health` is responsive (with 800ms timeout).
  2. If online:
     * Calls `POST /api/v1/enrich_snippet` with `code_snippet: finding.existing_code || finding.content`, `flaw_summary: finding.content`, `language: detectLanguage(finding.path)`.
     * Maps `cwe_id`, `cwe_title`, `closest_reference_cve`, `nvd_severity`, and `top_similarity` onto the finding object.
  3. If offline or times out:
     * Gracefully keeps `cwe_id: "CWE-Unknown"` and `cve_id: "N/A"`, ensuring scan never blocks or fails if the external API is down.
* Batch processing helper `enrichFindingsBatch(findings)`: Uses `p-limit` (concurrency 4) to rapidly enrich all findings in parallel within 1-2 seconds.

#### 2. Scanner Hook (`qbit-code-reviewer/src/cli/scan-cmd.js`)
* After AST/OCR returns findings:
  ```javascript
  const enriched = await enrichFindingsBatch(result.findings);
  // Persist enriched findings to ocr_output.json
  ```
* In `formatTqdmBar` & real-time stream:
  * When a vulnerability is printed during scan, display:
    `⚡ [#1] CRITICAL | CWE-120 | CVE-2018-10528 calibration.cpp:142`

#### 3. CLI Table Formatters (`qbit-code-reviewer/src/cli/formatters.js`)
* Update `printFindingsTable` to render:
  ```text
  [#1] CRITICAL  [SECURITY]  CWE-120 (Buffer Overflow)  CVE-2018-10528  calibPipeline.cpp:45
       Explanation: Insecure sprintf writes unbounded user data to static buffer.
       Existing:    char buf[10]; sprintf(buf, "%s", input);
       Suggestion:  snprintf(buf, sizeof(buf), "%s", input);
  ```

#### 4. Web UI Dashboard Integration (`qbit-code-reviewer/ui`)
* **Finding Data Model:** Update `Finding` TypeScript interface in `ui/src/types.ts` & `App.tsx`:
  ```typescript
  interface Finding {
    id: string;
    path: string;
    start_line: number;
    severity: 'critical' | 'high' | 'medium' | 'low';
    category: string;
    content: string;
    existing_code?: string;
    suggestion_code?: string;
    cwe_id?: string;
    cwe_title?: string;
    cve_id?: string;
    closest_reference_cve?: string;
    nvd_severity?: string;
    status: 'open' | 'fixing' | 'fixed';
  }
  ```
* **Vulnerability Card UI:**
  * Add MITRE CWE Pill: `[🛡️ CWE-120]` with hover tooltip showing full title. Clicking opens `https://cwe.mitre.org/data/definitions/120.html`.
  * Add Reference CVE Pill: `[⚠️ CVE-2018-10528]`. Clicking opens `https://nvd.nist.gov/vuln/detail/CVE-2018-10528`.
* **Telemetry & Metrics:**
  * Add CWE Distribution stat card to the dashboard header (e.g. `Top Root Cause: CWE-120`).

---

## 4. Phase-by-Phase Execution Plan

| Phase | Component | Key Deliverables | Risk Mitigation |
| :--- | :--- | :--- | :--- |
| **Phase 1** | `cve-enricher.js` | Fast client for `localhost:8080/api/v1/enrich_snippet` with concurrency limiting and timeout fallbacks. | Offline fallback prevents scan failures when API is down. |
| **Phase 2** | CLI Formatter | Color-coded severity chips, CWE/CVE badges, and interactive post-scan prompt in `scan-cmd.js`. | Keep terminal output clean with strip-ansi checks. |
| **Phase 3** | TUI Integration | `/fix ` autocomplete dropdown showing finding IDs, severities, and CWE codes from `ocr_output.json`. | Lazy-load `ocr_output.json` cache on input trigger. |
| **Phase 4** | Web Cockpit UI | Interactive CWE/CVE badges with MITRE & NVD external links; rebuild UI `dist`. | Zero layout shift; graceful degradation if CWE is null. |
| **Phase 5** | Verification | Run scan on test repo (`opencv`), verify CLI output, verify Web UI synchronization, and test prompt-to-fix. | Non-destructive dry run verification. |

---

## 5. User Decision Points

1. **Post-Scan Interaction Style:** Would you prefer the CLI automatically prompts for selection at the end of every scan, or should interaction be primarily driven via typing `/fix ` in the composer?
2. **CWE External Links:** Should the Web UI badges link directly to the official MITRE CWE database (`cwe.mitre.org`) and NIST NVD (`nvd.nist.gov`)?
