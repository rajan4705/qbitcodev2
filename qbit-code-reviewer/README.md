# lodash v4.7.0

The [lodash](https://lodash.com/) library exported as [npm packages](https://www.npmjs.com/browse/keyword/lodash-modularized) per method.

Generated using [lodash-cli](https://www.npmjs.com/package/lodash-cli):
```bash
$ lodash modularize exports=npm -o ./
```
## 🌟 Key Capabilities

1. **Deterministic Vulnerability Analysis (via Open Code Review)**:
   - Full repository auditing (`qbit scan`) or working-tree / branch diff review (`qbit review`).
   - Line-precise defect detection across security, bugs, maintainability, and style.
   - Zero hallucination or position drift thanks to OCR's deterministic file selection and rule-matching engine.

2. **Autonomous Remediation (via OpenCode)**:
   - One-click or CLI command (`qbit fix`) that dispatches OpenCode's agent to update files directly.
   - Handles imports, code formatting, and regression prevention.
   - Safe fallback patcher if external processes are constrained.

3. **Interactive Conversational AI (Chat Studio on CLI & Web)**:
   - Chat directly with Qbit about any vulnerability or code location.
   - Ask for exploit scenarios, standard library alternatives, or backwards compatibility checks.
   - Instruct Qbit in natural language: *"Apply the fix for finding #1, but use bcrypt with cost 12"*.

4. **Shared Local vLLM Inference**:
   - Both Open Code Review and OpenCode connect to the same GPU-accelerated local endpoint:
     `http://127.0.0.1:8000/v1` (`qwen2.5-coder-14b-instruct`).
   - 100% private, local inference with zero cloud API token cost.

---

## 🏗️ Architecture

```
                                  ┌────────────────────────────────────────────────────────┐
                                  │      Local vLLM Server (H100 / GPU - test_vllm.sh)     │
                                  │           Model: qwen2.5-coder-14b-instruct            │
                                  │          OpenAI Endpoint: http://127.0.0.1:8000/v1     │
                                  └──────────────────────────┬─────────────────────────────┘
                                                             │
                                   ┌─────────────────────────┴─────────────────────────┐
                                   ▼                                                   ▼
┌──────────────────────────────────────────────────┐        ┌──────────────────────────────────────────────────┐
│             Open Code Review (OCR)               │        │                    OpenCode                      │
│   • Scans repositories & git diffs               │        │   • Reads & edits workspace files                │
│   • High-precision defect identification         │        │   • Autonomous coding agent (plan & build)       │
│   • Emits structured JSON finding objects        │        │   • Applies code updates & verifies integrity    │
└──────────────────────────┬───────────────────────┘        └──────────────────────────▲───────────────────────┘
                           │                                                           │
                           │ 1. Findings (JSON)                                        │ 3. Remediation Prompt
                           ▼                                                           │    + Diff Application
┌──────────────────────────────────────────────────────────────────────────────────────┴───────────────────────┐
│                                       QBIT ORCHESTRATION ENGINE                                               │
│                                                                                                              │
│  • Finding Normalizer: Extracts severity, CVEs/vulnerabilities, file:line targets, and code snippets         │
│  • Remediation Synthesizer: Constructs constrained, bug-fixing prompts for OpenCode                          │
│  • Verification Loop: Re-runs OCR against modified files to ensure 0 regressions                            │
└──────────────────────────────────────────────┬───────────────────────────────────────────────────────────────┘
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
         ┌───────────────────────────┐                   ┌───────────────────────────┐
         │         QBIT CLI          │                   │        QBIT WEB UI        │
         │  • Interactive Terminal   │                   │  • Dashboard & Diff View  │
         │  • qbit scan / review     │                   │  • Severity Filter Cards  │
         │  • qbit fix --interactive │                   │  • One-Click "Fix" Button │
         │  • qbit chat              │                   │  • Real-Time Chat Studio  │
         └───────────────────────────┘                   └───────────────────────────┘
```

---

## 🚀 Quickstart

### 1. Run Automated Setup
Run the setup script to configure both OCR and OpenCode for vLLM:
```bash
cd qbit-code-reviewer
./scripts/setup.sh
```

### 2. Launch the Web Cockpit
```bash
qbit ui
# Or specify a custom port:
qbit ui --port 5432
```
Visit **http://localhost:5432** in your browser.

---

## 💻 CLI Commands

### 🔍 Vulnerability Scan (`qbit scan`)
Scan the current workspace or a specific subdirectory:
```bash
qbit scan
qbit scan src/auth/
```

### 🔎 Git Diff Review (`qbit review`)
Review uncommitted or staged changes:
```bash
qbit review           # Review unstaged changes
qbit review --staged  # Review staged changes
```

### ⚡ Autonomous Fix (`qbit fix`)
Apply suggested fixes directly into your files using OpenCode:
```bash
qbit fix              # Interactive prompt: select which findings to patch
qbit fix --all        # Fix all detected vulnerabilities automatically
qbit fix --id 1       # Fix a specific finding number
```

### 💬 Interactive Chat (`qbit chat`)
Chat directly with Qbit in the terminal:
```bash
qbit chat
qbit chat --finding 1  # Pre-seed chat with context from finding #1
```

Inside the chat REPL:
- Type your questions (e.g. *"Explain why timing attacks work on HMAC"*)
- Type `fix <#>` to immediately dispatch OpenCode to patch the file
- Type `findings` to review active issues
- Type `exit` to quit

---

## 🌐 Web Cockpit Features

- **Metric Cards**: Real-time counter of total, critical, medium, and remediated vulnerabilities.
- **Diff Viewer (Option 2 style)**: Line-by-line syntax-highlighted diffs showing `existing_code` in red vs `suggestion_code` in green.
- **One-Click Remediation**: Click **"⚡ Apply Fix with OpenCode"** on any card to patch the file and view streaming logs in the execution drawer.
- **Interactive Chat Studio**: Multi-turn chat pane with token streaming via local vLLM.
- **Discuss in Chat**: Click **"💬 Discuss in Chat"** on any finding card to immediately inject the file location and code context into the conversation.
- **Batch Remediation**: Select multiple finding checkboxes and click **"⚡ Fix Selected"**.
- **Settings Modal**: Verify vLLM server health and configure custom model endpoints.

---

## 🔁 Continuous Self-Healing Pipeline

Run the automated closed-loop script:
```bash
./scripts/pipeline.sh
```

**Pipeline Flow:**
1. **Detection**: OCR scans the repository and outputs structured findings.
2. **Remediation**: OpenCode autonomously patches the affected source code files.
3. **Verification**: Git status and diffs are validated to ensure clean, working updates.
4. **Completion**: Emits a verified remediation summary ready for commit or PR.

---

## ⚙️ Configuration & Environment

Configuration is stored in `~/.qbit/config.json` or configured via environment variables:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `VLLM_URL` | `http://127.0.0.1:8000/v1` | Local vLLM server endpoint |
| `VLLM_MODEL` | `qwen2.5-coder-14b-instruct` | Served model identifier |
| `PORT` | `5432` | Web Cockpit server port |
| `OCR_PATH` | `~/.local/bin/ocr` | Open Code Review binary |
| `OPENCODE_PATH` | `~/.opencode/bin/opencode` | OpenCode binary |
