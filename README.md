# 🛡️ QbitCode Autonomous Security Engine & Pipeline

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CUDA](https://img.shields.io/badge/CUDA-12.x%20%7C%2013.x-green.svg)](https://developer.nvidia.com/cuda-toolkit)
[![vLLM](https://img.shields.io/badge/vLLM-0.31.0-purple.svg)](https://github.com/vllm-project/vllm)
[![Vector DB](https://img.shields.io/badge/Qdrant-206k%2B%20CVEs-red.svg)](https://qdrant.tech/)

> **Autonomous AI-Driven Code Review, CWE/CVE Attribution, Vulnerability Scanning, and Concrete Patch Synthesis Engine.**

---

## ⚡ Quick Start (One Command Setup)

Clone this repository and run the automated installer:

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>

# 1. Run the one-click master setup script:
./setup.sh

# 2. Download the fast 14B model (if not already downloaded):
./scripts/download_models.sh 14b

# 3. Launch the complete pipeline anytime:
qbitcode
```

Running `qbitcode` automatically starts:
1. **Port 6333**: Qdrant Vector Database (206,000+ MITRE CWE/CVE vector embeddings)
2. **Port 8080**: SAST CWE/CVE Threat Attribution Engine (Jina Code 1.5B GPU backend)
3. **Port 8082**: SCA Universal 13-Language Dependency Advisory Engine (SQLite OSV)
4. **Port 8000**: Local vLLM AI Server (`Qwen2.5-Coder-14B-Instruct` or `Qwen3-Coder-30B-A3B-Instruct`)
5. **Port 5432**: Qbit Web Cockpit GUI (`http://localhost:5432`)
6. **Interactive Terminal TUI**: Rich CLI with `/scan`, `/fastscan`, `/findings`, `/vllm`, and `/ui` shortcuts.

---

## 📂 Repository Architecture

```text
├── code-review-engine/      # High-performance Go-based full-file AST scanner ('ocr')
├── terminal-tui/            # Interactive Bun/TypeScript terminal TUI ('opencode')
├── qbit-code-reviewer/      # Express backend & Cyberpunk React Web Cockpit GUI (:5432)
├── services/                # Microservices orchestration (Qdrant, SAST, SCA)
│   ├── docker-compose.yml   # Multi-container service definition
│   ├── Dockerfile.qdrant    # Pre-baked vector database
│   ├── Dockerfile.sast      # GPU-accelerated embedding service
│   ├── Dockerfile.sca       # Universal dependency vulnerability engine
│   └── services/            # Pre-indexed SQLite and vector collections
├── models/                  # Local Hugging Face LLM weights (ignored by git)
│   ├── qwen2.5-coder-14b-instruct/    # 28GB fast bug hunter (8 workers)
│   └── qwen3-coder-30b-a3b-instruct/  # 60GB deep reasoning MoE (4 workers)
├── scripts/
│   ├── qbitcode             # Master one-command pipeline orchestrator
│   ├── download_models.sh   # Automated Hugging Face model downloader
│   ├── start_vllm_14b.sh    # Dedicated 14B vLLM startup script
│   └── start_vllm_30b.sh    # Dedicated 30B vLLM startup script
├── environment_conda.yml    # Complete Conda environment definition
├── requirements_vllm_qwen3.txt # Python pip freeze for vLLM & CUDA
└── setup.sh                 # Master deployment & setup script
```

---

## 🤖 AI Models: 14B vs 30B Dynamic Switching

QbitCode supports live hot-swapping between models without restarting the pipeline:

| Model | Size | Workers | KV Cache | Best Used For |
| :--- | :--- | :--- | :--- | :--- |
| **Qwen2.5-Coder-14B-Instruct** | 28 GB | **8 workers** | FP16/Auto | High-speed sweeps (2x throughput), ultra-low latency, bulk vulnerability audits |
| **Qwen3-Coder-30B-A3B-Instruct** | 60 GB | **4 workers** | FP8 | Complex AST reasoning, formal verification, deep architectural refactoring |

### Switching via Web UI
Open `http://localhost:5432` and select your model from the header dropdown.

### Switching via CLI / TUI
```bash
# Switch to 14B model (8 concurrent workers):
qbit vllm switch 14b

# Switch to 30B model (4 concurrent workers):
qbit vllm switch 30b

# Inspect active status:
qbit vllm
```

---

## 💻 Headless CLI & Automated Benchmark Export

When the Web UI is not used, `qbit scan` provides a fail-safe CLI with full verbose logs and benchmark-compliant CSV export:

```bash
# 1. Full scan exporting directly to RFC 4180 CSV with patches and MITRE CWE/CVE:
qbit scan --format csv --output vulnerabilities.csv

# 2. Scan a specific directory:
qbit scan "path/to/module" --format csv --output module_findings.csv --min-severity high

# 3. FastScan (skips tests, docs, and non-code assets):
qbit fastscan --run-scan

# 4. JSON or SARIF 2.1 telemetry export:
qbit scan --format json --output ocr_output.json
qbit scan --format sarif --output scan.sarif
```

### Generated CSV Columns:
`SNo`, `Repository`, `Primary Language of Benchmark`, `Vulnerability`, `CVE ID`, `Severity`, `Common Weakness Enumeration (CWE) Id`, `Reference IDs`, `filename with path`, `line number`, `Code Snippet at the line`, `Patch`, `Patch Description`.

---

## 💾 Threat Intelligence & Database Setup

The platform uses pre-indexed threat intelligence databases hosted publicly on Hugging Face:
* **Hugging Face Dataset**: [**saad0503/qbitcode-dbs**](https://huggingface.co/datasets/saad0503/qbitcode-dbs)
* **SCA Vulnerability DB** (`vulnerabilities.db`): ~33 MB compressed (~138 MB uncompressed) — 185k+ OSV advisories across 13 languages.
* **Qdrant Vector DB** (`qdrant_storage.tar.gz`): ~760 MB compressed (~3.3 GB uncompressed) — 206k pre-embedded CWE/CVE vectors.
* **SAST NVD Index** (`sast_nvd_index.zip`): ~1.2 MB compressed (~9.6 MB uncompressed).
* **SAST Embedding Model**: Official [**jinaai/jina-code-embeddings-1.5b**](https://huggingface.co/jinaai/jina-code-embeddings-1.5b) on Hugging Face.

### 🚀 One-Command Database Downloader:
On any fresh clone or new server, run:
```bash
./scripts/download_databases.sh
```
This automatically downloads all pre-indexed databases from `saad0503/qbitcode-dbs` and pulls the official Jina 1.5B checkpoint.

### ⚡ Easy Microservices Launcher:
Launch and verify all three security services (:6333 Qdrant, :8080 SAST, :8082 SCA):
```bash
./scripts/launch_services.sh
```

---

## 🛠️ Requirements & Environment Details

- **OS**: Linux (Ubuntu 20.04/22.04 LTS recommended)
- **GPU**: NVIDIA GPU with >= 24 GB VRAM (RTX 3090, RTX 4090, A100, H100)
- **CUDA**: CUDA 12.1+ / 13.x with Driver >= 535
- **Runtimes**:
  - Python 3.10+ (via Conda or system)
  - Node.js >= 18.0.0
  - Go >= 1.22 (for code-review-engine compilation)
  - Docker & Docker Compose
  - Bun >= 1.0 (for terminal-tui)

---

## 📄 License
GNU General Public License v3.0 (GPL-3.0). See [LICENSE](LICENSE) for details.
