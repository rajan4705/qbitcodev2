# 📋 Master Task Checklist: Verification, Migration, & Testing

This checklist tracks testing and operational readiness across all newly built systems:

---

### Phase 1: Dynamic vLLM AI Model Switching & Concurrency
- [x] Download **Qwen2.5-Coder-14B-Instruct** into `qbitcode/models/` (28 GB, 6 safetensor shards).
- [x] Centralize **Qwen3-Coder-30B-A3B-Instruct** into `qbitcode/models/` (57 GB, 16 shards).
- [x] Implement core model manager [`vllm-manager.js`](file:///home/minakshi.katoch/Desktop/qbitcode/qbit-code-reviewer/src/core/vllm-manager.js) with clean VRAM deallocation (`pkill -9 -f "VLLM::"`).
- [x] Wire dynamic OCR runner concurrency (8 workers for 14B, 4 workers for 30B).
- [x] Implement CLI command: `qbit vllm` and `qbit vllm switch [14b|30b]`.
- [x] Implement OpenCode TUI slash command: `/vllm` (with aliases `/gpu`, `/engine`).
- [x] Implement Web UI dynamic `<select>` dropdown populated from disk.
- [x] Wire dynamic scan estimator recalculation upon model switch.
- [x] Test live vLLM switch from 30B to 14B (verified active on port 8000).

---

### Phase 2: Microservices & Database Verification
- [x] **Qdrant Vector DB** (`:6333`): Verify 3.3 GB storage with 206,000+ CWE/CVE embeddings.
- [x] **SAST Threat Attribution Engine** (`:8080`): Verify health endpoint and Jina 1.5B GPU embedding pipeline.
- [x] **Universal SCA Package Engine** (`:8082`): Verify 138 MB SQLite database (`vulnerabilities.db`) with 185,000+ OSV advisories across 13 languages.
- [x] Ensure all microservices run in isolated network (`codechecker-net`).

---

### Phase 3: Single-Command Deployment & Operations
- [x] Create comprehensive setup script: [`scripts/deploy_complete_pipeline.sh`](file:///home/minakshi.katoch/Desktop/qbitcode/scripts/deploy_complete_pipeline.sh).
- [x] Create master daily orchestrator: [`scripts/qbitcode`](file:///home/minakshi.katoch/Desktop/qbitcode/scripts/qbitcode) (symlinked to `~/.local/bin/qbitcode`).
- [x] Test boot sequence order: Containers (:6333, :8080, :8082) &rarr; vLLM (:8000) &rarr; Web UI (:5432) &rarr; OpenCode TUI.

---

### Phase 4: Migration & Backup Readiness
- [x] Measure total disk footprint:
  - Core code + microservice DBs: **~3.5 GB**.
  - Pipeline + 14B model: **~31.5 GB**.
  - Pipeline + both models: **~88.5 GB**.
- [x] Calculate SCP transfer benchmarks (100 Mbps, 1 Gbps, 10 Gbps).
- [x] Document step-by-step tar/scp transfer procedure.
- [x] Export exact Conda environment: [`environment_conda.yml`](file:///home/minakshi.katoch/Desktop/qbitcode/environment_conda.yml).
- [x] Export full pip freeze dependencies: [`requirements_vllm_qwen3.txt`](file:///home/minakshi.katoch/Desktop/qbitcode/requirements_vllm_qwen3.txt).
- [x] Document Node.js, Bun, NPM, CUDA, and OS prerequisites.

---

### Phase 5: Documentation & Architecture
- [x] Publish comprehensive documentation: [`docs/PIPELINE_ARCHITECTURE_AND_OPERATIONS.md`](file:///home/minakshi.katoch/Desktop/qbitcode/docs/PIPELINE_ARCHITECTURE_AND_OPERATIONS.md).
- [x] Include Mermaid pipeline architecture diagram.
- [x] Include complete REST API catalog and payload schemas.
- [x] Include CLI, TUI slash commands, and Web Cockpit navigation guide.
- [x] Document cost reductions and performance optimization metrics.

---

### Phase 6: Hugging Face Threat Intelligence Hosting & Deployment
- [x] Create public Hugging Face dataset repository: [`saad0503/qbitcode-dbs`](https://huggingface.co/datasets/saad0503/qbitcode-dbs).
- [x] Package and upload `sca_vulnerabilities_db.zip` (33 MB, 185k+ OSV advisories).
- [x] Package and upload `sast_nvd_index.zip` (1.2 MB, NVD CVE index).
- [x] Package and upload `qdrant_storage.tar.gz` (760 MB, 206k threat vectors).
- [x] Wire official Jina 1.5B direct download from [`jinaai/jina-code-embeddings-1.5b`](https://huggingface.co/jinaai/jina-code-embeddings-1.5b).
- [x] Create single-command database downloader: [`scripts/download_databases.sh`](file:///home/minakshi.katoch/Desktop/qbitcode/scripts/download_databases.sh).
- [x] Create simplified microservices launcher: [`scripts/launch_services.sh`](file:///home/minakshi.katoch/Desktop/qbitcode/scripts/launch_services.sh).
- [x] Update `setup.sh`, `scripts/qbitcode`, and `README.md` with streamlined database workflows.
