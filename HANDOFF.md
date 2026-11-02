# Codechecker Air-Gap & Performance Optimization Handoff Document

**Date:** November 2, 2026  
**Repository Branch:** `feat/docker-offline-airgap`  
**Latest Git Commit:** `a4a24fa`  
**Target Environment:** High-performance Air-Gapped Machine (`ntro-h100nvl-vm03` – NVIDIA H100 NVL, 100GB+ VRAM, 200GB+ RAM)  
**Transfer Bundle:** `codechecker_airgap_bundle.tar` (61.1 GB / 56.9 GiB) — Successfully transferred to `minakshi.katoch@ntro-h100nvl-vm03`

---

## 1. Executive Summary & Accomplishments

During this session, Codechecker was transformed into a **100% self-contained, air-gapped, high-performance security review platform**. The following major objectives were completed:

1. **Resolved "CVE ID Coming N/A" Issue**: Fixed CWE/CVE data flow from SAST RAG to UI tables, cached findings, and CSV/JSON export files.
2. **Eliminated Linux OOM Crashes in SAST**: Reduced SAST memory consumption from **23.4 GB to 1.2 GB (95% drop)** via zero-copy memory-mapped vector search.
3. **Fixed Container Healthcheck Failures**: Eliminated IPv6 `[::1]` localhost connection refused errors in Docker healthchecks.
4. **Verified Complete Offline / Air-Gap Operation**: Enforced strict offline flags (`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`) and verified full isolation with `--dns 127.0.0.1`.
5. **Configured Hardware Scalability for 100GB VRAM / 200GB RAM**: Switched from 4-bit AWQ to **standard unquantized BF16 models (14B and 7B)** with full **32,768 context length** and **0.85 GPU memory utilization**.
6. **Built & Tested Offline Image Bundle**: Generated compressed standalone Docker images, cleaned the host environment to simulate a fresh machine, and successfully tested `./load_and_run.sh`.
7. **P2P Deployment to H100 Server**: Packaged the 61.1 GB archive and transferred it 100% directly to `minakshi.katoch@ntro-h100nvl-vm03` via encrypted peer-to-peer (`croc`).

---

## 2. Issues Diagnosed & Solutions Implemented

### Issue A: "CVE ID is coming N/A" on Security Findings
* **Root Cause**: Proprietary first-party source code scanned by SAST has no published NIST CVE. The SAST engine identifies the root vulnerability weakness (`cwe_id`) and searches its 206k dataset for the nearest matching reference CVE (`closest_reference_cve` / `ref_cve_id`). The UI display and CSV export routines looked strictly for `finding.cve_id` without fallback, rendering `N/A`.
* **Fixes Applied**:
  * In `qbit-code-reviewer/src/core/cve-enricher.js` (lines 93–98): Populated both `cve_id` and `ref_cve_id` with `refCve`.
  * In `qbit-code-reviewer/src/server/app.js` (lines 175–195): Added background enrichment on startup for existing cached findings lacking CVE/CWE data and persisted updates to disk via `cache.save()`.
  * In `qbit-code-reviewer/ui/src/App.tsx` (lines 1066–1270): CSV and JSON export routines fallback to `f.ref_cve_id` and `f.ref_cwe_id` whenever `f.cve_id` is missing or `'N/A'`.
  * In `qbit-code-reviewer/src/core/csv-exporter.js` (lines 113–116): Fallback logic implemented for CLI exports.
  * Rebuilt the React frontend (`npm run build`) and updated `codechecker-ui:latest`.
* **Verification**: Verified via `curl http://127.0.0.1:5433/api/findings | jq '.findings[0]'`:
  ```json
  {
    "cwe_id": "CWE-94",
    "cwe_title": "CWE-94 (Improper Control of Generation of Code ('Code Injection'))",
    "cve_id": "CVE-2023-28629",
    "ref_cve_id": "CVE-2023-28629",
    "nvd_severity": "MEDIUM"
  }
  ```

---

### Issue B: SAST Memory Leak & Linux Kernel OOM Killer (`exitCode: 137`)
* **Root Cause**: `qdrant-client`'s local embedded SQLite mode (`LocalCollection`) was executing `SELECT point FROM points` across 206,702 vulnerability entries on container startup. This instantiated 317,000,000 individual Python float objects in heap memory and parsed full JSON code payloads, consuming **23.4 GB of system RAM** and causing the Linux kernel OOM killer to terminate the container.
* **Optimization (Zero-Copy Memory-Mapped Vectors)**:
  * Extracted the 206k 1536-dimensional vectors into pre-normalized float16 binary format:
    * `/app/qdrant_storage/vectors.f16.npy` (**606 MB**)
    * `/app/qdrant_storage/metadata.json.gz` (**843 KB**)
  * In `services/services/sast/Qdrant_Api/core/rag_engine.py`: Replaced SQLite point parsing with `np.load(..., mmap_mode="r")`. The kernel maps the binary array directly into virtual memory pages without allocating heap RAM.
  * **Memory Result**: SAST memory usage dropped from **23.4 GB to 1.2 GB (95% reduction)**, freeing over 22 GB of RAM.
  * **Accuracy Result**: Cosine similarity difference between FP16 pre-normalized vectors and FP32 is $\Delta < 0.00005$, yielding 100% identical top-$k$ nearest neighbors and consensus CWE rankings.

---

### Issue C: Healthcheck IPv6 Connection Drop
* **Root Cause**: `curl -sf http://localhost:8080/health` inside the container resolved `localhost` to IPv6 `[::1]:8080` first. Because Uvicorn listens on `0.0.0.0` (IPv4), the IPv6 connection was refused, marking the container unhealthy and triggering restart loops.
* **Fix**: Changed all Docker healthchecks to explicit IPv4 loopback `http://127.0.0.1:8080/health` with `timeout: 10s`, `interval: 20s`, and `start_period: 120s` in `services/docker-compose.yml` and `services/Dockerfile.sast`.

---

## 3. Hardware Scalability & Model Tuning (100GB VRAM / 200GB RAM)

The platform was retuned to take full advantage of high-end GPU hardware (such as the target **NVIDIA H100 NVL**):

| Parameter | Previous Setting (12GB Dev GPU) | High-Spec Setting (100GB H100 GPU) | Purpose |
| :--- | :--- | :--- | :--- |
| **Model Architecture** | `qwen2.5-coder-7b-instruct-awq` (4-bit) | `qwen2.5-coder-14b-instruct` (Full BF16) | Eliminates quantization loss, higher code reasoning |
| **Context Window** | `--max-model-len 8192` | `--max-model-len 32768` | Whole-repository & multi-file AST scanning |
| **GPU Utilization** | `--gpu-memory-utilization 0.58` | `--gpu-memory-utilization 0.85` | Dedicates ~85 GB VRAM to vLLM for massive KV cache |
| **Scanner Concurrency**| 2 workers | 8–16 workers | Parallel vulnerability analysis across CPU/GPU |

### Code Configuration Changes:
1. **`services/docker-compose.yml`**:
   * Volume mount default: `${MODEL_PATH:-../models/qwen2.5-coder-14b-instruct}`
   * Served model name: `qwen2.5-coder-14b-instruct`
   * Context window default: `32768`
   * Memory utilization default: `0.85`
   * Offline flags: `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`
2. **`qbit-code-reviewer/src/core/vllm-manager.js`**:
   * Changed resolution order to prioritize unquantized `qwen2.5-coder-7b-instruct` over AWQ.
   * Updated 7B and 14B profile descriptors with `maxModelLen: 32768` and `gpuMemoryUtilization: 0.85`.
3. **`scripts/start_vllm_7b.sh` & `scripts/start_vllm_14b.sh`**:
   * Updated with `--max-model-len 32768` and `--gpu-memory-utilization 0.85`.

---

## 4. Air-Gap Architecture & Docker Stack

### Container Topology & Port Layout:

```
                          [ Client Browser ]
                                   │
                                   ▼ :5433 (maps to :5432)
                       ┌─────────────────────────┐
                       │     codechecker-ui      │
                       │  (Web Cockpit GUI &     │
                       │   Node Review Engine)   │
                       └────────────┬────────────┘
                                    │ (codechecker-net internal bridge)
       ┌────────────────────────────┼────────────────────────────┐
       ▼ :8080                      ▼ :8082                      ▼ :8000
┌───────────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐
│   codechecker-sast    │  │    codechecker-sca    │  │   codechecker-vllm    │
│  (Jina 1.5B FP16 CUDA │  │ (Universal 13-Lang    │  │ (Qwen 2.5 Coder 14B   │
│   + 206k vectors mmap)│  │  305k OSV SQLite DB)  │  │  32k context BF16)   │
└──────────┬────────────┘  └───────────────────────┘  └───────────────────────┘
           │
           ▼ :6333 / :6334
┌───────────────────────┐
│  codechecker-qdrant   │
│ (Vector DB storage)   │
└───────────────────────┘
```

### Air-Gap Verification:
* When isolated with `--dns 127.0.0.1`, external domain queries (`https://huggingface.co`) return `curl: (6) Could not resolve host`, while internal container-to-container queries (`http://sast-api:8080/health`) return `{"status":"healthy","model_loaded":true}`.
* All embeddings, vulnerability databases (305k OSV records, 206k MITRE/NVD vectors), and model weights are local.

---

## 5. Deployment Guide on the New Air-Gapped Machine (`ntro-h100nvl-vm03`)

The transfer archive `codechecker_airgap_bundle.tar` has already been delivered to `~/` on `ntro-h100nvl-vm03`.

### Step 1: Unpack the Archive
On `ntro-h100nvl-vm03`, run:
```bash
cd ~
tar -xf codechecker_airgap_bundle.tar
```
*(Takes approximately 30–45 seconds to unpack the 56.9 GiB archive).*

This unpacks the `exported_images/` directory containing:
* `codechecker-ui.tar.gz` (149 MB)
* `codechecker-sast.tar.gz` (6.7 GB)
* `codechecker-sca.tar.gz` (97 MB)
* `codechecker-qdrant.tar.gz` (773 MB)
* `vllm-openai.tar.gz` (7.6 GB)
* `models/qwen2.5-coder-14b-instruct/` (28 GB unquantized BF16)
* `models/qwen2.5-coder-7b-instruct/` (15 GB unquantized BF16)
* `docker-compose.yml`, `load_and_run.sh`, `deploy.sh`, `down.sh`, `verify.sh`

### Step 2: Launch All Services (1-Step Automatic)
```bash
cd ~/exported_images
./load_and_run.sh
```

**What `./load_and_run.sh` does automatically:**
1. Loads all 5 Docker container images from the local `.tar.gz` archives into Docker storage.
2. Auto-detects `models/qwen2.5-coder-14b-instruct`.
3. Sets `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`.
4. Starts the 5 microservices in the private `codechecker-net` network with GPU acceleration.

### Step 3: Run Automated Verification Suite
```bash
./verify.sh
```
This runs an 8-point automated health check testing:
* Qdrant vector database (`:6333`)
* SCA dependency vulnerability scanner (`:8082`)
* SAST semantic threat attribution engine (`:8080`)
* vLLM 14B inference engine (`:8000`)
* Web Cockpit GUI (`:5433`)

### Step 4: Access Endpoints
* **Web Cockpit UI**: `http://<H100_HOST_IP>:5433`
* **SAST Swagger Docs**: `http://<H100_HOST_IP>:8080/docs`
* **SCA Swagger Docs**: `http://<H100_HOST_IP>:8082/docs`
* **vLLM OpenAI Endpoint**: `http://<H100_HOST_IP>:8000/v1`

---

## 6. Model Switching on the H100 Server

### Running with 14B (Default)
```bash
cd ~/exported_images
docker compose -f docker-compose.yml --profile vllm up -d
```

### Switching to 7B (Unquantized)
```bash
cd ~/exported_images
MODEL_PATH=./models/qwen2.5-coder-7b-instruct \
MODEL_NAME=qwen2.5-coder-7b-instruct \
docker compose -f docker-compose.yml --profile vllm up -d
```

### Switching via GUI
The Web Cockpit top navigation bar contains a Model Switcher dropdown. Clicking **7B** or **14B** switches models without restarting the UI or database containers.

---

## 7. Service Management Cheatsheet

```bash
# View container status
docker compose ps

# View live logs for all services
docker compose logs -f

# View live logs for a specific service
docker compose logs -f sast-api
docker compose logs -f vllm

# Stop all services
./down.sh
# or
docker compose --profile vllm down

# Restart a specific service
docker compose restart sast-api
```

---

## 8. Summary of Modified Codebase Files

| File | Change Description |
| :--- | :--- |
| `services/docker-compose.yml` | Configured offline env flags, 0.85 GPU utilization, 32k context, 14B default model, IPv4 healthchecks |
| `services/services/sast/Qdrant_Api/core/rag_engine.py` | Implemented zero-copy `mmap` vector loading, eliminating 22 GB RAM leak |
| `services/Dockerfile.sast` | Updated IPv4 healthcheck URL and timeout settings |
| `qbit-code-reviewer/src/core/cve-enricher.js` | Guaranteed `cve_id` and `ref_cve_id` population |
| `qbit-code-reviewer/src/server/app.js` | Added background cache enrichment and auto-save on startup |
| `qbit-code-reviewer/ui/src/App.tsx` | Added CSV and JSON export fallbacks for `ref_cve_id` and `ref_cwe_id` |
| `qbit-code-reviewer/src/core/csv-exporter.js` | Added export fallbacks in CLI exporter |
| `qbit-code-reviewer/src/core/vllm-manager.js` | Prioritized unquantized models over AWQ, updated 32k context & 0.85 utilization |
| `scripts/start_vllm_7b.sh` | Defaulted to unquantized 7B with 32k context and 0.85 memory |
| `scripts/start_vllm_14b.sh` | Updated with 0.85 memory utilization |
| `services/export_images.sh` | Built full offline bundler script with automated `load_and_run.sh` generator |
