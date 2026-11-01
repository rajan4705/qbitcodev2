# Standalone CWE-ID & CVE-ID Extraction and Threat Attribution Engine

This directory provides a dedicated, lightweight, production-ready module to extract **MITRE CWE-IDs** (root-cause weakness classification) and **CVE-IDs** (vulnerability attribution) from confirmed vulnerability findings.

---

## 1. Directory Structure

```
Qdrant_Api/
├── api_server.py          # FastAPI REST HTTP server (Port 8080)
├── extractor.py           # Main extraction engine (API + CLI)
├── enrich_scan_results.py # Production enrichment tool for scan-res.json
├── test_extractor.py      # Verification and demo suite
├── config.py              # Configuration & path definitions
├── README.md              # Documentation
├── core/
│   ├── cwe_catalog.py       # Official MITRE CWE taxonomy & language boundary validation
│   ├── rag_engine.py        # Vector search (206,702 Qdrant vectors + Jina embeddings)
│   └── language_profiles.py # Language key normalization
├── data/
│   └── nvd_index.json       # 400k+ NVD CVE catalog with CVSS severities
├── models/
│   └── jina-code-embeddings-1.5b  # Semantic code embedding model
└── qdrant_storage/          # 206k vectors in Qdrant vector database
```

> **Clean & Lightweight:** Operates purely with Jina Code Embeddings, Qdrant vector search, and the MITRE catalog. Uses only ~3.2 GB VRAM, allowing it to run smoothly alongside active GPU processes with zero memory collisions.

---

## 2. Quick Start

### A. Run Verification Test Suite
```bash
/home/minakshi.katoch/anaconda3/envs/mrk_code_vul/bin/python test_extractor.py
```

### B. Enrich Whole Scan Findings (`scan-res.json`)
```bash
/home/minakshi.katoch/anaconda3/envs/mrk_code_vul/bin/python enrich_scan_results.py \
    --input scan-res.json \
    --output scan-res-enriched.json \
    --repo-dir ../opencv
```

### C. Single Code Snippet (CLI)
```bash
/home/minakshi.katoch/anaconda3/envs/mrk_code_vul/bin/python extractor.py \
    --language c \
    --code "char buf[16]; strcpy(buf, input);"
```

---

## 3. Python API Integration

```python
from extractor import CweCveExtractor

# Initialize once (loads Jina embeddings & Qdrant vector index)
extractor = CweCveExtractor()

# Confirmed vulnerability finding
result = extractor.extract(
    code_snippet="""
    def checkin(pickledata):
        return pickle.loads(bz2.decompress(base64.b64decode(pickledata)))
    """,
    language="python",
    flaw_summary="Unsafe deserialization of untrusted data"
)

print(result["cwe_id"])     # 'CWE-502'
print(result["cwe_title"])  # 'CWE-502 (Deserialization of Untrusted Data)'
print(result["cve_id"])     # 'N/A' (or attributed CVE if matching published library)
print(result["nvd_severity"])# 'CRITICAL' / 'HIGH'
```

### B. FastAPI REST Microservice (HTTP API)

Start the server:
```bash
/home/minakshi.katoch/anaconda3/envs/mrk_code_vul/bin/python api_server.py --port 8080
```

Call via `curl`:
```bash
curl -X POST http://localhost:8080/api/v1/enrich_snippet \
  -H "Content-Type: application/json" \
  -d '{
    "code_snippet": "char buf[16]; strcpy(buf, input);",
    "language": "c",
    "flaw_summary": "Classic buffer overflow with strcpy"
  }'
```
Interactive docs at: `http://localhost:8080/docs`

---

## 4. Input & Output Contract

### Output Fields Added to Every Security Finding
| Field | Type | Description |
| :--- | :--- | :--- |
| `cwe_id` | `str` | Exact root-cause MITRE CWE (e.g. `CWE-120`, `CWE-190`, `CWE-79`) |
| `cwe_title` | `str` | Official MITRE CWE title and description |
| `cve_id` | `str` | Attributed public CVE (e.g. `CVE-2023-34095`) or `N/A` for custom code |
| `is_known_library_cve` | `bool` | `True` if matched to a known published CVE with $\ge 85\%$ similarity |
| `top_similarity` | `float` | Cosine similarity score against the nearest historical vector |
| `nvd_severity` | `str` | Official NVD CVSS severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `closest_reference_cve`| `str` | Closest historical reference vulnerability in NVD |
| `candidate_matches` | `list` | Top-3 nearest candidate CVE/CWE matches with similarity scores |
