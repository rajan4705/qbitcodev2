# Universal 13-Language Vulnerability Scanner (`vul_packages`)

Local vulnerability database and automated repository auditing engine powered by Google OSV.

---

## 13 Supported Languages & Ecosystems

| # | Language | Ecosystem | Supported Dependency Manifests | Code Reachability Check |
|---|---|---|---|---|
| 1 | **Python** | `PyPI` | `requirements*.txt`, `requirements/*.txt`, `pyproject.toml`, `Pipfile`, `setup.py` | `import X`, `from X import ...` |
| 2 | **JavaScript** | `npm` | `package.json`, `package-lock.json` | `require('X')`, `import ... from 'X'` |
| 3 | **TypeScript** | `npm` | `package.json`, `package-lock.json` | `require('X')`, `import ... from 'X'` |
| 4 | **Go** | `Go` | `go.mod`, `go.sum` | `import "X"`, `import ( ... "X" ... )` |
| 5 | **Java** | `Maven` | `pom.xml`, `build.gradle`, `libs.versions.toml` | `import ...X...;` |
| 6 | **Kotlin** | `Maven` | `build.gradle.kts`, `pom.xml`, `libs.versions.toml` | `import ...X...;` |
| 7 | **Rust** | `crates.io` | `Cargo.toml`, `Cargo.lock` | `use X::`, `extern crate X;` |
| 8 | **C# / .NET** | `NuGet` | `*.csproj`, `packages.config`, `*.fsproj` | `using X;` |
| 9 | **PHP** | `Packagist` | `composer.json`, `composer.lock` | `use X;`, `require ...;` |
| 10 | **Ruby** | `RubyGems` | `Gemfile`, `Gemfile.lock` | `require 'X'`, `gem 'X'` |
| 11 | **Swift** | `SwiftURL` | `Package.swift`, `Package.resolved` | `import X` |
| 12 | **C** | `OSS-Fuzz` | `conanfile.txt`, `vcpkg.json`, `CMakeLists.txt` | `#include <X...>`, `#include "X..."` |
| 13 | **C++** | `OSS-Fuzz` | `conanfile.txt`, `vcpkg.json`, `CMakeLists.txt` | `#include <X...>`, `#include "X..."` |

---

## Quick Reference Commands

### 1. Scan a Single Repository
```bash
# Scan any single repository:
python vul_packages/scan_repo.py "mock_data/Software_Python/Software Stack Python 2"
```

### 2. Multi-Repo Batch Scanning (All Repositories at Once)
```bash
# Point directly to mock_data or any folder containing multiple repos:
python vul_packages/scan_repo.py mock_data
```
*(It automatically detects all sub-repositories, audits their dependencies across all 13 languages, pinpoints code import locations, and compiles a single aggregated JSON report).*

### 3. Filters & Output Options
```bash
# Focus only on packages actively imported in source code:
python vul_packages/scan_repo.py mock_data --active-only

# Filter by minimum severity:
python vul_packages/scan_repo.py mock_data --min-severity HIGH

# Output pure JSON to stdout (for pipelines or scripts):
python vul_packages/scan_repo.py mock_data --json
```

All results are automatically saved inside:  
[`vul_packages/vulnerability_report.json`](file:///home/minakshi.katoch/Desktop/codechecker/vul_packages/vulnerability_report.json)

---

## REST API Server (Port 8082)

The engine can run as a high-performance REST microservice so teammates, CI/CD workers, or frontends can query it over the network.

### Start the API Server
```bash
python vul_packages/api_server.py --port 8082 --host 0.0.0.0
```

- **Interactive Swagger UI**: `http://localhost:8082/docs`
- **Visual Web Dashboard**: `http://localhost:8082/`
- **Health & DB Stats**: `http://localhost:8082/health`

### Key REST Endpoints

#### 1. Audit an On-Disk Repository or Multi-Repo Folder
```bash
curl -X POST "http://localhost:8082/api/v1/scan" \
     -H "Content-Type: application/json" \
     -d '{
       "target_path": "/home/minakshi.katoch/Desktop/codechecker/mock_data",
       "active_only": false,
       "min_severity": "HIGH",
       "save_report": true
     }'
```

#### 2. Upload and Audit a Repository Archive (.zip or .tar.gz)
```bash
curl -X POST "http://localhost:8082/api/v1/scan/upload" \
     -F "file=@/path/to/my_project.zip" \
     -F "active_only=false"
```

#### 3. Instant Single Package Vulnerability Check
```bash
curl -X POST "http://localhost:8082/api/v1/check/package" \
     -H "Content-Type: application/json" \
     -d '{
       "package": "jinja2",
       "version": "2.3",
       "ecosystem": "PyPI"
     }'
```

#### 4. Audit Raw Manifest Text (In-Memory)
```bash
curl -X POST "http://localhost:8082/api/v1/check/manifest" \
     -H "Content-Type: application/json" \
     -d '{
       "filename": "requirements.txt",
       "content": "jinja2==2.3\nurllib3==1.25.8\nrequests==2.20.0"
     }'
```

---

## Role in the Code Vulnerability Detection Project (`codechecker`)

Modern application security requires a **Two-Pillar Architecture**:

1. **SAST (Static Application Security Testing) / `Qdrant_Api` (Port 8080)**:
   - Detects code flaws, memory safety issues, injection flaws (SQLi, XSS), and logic bugs in **custom first-party code**.
   - Uses Jina 1.5B embeddings + Qdrant vector database to attribute MITRE CWE-IDs.

2. **SCA (Software Composition Analysis) / `vul_packages` (Port 8082)**:
   - Audits the **third-party open-source supply chain** (PyPI, npm, Maven, Crates, Go, etc.) for known CVEs.
   - Computes exact SemVer patched versions (`recommended_fix`).

### The Reachability Bridge (SAST + SCA Unified)
Traditional SCA scanners dump hundreds of dormant alerts. This scanner performs **code reachability analysis**:
- If a package is vulnerable, it scans the repository's source code and extracts the exact `file`, `line`, and `snippet` where the library is actively imported.
- These traces can be piped directly into the SAST pipeline (`Qdrant_Api/enrich_scan_results.py`) to verify if the vulnerable function is actually reached with untrusted user input, turning noisy dependency alerts into validated, high-confidence security findings.
