# Codechecker Container Infrastructure

Standalone, self-contained Docker microservices for the Codechecker security platform.

All models, vector indices, vulnerability databases, and dependencies are baked directly into the images so the platform runs fully offline without external network requirements.

---

## Architecture & Ports

| Service | Container Name | Port | Description | Acceleration |
| :--- | :--- | :--- | :--- | :--- |
| **Qdrant** | `codechecker-qdrant` | `6333` (REST), `6334` (gRPC) | Vector DB with 206k vulnerability vectors | CPU |
| **SAST Engine** | `codechecker-sast` | `8080` (Web UI & REST) | CWE/CVE Threat Attribution & Jina 1.5B | GPU (CUDA 13.0) |
| **SCA Engine** | `codechecker-sca` | `8082` (Web UI & REST) | 13-Language Dependency Scanner & OSV DB | CPU |
| **Web Cockpit** | `codechecker-ui` | `5433` (maps to `5432`) | Cyberpunk Web Cockpit GUI & Review Orchestrator | CPU |

---

## Directory Contents

```
services/
├── Dockerfile.qdrant    # Standalone Qdrant image with baked-in vector storage
├── Dockerfile.sast      # Standalone SAST image with Jina-1.5B, NVD index & GPU support
├── Dockerfile.sca       # Standalone SCA image with SQLite OSV database (305k records)
├── Dockerfile.ui        # Standalone Web Cockpit UI & OCR runner container
├── docker-compose.yml   # Multi-service production compose configuration
├── clean.sh             # Dedicated cleanup: removes all containers, images, and frees disk space
├── deploy.sh            # Builds and launches the containers on production ports
├── down.sh              # Stops all running Codechecker containers
├── verify.sh            # 8-point health & functional test suite for the running APIs & GUI
├── export_images.sh     # Bundles built images for 100% offline deployment on other machines
└── README.md            # This documentation
```

---

## Quick Start

### 1. Launch Services
Run the automated deployment script from this directory:
```bash
sudo ./deploy.sh
```
Or start directly via Docker Compose:
```bash
sudo docker compose -f docker-compose.yml up -d
```

### 2. Verify Deployment
Run the automated verification suite:
```bash
./verify.sh
```

---

## Access Points

- **SAST Dashboard**: [http://localhost:8080/](http://localhost:8080/)
- **SAST Swagger API**: [http://localhost:8080/docs](http://localhost:8080/docs)
- **SCA Dashboard**: [http://localhost:8082/](http://localhost:8082/)
- **SCA Swagger API**: [http://localhost:8082/docs](http://localhost:8082/docs)
- **Qdrant Web UI**: [http://localhost:6333/dashboard](http://localhost:6333/dashboard)

---

## Management Cheatsheet

```bash
# View running status
sudo docker compose ps

# View live logs
sudo docker compose logs -f

# View logs for a specific service
sudo docker compose logs -f sast-api

# Restart a service
sudo docker compose restart sast-api

# Stop all services
sudo docker compose down
```

---

## Moving to Another System

### Option A: Transfer Built Images (Fastest & Zero-Build)
Export the already-built standalone images:
```bash
sudo ./export_images.sh
```
Copy the resulting `exported_images/` folder to the target system and run:
```bash
sudo ./load_and_run.sh
```

### Option B: Build from Source on Target System
Only copy the required folders (~6.5 GB):
```bash
tar -czvf codechecker_portable.tar.gz \
  docker/ \
  .dockerignore \
  API_qdrant_Vul_db/Qdrant_Api/ \
  API_qdrant_Vul_db/vul_packages/ \
  Project/models/jina-code-embeddings-1.5b/ \
  Project/data/nvd_index.json \
  Project/qdrant_storage/ \
  --exclude='API_qdrant_Vul_db/vul_packages/zips' \
  --exclude='API_qdrant_Vul_db/vul_packages/reports' \
  --exclude='*.db-shm' --exclude='*.db-wal' --exclude='__pycache__'
```
On the target machine:
```bash
tar -xzvf codechecker_portable.tar.gz
cd docker && sudo ./deploy.sh
```


