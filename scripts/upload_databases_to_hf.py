#!/usr/bin/env python3
"""
Upload QbitCode pre-indexed databases to Hugging Face Hub dataset repository.
Uploads:
1. sca_vulnerabilities_db.zip (~33 MB) -> 185k+ OSV SQLite vulnerability DB (:8082)
2. sast_nvd_index.zip (~1.2 MB) -> NVD CVE metadata mapping (:8080)
3. qdrant_storage.tar.gz (~760 MB) -> Qdrant vector database (206k embeddings) (:6333)
"""

import os
import sys
from pathlib import Path
from huggingface_hub import HfApi

REPO_ID = "saad0503/qbitcode-dbs"
SCRIPT_DIR = Path(__file__).parent.resolve()
ROOT_DIR = SCRIPT_DIR.parent
UPLOAD_DIR = Path("/tmp/hf_upload")

# Read token
token = os.environ.get("HF_TOKEN")
if not token:
    env_file = ROOT_DIR / ".env.hftoken"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HF_TOKEN="):
                token = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

if not token:
    print("❌ Error: HF_TOKEN not found in environment or .env.hftoken")
    sys.exit(1)

api = HfApi(token=token)

print(f"🚀 Initializing upload to Hugging Face: https://huggingface.co/datasets/{REPO_ID}")

# Ensure repo exists
api.create_repo(repo_id=REPO_ID, repo_type="dataset", private=False, exist_ok=True)
print(f"✓ Repository ready: {REPO_ID}")

FILES_TO_UPLOAD = [
    ("README.md", "README.md", "Dataset documentation"),
    ("sca_vulnerabilities_db.zip", "sca_vulnerabilities_db.zip", "SCA package vulnerabilities SQLite database"),
    ("sast_nvd_index.zip", "sast_nvd_index.zip", "SAST NVD CVE index catalog"),
    ("qdrant_storage.tar.gz", "qdrant_storage.tar.gz", "Qdrant vector collection storage (206k vectors)"),
]

for filename, repo_path, msg in FILES_TO_UPLOAD:
    filepath = UPLOAD_DIR / filename
    if not filepath.exists():
        print(f"⚠️ Warning: File not found: {filepath}, skipping...")
        continue
    size_mb = filepath.stat().st_size / (1024 * 1024)
    print(f"\n⏳ Uploading {filename} ({size_mb:.1f} MB)...")
    try:
        api.upload_file(
            path_or_fileobj=str(filepath),
            path_in_repo=repo_path,
            repo_id=REPO_ID,
            repo_type="dataset",
            commit_message=f"Add {msg}",
        )
        print(f"✓ Successfully uploaded: {filename}")
    except Exception as e:
        print(f"❌ Failed to upload {filename}: {e}")

print("\n" + "=" * 60)
print(f"🎉 All databases uploaded successfully to: https://huggingface.co/datasets/{REPO_ID}")
print("=" * 60)
