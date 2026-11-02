import sqlite3
import pickle
import gzip
import json
import time
import numpy as np
from pathlib import Path

db_path = "/app/qdrant_storage/collection/vulnerability_dataset/storage.sqlite"
out_dir = Path("/app/qdrant_storage")
vec_file = out_dir / "vectors.f16.npy"
meta_file = out_dir / "metadata.json.gz"

print(f"Connecting to {db_path}...")
con = sqlite3.connect(db_path)
cur = con.cursor()
total = cur.execute("SELECT count(*) FROM points").fetchone()[0]
print(f"Total points to convert: {total}")

start_time = time.time()

# Preallocate mmap file on disk
mmap_vecs = np.lib.format.open_memmap(
    str(vec_file),
    mode='w+',
    dtype=np.float16,
    shape=(total, 1536)
)

metadata = []
batch_size = 5000

cur.execute("SELECT id, point FROM points")
count = 0
eps = 1.1920929e-7

while True:
    rows = cur.fetchmany(batch_size)
    if not rows:
        break
    
    batch_vecs = np.zeros((len(rows), 1536), dtype=np.float32)
    for i, (row_id, blob) in enumerate(rows):
        pt = pickle.loads(blob)
        vec = getattr(pt, "vector", None)
        if isinstance(vec, dict):
            vec = next(iter(vec.values()))
        batch_vecs[i] = vec
        
        payload = getattr(pt, "payload", {}) or {}
        metadata.append({
            "id": getattr(pt, "id", count + i),
            "cwe": payload.get("cwe", "UNKNOWN"),
            "cve": payload.get("cve", "N/A"),
            "repo": payload.get("repo", "N/A"),
            "language": payload.get("language", "")
        })

    # Pre-normalize for instant cosine dot product
    norms = np.linalg.norm(batch_vecs, axis=-1, keepdims=True)
    batch_vecs /= np.where(norms != 0.0, norms, eps)
    
    mmap_vecs[count:count + len(rows)] = batch_vecs.astype(np.float16)
    count += len(rows)
    elapsed = time.time() - start_time
    print(f"  Processed {count}/{total} points ({count*100//total}%) in {elapsed:.1f}s...")

del mmap_vecs
print(f"✓ Saved vectors: {vec_file} ({vec_file.stat().st_size / (1024*1024):.1f} MB)")

print(f"Compressing metadata to {meta_file}...")
with gzip.open(meta_file, "wt", encoding="utf-8") as f:
    json.dump(metadata, f)
print(f"✓ Saved metadata: {meta_file} ({meta_file.stat().st_size / 1024:.1f} KB)")
print(f"All done in {time.time() - start_time:.1f}s!")
