"""
Configuration for Standalone CWE-ID & CVE-ID Extraction Engine
==============================================================
Defines paths and parameters required for Jina embeddings,
Qdrant vector search, and MITRE CWE / NVD threat attribution.
"""

import os
from pathlib import Path

# Prevent CUDA memory fragmentation
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

# Base Directories
PROJECT_ROOT = Path(__file__).parent.resolve()
MODELS_DIR = Path(os.environ.get("MODELS_DIR", str(PROJECT_ROOT / "models"))).resolve()
DATA_DIR = Path(os.environ.get("DATA_DIR", str(PROJECT_ROOT / "data"))).resolve()
STORAGE_DIR = Path(os.environ.get("STORAGE_DIR", str(PROJECT_ROOT / "qdrant_storage"))).resolve()

# Asset Paths
EMBED_MODEL_PATH = os.environ.get("EMBED_MODEL_PATH", str(MODELS_DIR / "jina-code-embeddings-1.5b"))
NVD_INDEX_PATH = os.environ.get("NVD_INDEX_PATH", str(DATA_DIR / "nvd_index.json"))

# Server Parameters
API_SERVER_HOST = os.environ.get("API_SERVER_HOST", "127.0.0.1")
API_SERVER_PORT = int(os.environ.get("API_SERVER_PORT", "8080"))
API_SERVER_URL = f"http://{API_SERVER_HOST}:{API_SERVER_PORT}"

# Qdrant Database Parameters
COLLECTION_NAME = os.environ.get("COLLECTION_NAME", "vulnerability_dataset")
QDRANT_HOST = os.environ.get("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.environ.get("QDRANT_PORT", "6333"))
MIN_LANG_MATCHES = 5
RAG_MAX_SEQ_LENGTH = 512

# Extraction & Matching Parameters
SIMILARITY_THRESHOLD = 0.85
EMBED_BATCH_SIZE = 128
EMBED_DIM = 1536
MIN_RAG_SCORE = 0.30
LANG_MIN_RAG_SCORE = {
    'c': 0.35,
    'cpp': 0.35,
    'java': 0.32,
    'python': 0.30,
    'javascript': 0.30,
    'csharp': 0.32,
    'go': 0.30,
    'rust': 0.30,
}

# File extension to normalized language key
EXT_TO_LANG = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".cs": "csharp",
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".php": "php",
    ".rb": "ruby",
    ".cu": "cpp", ".cuh": "cpp"
}

# File extension to Qdrant language payload capitalization
EXT_TO_QDRANT_LANG = {
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++", ".hxx": "C++",
    ".cs": "C#",
    ".py": "Python", ".pyw": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin", ".kts": "Kotlin",
    ".swift": "Swift",
    ".php": "PHP",
    ".rb": "Ruby",
    ".cu": "C++", ".cuh": "C++"
}
