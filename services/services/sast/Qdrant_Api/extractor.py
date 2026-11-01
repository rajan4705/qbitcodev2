"""
Dedicated CWE-ID & CVE-ID Extraction and Threat Attribution Engine
==================================================================
Specialized module for extracting root-cause MITRE CWE-IDs and 
attributing known CVE-IDs from confirmed vulnerability findings.

Author: Antigravity AI & Minakshi Katoch
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional

# Ensure local and package modules resolve cleanly
CURRENT_DIR = Path(__file__).parent.resolve()
API_ROOT = CURRENT_DIR.parent.resolve()
WORKSPACE_ROOT = API_ROOT.parent.resolve()

for p in [CURRENT_DIR, API_ROOT, WORKSPACE_ROOT]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    import API_qdrant_Vul_db.Qdrant_Api.config as config
    from API_qdrant_Vul_db.Qdrant_Api.core.rag_engine import RAGEngine
    from API_qdrant_Vul_db.Qdrant_Api.core.cwe_catalog import (
        normalize_cwe, get_cwe_title, is_impossible_managed_memory_cwe, infer_cwe_from_flaw_summary
    )
    from API_qdrant_Vul_db.Qdrant_Api.core.language_profiles import normalize_language_key, get_language_profile
except ImportError:
    try:
        from Qdrant_Api import config
        from Qdrant_Api.core.rag_engine import RAGEngine
        from Qdrant_Api.core.cwe_catalog import (
            normalize_cwe, get_cwe_title, is_impossible_managed_memory_cwe, infer_cwe_from_flaw_summary
        )
        from Qdrant_Api.core.language_profiles import normalize_language_key, get_language_profile
    except ImportError:
        import config
        from core.rag_engine import RAGEngine
        from core.cwe_catalog import (
            normalize_cwe, get_cwe_title, is_impossible_managed_memory_cwe, infer_cwe_from_flaw_summary
        )
        from core.language_profiles import normalize_language_key, get_language_profile


class CweCveExtractor:
    """
    High-Precision CWE-ID and CVE-ID Extraction and Threat Attribution Engine.
    Combines Jina Code Embeddings (1.5B), 206,702 Qdrant vector patterns,
    400k+ NVD CVE records, and MITRE hierarchical taxonomy deduction.
    """

    def __init__(self, enable_llm: bool = False, force_local: bool = False, api_url: Optional[str] = None):
        """
        Initialize the extraction engine.
        If an API server is already running, seamlessly connects via client mode
        to prevent duplicate GPU VRAM usage and database locks. Otherwise loads in-memory.
        """
        self.remote_mode = False
        self.api_url = api_url or getattr(config, "API_SERVER_URL", "http://127.0.0.1:8080")
        self.rag: Optional[RAGEngine] = None

        if not force_local and self._check_api_server(self.api_url):
            print(f"✓ Connected to live Extraction Server at {self.api_url} (Fast Client Mode)")
            self.remote_mode = True
            return

        print("Initializing CWE & CVE Extraction Engine (Jina + Qdrant + MITRE)...")
        self.rag = RAGEngine()
        connected = self.rag.connect()
        if not connected:
            if self._check_api_server(self.api_url):
                print(f"  Local storage locked; falling back to live API server at {self.api_url}")
                self.remote_mode = True
                return
            raise RuntimeError("Could not connect to Qdrant storage or live API server.")

        self.rag.load_embedding_model()
        print("✓ Extraction Engine ready!")

    def _check_api_server(self, base_url: str) -> bool:
        """Check if an existing API server instance is responsive."""
        try:
            import urllib.request
            req = urllib.request.Request(f"{base_url}/health", headers={"User-Agent": "CweCveExtractor"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("status") == "healthy"
        except Exception:
            pass
        return False

    def extract(
        self,
        code_snippet: str,
        language: str = "c",
        flaw_summary: str = "",
        package_name: str = "",
        min_similarity_threshold: float = config.SIMILARITY_THRESHOLD
    ) -> Dict[str, Any]:
        """
        Extract exact root-cause CWE-ID and candidate/attributed CVE-ID for a vulnerability.
        
        :param code_snippet: The vulnerable code block / function body
        :param language: Programming language (e.g., 'python', 'c', 'go', 'javascript', etc.)
        :param flaw_summary: Optional defect description provided by the vulnerability detector
        :param package_name: Optional library / repository name
        :param min_similarity_threshold: Minimum cosine similarity to attribute an exact CVE (default: 0.85)
        :return: Standardized dictionary containing CWE-ID, CVE-ID, severity, and references
        """
        lang_norm = normalize_language_key(language)

        if not code_snippet or not str(code_snippet).strip():
            return {
                "cwe_id": "NONE",
                "cwe_title": "NONE",
                "cve_id": "N/A",
                "is_known_library_cve": False,
                "top_similarity": 0.0,
                "nvd_severity": "LOW",
                "language": lang_norm,
                "closest_reference_cve": "N/A",
                "candidate_matches": []
            }

        if self.remote_mode:
            return self._remote_extract(code_snippet, lang_norm, flaw_summary, package_name, min_similarity_threshold)

        # 0. Deduce semantic weakness indicator from flaw summary
        semantic_cwe = infer_cwe_from_flaw_summary(flaw_summary, language=lang_norm, code_snippet=code_snippet)
        if semantic_cwe:
            semantic_cwe = normalize_cwe(semantic_cwe)

        # 1. Vector Search against 206,702 historical vulnerability patterns
        q_vec = self.rag.encode_code(code_snippet)
        top_matches = self.rag.query_qdrant(q_vec, language=lang_norm, limit=6)

        best_cwe = semantic_cwe or "CWE-UNKNOWN"
        best_cve = "N/A"
        top_score = 0.0
        candidate_matches = []
        cwe_vote_counts: Dict[str, float] = {}

        cve_pat = re.compile(r'^(CVE-\d{4}-\d{4,7}|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})$', re.IGNORECASE)

        if top_matches:
            top_hit = top_matches[0]
            top_score = float(getattr(top_hit, "score", 0.0) or 0.0)

            for hit in top_matches:
                payload = getattr(hit, "payload", {}) or {}
                if not isinstance(payload, dict):
                    continue
                h_cve = str(payload.get("cve", "N/A")).strip().upper()
                h_cwe = normalize_cwe(str(payload.get("cwe", "UNKNOWN")).strip())
                h_score = float(getattr(hit, "score", 0.0) or 0.0)

                # Collect candidate references
                candidate_matches.append({
                    "cve_id": h_cve,
                    "cwe_id": h_cwe,
                    "similarity": round(h_score, 4),
                    "repo": payload.get("repo", "N/A")
                })

                # Weighted voting for consensus CWE
                if h_cwe not in ("UNKNOWN", "NONE", "N/A"):
                    # Validate against impossible managed memory CWEs
                    if not is_impossible_managed_memory_cwe(lang_norm, h_cwe, code_snippet):
                        weight = h_score ** 2
                        # Match regex numbers safely
                        m_h = re.search(r'\d+', h_cwe)
                        m_s = re.search(r'\d+', semantic_cwe) if semantic_cwe else None
                        if semantic_cwe and (h_cwe == semantic_cwe or (m_h and m_s and m_h.group(0) == m_s.group(0))):
                            weight *= 3.0
                        cwe_vote_counts[h_cwe] = cwe_vote_counts.get(h_cwe, 0.0) + weight

            # Consensus CWE from weighted nearest neighbors
            if cwe_vote_counts:
                consensus_cwe = max(cwe_vote_counts.items(), key=lambda x: x[1])[0]
                if semantic_cwe and (top_score < min_similarity_threshold or consensus_cwe in ("UNKNOWN", "NONE", "CWE-UNKNOWN")):
                    best_cwe = semantic_cwe
                else:
                    best_cwe = consensus_cwe
            elif semantic_cwe:
                best_cwe = semantic_cwe
            else:
                top_payload = getattr(top_hit, "payload", {}) or {}
                raw_cwe = normalize_cwe(str(top_payload.get("cwe", "UNKNOWN")).strip())
                if raw_cwe not in ("UNKNOWN", "NONE", "N/A") and not is_impossible_managed_memory_cwe(lang_norm, raw_cwe, code_snippet):
                    best_cwe = raw_cwe

            # 2. CVE Attribution
            # Direct attribution if vector match is highly similar (>= threshold)
            for cand in candidate_matches:
                cand_cve = cand["cve_id"]
                cand_score = cand["similarity"]
                if cand_score >= min_similarity_threshold and cve_pat.match(cand_cve):
                    best_cve = cand_cve
                    break

        if best_cwe in ("CWE-UNKNOWN", "NONE", "UNKNOWN"):
            best_cwe = semantic_cwe if semantic_cwe else "CWE-20"

        # 3. MITRE CWE Human-Readable Title Lookup
        cwe_full_title = get_cwe_title(best_cwe)

        # 4. Resolve closest reference CVE from candidates
        closest_ref = "N/A"
        for cand in candidate_matches:
            if cve_pat.match(cand["cve_id"]):
                closest_ref = cand["cve_id"]
                break

        # 5. Official NVD Severity Lookup
        nvd_severity = self.rag.get_cve_severity(best_cve, fallback="HIGH")
        if best_cve == "N/A" and closest_ref != "N/A":
            nvd_severity = self.rag.get_cve_severity(closest_ref, fallback="HIGH")

        return {
            "cwe_id": best_cwe,
            "cwe_title": cwe_full_title,
            "cve_id": best_cve,
            "is_known_library_cve": best_cve != "N/A",
            "top_similarity": round(top_score, 4),
            "nvd_severity": nvd_severity,
            "language": lang_norm,
            "closest_reference_cve": closest_ref,
            "candidate_matches": candidate_matches[:3]
        }

    def _remote_extract(self, code_snippet: str, language: str, flaw_summary: str, package_name: str, threshold: float) -> Dict[str, Any]:
        """Query running API server."""
        import urllib.request
        req_data = {
            "code_snippet": code_snippet,
            "language": language,
            "flaw_summary": flaw_summary or "",
            "package_name": package_name or ""
        }
        req = urllib.request.Request(
            f"{self.api_url}/api/v1/enrich_snippet",
            data=json.dumps(req_data).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def extract_batch(self, items: List[Dict[str, Any]], batch_size: int = 128) -> List[Dict[str, Any]]:
        """
        High-throughput batch extraction on lists of vulnerability dictionaries.
        Optimized with GPU-batched embeddings and batched matrix multiplication.
        """
        if not items:
            return []

        # In remote client mode, process sequentially or in chunks
        if self.remote_mode:
            results = []
            for it in items:
                res = self.extract(
                    code_snippet=it.get("code_snippet") or it.get("code") or it.get("existing_code") or "",
                    language=it.get("language") or "c",
                    flaw_summary=it.get("flaw_summary") or it.get("vulnerability_description") or it.get("reason") or it.get("content") or "",
                    package_name=it.get("package_name") or it.get("repo_name") or ""
                )
                results.append({**it, **res})
            return results

        # High-speed GPU batch mode
        results = []
        cve_pat = re.compile(r'^(CVE-\d{4}-\d{4,7}|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})$', re.IGNORECASE)

        for i in range(0, len(items), batch_size):
            chunk = items[i : i + batch_size]
            codes = []
            langs = []
            flaws = []
            valid_indices = []

            for idx, it in enumerate(chunk):
                code = it.get("code_snippet") or it.get("code") or it.get("existing_code") or ""
                lang = normalize_language_key(it.get("language") or "c")
                flaw = it.get("flaw_summary") or it.get("vulnerability_description") or it.get("reason") or it.get("content") or ""
                codes.append(code)
                langs.append(lang)
                flaws.append(flaw)
                if code and str(code).strip():
                    valid_indices.append(idx)

            # Batch encode valid snippets on GPU
            valid_codes = [codes[idx] for idx in valid_indices]
            valid_langs = [langs[idx] for idx in valid_indices]
            if valid_codes:
                vectors = self.rag.encode_code_batch(valid_codes, batch_size=batch_size, show_progress_bar=False)
                all_matches = self.rag._query_qdrant_batch_fast(vectors, valid_langs, limit=6)
            else:
                all_matches = []

            match_map = {idx: matches for idx, matches in zip(valid_indices, all_matches)}

            for idx, it in enumerate(chunk):
                code = codes[idx]
                lang_norm = langs[idx]
                flaw_summary = flaws[idx]

                if not code or not str(code).strip():
                    res = {
                        "cwe_id": "NONE",
                        "cwe_title": "NONE",
                        "cve_id": "N/A",
                        "is_known_library_cve": False,
                        "top_similarity": 0.0,
                        "nvd_severity": "LOW",
                        "language": lang_norm,
                        "closest_reference_cve": "N/A",
                        "candidate_matches": []
                    }
                    results.append({**it, **res})
                    continue

                semantic_cwe = infer_cwe_from_flaw_summary(flaw_summary, language=lang_norm, code_snippet=code)
                if semantic_cwe:
                    semantic_cwe = normalize_cwe(semantic_cwe)

                top_matches = match_map.get(idx, [])
                best_cwe = semantic_cwe or "CWE-UNKNOWN"
                best_cve = "N/A"
                top_score = 0.0
                candidate_matches = []
                cwe_vote_counts = {}

                if top_matches:
                    top_hit = top_matches[0]
                    top_score = float(getattr(top_hit, "score", 0.0) or 0.0)

                    for hit in top_matches:
                        payload = getattr(hit, "payload", {}) or {}
                        if not isinstance(payload, dict):
                            continue
                        h_cve = str(payload.get("cve", "N/A")).strip().upper()
                        h_cwe = normalize_cwe(str(payload.get("cwe", "UNKNOWN")).strip())
                        h_score = float(getattr(hit, "score", 0.0) or 0.0)

                        candidate_matches.append({
                            "cve_id": h_cve,
                            "cwe_id": h_cwe,
                            "similarity": round(h_score, 4),
                            "repo": payload.get("repo", "N/A")
                        })

                        if h_cwe not in ("UNKNOWN", "NONE", "N/A"):
                            if not is_impossible_managed_memory_cwe(lang_norm, h_cwe, code):
                                weight = h_score ** 2
                                m_h = re.search(r'\d+', h_cwe)
                                m_s = re.search(r'\d+', semantic_cwe) if semantic_cwe else None
                                if semantic_cwe and (h_cwe == semantic_cwe or (m_h and m_s and m_h.group(0) == m_s.group(0))):
                                    weight *= 3.0
                                cwe_vote_counts[h_cwe] = cwe_vote_counts.get(h_cwe, 0.0) + weight

                    if cwe_vote_counts:
                        consensus_cwe = max(cwe_vote_counts.items(), key=lambda x: x[1])[0]
                        if semantic_cwe and (top_score < config.SIMILARITY_THRESHOLD or consensus_cwe in ("UNKNOWN", "NONE", "CWE-UNKNOWN")):
                            best_cwe = semantic_cwe
                        else:
                            best_cwe = consensus_cwe
                    elif semantic_cwe:
                        best_cwe = semantic_cwe
                    else:
                        top_payload = getattr(top_hit, "payload", {}) or {}
                        raw_cwe = normalize_cwe(str(top_payload.get("cwe", "UNKNOWN")).strip())
                        if raw_cwe not in ("UNKNOWN", "NONE", "N/A") and not is_impossible_managed_memory_cwe(lang_norm, raw_cwe, code):
                            best_cwe = raw_cwe

                    for cand in candidate_matches:
                        if cand["similarity"] >= config.SIMILARITY_THRESHOLD and cve_pat.match(cand["cve_id"]):
                            best_cve = cand["cve_id"]
                            break

                if best_cwe in ("CWE-UNKNOWN", "NONE", "UNKNOWN"):
                    best_cwe = semantic_cwe if semantic_cwe else "CWE-20"

                cwe_full_title = get_cwe_title(best_cwe)
                closest_ref = "N/A"
                for cand in candidate_matches:
                    if cve_pat.match(cand["cve_id"]):
                        closest_ref = cand["cve_id"]
                        break

                nvd_severity = self.rag.get_cve_severity(best_cve, fallback="HIGH")
                if best_cve == "N/A" and closest_ref != "N/A":
                    nvd_severity = self.rag.get_cve_severity(closest_ref, fallback="HIGH")

                res = {
                    "cwe_id": best_cwe,
                    "cwe_title": cwe_full_title,
                    "cve_id": best_cve,
                    "is_known_library_cve": best_cve != "N/A",
                    "top_similarity": round(top_score, 4),
                    "nvd_severity": nvd_severity,
                    "language": lang_norm,
                    "closest_reference_cve": closest_ref,
                    "candidate_matches": candidate_matches[:3]
                }
                results.append({**it, **res})

        return results


def main():
    parser = argparse.ArgumentParser(description="Standalone CWE-ID & CVE-ID Extraction Engine")
    parser.add_argument("--code", type=str, help="Vulnerable code snippet to analyze")
    parser.add_argument("--language", type=str, default="c", help="Programming language of code snippet")
    parser.add_argument("--flaw", type=str, default="", help="Optional defect description or flaw summary")
    parser.add_argument("--input-json", type=str, help="Path to input JSON file containing vulnerability findings")
    parser.add_argument("--output-json", type=str, help="Path to save output JSON with extracted IDs")
    parser.add_argument("--local", action="store_true", help="Force local model loading even if API server is running")
    args = parser.parse_args()

    extractor = CweCveExtractor(enable_llm=False, force_local=args.local)

    if args.code:
        res = extractor.extract(args.code, language=args.language, flaw_summary=args.flaw)
        print("\n" + "=" * 60)
        print("EXTRACTION RESULT:")
        print("=" * 60)
        print(json.dumps(res, indent=2))
    elif args.input_json:
        with open(args.input_json, "r") as f:
            items = json.load(f)
        if isinstance(items, dict):
            items = [items]
        out_items = extractor.extract_batch(items)
        if args.output_json:
            with open(args.output_json, "w") as f:
                json.dump(out_items, f, indent=2)
            print(f"Results written to {args.output_json}")
        else:
            print(json.dumps(out_items, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
