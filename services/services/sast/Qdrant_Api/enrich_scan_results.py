"""
Scan Results Enrichment Utility & Core In-Memory Engine
======================================================
Enriches review findings with:
  1. Root-cause MITRE CWE-ID & official title
  2. Candidate or Attributed historical CVE-ID (from 400k+ NVD records)
  3. Official NVD Severity (CRITICAL, HIGH, MEDIUM, LOW)
  4. Top-3 historical similarity references (from 206,702 Qdrant vectors)

Architecture:
  Jina Code Embeddings (1.5B) + Qdrant Vector Search + MITRE CWE Catalog
"""

import sys
import re
import json
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from tqdm import tqdm

CURRENT_DIR = Path(__file__).parent.resolve()
API_ROOT = CURRENT_DIR.parent.resolve()
WORKSPACE_ROOT = API_ROOT.parent.resolve()

for p in [CURRENT_DIR, API_ROOT, WORKSPACE_ROOT]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    from API_qdrant_Vul_db.Qdrant_Api.extractor import CweCveExtractor
    from API_qdrant_Vul_db.Qdrant_Api.core.cwe_catalog import (
        normalize_cwe, get_cwe_title, is_impossible_managed_memory_cwe, infer_cwe_from_flaw_summary
    )
    from API_qdrant_Vul_db.Qdrant_Api.core.language_profiles import normalize_language_key
    import API_qdrant_Vul_db.Qdrant_Api.config as config
except ImportError:
    try:
        from Qdrant_Api.extractor import CweCveExtractor
        from Qdrant_Api.core.cwe_catalog import (
            normalize_cwe, get_cwe_title, is_impossible_managed_memory_cwe, infer_cwe_from_flaw_summary
        )
        from Qdrant_Api.core.language_profiles import normalize_language_key
        import Qdrant_Api.config as config
    except ImportError:
        from extractor import CweCveExtractor
        from core.cwe_catalog import (
            normalize_cwe, get_cwe_title, is_impossible_managed_memory_cwe, infer_cwe_from_flaw_summary
        )
        from core.language_profiles import normalize_language_key
        import config


def infer_language_from_path(file_path: str) -> str:
    """Infer canonical programming language from file path extension."""
    if not file_path:
        return "c"
    ext = Path(file_path).suffix.lower()
    lang = getattr(config, "EXT_TO_LANG", {}).get(ext)
    if lang:
        return lang
    clean_ext = ext.lstrip(".")
    return normalize_language_key(clean_ext or "c")


def fetch_file_context(
    codebase_root: Optional[Path],
    file_path: str,
    start_line: Any,
    end_line: Any,
    existing_code: str = "",
    padding: int = 15
) -> str:
    """
    Extract snippet from local repository file using start_line and end_line.
    Falls back to existing_code if file cannot be read.
    """
    if existing_code and str(existing_code).strip():
        # If code is already present, verify line count or use it
        if len(str(existing_code).strip().splitlines()) >= 3:
            return str(existing_code)

    if not file_path:
        return existing_code or ""

    # Parse line numbers safely
    try:
        s_idx = max(1, int(start_line)) if start_line is not None else 1
    except (ValueError, TypeError):
        s_idx = 1
    try:
        e_idx = max(s_idx, int(end_line)) if end_line is not None else s_idx
    except (ValueError, TypeError):
        e_idx = s_idx

    p = Path(file_path)
    candidates: List[Path] = []
    if p.is_absolute():
        candidates.append(p)

    if codebase_root and Path(codebase_root).is_dir():
        c_root = Path(codebase_root).resolve()
        candidates.append(c_root / file_path)
        candidates.append(c_root / p.name)
        for sub in ["modules", "include", "src", "3rdparty"]:
            candidates.append(c_root / sub / file_path)

    # Check workspace directories if root did not find it
    for candidate_dir in [WORKSPACE_ROOT, CURRENT_DIR.parent]:
        candidates.append(candidate_dir / file_path)
        opencv_sub = candidate_dir / "opencv"
        if opencv_sub.is_dir():
            candidates.append(opencv_sub / file_path)
            for sub in ["modules", "include", "src", "3rdparty"]:
                candidates.append(opencv_sub / sub / file_path)

    target_file = None
    for cand in candidates:
        if cand.is_file():
            target_file = cand
            break

    if not target_file:
        return existing_code or ""

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if not lines:
            return existing_code or ""
        s_line = max(1, s_idx - padding)
        e_line = min(len(lines), e_idx + padding)
        ctx = "".join(lines[s_line - 1 : e_line])
        return ctx if ctx.strip() else (existing_code or "")
    except Exception:
        return existing_code or ""


def enrich_scan_data(
    scan_data: Union[Dict[str, Any], List[Dict[str, Any]]],
    codebase_root: Optional[Path] = None,
    target_categories: tuple = ("security",),
    limit: Optional[int] = None,
    security_only: bool = False,
    extractor: Optional[CweCveExtractor] = None,
    show_progress: bool = True,
    progress_callback: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Pure in-memory JSON-in / JSON-out API.
    Takes a parsed scan dictionary or comment list, enriches security findings with CWE/CVE,
    and returns the enriched standardized scan dictionary.
    """
    is_list_input = isinstance(scan_data, list)
    if is_list_input:
        all_comments = list(scan_data)
        original_summary = {}
    else:
        all_comments = list(scan_data.get("comments", []))
        original_summary = scan_data.get("summary", {})

    target_indices = [
        i for i, c in enumerate(all_comments)
        if isinstance(c, dict) and (not target_categories or c.get("category") in target_categories)
    ]

    if limit and limit > 0:
        target_indices = target_indices[:limit]

    if not target_indices:
        if progress_callback:
            progress_callback(100, "No security findings found in input.")
        return {
            "summary": {
                **original_summary,
                "total_comments": len(all_comments),
                "enriched_security_findings": 0,
                "classification_mode": "jina-code-embeddings-1.5b + qdrant-vector-rag + mitre-catalog",
                "cwe_cve_attribution": "none_needed"
            },
            "comments": all_comments
        }

    if progress_callback:
        progress_callback(5, f"Identified {len(target_indices):,} security findings to enrich...")

    if extractor is None:
        extractor = CweCveExtractor()

    findings_to_process = []
    for idx in target_indices:
        item = all_comments[idx]
        file_p = item.get("path") or item.get("file_path", "")
        lang = infer_language_from_path(file_p)

        code = fetch_file_context(
            codebase_root=codebase_root,
            file_path=file_p,
            start_line=item.get("start_line", 1),
            end_line=item.get("end_line", 1),
            existing_code=item.get("existing_code") or item.get("code_snippet") or item.get("code") or ""
        )

        flaw_desc = item.get("content") or item.get("vulnerability_description") or item.get("comment") or item.get("reason") or ""
        findings_to_process.append({
            "comment_index": idx,
            "raw_item": item,
            "code": code.strip(),
            "language": lang,
            "flaw_desc": flaw_desc
        })

    # Separate items that have code from empty ones
    valid_items = [f for f in findings_to_process if f["code"]]
    empty_items = [f for f in findings_to_process if not f["code"]]

    cve_pat = re.compile(r'^(CVE-\d{4}-\d{4,7}|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})$', re.IGNORECASE)
    enriched_items = []

    # Handle empty code items immediately without querying vector DB
    for f_info in empty_items:
        it = dict(f_info["raw_item"])
        lang = f_info["language"]
        flaw_desc = f_info["flaw_desc"]
        sem_cwe = infer_cwe_from_flaw_summary(flaw_desc, language=lang, code_snippet="") or "NONE"
        sem_cwe = normalize_cwe(sem_cwe)
        it["cwe_id"] = sem_cwe
        it["cwe_title"] = get_cwe_title(sem_cwe)
        it["cve_id"] = "N/A"
        it["is_known_library_cve"] = False
        it["top_similarity"] = 0.0
        it["nvd_severity"] = "LOW"
        it["closest_reference_cve"] = "N/A"
        it["candidate_matches"] = []
        it["comment_index"] = f_info["comment_index"]
        enriched_items.append(it)

    # Process items with code
    if valid_items:
        if progress_callback:
            progress_callback(15, f"Batch encoding {len(valid_items):,} code snippets via Jina Embeddings...")

        if extractor.remote_mode:
            # Remote client mode via API server
            total_v = len(valid_items)
            for i, f_info in enumerate(valid_items):
                if progress_callback and (i % 5 == 0 or i == total_v - 1):
                    pct = int(20 + ((i + 1) / total_v) * 75)
                    progress_callback(pct, f"Enriching finding {i + 1}/{total_v} via API...")
                it = dict(f_info["raw_item"])
                res = extractor.extract(
                    code_snippet=f_info["code"],
                    language=f_info["language"],
                    flaw_summary=f_info["flaw_desc"]
                )
                it.update(res)
                it["comment_index"] = f_info["comment_index"]
                enriched_items.append(it)
        else:
            # High-throughput GPU batched mode
            all_codes = [f["code"] for f in valid_items]
            all_langs = [f["language"] for f in valid_items]

            all_vecs = extractor.rag.encode_code_batch(
                all_codes,
                batch_size=config.EMBED_BATCH_SIZE,
                show_progress_bar=show_progress
            )

            if progress_callback:
                progress_callback(35, "GPU encoding complete. Querying Qdrant vectors...")

            all_matches = extractor.rag._query_qdrant_batch_fast(all_vecs, all_langs, limit=6)

            total_findings = len(valid_items)
            iterator = zip(valid_items, all_matches)
            if show_progress:
                iterator = tqdm(iterator, total=total_findings, desc="Attributing CWE/CVEs", unit="finding")

            for i, (f_info, top_matches) in enumerate(iterator):
                if progress_callback and (i % 5 == 0 or i == total_findings - 1):
                    pct = int(35 + ((i + 1) / total_findings) * 60)
                    progress_callback(pct, f"Attributing CWE/CVEs ({i + 1}/{total_findings})...")

                it = dict(f_info["raw_item"])
                code = f_info["code"]
                lang = f_info["language"]
                flaw_desc = f_info["flaw_desc"]
                idx = f_info["comment_index"]

                semantic_cwe = infer_cwe_from_flaw_summary(flaw_desc, language=lang, code_snippet=code)
                if semantic_cwe:
                    semantic_cwe = normalize_cwe(semantic_cwe)

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
                            if not is_impossible_managed_memory_cwe(lang, h_cwe, code):
                                weight = h_score ** 2
                                m_h = re.search(r'\d+', h_cwe)
                                m_s = re.search(r'\d+', semantic_cwe) if semantic_cwe else None
                                if semantic_cwe and (h_cwe == semantic_cwe or (m_h and m_s and m_h.group(0) == m_s.group(0))):
                                    weight *= 3.0
                                cwe_vote_counts[h_cwe] = cwe_vote_counts.get(h_cwe, 0.0) + weight

                best_cwe = semantic_cwe or "CWE-UNKNOWN"
                if cwe_vote_counts:
                    consensus_cwe = max(cwe_vote_counts.items(), key=lambda x: x[1])[0]
                    if semantic_cwe and (top_score < config.SIMILARITY_THRESHOLD or consensus_cwe in ("UNKNOWN", "NONE", "CWE-UNKNOWN")):
                        best_cwe = semantic_cwe
                    else:
                        best_cwe = consensus_cwe
                elif semantic_cwe:
                    best_cwe = semantic_cwe
                elif top_matches:
                    top_payload = getattr(top_matches[0], "payload", {}) or {}
                    raw_cwe = normalize_cwe(str(top_payload.get("cwe", "UNKNOWN")).strip())
                    if raw_cwe not in ("UNKNOWN", "NONE", "N/A") and not is_impossible_managed_memory_cwe(lang, raw_cwe, code):
                        best_cwe = raw_cwe

                if best_cwe in ("CWE-UNKNOWN", "NONE", "UNKNOWN"):
                    best_cwe = semantic_cwe if semantic_cwe else "CWE-20"

                best_cve = "N/A"
                for cand in candidate_matches:
                    if cand["similarity"] >= config.SIMILARITY_THRESHOLD and cve_pat.match(cand["cve_id"]):
                        best_cve = cand["cve_id"]
                        break

                closest_ref = "N/A"
                for cand in candidate_matches:
                    if cve_pat.match(cand["cve_id"]):
                        closest_ref = cand["cve_id"]
                        break

                nvd_sev = extractor.rag.get_cve_severity(best_cve if best_cve != "N/A" else closest_ref, fallback="HIGH")

                it["cwe_id"] = best_cwe
                it["cwe_title"] = get_cwe_title(best_cwe)
                it["cve_id"] = best_cve
                it["is_known_library_cve"] = best_cve != "N/A"
                it["top_similarity"] = round(top_score, 4)
                it["nvd_severity"] = nvd_sev
                it["closest_reference_cve"] = closest_ref
                it["candidate_matches"] = candidate_matches[:3]
                it["comment_index"] = idx

                enriched_items.append(it)

    # In-place replacement preserving exact original comments list
    output_comments = list(all_comments)
    for enriched_item in enriched_items:
        orig_idx = enriched_item.get("comment_index")
        clean_item = dict(enriched_item)
        clean_item.pop("comment_index", None)
        if orig_idx is not None and orig_idx < len(output_comments):
            output_comments[orig_idx] = clean_item

    final_comments = enriched_items if security_only else output_comments
    for c in final_comments:
        c.pop("comment_index", None)

    if progress_callback:
        progress_callback(100, "Enrichment complete! Ready to download.")

    return {
        "summary": {
            **original_summary,
            "total_comments": len(final_comments),
            "enriched_security_findings": len(enriched_items),
            "classification_mode": "jina-code-embeddings-1.5b + qdrant-vector-rag + mitre-catalog",
            "cwe_cve_attribution": "complete"
        },
        "comments": final_comments
    }


def enrich_scan_results(
    input_path: str,
    output_path: str,
    repo_dir: Optional[str] = None,
    target_categories: tuple = ("security",),
    limit: Optional[int] = None,
    security_only: bool = False
):
    """File CLI wrapper around enrich_scan_data."""
    inp = Path(input_path).resolve()
    print(f"Loading scan findings from: {inp} ...")
    with open(inp, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    if repo_dir:
        codebase_root = Path(repo_dir).resolve()
    elif inp.parent.is_dir() and (inp.parent / "CMakeLists.txt").is_file():
        codebase_root = inp.parent
    elif (WORKSPACE_ROOT / "opencv").is_dir():
        codebase_root = WORKSPACE_ROOT / "opencv"
    else:
        codebase_root = inp.parent

    print(f"Codebase source root: {codebase_root}")
    enriched_data = enrich_scan_data(
        scan_data=scan_data,
        codebase_root=codebase_root,
        target_categories=target_categories,
        limit=limit,
        security_only=security_only,
        show_progress=True
    )

    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(enriched_data, f, indent=2)

    total_enriched = enriched_data.get("summary", {}).get("enriched_security_findings", 0)
    print(f"\n✓ Successfully enriched {total_enriched:,} security findings!")
    print(f"✓ Output saved to: {out_p}")


def main():
    parser = argparse.ArgumentParser(description="Enrich scan-res.json with CWE-ID and CVE-ID via Jina + Qdrant + MITRE")
    parser.add_argument("--input", default="scan-res.json", help="Path to input scan-res.json")
    parser.add_argument("--output", default="scan-res-enriched.json", help="Path to save enriched output JSON")
    parser.add_argument("--repo-dir", default=None, help="Path to codebase root directory")
    parser.add_argument("--category", default="security", help="Category to filter (default: security)")
    parser.add_argument("--security-only", action="store_true", help="Output only the enriched security comments")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of findings to process")
    args = parser.parse_args()

    cats = tuple(c.strip() for c in args.category.split(",")) if args.category else ()
    enrich_scan_results(
        input_path=args.input,
        output_path=args.output,
        repo_dir=args.repo_dir,
        target_categories=cats,
        limit=args.limit,
        security_only=args.security_only
    )


if __name__ == "__main__":
    main()
