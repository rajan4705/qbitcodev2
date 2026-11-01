"""
Local Vulnerability Database Builder
====================================
Reads the downloaded OSV ecosystem zip files from 'vul_packages/zips/'
and builds an indexed, high-performance SQLite database:
  'vul_packages/vulnerabilities.db'

Usage:
  python vul_packages/build_db.py --build
  python vul_packages/build_db.py --stats
"""

import sys
import os
import io
import json
import sqlite3
import zipfile
import argparse
from pathlib import Path

DEFAULT_ZIPS_DIR = Path(__file__).parent / "zips"
DEFAULT_DB_PATH = Path(__file__).parent / "vulnerabilities.db"


def get_db_connection(db_path=DEFAULT_DB_PATH):
    """Create SQLite connection optimized for bulk ingestion and fast queries."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA cache_size = -64000;")
    return conn


def init_database(conn):
    """Initialize table schema and lookup indexes."""
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS advisories (
                vuln_id TEXT NOT NULL,
                cve_id TEXT,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                summary TEXT,
                severity TEXT,
                cwe_id TEXT,
                introduced_version TEXT,
                fixed_version TEXT,
                affected_versions_json TEXT,
                published TEXT,
                modified TEXT,
                PRIMARY KEY (vuln_id, package_name, ecosystem)
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pkg_eco ON advisories(package_name, ecosystem);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pkg_only ON advisories(package_name);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cve ON advisories(cve_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cwe ON advisories(cwe_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sev ON advisories(severity);")


def parse_osv_record(record):
    """Parses a single OSV JSON advisory and returns list of rows for the database."""
    vuln_id = record.get("id")
    if not vuln_id or record.get("withdrawn"):
        return []

    aliases = record.get("aliases", []) or []
    cve_id = vuln_id if vuln_id.startswith("CVE-") else next((a for a in aliases if a.startswith("CVE-")), None)

    db_spec = record.get("database_specific", {}) or {}
    cwe_ids = db_spec.get("cwe_ids", []) or []
    cwe_id = cwe_ids[0] if cwe_ids else None

    severity = db_spec.get("severity") or "UNKNOWN"
    if severity in ["MODERATE", "MED"]:
        severity = "MEDIUM"

    summary = record.get("summary") or (record.get("details", "")[:120] if record.get("details") else "No summary")
    published = record.get("published", "")
    modified = record.get("modified", "")

    rows = []
    for affected in record.get("affected", []):
        pkg_info = affected.get("package", {})
        pkg_name = pkg_info.get("name", "").strip()
        ecosystem = pkg_info.get("ecosystem", "").strip()

        if not pkg_name or not ecosystem:
            continue

        introduced_list = []
        fixed_list = []
        for r in affected.get("ranges", []):
            for ev in r.get("events", []):
                if "introduced" in ev:
                    introduced_list.append(str(ev["introduced"]))
                if "fixed" in ev:
                    fixed_list.append(str(ev["fixed"]))

        introduced_str = ", ".join(introduced_list) if introduced_list else "0"
        fixed_str = ", ".join(sorted(set(fixed_list))) if fixed_list else None

        exact_versions = affected.get("versions", []) or []
        exact_versions_json = json.dumps(exact_versions) if exact_versions else "[]"

        rows.append((
            vuln_id,
            cve_id,
            pkg_name.lower(),
            ecosystem,
            summary,
            severity,
            cwe_id,
            introduced_str,
            fixed_str,
            exact_versions_json,
            published,
            modified
        ))

    return rows


def ingest_zip_file(conn, zip_path):
    """Reads JSON files directly out of a zip archive and inserts into SQLite in batches."""
    path = Path(zip_path)
    if not path.is_file():
        print(f"[!] Zip file not found: {path}")
        return 0

    print(f"\n[*] Processing archive: {path.name} ({path.stat().st_size / (1024*1024):.2f} MB)...")

    inserted = 0
    batch = []
    batch_size = 10000

    try:
        with zipfile.ZipFile(path, "r") as z:
            json_files = [n for n in z.namelist() if n.endswith(".json")]
            total_files = len(json_files)
            print(f"    Found {total_files:,} vulnerability records. Ingesting...")

            for i, fname in enumerate(json_files, 1):
                try:
                    with z.open(fname) as f:
                        data = json.load(f)
                        rows = parse_osv_record(data)
                        batch.extend(rows)
                except Exception:
                    continue

                if len(batch) >= batch_size:
                    with conn:
                        conn.executemany("""
                            INSERT OR REPLACE INTO advisories 
                            (vuln_id, cve_id, package_name, ecosystem, summary, severity, 
                             cwe_id, introduced_version, fixed_version, affected_versions_json, published, modified)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, batch)
                    inserted += len(batch)
                    batch = []
                    print(f"\r    Processed {i:,} / {total_files:,} files ({inserted:,} rows inserted)", end="", flush=True)

            if batch:
                with conn:
                    conn.executemany("""
                        INSERT OR REPLACE INTO advisories 
                        (vuln_id, cve_id, package_name, ecosystem, summary, severity, 
                         cwe_id, introduced_version, fixed_version, affected_versions_json, published, modified)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, batch)
                inserted += len(batch)

        print(f"\n[+] Finished {path.name}: {inserted:,} records indexed.")
        return inserted

    except Exception as e:
        print(f"\n[!] Error processing {path.name}: {e}")
        return 0


def build_database(zips_dir=DEFAULT_ZIPS_DIR, db_path=DEFAULT_DB_PATH):
    """Finds all *.zip files in zips_dir and builds the SQLite database."""
    zdir = Path(zips_dir)
    if not zdir.is_dir():
        print(f"[!] Zips directory not found: {zdir}")
        return

    zip_files = sorted(list(zdir.glob("*_all.zip")) + list(zdir.glob("*.zip")))
    if not zip_files:
        print(f"[!] No zip files found in '{zdir}'.")
        return

    print("=" * 65)
    print("BUILDING LOCAL VULNERABILITY DATABASE")
    print(f"Source Directory : {zdir}")
    print(f"Target Database  : {db_path}")
    print(f"Zip Archives     : {len(zip_files)} file(s) found")
    print("=" * 65)

    conn = get_db_connection(db_path)
    init_database(conn)

    total_records = 0
    for zf in zip_files:
        total_records += ingest_zip_file(conn, zf)

    print("\n[*] Optimizing indexes...")
    conn.execute("PRAGMA optimize;")
    conn.close()

    print("\n" + "=" * 65)
    print(f"[+] SUCCESS: Database built at '{db_path}'")
    print(f"[+] Total records indexed: {total_records:,}")
    print("=" * 65)


def display_stats(db_path=DEFAULT_DB_PATH):
    """Show statistics of the built database."""
    path = Path(db_path)
    if not path.is_file():
        print(f"[!] Database not found at: {path}")
        return

    conn = sqlite3.connect(path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM advisories;")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT package_name) FROM advisories;")
    pkgs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT cve_id) FROM advisories WHERE cve_id IS NOT NULL;")
    cves = cur.fetchone()[0]

    cur.execute("SELECT ecosystem, COUNT(*) FROM advisories GROUP BY ecosystem ORDER BY COUNT(*) DESC;")
    eco_breakdown = cur.fetchall()

    db_size_mb = path.stat().st_size / (1024 * 1024)

    print("\n" + "=" * 60)
    print("LOCAL VULNERABILITY DATABASE STATISTICS")
    print(f"Database File    : {path}")
    print(f"Database Size    : {db_size_mb:.2f} MB")
    print(f"Total Advisories : {total:,}")
    print(f"Unique Packages  : {pkgs:,}")
    print(f"Unique CVEs      : {cves:,}")
    print("-" * 60)
    print("Breakdown by Ecosystem:")
    for eco, cnt in eco_breakdown:
        print(f"  - {eco:<15}: {cnt:,} records")
    print("=" * 60 + "\n")
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Build or inspect local SQLite vulnerability database.")
    parser.add_argument("--build", action="store_true", help="Build database from all zip files in vul_packages/zips/")
    parser.add_argument("--zips-dir", default=str(DEFAULT_ZIPS_DIR), help=f"Directory containing zip files (default: {DEFAULT_ZIPS_DIR})")
    parser.add_argument("--db-path", default=str(DEFAULT_DB_PATH), help=f"Target database file path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--stats", action="store_true", help="Show statistics of the local database")

    args = parser.parse_args()

    if args.stats:
        display_stats(db_path=args.db_path)
    else:
        build_database(zips_dir=args.zips_dir, db_path=args.db_path)
        display_stats(db_path=args.db_path)


if __name__ == "__main__":
    main()

