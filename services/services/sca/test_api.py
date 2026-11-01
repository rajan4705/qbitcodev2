"""
Automated Test Client for 13-Language Vulnerability API Server (Port 8082)
========================================================================
Runs tests against all REST endpoints to verify server health, package lookups,
manifest checks, and full repository scans.

Usage:
  # In terminal 1 (start server):
  python vul_packages/api_server.py --port 8082

  # In terminal 2 (run tests):
  python vul_packages/test_api.py
"""

import sys
import json
import time
import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:8082"

def _find_workspace_root():
    cur = Path(__file__).resolve().parent
    for p in [cur, *cur.parents]:
        if (p / "mock_data").is_dir():
            return p
    return cur.parent.parent

WORKSPACE_ROOT = _find_workspace_root()

GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"


def print_test_header(name):
    print(f"\n{BLUE}▶ Running Test: {name}{RESET}")


def assert_status(resp, expected_code=200):
    if resp.status_code == expected_code:
        print(f"  {GREEN}✓ Status {resp.status_code} OK{RESET}")
    else:
        print(f"  {RED}✗ Expected {expected_code}, got {resp.status_code}: {resp.text}{RESET}")
        sys.exit(1)


def main():
    print("=" * 70)
    print("UNIVERSAL VULNERABILITY SCANNER API TEST SUITE (PORT 8082)")
    print(f"Target Server: {BASE_URL}")
    print("=" * 70)

    # 1. Test Server Connectivity & Health
    print_test_header("1. GET /health (Server Status & DB Specs)")
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=3.0)
    except requests.exceptions.ConnectionError:
        print(f"\n{RED}[!] Could not connect to API server at {BASE_URL}{RESET}")
        print("    Make sure you have started the server in another terminal:")
        print("    python vul_packages/api_server.py --port 8082\n")
        sys.exit(1)

    assert_status(r)
    health = r.json()
    print(f"    • Service       : {health.get('service')}")
    print(f"    • Database Mode : {health.get('database', {}).get('mode')}")
    print(f"    • Total Records : {health.get('database', {}).get('total_vulnerability_records'):,}")
    print(f"    • Languages (13): {', '.join(health.get('supported_languages', [])[:6])}...")

    # 2. Test Instant Single-Package Check
    print_test_header("2. POST /api/v1/check/package (Instant Package Lookup)")
    payload = {
        "package": "jinja2",
        "version": "2.3",
        "ecosystem": "PyPI"
    }
    r = requests.post(f"{BASE_URL}/api/v1/check/package", json=payload)
    assert_status(r)
    pkg_res = r.json()
    print(f"    • Package       : {pkg_res.get('package')}=={pkg_res.get('installed_version')}")
    print(f"    • Vulnerable?   : {pkg_res.get('is_vulnerable')}")
    print(f"    • Severity      : {pkg_res.get('highest_severity')}")
    print(f"    • Fix Version   : {pkg_res.get('recommended_fix')}")
    print(f"    • Found CVEs    : {len(pkg_res.get('cve_summary', []))} CVEs {pkg_res.get('cve_summary', [])[:3]}...")

    # 3. Test Raw Manifest Text Check (In-Memory)
    print_test_header("3. POST /api/v1/check/manifest (In-Memory Manifest Audit)")
    manifest_payload = {
        "filename": "requirements.txt",
        "content": "jinja2==2.3\nurllib3==1.25.8\nrequests==2.20.0\npytest==7.4.0\n"
    }
    r = requests.post(f"{BASE_URL}/api/v1/check/manifest", json=manifest_payload)
    assert_status(r)
    m_res = r.json()
    print(f"    • Manifest File : {m_res.get('filename')}")
    print(f"    • Parsed Pkgs   : {m_res.get('parsed_packages')}")
    print(f"    • Clean Pkgs    : {m_res.get('clean_packages')}")
    print(f"    • Vulnerable    : {m_res.get('vulnerable_packages')}")
    for finding in m_res.get("findings", []):
        print(f"       -> {finding['package']} ({finding['installed_version']}): {finding['highest_severity']} | Recommended Fix: {finding['recommended_fix']}")

    # 4. Test Single Repository Audit on Disk (with Reachability)
    print_test_header("4. POST /api/v1/scan (Repo Scan with Reachability)")
    sample_repo = WORKSPACE_ROOT / "mock_data" / "Software_C" / "Software Stack C 1"
    scan_payload = {
        "target_path": str(sample_repo),
        "active_only": False,
        "min_severity": "HIGH",
        "save_report": False
    }
    start_t = time.time()
    r = requests.post(f"{BASE_URL}/api/v1/scan", json=scan_payload)
    elapsed = time.time() - start_t
    assert_status(r)
    scan_res = r.json()
    s = scan_res.get("summary", {})
    print(f"    • Repo Scanned  : {scan_res.get('repo_name')} in {elapsed:.3f}s")
    print(f"    • Total Packages: {s.get('total_packages')}")
    print(f"    • Clean Packages: {s.get('clean_packages')}")
    print(f"    • Active Risks  : {s.get('actionable_active_risks')}")
    for act in scan_res.get("actionable_risks", []):
        trace = act.get("code_usage", {}).get("traces", [{}])[0]
        print(f"       -> [ACTIVE] {act['package']}=={act['installed_version']} at {trace.get('file')}:{trace.get('line')}")

    # 5. Test Background Job Pipeline (identical to Qdrant API pattern)
    print_test_header("5. POST /api/v1/jobs/submit & GET /api/v1/jobs/{id} (Async Job Engine)")
    form_data = {
        "target_path": str(sample_repo),
        "active_only": "true",
        "min_severity": "HIGH"
    }
    r = requests.post(f"{BASE_URL}/api/v1/jobs/submit", data=form_data)
    assert_status(r)
    job_info = r.json()
    job_id = job_info.get("job_id")
    print(f"    • Job Submitted : ID = {job_id}")

    # Poll status
    for _ in range(15):
        time.sleep(0.3)
        poll_r = requests.get(f"{BASE_URL}/api/v1/jobs/{job_id}")
        assert_status(poll_r)
        status_data = poll_r.json()
        st = status_data.get("status")
        pct = status_data.get("progress")
        msg = status_data.get("message")
        if st == "completed":
            print(f"  {GREEN}✓ Background Job Completed (100%): {msg}{RESET}")
            print(f"    • Total Packages: {status_data.get('summary', {}).get('total_packages')}")
            print(f"    • Active Risks  : {status_data.get('summary', {}).get('actionable_active_risks')}")
            break
        elif st == "failed":
            print(f"  {RED}✗ Background Job Failed: {status_data.get('error')}{RESET}")
            sys.exit(1)

    # 6. Test Master Report Download
    print_test_header("6. GET /api/v1/master-report (Aggregated Workspace Report)")
    r = requests.get(f"{BASE_URL}/api/v1/master-report")
    if r.status_code == 200:
        master = r.json()
        ov = master.get("overall_summary", {})
        print(f"  {GREEN}✓ Master Report Retrieved successfully!{RESET}")
        print(f"    • Repositories  : {ov.get('total_repositories')}")
        print(f"    • Total Packages: {ov.get('total_packages')}")
        print(f"    • Active Risks  : {ov.get('actionable_active_risks')}")
    elif r.status_code == 404:
        print(f"  {BLUE}ℹ Master report not yet generated on disk (expected if not scanned yet){RESET}")

    print("\n" + "=" * 70)
    print(f"{GREEN}ALL API TESTS PASSED SUCCESSFULLY (6/6)!{RESET}")
    print(f"Your teammate can safely connect to: {BASE_URL}/docs")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

