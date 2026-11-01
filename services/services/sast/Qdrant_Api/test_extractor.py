"""
Verification and Demo Suite for CWE & CVE Extraction Engine
===========================================================
Tests standalone CWE-ID and CVE-ID extraction on confirmed vulnerabilities
across multiple programming languages.
"""

import sys
import json
import argparse
from pathlib import Path

CURRENT_DIR = Path(__file__).parent.resolve()
WORKSPACE_ROOT = CURRENT_DIR.parent.resolve()
sys.path.insert(0, str(CURRENT_DIR))
sys.path.insert(0, str(WORKSPACE_ROOT))

try:
    from API_qdrant_Vul_db.Qdrant_Api.extractor import CweCveExtractor
except ImportError:
    from API_qdrant_Vul_db.Qdrant_Api.extractor import CweCveExtractor

TEST_VULNERABILITIES = [
    {
        "name": "C Stack Buffer Overflow (CPDB)",
        "language": "c",
        "code": """
        PrintBackend *cpdbCreateBackendFromFile(GDBusConnection *connection, const char *backend_file_name) {
            char obj_path[CPDB_BSIZE];
            backend_name = cpdbGetStringCopy(backend_file_name);
            sprintf(obj_path, "%s/%s", cpdb_dir, backend_name);
            return proxy;
        }
        """,
        "expected_cwe": "CWE-121",
        "expected_cve": "CVE-2023-34095"
    },
    {
        "name": "Python Arbitrary Code Execution / Unsafe Deserialization",
        "language": "python",
        "code": """
        def checkin(pickledata):
            config = pickle.loads(bz2.decompress(base64.urlsafe_b64decode(pickledata)))
            return config
        """,
        "expected_cwe": "CWE-502",
        "expected_cve": "CVE-2021-41223"
    },
    {
        "name": "JavaScript Prototype Pollution",
        "language": "javascript",
        "code": """
        var removeSearch = module.exports.removeSearch = function removeSearch(object, path){
            search(object, path, function(value, object, key){
                delete object[key];
            });
            return object;
        };
        """,
        "expected_cwe": "CWE-1321",
        "expected_cve": "CVE-2021-25912"
    },
    {
        "name": "Rust Use-After-Free in FFI",
        "language": "rust",
        "code": """
        pub fn play_sample_with_proplist(&mut self, name: &str, dev: Option<&str>) {
            let c_name = CString::new(name.clone()).unwrap();
            let c_dev = match dev {
                Some(dev) => CString::new(dev.clone()).unwrap(),
                None => CString::new("").unwrap(),
            };
            let p_dev: *const c_char = c_dev.as_ptr();
            unsafe { capi::pa_context_play_sample(self.ptr, c_name.as_ptr(), p_dev) };
        }
        """,
        "expected_cwe": "CWE-416",
        "expected_cve": "GHSA-F56G-CHQP-22M9"
    }
]

def main():
    parser = argparse.ArgumentParser(description="Test Extraction Engine")
    parser.add_argument("--local", action="store_true", help="Force local execution even if server is running")
    args = parser.parse_args()

    print("=" * 75)
    print("STARTING STANDALONE CWE-ID & CVE-ID EXTRACTION DEMO")
    print("=" * 75)
    
    extractor = CweCveExtractor(enable_llm=False, force_local=args.local)
    
    print("\nRunning extraction on test vulnerability findings...")
    print("-" * 75)
    
    passed = 0
    for i, test in enumerate(TEST_VULNERABILITIES, 1):
        print(f"\n[Test Case {i}] {test['name']}")
        print(f"  Target Language : {test['language']}")
        print(f"  Expected CWE    : {test['expected_cwe']}")
        
        result = extractor.extract(
            code_snippet=test["code"],
            language=test["language"],
            flaw_summary=test["name"]
        )
        
        cwe_match = result['cwe_id'] == test['expected_cwe']
        if cwe_match:
            passed += 1
            status = "✓ PASS"
        else:
            status = "✗ MISMATCH"

        print(f"  -> Extracted CWE : {result['cwe_id']} ({result['cwe_title']}) [{status}]")
        print(f"  -> Extracted CVE : {result['cve_id']} (Similarity: {result['top_similarity']*100:.1f}%)")
        print(f"  -> NVD Severity  : {result['nvd_severity']}")
        print(f"  -> Known Library : {'YES' if result['is_known_library_cve'] else 'NO (Custom/0-Day)'}")
        print(f"  -> Nearest Ref   : {result['closest_reference_cve']}")
        
    print("\n" + "=" * 75)
    print(f"✓ Summary: {passed}/{len(TEST_VULNERABILITIES)} CWE classifications matched expected taxonomy!")
    print("=" * 75)

if __name__ == "__main__":
    main()
