"""
MITRE CWE Catalog and Language-Specific Memory Boundary Validator
================================================================
Defines official MITRE Common Weakness Enumeration (CWE) metadata,
taxonomy descriptions, and language-specific defensive validity checks.
"""

import re
from typing import Dict, List, Optional, Any
try:
    from API_qdrant_Vul_db.Qdrant_Api.core.language_profiles import normalize_language_key
except ImportError:
    try:
        from Qdrant_Api.core.language_profiles import normalize_language_key
    except ImportError:
        from core.language_profiles import normalize_language_key

# Official Standard MITRE CWE Descriptions
MITRE_CWE_DESCRIPTIONS: Dict[str, str] = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-59": "Improper Link Resolution Before File Access ('Link Following')",
    "CWE-61": "UNIX Symbolic Link (Symlink) Following",
    "CWE-73": "External Control of File Name or Path",
    "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    "CWE-75": "Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-88": "Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-90": "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
    "CWE-91": "XML Injection (aka Blind XPath Injection)",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-98": "Improper Control of Filename for Include/Require Statement in PHP Program",
    "CWE-113": "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
    "CWE-116": "Improper Encoding or Escaping of Output",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-170": "Improper Null Termination",
    "CWE-189": "Numeric Errors",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-193": "Off-by-one Error",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-203": "Observable Discrepancy",
    "CWE-208": "Observable Timing Discrepancy",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-228": "Improper Handling of Syntactically Invalid Structure",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-310": "Cryptographic Issues",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-346": "Origin Validation Error",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-369": "Divide By Zero",
    "CWE-384": "Session Fixation",
    "CWE-399": "Resource Management Errors",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-404": "Improper Resource Shutdown or Release",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-425": "Direct Request ('Forced Browsing')",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-497": "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-617": "Reachable Assertion",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-665": "Improper Initialization",
    "CWE-667": "Improper Locking",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-674": "Uncontrolled Recursion",
    "CWE-681": "Incorrect Conversion between Numeric Types",
    "CWE-682": "Incorrect Calculation",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-697": "Incorrect Comparison",
    "CWE-704": "Incorrect Type Conversion or Cast",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-772": "Missing Release of Resource after Effective Lifetime",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-820": "Missing Synchronization",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-835": "Loop with Unreachable Exit Condition ('Infinite Loop')",
    "CWE-843": "Access of Resource Using Incompatible Type ('Type Confusion')",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-1077": "Floating Point Comparison with Incorrect Precision",
    "CWE-1284": "Improper Validation of Specified Quantity in Input",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
    "CWE-1333": "Inefficient Regular Expression Complexity",
}

MANAGED_MEMORY_SAFE_LANGUAGES = {
    "javascript", "typescript", "python", "java", "php", "ruby", "csharp", "c_sharp", "kotlin", "go", "golang", "swift"
}

NATIVE_MEMORY_CWES = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125",
    "CWE-126", "CWE-127", "CWE-131", "CWE-170", "CWE-415", "CWE-416", "CWE-476", "CWE-787", "CWE-824"
}

NATIVE_FFI_PATTERNS = (
    re.compile(r"\bunsafe\b", re.IGNORECASE),
    re.compile(r"\bjni\b", re.IGNORECASE),
    re.compile(r"\bctypes\b", re.IGNORECASE),
    re.compile(r"\bcffi\b", re.IGNORECASE),
    re.compile(r"\bpointer\b", re.IGNORECASE),
    re.compile(r"\bnative\s+[a-zA-Z]", re.IGNORECASE),
    re.compile(r"marshal\.", re.IGNORECASE),
    re.compile(r"memorymarshal", re.IGNORECASE),
    re.compile(r"allocatedirect", re.IGNORECASE),
    re.compile(r"withunsafebytes", re.IGNORECASE)
)


def normalize_cwe(cwe_val: Any) -> str:
    """Normalize raw CWE string (e.g., 'cwe-120', 'CWE_120', '120') to standard 'CWE-120'."""
    s = str(cwe_val or "").strip().upper()
    if not s or s in ("NONE", "N/A", "NAN", "UNKNOWN", "NONE/NULL"):
        return "NONE"
    if s.startswith("NVD-CWE"):
        return "CWE-20"
    m = re.search(r"CWE[_\s-]?(\d+)", s, re.IGNORECASE)
    if m:
        return f"CWE-{m.group(1)}"
    m_num = re.match(r"^(\d+)$", s)
    if m_num:
        return f"CWE-{m_num.group(1)}"
    return s


def get_cwe_title(cwe_id: str) -> str:
    """Return standard human-readable MITRE CWE title with ID, e.g. 'CWE-121 (Stack-based Buffer Overflow)'."""
    clean = normalize_cwe(cwe_id)
    desc = MITRE_CWE_DESCRIPTIONS.get(clean)
    return f"{clean} ({desc})" if desc else clean


def is_impossible_managed_memory_cwe(language: str, cwe_id: str, code_snippet: str = "") -> bool:
    """
    Returns True if a native C/C++ memory-corruption CWE (e.g., CWE-787, CWE-120, CWE-416)
    is erroneously assigned to a managed memory-safe language that contains no FFI/unsafe block.
    """
    lang_norm = normalize_language_key(language)
    cwe_clean = normalize_cwe(cwe_id)
    code_str = str(code_snippet or "")

    if lang_norm in MANAGED_MEMORY_SAFE_LANGUAGES and cwe_clean in NATIVE_MEMORY_CWES:
        if not any(pat.search(code_str) for pat in NATIVE_FFI_PATTERNS):
            return True

    if lang_norm == "rust" and cwe_clean in {
        "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-415", "CWE-416", "CWE-476", "CWE-787"
    }:
        if not re.search(r"\bunsafe\b", code_str):
            return True

    return False


SEMANTIC_CWE_RULES = [
    # 1. High-Impact Memory & Deserialization Vulnerabilities
    (re.compile(r'(deserializ|pickle\.loads|yaml\.load|unserialize|objectinputstream|readobject)', re.IGNORECASE), "CWE-502"),
    (re.compile(r'(prototype pollution|__proto__|prototype attribute)', re.IGNORECASE), "CWE-1321"),

    # 2. Mathematical & Arithmetic Root Causes (cause downstream buffer/malloc corruptions)
    (re.compile(r'(integer underflow)', re.IGNORECASE), "CWE-191"),
    (re.compile(r'(integer overflow|wraparound|numeric overflow|numeric error)', re.IGNORECASE), "CWE-190"),
    (re.compile(r'(divide by zero|division by zero)', re.IGNORECASE), "CWE-369"),

    # 3. Pointer & Array Index Boundary Check Root Causes
    (re.compile(r'(null byte|null termination|string.*contain.*null)', re.IGNORECASE), "CWE-170"),
    (re.compile(r'(null pointer|null dereference|nullptr)', re.IGNORECASE), "CWE-476"),
    (re.compile(r'(array access|array index|bounds check|index out|invalid index|out[- ]of[- ]bounds index)', re.IGNORECASE), "CWE-129"),
    (re.compile(r'(out[- ]of[- ]bounds write|oob write)', re.IGNORECASE), "CWE-787"),
    (re.compile(r'(out[- ]of[- ]bounds read|oob read)', re.IGNORECASE), "CWE-125"),

    # 4. Memory Lifecycle & Allocation Flaws
    (re.compile(r'(use[- ]after[- ]free|dangling pointer)', re.IGNORECASE), "CWE-416"),
    (re.compile(r'(double free)', re.IGNORECASE), "CWE-415"),
    (re.compile(r'(memory leak|resource leak)', re.IGNORECASE), "CWE-401"),
    (re.compile(r'(uninitialized variable|not initialized)', re.IGNORECASE), "CWE-457"),

    # 5. Buffer Copying & Memory Buffer Violations
    (re.compile(r'(stack[- ]based buffer overflow|stack overflow)', re.IGNORECASE), "CWE-121"),
    (re.compile(r'(heap[- ]based buffer overflow|heap overflow)', re.IGNORECASE), "CWE-122"),
    (re.compile(r'(buffer overflow|overflow.*buffer|memcpy.*without.*checking|strcpy|strcat|sprintf)', re.IGNORECASE), "CWE-120"),
    (re.compile(r'(buffer over[- ]?read)', re.IGNORECASE), "CWE-125"),
    (re.compile(r'(memory corruption)', re.IGNORECASE), "CWE-119"),

    # 6. Specific Injections
    (re.compile(r'(sql injection)', re.IGNORECASE), "CWE-89"),
    (re.compile(r'(command injection|os command injection)', re.IGNORECASE), "CWE-78"),
    (re.compile(r'(code injection|arbitrary code execution|eval\()', re.IGNORECASE), "CWE-94"),
    (re.compile(r'(cross[- ]site scripting|\bxss\b)', re.IGNORECASE), "CWE-79"),
    (re.compile(r'(xpath injection|xml injection)', re.IGNORECASE), "CWE-91"),
    (re.compile(r'(ldap injection)', re.IGNORECASE), "CWE-90"),

    # 7. File, URL & Path Handlers
    (re.compile(r'(path traversal|directory traversal|\.\./)', re.IGNORECASE), "CWE-22"),
    (re.compile(r'(open redirect|url redirect)', re.IGNORECASE), "CWE-601"),
    (re.compile(r'(ssrf|server[- ]side request forgery)', re.IGNORECASE), "CWE-918"),

    # 8. Cryptography, Credentials & Information Leaks
    (re.compile(r'(weak hash|broken.*crypt|md5|sha1|risky cryptographic)', re.IGNORECASE), "CWE-327"),
    (re.compile(r'(hardcoded|hard-coded|secret in code|credential in code)', re.IGNORECASE), "CWE-798"),
    (re.compile(r'(sensitive information in log|log.*exposure|log.*leak)', re.IGNORECASE), "CWE-532"),
    (re.compile(r'(file access permission|directory permission|chmod|umask|insecure permission)', re.IGNORECASE), "CWE-732"),

    # 9. Concurrency & Format Strings
    (re.compile(r'(race condition|toctou|time-of-check)', re.IGNORECASE), "CWE-362"),
    (re.compile(r'(format string)', re.IGNORECASE), "CWE-134"),

    # 10. Generic Input Validation Fallback
    (re.compile(r'(input validation|sanitize|sanitization|validate.*input|untrusted input)', re.IGNORECASE), "CWE-20"),
]


def infer_cwe_from_flaw_summary(flaw_summary: str, language: str = "c", code_snippet: str = "") -> Optional[str]:
    """
    Deduce canonical MITRE CWE from vulnerability defect description and code keywords.
    Ensures language validity constraints are respected.
    """
    flaw_str = str(flaw_summary or "").strip()
    code_str = str(code_snippet or "")

    # 1. Check for direct explicit CWE mentions in flaw summary (e.g. "CWE-120")
    if flaw_str:
        m = re.search(r'\b(CWE-\d+)\b', flaw_str, re.IGNORECASE)
        if m:
            cwe_cand = normalize_cwe(m.group(1))
            if not is_impossible_managed_memory_cwe(language, cwe_cand, code_str):
                return cwe_cand

        # 2. Check semantic natural language patterns against flaw summary
        for pattern, cwe_id in SEMANTIC_CWE_RULES:
            if pattern.search(flaw_str):
                if not is_impossible_managed_memory_cwe(language, cwe_id, code_str):
                    return cwe_id

    # 3. High-signal code API calls fallback (only checked if flaw summary gave no match)
    if code_str:
        code_specific_rules = [
            (re.compile(r'\b(pickle\.loads|yaml\.load|unserialize)\b', re.IGNORECASE), "CWE-502"),
            (re.compile(r'(__proto__|prototype\s*\[)', re.IGNORECASE), "CWE-1321"),
            (re.compile(r'\b(strcpy|strcat|sprintf|gets)\b'), "CWE-120"),
            (re.compile(r'\b(eval|exec)\s*\(', re.IGNORECASE), "CWE-94"),
        ]
        for pat, cwe_id in code_specific_rules:
            if pat.search(code_str):
                if not is_impossible_managed_memory_cwe(language, cwe_id, code_str):
                    return cwe_id

    return None

