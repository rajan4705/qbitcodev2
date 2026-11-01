"""
Language-Specific Security Knowledge Profiles.
Provides general, textbook language memory-model and standard-library security
characteristics (dangerous sink categories and recognized defensive idioms)
across all 13 supported programming languages.

Strictly general first-principles guidance:
- ZERO hardcoded CWE IDs (prevents CWE tunnel-vision bias).
- ZERO benchmark-specific function or CVE hints.
"""

from typing import Dict, Any


LANGUAGE_PROFILES: Dict[str, Dict[str, Any]] = {
    "c": {
        "display_name": "C",
        "vuln_indicators": [
            "Unbounded memory or string copies (strcpy, strcat, sprintf, gets, memcpy) where the length can exceed the destination buffer capacity.",
            "Out-of-bounds array or pointer indexing where the index or offset is not checked against valid bounds.",
            "Use-after-free, double-free, or dereferencing pointers returned by allocation/lookup functions without a NULL check.",
            "Integer overflow, underflow, or signedness truncation in allocation sizes or loop bounds.",
            "User-controlled strings passed directly as the format string argument to printf/syslog family functions."
        ],
        "safeguards": [
            "Explicit boundary validation before copy or index operations (e.g., verifying length < sizeof(dest)).",
            "Bounded string/memory APIs (snprintf, strlcpy, memcpy with verified size).",
            "Immediate NULL pointer checks after allocations and setting freed pointers to NULL.",
            "Arithmetic overflow checks prior to size calculations (e.g., a > SIZE_MAX - b)."
        ]
    },

    "cpp": {
        "display_name": "C++",
        "vuln_indicators": [
            "Unchecked pointer arithmetic, raw array indexing, or std::vector operator[] access with unvalidated indices.",
            "Lifetime errors: returning references/pointers to local stack variables, iterator invalidation, or use-after-free on raw pointers.",
            "Unsafe type casts (reinterpret_cast or C-style casts) on polymorphic or incompatible types.",
            "Integer overflow in buffer size calculations or manual new/delete paths that leak or double-free."
        ],
        "safeguards": [
            "RAII smart pointers (std::unique_ptr, std::shared_ptr) and standard containers (std::string, std::vector).",
            "Bounds-checked container access (.at() or explicit index < .size() guards).",
            "Exception-safe resource wrappers (std::lock_guard, std::scoped_lock)."
        ]
    },

    "csharp": {
        "display_name": "C# (.NET)",
        "vuln_indicators": [
            "SQL, OS command, or LDAP queries built via string concatenation or interpolation with untrusted input.",
            "Insecure deserialization using untrusted type resolvers (BinaryFormatter, NetDataContractSerializer, TypeNameHandling).",
            "File system operations (Path.Combine, File.ReadAllText) without verifying the canonical path stays inside the intended base directory.",
            "Missing authentication, authorization, or anti-forgery verification on sensitive state-changing actions.",
            "XML parsing with external DTD/entity resolution enabled, or unvalidated resource allocation sizes."
        ],
        "safeguards": [
            "Parameterized database queries (SqlParameter, FromSqlInterpolated, LINQ parameter binding).",
            "Safe serializers (System.Text.Json) with explicit static types.",
            "Canonical path validation via Path.GetFullPath().StartsWith(baseDir).",
            "XmlReaderSettings with DtdProcessing.Prohibit and XmlResolver = null."
        ]
    },

    "java": {
        "display_name": "Java",
        "vuln_indicators": [
            "SQL, OS command, or expression/template evaluation using concatenated untrusted strings.",
            "File or archive extraction paths resolved without verifying the normalized canonical path stays within the base directory.",
            "Insecure object deserialization (ObjectInputStream.readObject) or XML parsers without external entity (XXE) restrictions.",
            "Missing authentication, authorization, or CSRF verification on sensitive endpoints, or unbounded allocation/loops on untrusted lengths."
        ],
        "safeguards": [
            "PreparedStatement with '?' parameter binding or parameterized JPA/Hibernate queries.",
            "ProcessBuilder with explicit argument arrays (no shell invocation).",
            "Canonical path verification (file.getCanonicalPath().startsWith(baseCanonicalPath) or Path.normalize().startsWith(base)).",
            "XML parser hardening (disallow-doctype-decl enabled, external entities disabled)."
        ]
    },

    "python": {
        "display_name": "Python",
        "vuln_indicators": [
            "OS command execution (os.system, os.popen, subprocess with shell=True) or dynamic evaluation (eval, exec) with untrusted input.",
            "Insecure deserialization (pickle.loads, yaml.load without SafeLoader) on untrusted payloads.",
            "SQL queries or server-side templates constructed via f-strings, % formatting, or .format() with raw user input.",
            "File path operations (open, os.path.join) without resolving and verifying the path stays inside a permitted base directory.",
            "Unrestricted outbound network requests (SSRF) or unbounded memory/regex consumption on user input."
        ],
        "safeguards": [
            "subprocess.run/Popen with an argument list and shell=False, or shlex.quote().",
            "Safe parsers (json.loads, yaml.safe_load, ast.literal_eval).",
            "Parameterized SQL execution (cursor.execute(sql, (param,))) and auto-escaped templates.",
            "Canonical path verification via os.path.realpath / pathlib.Path.resolve()."
        ]
    },

    "javascript": {
        "display_name": "JavaScript (Node.js / Browser)",
        "vuln_indicators": [
            "DOM or HTML injection: assigning unescaped input to innerHTML, outerHTML, document.write, or unescaped HTTP response bodies.",
            "Recursive object merging or dynamic property assignment without blocking '__proto__', 'constructor', and 'prototype'.",
            "OS command or code execution (child_process.exec, eval, new Function) or SQL/NoSQL queries concatenated with user input.",
            "Path traversal in fs module calls or catastrophic backtracking regular expressions on untrusted input."
        ],
        "safeguards": [
            "Safe text rendering (textContent, innerText, createTextNode) or explicit HTML sanitization (DOMPurify.sanitize).",
            "Prototype key guards blocking '__proto__', 'constructor', and 'prototype', or using Map / Object.create(null).",
            "child_process.execFile / spawn with argument arrays and parameterized SQL/NoSQL queries."
        ]
    },

    "typescript": {
        "display_name": "TypeScript",
        "vuln_indicators": [
            "Note: TypeScript type annotations are erased at runtime and do NOT sanitize runtime HTTP/user inputs.",
            "DOM/HTML injection (innerHTML, dangerouslySetInnerHTML), SQL/command injection, or path traversal with unvalidated runtime inputs.",
            "API handlers accessing or mutating resources without verifying caller authorization or resource ownership.",
            "Unrestricted server-side URL fetching (SSRF) or recursive object merges allowing prototype pollution."
        ],
        "safeguards": [
            "Runtime schema validation (Zod, Joi, Yup) and explicit authorization/ownership checks.",
            "Parameterized queries, argument-array process execution, and path.resolve() prefix checks.",
            "Safe DOM APIs (textContent) or explicit HTML/URL sanitization."
        ]
    },

    "php": {
        "display_name": "PHP",
        "vuln_indicators": [
            "Echoing or rendering unescaped request parameters into HTML/JavaScript responses.",
            "SQL queries concatenated with variables instead of bound prepared statements.",
            "Dynamic file inclusion (include, require), file uploads, or path operations using unvalidated user filenames.",
            "Command execution (exec, system, passthru, shell_exec), eval(), or unserialize() on untrusted input.",
            "State-changing controller actions missing session authentication, authorization, or CSRF token verification."
        ],
        "safeguards": [
            "PDO or MySQLi prepared statements with bound parameters.",
            "Output encoding via htmlspecialchars($val, ENT_QUOTES, 'UTF-8').",
            "escapeshellarg() for command arguments and strict allowlists for file inclusion.",
            "json_decode() instead of unserialize(), and explicit permission/CSRF token checks."
        ]
    },

    "ruby": {
        "display_name": "Ruby (Rails)",
        "vuln_indicators": [
            "String interpolation (#{...}) inside ActiveRecord SQL clauses (where, order, group, from) or raw SQL execution.",
            "Command execution via backticks, system() with a single interpolated string, %x(), or Kernel.open() with user input.",
            "Controller actions accessing or modifying records without verifying user authorization or trusting spoofable request headers.",
            "Insecure deserialization (Marshal.load, YAML.load) or rendering unescaped HTML (raw, html_safe) on user data."
        ],
        "safeguards": [
            "ActiveRecord hash conditions or '?' placeholder bindings, and Strong Parameters (params.require.permit).",
            "Multi-argument system('cmd', arg1, arg2) bypassing the shell, and File.open instead of Kernel.open.",
            "YAML.safe_load and explicit authorization policy checks."
        ]
    },

    "go": {
        "display_name": "Go (Golang)",
        "vuln_indicators": [
            "SQL queries or OS commands constructed via fmt.Sprintf or string concatenation with untrusted input.",
            "File path operations (filepath.Join, os.Open) without verifying the cleaned path remains inside the intended root directory.",
            "Unvalidated HTTP redirects/requests (SSRF), writing unescaped user data to http.ResponseWriter, or missing auth/session checks.",
            "Unchecked error returns, nil dereferences, or slice bounds panics triggered by untrusted input."
        ],
        "safeguards": [
            "Parameterized database queries (db.Query with '?' or '$1' placeholders).",
            "exec.Command('binary', arg1, arg2) without shell invocation.",
            "Path containment checks using filepath.Clean and strings.HasPrefix, and html/template auto-escaping."
        ]
    },

    "rust": {
        "display_name": "Rust",
        "vuln_indicators": [
            "Unsound 'unsafe' blocks: raw pointer dereferences, std::slice::from_raw_parts with unverified lengths, or dangling FFI pointers.",
            "Denial of service via panics: calling .unwrap(), .expect(), or direct slice indexing [i] on untrusted external input, or unbounded allocations.",
            "Path or symlink traversal when opening or extracting files without canonical root verification.",
            "Missing cryptographic/signature verification or passing formatted strings to shell commands."
        ],
        "safeguards": [
            "Pure safe Rust without 'unsafe' blocks, using checked arithmetic and .get(i) bounds-safe indexing.",
            "Propagating errors via Result<T, E> and '?' instead of panicking on malformed input.",
            "Canonical path validation and std::process::Command::new(bin).args(&[...])."
        ]
    },

    "swift": {
        "display_name": "Swift",
        "vuln_indicators": [
            "File or archive path construction without resolving symlinks/standardized paths and verifying containment in the target directory.",
            "Incomplete or misordered string escaping/sanitization, or loading untrusted URLs/HTML into WebViews or SQLite queries.",
            "Force-unwrapping (!) optional values or unbounded parsing on untrusted network/file input causing runtime traps.",
            "Insecure credential storage or weak cryptographic primitives."
        ],
        "safeguards": [
            "Safe optional binding (if let / guard let) and standard ARC-managed collections.",
            "Parameterized SQLite statements (sqlite3_bind_text) and standardizedFileURL prefix validation.",
            "Keychain storage and CryptoKit standard algorithms."
        ]
    },

    "kotlin": {
        "display_name": "Kotlin (Android / JVM)",
        "vuln_indicators": [
            "File or Zip entry extraction (File(dir, name)) without verifying canonicalPath starts with the canonical target directory.",
            "SQL injection in rawQuery/execSQL, or launching Intents/WebViews/redirects with unvalidated external URIs.",
            "Missing authentication or permission enforcement on exported components/endpoints, or cleartext credential handling.",
            "OS command execution via Runtime.getRuntime().exec or ProcessBuilder with concatenated user input."
        ],
        "safeguards": [
            "Parameterized Room DAO queries or '?' placeholders with selectionArgs.",
            "Canonical path verification (file.canonicalPath.startsWith(baseDir.canonicalPath)).",
            "Explicit Intent component targeting, non-exported private components, and strict URI host allowlisting."
        ]
    }
}


# Mapping of aliases and file extensions to canonical language keys
LANGUAGE_ALIASES: Dict[str, str] = {
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "cc": "cpp",
    "cxx": "cpp",
    "c#": "csharp",
    "csharp": "csharp",
    "c_sharp": "csharp",
    "cs": "csharp",
    "java": "java",
    "python": "python",
    "py": "python",
    "javascript": "javascript",
    "js": "javascript",
    "node": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "php": "php",
    "ruby": "ruby",
    "rb": "ruby",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    "rs": "rust",
    "swift": "swift",
    "kotlin": "kotlin",
    "kt": "kotlin",
}


def normalize_language_key(language: str) -> str:
    """Normalize language string or alias into a canonical key."""
    if not language:
        return "c"
    cleaned = str(language).lower().strip()
    return LANGUAGE_ALIASES.get(cleaned, cleaned)


def get_language_profile(language: str) -> Dict[str, Any]:
    """Retrieve the general security profile for a given language."""
    key = normalize_language_key(language)
    if key in LANGUAGE_PROFILES:
        return LANGUAGE_PROFILES[key]
    return {
        "display_name": language.capitalize() if language else "Generic Code",
        "vuln_indicators": [
            "Unsanitized user input passed directly to system commands, queries, paths, or interpreters.",
            "Unbounded memory, array, or resource operations without length checks.",
            "Insecure deserialization, missing authentication/authorization, or direct code evaluation."
        ],
        "safeguards": [
            "Input validation, boundary checks, and strict query parameterization.",
            "Use of safe standard library APIs and framework abstractions."
        ]
    }


def format_language_instructions(language: str) -> str:
    """Format general language-specific sink and defense rules (zero hardcoded CWEs)."""
    profile = get_language_profile(language)
    name = profile["display_name"]
    vuln_bullets = "\n".join(f"     * {v}" for v in profile["vuln_indicators"])
    safe_bullets = "\n".join(f"     * {s}" for s in profile["safeguards"])

    return f"""LANGUAGE-SPECIFIC SECURITY RULES FOR {name.upper()}:
  A. Common Dangerous Sink Categories:
{vuln_bullets}
  B. Recognized Defensive Idioms:
{safe_bullets}"""
