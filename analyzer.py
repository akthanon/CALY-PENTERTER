#!/usr/bin/env python3
"""
analyzer.py — File analyzer for HIVEPLUS pentest agent (v3.4).

New in v3.4 (think-mode invariants):
  • _FORCED_THINK = False at module level — single source of truth.
  • _build_payload() rejects any `think` key in extra_options (it must be
    top-level in the Ollama payload, not inside `options`).
  • ollama_chat()/ollama_chat_stream() detect `message.thinking` in the
    response. If the server ignores think=False (old Ollama, weird model),
    we surface it instead of silently burning num_predict on CoT.
  • _emit_done() prints a visible ⚠️ warning when reasoning tokens leak.

Retained from v3.3:
  • HOT_CHUNK_PROMPT TRIAGE PROTOCOL + anti-FP rules
  • SAFE handlers → NOTES, not VULNERABILITIES
  • strip_not_exploitable_blocks() safety net
  • Live streaming, --stats, --stream-dir, --parallel, --adaptive-ctx
  • HTML prescan <script>, evidence verification, dedup, etc.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("[!] needs requests: pip install requests")

# ============================================================
# Config / constants
# ============================================================
DEFAULT_MODEL    = os.environ.get("ANALYZER_MODEL", "qwen2.5-coder:14b")
DEFAULT_HOST     = os.environ.get("ANALYZER_HOST",  "http://127.0.0.1:11434")
DEFAULT_CHUNK    = int(os.environ.get("ANALYZER_CHUNK", "20000"))
DEFAULT_TIMEOUT  = int(os.environ.get("ANALYZER_TIMEOUT", "600"))
DEFAULT_NUM_CTX  = int(os.environ.get("ANALYZER_NUM_CTX", "32768"))
DEFAULT_NUM_GPU  = os.environ.get("ANALYZER_NUM_GPU")
DEFAULT_STOP     = os.environ.get("ANALYZER_STOP")
DEFAULT_NUM_PRED = int(os.environ.get("ANALYZER_NUM_PRED", "2048"))
DEFAULT_PARALLEL = int(os.environ.get("ANALYZER_PARALLEL", "1"))
DEFAULT_KEEPALIVE = os.environ.get("ANALYZER_KEEP_ALIVE", "30m")
CHUNK_OVERLAP    = int(os.environ.get("ANALYZER_OVERLAP", "300"))
PRESCAN_CONTEXT  = int(os.environ.get("ANALYZER_PRESCAN_CTX", "3"))

# v3.4 — think-mode invariant.
# Reasoning models (qwen3, deepseek-r1, ...) emit `thinking` tokens by
# default. We FORCE it off: findings must be deterministic and the
# `message.content` stream must not be diluted by chain-of-thought.
# This is the single source of truth. Do not parameterize without a
# very good reason.
_FORCED_THINK = False

ANALYSIS_SUFFIX = ".analysis"
HEADER_DELIM    = "---"
SECTION_ORDER = [
    "SUMMARY", "VULNERABILITIES", "ENDPOINTS",
    "SECRETS / CREDENTIALS", "INTERESTING STRINGS", "NOTES",
]

FILE_TYPE_MAP = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".jsx": "javascript", ".tsx": "typescript",
    ".php": "php", ".phtml": "php", ".rb": "ruby", ".go": "go",
    ".java": "java", ".cs": "csharp", ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".rs": "rust",
    ".html": "html", ".htm": "html", ".xml": "xml", ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".pdf": "pdf",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml",
    ".conf": "config", ".ini": "config", ".env": "env",
    ".log": "log", ".txt": "text", ".md": "text",
}
CODE_TYPES = {"python", "javascript", "typescript", "php", "ruby",
              "go", "java", "csharp", "c", "cpp", "rust", "shell"}

_STREAM_LOCK = threading.Lock()

# ============================================================
# Pre-scan patterns
# ============================================================
SCRIPT_BLOCK_RE = re.compile(r"<script[^>]*>([\s\S]*?)</script>", re.I)
EVENT_HANDLER_RE = re.compile(
    r"\bon(click|input|submit|change|mouseover|mouseout|focus|blur|error|load"
    r"|keyup|keydown|dblclick|contextmenu|paste|drop)\s*=\s*[\"']([^\"']{1,200})[\"']",
    re.I,
)

# --- Handler classifier (v3.3) ---
_SAFE_HANDLER_BODY_RE = re.compile(
    r"^\s*[\w\.\$]+(?:\.\w+)*\(\s*"
    r"(?:"
    r"|this(?:\.value)?"
    r"|event"
    r"|'[^']{0,80}'"
    r"|\"[^\"]{0,80}\""
    r"|\d{1,10}"
    r"|true|false|null|undefined"
    r")?"
    r"\s*\)\s*;?\s*$"
)
_SUSPICIOUS_HANDLER_TOKENS = re.compile(
    r"\b(?:location|document\.cookie|localStorage|sessionStorage|"
    r"innerHTML|outerHTML|eval|Function|window\.name|"
    r"URLSearchParams|\.querySelector\(|getElementById\()"
)


def is_safe_handler_body(body: str) -> bool:
    if not body:
        return True
    b = body.strip()
    if _SUSPICIOUS_HANDLER_TOKENS.search(b):
        return False
    if "${" in b or "`" in b:
        return False
    return bool(_SAFE_HANDLER_BODY_RE.match(b))


SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})", "AWS Secret Key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
    (r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|"
     r"auth[_-]?token|client[_-]?secret)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{16,}",
     "Generic API Key/Token"),
    (r"(?i)password\s*[=:]\s*[\"'][^\s\"']{4,}", "Password"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub Fine PAT"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack Token"),
    (r"sk_live_[A-Za-z0-9]{20,}", "Stripe Live Key"),
    (r"rk_live_[A-Za-z0-9]{20,}", "Stripe Restricted Key"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
    (r"ya29\.[A-Za-z0-9_-]+", "Google OAuth Access"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate"),
    (r"mongodb(?:\+srv)?://[^\s\"']+", "MongoDB URI"),
    (r"(?:postgres|postgresql|mysql|redis|mssql)://[^\s\"']+", "DB URI"),
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid Key"),
    (r"sq0atp-[A-Za-z0-9_-]{22}", "Square Token"),
    (r"(?i)(?:heroku|twilio|mailgun|firebase)[_-]?(?:api[_-]?)?key\s*[=:]",
     "Cloud provider key"),
    (r"npm_[A-Za-z0-9]{36}", "npm Token"),
    (r"pypi-[A-Za-z0-9]{50,}", "PyPI Token"),
    (r"glpat-[A-Za-z0-9_-]{20}", "GitLab PAT"),
    (r"dckr_pat_[A-Za-z0-9_-]{27}", "Docker PAT"),
    (r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}", "Dynatrace Token"),
    (r"AGE-SECRET-KEY-1[0-9A-Z]{58}", "Age Secret Key"),
    (r"ssh-(?:rsa|ed25519|ecdsa)\s+AAAA[0-9A-Za-z+/]+", "SSH Public Key"),
]

DANGER_PATTERNS = {
    "javascript": [
        (r"\beval\s*\(", "eval()"),
        (r"\binnerHTML\s*=", "innerHTML assignment (XSS)"),
        (r"\bouterHTML\s*=", "outerHTML (XSS)"),
        (r"\bdocument\.write\s*\(", "document.write"),
        (r"\bsetTimeout\s*\(\s*[\"']", "setTimeout string (eval)"),
        (r"\bsetInterval\s*\(\s*[\"']", "setInterval string"),
        (r"\bnew\s+Function\s*\(", "new Function() (eval)"),
        (r"\bchild_process\b", "child_process import"),
        (r"\.exec\s*\(|\.spawn\s*\(", "process exec/spawn"),
        (r"\.postMessage\s*\(", "postMessage"),
        (r"\bdangerouslySetInnerHTML\b", "React dangerouslySetInnerHTML"),
        (r"\bv-html\b", "Vue v-html (XSS)"),
        (r"(?i)\b(select|insert|update|delete)\b.*\+\s*(req|params|query|input)",
         "possible SQL string concat"),
        (r"window\.location\s*=\s*(?!['\"])", "open redirect candidate"),
        (r"\brequire\s*\(\s*(?:req|params|query)", "dynamic require (SSRF/LFI)"),
        (r"document\.cookie\s*=", "document.cookie write"),
        (r"\blocalStorage\.(?:set|get)Item\b", "localStorage use"),
        (r"\b__proto__\b|\bconstructor\.prototype\b", "prototype pollution candidate"),
        (r"\bObject\.assign\s*\([^)]*\.\.\.", "shallow merge (proto pollution?)"),
        (r"\bJSON\.parse\s*\(\s*(?:req|params|query|input)", "untrusted JSON.parse"),
        (r"\bjwt\.decode\s*\([^)]*verify\s*[:=]\s*false", "JWT verify disabled"),
        (r"(?i)algorithm\s*[:=]\s*['\"]none['\"]", "JWT 'none' algorithm"),
        (r"sourceMappingURL\s*=", "sourceMappingURL leak"),
        (r"(?:http|ws)s?://localhost[:/]", "localhost URL leaked"),
        (r"\bExpress\b|\bapp\.(?:get|post|put|delete|use)\(", "Express route"),
        (r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]\*", "CORS *"),
        (r"\bno-cors\b", "no-cors mode"),
        (r"\beval\b.*\bwindow\b", "eval(window)"),
        (r"\bFunction\s*\(\s*['\"]", "Function() ctor"),
        (r"(?i)process\.env\.[A-Z_]+", "process.env read (check defaults)"),
        (r"fetch\s*\(\s*[`\"']/api/", "fetch to /api/ (check authz)"),
    ],
    "typescript": None,
    "python": [
        (r"\beval\s*\(", "eval()"),
        (r"\bexec\s*\(", "exec()"),
        (r"\bpickle\.loads?\s*\(", "pickle deserialization"),
        (r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)", "yaml.load (unsafe)"),
        (r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\b", "subprocess"),
        (r"subprocess\.[a-z_]+\([^)]*shell\s*=\s*True", "subprocess shell=True"),
        (r"\bos\.system\s*\(", "os.system"),
        (r"\b__import__\s*\(", "__import__"),
        (r"\brender_template_string\b", "render_template_string (SSTI)"),
        (r"\bMarkup\s*\(", "Markup (XSS)"),
        (r"\bexecute\s*\(\s*f?[\"'].*\{", "SQL f-string (SQLi?)"),
        (r"(?i)debug\s*=\s*True", "debug=True"),
        (r"\bapp\.run\s*\([^)]*debug\s*=\s*True", "Flask debug=True"),
        (r"\bopen\s*\([^)]*(?:request|input|param|query)", "path traversal?"),
        (r"\brequests\.(?:get|post)\s*\([^)]*(?:url|param|req)", "SSRF?"),
        (r"\bSECRET_KEY\s*=\s*['\"]", "hardcoded SECRET_KEY"),
        (r"\bdeserialize\b|\bmarshal\.loads\b", "unsafe deserialization"),
        (r"\bassert\s+\w+\s*,?\s*$", "assert (disabled with -O)"),
        (r"\binput\s*\(", "input() call (may process untrusted)"),
        (r"\bflask\.Flask\b|\bFlask\s*\(", "Flask app"),
        (r"\bdjango\b", "Django ref"),
        (r"@\w+\.route\(", "Flask route"),
        (r"@app\.(?:get|post|put|delete)\(", "FastAPI route"),
        (r"\bJWT\b.*\b(?:decode|encode)\b", "JWT handling"),
        (r"(?i)verify\s*=\s*False", "TLS/JWT verify=False"),
        (r"\brequests\.(?:get|post)\([^)]*verify\s*=\s*False", "requests verify=False"),
        (r"(?i)allowed_hosts\s*=\s*\[\s*['\"]\*", "ALLOWED_HOSTS=*"),
        (r"\bos\.popen\s*\(", "os.popen"),
        (r"\bchmod\s*\(\s*[^,]+,\s*0o?777", "chmod 777"),
        (r"\bexcept\s*:", "bare except"),
        (r"\bexcept\s+Exception\s*:\s*pass", "silent except"),
        (r"\bimport\s+pickle\b", "pickle import"),
    ],
    "php": [
        (r"\beval\s*\(", "eval()"),
        (r"\bassert\s*\(", "assert()"),
        (r"\bsystem\s*\(|\bexec\s*\(|\bpassthru\s*\(|\bshell_exec\s*\(",
         "command exec"),
        (r"\bunserialize\s*\(", "unserialize"),
        (r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b", "user input superglobal"),
        (r"\b(?:mysql_query|mysqli_query|pg_query)\b", "raw DB query"),
        (r"\binclude\s*\(|\brequire\s*\(", "include/require (LFI?)"),
        (r"\bmove_uploaded_file\s*\(", "file upload"),
        (r"\bextract\s*\(", "extract() (var injection)"),
        (r"\bheader\s*\(\s*['\"]Location", "header Location (open redirect)"),
        (r"\bpreg_replace\s*\([^)]*/e", "preg_replace /e (RCE)"),
        (r"\bcreate_function\s*\(", "create_function (RCE)"),
        (r"\bparse_str\s*\([^)]*\$_(?:GET|POST)", "parse_str into var (injection)"),
        (r"\bmd5\s*\(|\bsha1\s*\(", "weak hash"),
        (r"\bstrcmp\s*\([^)]*\$_(?:GET|POST|REQUEST)", "strcmp bypass candidate"),
        (r"APP_KEY\s*=\s*base64:", "Laravel APP_KEY leaked"),
        (r"DB_PASSWORD\s*=\s*\S+", "Laravel DB_PASSWORD"),
    ],
    "sql": [
        (r"(?i)\bunion\s+select\b", "UNION SELECT"),
        (r"(?i)\bor\s+1\s*=\s*1\b", "OR 1=1"),
        (r"(?i)\bdrop\s+table\b", "DROP TABLE"),
        (r"(?i)\bxp_cmdshell\b", "xp_cmdshell"),
        (r"(?i)\bgrant\s+all\b", "GRANT ALL"),
        (r"(?i)\b(?:password|passwd|pwd)\s+(?:varchar|text)", "password column"),
        (r"(?i)\b(?:md5|sha1)\s*\(", "weak hash in SQL"),
    ],
    "shell": [
        (r"\beval\b", "eval"),
        (r"\bcurl\b[^\n|]*\|\s*(?:sh|bash)", "curl|sh (RCE)"),
        (r"\bwget\b[^\n|]*\|\s*(?:sh|bash)", "wget|sh (RCE)"),
        (r"\bchmod\s+777\b", "chmod 777"),
        (r"/dev/tcp/", "reverse shell /dev/tcp"),
        (r"\bnc\b.*-e\s+/bin/(?:sh|bash)", "netcat reverse shell"),
        (r"\bbash\s+-i\b", "bash -i"),
        (r"\bsudo\b", "sudo use"),
        (r"\brm\s+-rf\s+(?:/|\$\w+)", "dangerous rm"),
        (r"\bset\s*-[a-z]*x", "set -x (debug leak)"),
    ],
    "html": [
        (r"\.innerHTML\s*=\s*[`\"'][^`\"']*\$\{", "innerHTML with template literal (XSS sink)"),
        (r"\.innerHTML\s*=", "innerHTML assignment"),
        (r"\.outerHTML\s*=", "outerHTML assignment"),
        (r"\bdocument\.write\s*\(", "document.write"),
        (r"\$\([^)]+\)\.html\s*\(", "jQuery .html() (XSS sink)"),
        (r"\bdangerouslySetInnerHTML\b", "React dangerouslySetInnerHTML"),
        (r"\bv-html\b", "Vue v-html"),
        (r"<script[^>]*>[\s\S]*?eval\s*\(", "inline eval"),
        (r"<script[^>]+src\s*=\s*[\"']https?://", "external script (supply chain)"),
        (r"javascript:\s*", "javascript: href"),
        (r"<form[^>]*action\s*=\s*[\"'][^\"']+[\"'][^>]*>",
         "form action (check CSRF)"),
        (r"sourceMappingURL\s*=", "sourceMappingURL leak"),
        (r"(?i)<!--.*\bTODO\b", "TODO in comment"),
        (r"(?i)<meta[^>]*name=['\"]?csrf", "CSRF meta (check enforcement)"),
        (r"fetch\s*\(\s*[`\"']/api/", "fetch to /api/ (check authz)"),
        (r"localStorage\.(?:set|get)Item", "localStorage use (token leak?)"),
        (r"document\.cookie\s*=", "document.cookie write"),
    ],
}
DANGER_PATTERNS["typescript"] = DANGER_PATTERNS["javascript"]

# ============================================================
# Framework detection
# ============================================================
FRAMEWORK_SIGNATURES = {
    "Flask":     [r"\bfrom\s+flask\s+import", r"\bFlask\s*\(", r"@app\.route"],
    "Django":    [r"\bdjango\b", r"DJANGO_SETTINGS", r"from\s+django\."],
    "FastAPI":   [r"\bFastAPI\s*\(", r"@app\.(?:get|post|put|delete)\("],
    "Express":   [r"\brequire\(['\"]express['\"]\)", r"\bapp\.use\(", r"\bapp\.listen\("],
    "Next.js":   [r"\bnext/", r"getServerSideProps", r"getStaticProps"],
    "React":     [r"\bfrom\s+['\"]react['\"]", r"\bReact\.createElement", r"dangerouslySetInnerHTML"],
    "Vue":       [r"\bfrom\s+['\"]vue['\"]", r"\bcreateApp\("],
    "Laravel":   [r"\bIlluminate\\", r"APP_KEY\s*=", r"\bDB_PASSWORD\s*="],
    "Symfony":   [r"\bSymfony\\", r"#\[Route"],
    "Spring":    [r"@SpringBootApplication", r"@RestController", r"@RequestMapping"],
    "Rails":     [r"\bRails\.", r"< ApplicationController", r"ActiveRecord"],
    "ASP.NET":   [r"System\.Web\.Mvc", r"\[Http(?:Get|Post|Put|Delete)\]", r"public\s+IActionResult"],
    "jQuery":    [r"jquery(?:[-.]min)?\.js", r"\$\(document\)\.ready"],
    "GraphQL":   [r"\btype\s+Query\b", r"\btype\s+Mutation\b", r"apollo-server"],
}

FRAMEWORK_HINTS = {}  # empty by default; add entries only if needed for your env

TYPE_HINTS = {
    "javascript": "JS/TS FOCUS: DOM-XSS (innerHTML/eval/document.write), prototype pollution, SSRF via fetch, hardcoded secrets, JWT none-alg, CORS *, postMessage origin.",
    "typescript": None,
    "python": "PY FOCUS: eval/exec, pickle/yaml.load, subprocess shell=True, SSTI (render_template_string), SQLi via f-string, debug=True, SECRET_KEY hardcoded.",
    "php": "PHP FOCUS: eval/system/exec with user input, unserialize, SQLi (concat), LFI (include), file upload, extract(), preg_replace /e, md5/sha1 passwords, type juggling.",
    "sql": """
SQL CHECKLIST:
Dangerous DDL/DML, UPDATE/DELETE without WHERE, GRANT ALL, cleartext
passwords/hashes, xp_cmdshell, sensitive tables exposed, MD5/SHA1 use.""",
"html": 'HTML FOCUS: innerHTML/eval sinks, forms without CSRF, hardcoded keys in JS, sourceMappingURL, unsafe onclick args (only if user data flows), localStorage tokens, old jQuery. NOTE: plain onclick="f()" is NOT XSS.',
    "shell": """
SHELL CHECKLIST:
Unquoted variables, eval, curl|sh, chmod 777, sudo without validation,
hardcoded creds, rm/mv dangerous, reverse shells (/dev/tcp, nc -e, bash -i),
download-and-run patterns, set -x leaking secrets.""",
    "pdf": """
PDF NOTE:
You are seeing text extracted by pdftotext. Images, embedded JS, and
attachments are NOT visible. Focus on: internal URLs, credentials, metadata
leaks (author, company), business intel, hidden endpoints.""",
}
TYPE_HINTS["typescript"] = TYPE_HINTS["javascript"]


# ============================================================
# Dataclasses
# ============================================================
@dataclass
class Chunk:
    text: str
    start_line: int
    end_line: int
    idx: int
    danger_count: int = 0
    secret_count: int = 0


# ============================================================
# Utilities
# ============================================================
def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def is_binary(path: str, sample: int = 8192) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read(sample)
    except Exception:
        return True
    if not data:
        return False
    if b"\x00" in data:
        return True
    allowed = bytearray({7, 8, 9, 10, 11, 12, 13, 27} |
                        set(range(0x20, 0x7F)) |
                        set(range(0x80, 0x100)))
    nontext = sum(1 for b in data if b not in allowed)
    return (nontext / max(len(data), 1)) > 0.30


def extract_text(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        if not shutil.which("pdftotext"):
            raise RuntimeError(
                "PDF support requires `pdftotext` (apt install poppler-utils)")
        try:
            r = subprocess.run(
                ["pdftotext", "-layout", "-nopgbrk", path, "-"],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode != 0:
                raise RuntimeError(f"pdftotext failed: {r.stderr.strip()}")
            return r.stdout
        except subprocess.TimeoutExpired:
            raise RuntimeError("pdftotext timed out")
    if is_binary(path):
        raise RuntimeError(f"binary file (not analyzable as text): {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def detect_type(path: str, text: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in FILE_TYPE_MAP:
        return FILE_TYPE_MAP[ext]
    head = text[:200]
    if head.startswith("#!"):
        if "python" in head: return "python"
        if "bash" in head or "/sh" in head: return "shell"
        if "node" in head: return "javascript"
        if "ruby" in head: return "ruby"
    if text.lstrip().startswith("<?php"):
        return "php"
    if text.lstrip().startswith("<"):
        return "html"
    return "text"


def detect_frameworks(text: str) -> list:
    found = []
    for name, sigs in FRAMEWORK_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, text):
                found.append(name)
                break
    return found


def number_lines(text: str, start_line: int) -> str:
    if not text:
        return text
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        out.append(f"L{start_line + i:04d}: {line}")
    return "\n".join(out)


def build_file_toc(ftype: str, text: str, max_items: int = 70) -> str:
    lines = text.splitlines()
    imports, funcs, classes, routes = [], [], [], []

    if ftype == "python":
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"(?:from\s+(\S+)\s+import|import\s+(\S+))", s)
            if m:
                imports.append(m.group(1) or m.group(2))
            m = re.match(r"^(?:async\s+)?def\s+(\w+)", line)
            if m:
                funcs.append(f"L{i:04d}: def {m.group(1)}")
            m = re.match(r"^class\s+(\w+)", line)
            if m:
                classes.append(f"L{i:04d}: class {m.group(1)}")
            m = re.match(r"@\w+\.route\(['\"]([^'\"]+)", s)
            if m:
                routes.append(f"L{i:04d}: ROUTE {m.group(1)}")
            m = re.match(r"@app\.(get|post|put|delete|patch)\(['\"]([^'\"]+)",
                         s)
            if m:
                routes.append(f"L{i:04d}: {m.group(1).upper()} {m.group(2)}")

    elif ftype in ("javascript", "typescript"):
        for i, line in enumerate(lines, 1):
            s = line.strip()
            m = re.match(r"(?:import|require)\b.*['\"]([^'\"]+)['\"]", s)
            if m:
                imports.append(m.group(1))
            m = re.match(r"(?:async\s+)?function\s+(\w+)", s)
            if m:
                funcs.append(f"L{i:04d}: function {m.group(1)}")
            m = re.match(r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*"
                         r"(?:async\s*)?(?:\(|function)", s)
            if m:
                funcs.append(f"L{i:04d}: {m.group(1)} = (fn)")
            m = re.match(r"app\.(get|post|put|delete|patch)\(['\"]([^'\"]+)", s)
            if m:
                routes.append(f"L{i:04d}: {m.group(1).upper()} {m.group(2)}")
            m = re.match(r"class\s+(\w+)", s)
            if m:
                classes.append(f"L{i:04d}: class {m.group(1)}")

    elif ftype == "php":
        for i, line in enumerate(lines, 1):
            s = line.strip()
            m = re.match(r"(?:require|include)(?:_once)?\s*\(?\s*['\"]([^'\"]+)",
                         s)
            if m:
                imports.append(m.group(1))
            m = re.match(r"(?:public\s+|private\s+|protected\s+)?"
                         r"function\s+(\w+)", s)
            if m:
                funcs.append(f"L{i:04d}: function {m.group(1)}")
            m = re.match(r"class\s+(\w+)", s)
            if m:
                classes.append(f"L{i:04d}: class {m.group(1)}")

    elif ftype in ("go", "rust", "java", "csharp", "ruby"):
        for i, line in enumerate(lines, 1):
            s = line.strip()
            m = re.match(r"(?:func|fn|def|public\s+\w+|private\s+\w+)"
                         r"\s+(\w+)\s*\(", s)
            if m:
                funcs.append(f"L{i:04d}: {m.group(1)}()")

    elif ftype == "html":
        for i, line in enumerate(lines, 1):
            s = line.strip()
            m = re.match(r"(?:async\s+)?function\s+(\w+)", s)
            if m:
                funcs.append(f"L{i:04d}: function {m.group(1)}")
            m = re.match(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(",
                         s)
            if m:
                funcs.append(f"L{i:04d}: {m.group(1)} = (fn)")
            m = re.match(r"fetch\s*\(\s*[`\"']([^`\"']+)", s)
            if m:
                routes.append(f"L{i:04d}: FETCH {m.group(1)}")
            m = re.search(r"<form[^>]*action\s*=\s*[\"']([^\"']+)", line)
            if m:
                routes.append(f"L{i:04d}: FORM {m.group(1)}")

    imports = list(dict.fromkeys(imports))[:25]
    classes = classes[:30]
    funcs = funcs[:50]
    routes = routes[:30]

    parts = []
    if imports:
        parts.append("Imports/deps: " + ", ".join(imports))
    if classes:
        parts.append("Classes:\n  " + "\n  ".join(classes))
    if funcs:
        parts.append("Functions:\n  " + "\n  ".join(funcs))
    if routes:
        parts.append("Routes/endpoints:\n  " + "\n  ".join(routes))

    if not parts:
        return ""
    text_toc = "\n\n".join(parts)
    if len(text_toc) > 2000:
        text_toc = text_toc[:2000] + "\n  ... (TOC truncated)"
    return text_toc


# ============================================================
# Pre-scan
# ============================================================
def extract_inline_js(text: str) -> str:
    return "\n\n".join(m.group(1) for m in SCRIPT_BLOCK_RE.finditer(text))


def prescan(text: str, ftype: str) -> dict:
    out = {
        "secrets": [], "dangers": [], "urls": [], "imports": [],
        "ips": [], "emails": [], "frameworks": [],
        "line_count": text.count("\n") + 1,
        "inline_scripts": 0,
        "event_handlers": 0,
        "safe_handlers": 0,
    }

    for pat, label in SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            s = m.group(0)
            red = (s[:8] + "…" + s[-4:]) if len(s) > 16 else s
            line = text[:m.start()].count("\n") + 1
            out["secrets"].append({"type": label, "value": red, "line": line,
                                    "raw_len": len(s)})

    for pat, label in DANGER_PATTERNS.get(ftype, []):
        for m in re.finditer(pat, text, re.MULTILINE):
            line = text[:m.start()].count("\n") + 1
            out["dangers"].append({
                "type": label, "line": line,
                "match": m.group(0)[:120].replace("\n", " "),
            })

    if ftype == "html":
        blocks = list(SCRIPT_BLOCK_RE.finditer(text))
        out["inline_scripts"] = len(blocks)
        if blocks:
            inline_js = "\n\n".join(m.group(1) for m in blocks)
            for pat, label in DANGER_PATTERNS.get("javascript", []):
                for m in re.finditer(pat, inline_js, re.MULTILINE):
                    snippet = m.group(0)
                    orig = text.find(snippet)
                    line = text[:orig].count("\n") + 1 if orig >= 0 else 0
                    out["dangers"].append({
                        "type": f"[inline JS] {label}",
                        "line": line,
                        "match": snippet[:120].replace("\n", " "),
                    })

        # v3.3: classify handlers before flagging
        handlers = list(EVENT_HANDLER_RE.finditer(text))
        out["event_handlers"] = len(handlers)
        for m in handlers:
            body = m.group(2).strip()
            if is_safe_handler_body(body):
                out["safe_handlers"] += 1
                continue  # do NOT trigger hot pass
            line = text[:m.start()].count("\n") + 1
            out["dangers"].append({
                "type": f"inline on{m.group(1)}= (suspicious — verify source)",
                "line": line,
                "match": m.group(0)[:120].replace("\n", " "),
            })

    for m in re.finditer(r"https?://[^\s\"'\)<>]+", text):
        out["urls"].append(m.group(0)[:200])
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        out["ips"].append(m.group(0))
    for m in re.finditer(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
        out["emails"].append(m.group(0))

    if ftype == "python":
        for m in re.finditer(r"^\s*(?:from\s+\S+\s+)?import\s+.+$",
                             text, re.MULTILINE):
            out["imports"].append(m.group(0).strip()[:120])
    elif ftype in ("javascript", "typescript"):
        for m in re.finditer(
                r"(?:require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
                r"|from\s+['\"]([^'\"]+)['\"])", text):
            out["imports"].append((m.group(1) or m.group(2))[:120])

    out["frameworks"] = detect_frameworks(text)

    for k in ("urls", "imports", "ips", "emails"):
        out[k] = list(dict.fromkeys(out[k]))[:50]

    return out


def _hits_with_context(text: str, hits: list, max_hits: int = 12,
                       context: int = PRESCAN_CONTEXT) -> str:
    if not hits:
        return ""
    lines = text.splitlines()
    out = []
    shown = 0
    seen = set()
    for hit in hits:
        key = (hit["line"], hit["type"])
        if key in seen:
            continue
        seen.add(key)
        if shown >= max_hits:
            out.append(f"  ... ({len(hits) - shown} more hits truncated)")
            break
        shown += 1
        n = hit["line"]
        if n < 1:
            continue
        start = max(1, n - context)
        end = min(len(lines), n + context)
        out.append(f"- {hit['type']} (L{n:04d}):")
        for i in range(start, end + 1):
            marker = ">" if i == n else " "
            content = lines[i - 1] if i - 1 < len(lines) else ""
            out.append(f"  {marker}L{i:04d}: {content[:180]}")
    return "\n".join(out)


def _format_prescan_hints(text: str, dangers: list, secrets: list) -> str:
    if not dangers and not secrets:
        return ""
    parts = []
    if dangers:
        parts.append("DANGEROUS PATTERNS (regex-detected — verify below):")
        parts.append(_hits_with_context(text, dangers, max_hits=10,
                                        context=PRESCAN_CONTEXT))
    if secrets:
        parts.append("POSSIBLE SECRETS (regex-detected — verify below):")
        parts.append(_hits_with_context(text, secrets, max_hits=8,
                                        context=PRESCAN_CONTEXT))
    return "\n".join(parts)


def prescan_markdown(p: dict, text: str = "") -> str:
    has_any = (p["secrets"] or p["dangers"] or p["urls"]
               or p["imports"] or p["frameworks"])
    if not has_any:
        note = "_no regex hits_"
        if p.get("inline_scripts") or p.get("event_handlers"):
            note += (f"\n\n_File contains {p.get('inline_scripts', 0)} "
                     f"<script> block(s) and {p.get('event_handlers', 0)} "
                     f"inline event handler(s). LLM review is authoritative._")
        return note + "\n"

    lines = []
    if p["frameworks"]:
        lines.append("**Detected frameworks:** " + ", ".join(p["frameworks"]))
    if p.get("inline_scripts"):
        lines.append(f"**Inline <script> blocks:** {p['inline_scripts']}")
    if p.get("event_handlers"):
        safe = p.get("safe_handlers", 0)
        susp = p["event_handlers"] - safe
        lines.append(
            f"**Inline event handlers:** {p['event_handlers']} total, "
            f"{safe} safe, {susp} suspicious")

    if p["secrets"]:
        lines.append("\n**Possible secrets (regex):**")
        for s in p["secrets"][:40]:
            lines.append(f"- L{s['line']:04d}: `{s['type']}` → `{s['value']}`")

    if p["dangers"]:
        lines.append("\n**Dangerous patterns:**")
        by_type = {}
        for d in p["dangers"]:
            by_type.setdefault(d["type"], []).append(d)
        for typ, hits in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"- `{typ}` ×{len(hits)}: " +
                         ", ".join(f"L{h['line']:04d}" for h in hits[:8]) +
                         (" ..." if len(hits) > 8 else ""))

    if p["urls"]:
        lines.append("\n**URLs:**")
        for u in p["urls"][:30]:
            lines.append(f"- {u}")

    if p["ips"]:
        lines.append("\n**IPs:** " + ", ".join(p["ips"][:20]))
    if p["emails"]:
        lines.append("\n**Emails:** " + ", ".join(p["emails"][:20]))
    if p["imports"]:
        lines.append("\n**Imports / deps:**")
        for i in p["imports"][:40]:
            lines.append(f"- `{i}`")

    return "\n".join(lines) + "\n"


# ============================================================
# Chunking
# ============================================================
def _count_lines(s: str) -> int:
    return s.count("\n") + (1 if s and not s.endswith("\n") else 0)


_BOUNDARY_RE = re.compile(
    r"^(?:"
    r"(?:async\s+)?def\s+\w+"
    r"|class\s+\w+"
    r"|(?:async\s+)?function\s+\w+"
    r"|(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\("
    r"|(?:public\s+|private\s+|protected\s+)?function\s+\w+"
    r"|func\s+\w+"
    r"|fn\s+\w+"
    r"|public\s+(?:static\s+)?\w+\s+\w+\s*\("
    r"|@\w+"
    r")",
    re.MULTILINE,
)


def _split_at_boundaries(text: str) -> list:
    parts = re.split(r"\n\s*\n", text)
    out = []
    for p in parts:
        if len(p) < 200:
            out.append(p)
            continue
        cut_points = [m.start() for m in _BOUNDARY_RE.finditer(p)]
        if not cut_points or (cut_points[0] == 0 and len(cut_points) == 1):
            out.append(p)
            continue
        prev = 0
        for cp in cut_points[1:]:
            if cp - prev > 200:
                out.append(p[prev:cp])
                prev = cp
        out.append(p[prev:])
    return out


def _chunk_code(text: str, max_chars: int, overlap: int) -> list:
    parts = _split_at_boundaries(text)
    if not parts:
        return [Chunk(text, 1, _count_lines(text), 0)]
    chunks, cur, cur_len, start_line, line_cursor = [], [], 0, 1, 1
    for p in parts:
        plen = len(p) + 2
        p_lines = _count_lines(p) + 2
        if cur_len + plen > max_chars and cur:
            body = "\n\n".join(cur)
            chunks.append(Chunk(body, start_line, line_cursor - 1,
                                len(chunks)))
            tail = cur[-1] if len(cur[-1]) <= overlap else ""
            cur = [tail] if tail else []
            cur_len = len(tail) + 2 if tail else 0
            start_line = line_cursor - (tail.count("\n") + 1 if tail else 0)
        cur.append(p)
        cur_len += plen
        line_cursor += p_lines
    if cur:
        body = "\n\n".join(cur)
        chunks.append(Chunk(body, start_line, line_cursor - 1, len(chunks)))
    return [c for c in chunks if c.text.strip()]


def _chunk_lines(text: str, max_chars: int, overlap: int) -> list:
    if max_chars <= 0 or len(text) <= max_chars:
        return [Chunk(text, 1, _count_lines(text), 0)]
    chunks, cur, cur_len, start_line, line_cursor = [], [], 0, 1, 1
    for line in text.splitlines(keepends=True):
        if cur_len + len(line) > max_chars and cur:
            body = "".join(cur)
            chunks.append(Chunk(body, start_line, line_cursor - 1,
                                len(chunks)))
            tail = cur[-1] if len(cur[-1]) <= overlap else ""
            cur = [tail] if tail else []
            cur_len = len(tail) if tail else 0
            start_line = line_cursor - (1 if tail else 0)
        if len(line) > max_chars:
            for i in range(0, len(line), max_chars - overlap):
                chunks.append(Chunk(line[i:i + max_chars],
                                    line_cursor, line_cursor,
                                    len(chunks)))
            cur, cur_len = [], 0
            start_line = line_cursor
        else:
            cur.append(line)
            cur_len += len(line)
        line_cursor += 1
    if cur:
        body = "".join(cur)
        chunks.append(Chunk(body, start_line, line_cursor - 1, len(chunks)))
    return chunks


def chunk_text(text: str, max_chars: int, ftype: str,
               overlap: int = CHUNK_OVERLAP) -> list:
    if max_chars <= 0 or len(text) <= max_chars:
        return [Chunk(text, 1, _count_lines(text), 0)]
    if ftype in CODE_TYPES:
        return _chunk_code(text, max_chars, overlap)
    return _chunk_lines(text, max_chars, overlap)


def annotate_chunks_with_dangers(chunks: list, prescan_data: dict) -> None:
    for c in chunks:
        c.danger_count = sum(
            1 for d in prescan_data["dangers"]
            if c.start_line <= d["line"] <= c.end_line
        )
        c.secret_count = sum(
            1 for s in prescan_data["secrets"]
            if c.start_line <= s["line"] <= c.end_line
        )


# ============================================================
# Prompts
# ============================================================
SEVERITY_RUBRIC = """CRITICAL=RCE/auth-bypass | HIGH=SQLi/XSS/SSRF/LFI/IDOR | MEDIUM=CSRF/open-redirect/missing-authz | INFO=version-leak. Never LOW."""

EVIDENCE_RULES = """Cite `L####: <exact code>`. No quote=no finding. Uncertain=`(?)`.
Anti-FP: onclick="f()"/onsubmit="h()" NOT XSS unless user input flows. <img src=${v}> NOT SSRF (browser-side). Don't invent form action=."""

BASE_ANALYSIS_TMPL = """Senior pentester. Audit this chunk. Real findings only.

{severity_rubric}

{evidence_rules}

{type_hints}
{framework_hints}

TOC (context only, findings from chunk):
{toc}

Output only these ## sections. "(none)" if empty. No filler.

## SUMMARY
## VULNERABILITIES
- **[SEV]** Type (CWE-xxx) — `L####: code` — impact
## ENDPOINTS
- `METHOD /path` — purpose
## SECRETS / CREDENTIALS
- `L####: token/key/password`
## INTERESTING STRINGS
- paths, URLs, IPs, emails, TODOs, versions
## NOTES
- obfuscation, gaps

<file path="{path}" type="{ftype}" chunk="{idx1}/{total}" lines="{start_line}-{end_line}/{total_lines}">
{hints}
{chunk}
</file>
"""

SYNTHESIS_PROMPT = """Merge N partial reports of ONE file into one report.
Sections in order: ## SUMMARY, ## VULNERABILITIES, ## ENDPOINTS, ## SECRETS / CREDENTIALS, ## INTERESTING STRINGS, ## NOTES.
SUMMARY = whole file (never "this chunk"). Dedupe by (CWE+evidence). On severity conflict keep HIGHEST. Preserve line numbers. Never LOW. No filler. No ``` fences.

PARTIAL REPORTS:
"""

HOT_CHUNK_PROMPT = """Deep review of a prescan-flagged chunk. Triage, don't list.

SAFE → one NOTES line, do not report:
- onclick/oninput/onsubmit with literal or no args (no user data flows)
- <img src=${v}> server-rendered (browser-side, not SSRF)
- innerHTML="literal"
- fetch("/api/x") fixed URL
- any pattern where user→sink chain isn't visible

SUSPICIOUS → report with `(?)`:
- sink has var whose source isn't in chunk
- innerHTML=${v} where v could be JSON
- location=<var>, eval(<var>), Function(<var>), document.write(<var>)
- fetch(<var>) from query/body/storage

VULNERABLE → report without `(?)`:
- full source→sink chain visible
- hardcoded prod secret
- direct user input in command/SQL/path

## VULNERABILITIES
- **[SEV]** Type (CWE-xxx) — `L####: code`
  Source: <where> | Sink: <what> | Exploitable: yes/prereq/unknown | Payload: <sketch>
Never LOW. Nothing suspicious → exactly "(none)".

## NOTES
- `L####: safe — <why>`

No "**Severity:**" for non-exploitable (→ NOTES). No ``` fences.

<chunk path="{path}" type="{ftype}" lines="{start_line}-{end_line}">
{framework_hints}
{hits}
{chunk}
</chunk>
"""


# ============================================================
# Streaming helpers
# ============================================================
def _resolve_stream_mode(args) -> str:
    if not args.stream:
        return "quiet"
    if args.stream_mode == "auto":
        return "raw" if args.parallel == 1 else "offs"
    return args.stream_mode


def _make_stream_cb(mode: str, tag: str, stream_dir: str = None):
    if mode == "quiet" or mode == "offs":
        return None
    if mode == "dir" and stream_dir:
        os.makedirs(stream_dir, exist_ok=True)
        fname = re.sub(r"[^\w\-]+", "_", tag) + ".txt"
        fpath = os.path.join(stream_dir, fname)
        fh = open(fpath, "w", encoding="utf-8")

        def _cb(tok):
            try:
                fh.write(tok)
                fh.flush()
            except Exception:
                pass
        _cb._fpath = fpath
        _cb._fh = fh
        return _cb

    def _cb(tok):
        with _STREAM_LOCK:
            sys.stderr.write(tok)
            sys.stderr.flush()
    return _cb


def _emit_start(tag, mode, num_ctx, num_predict, show_stats):
    if mode == "quiet" and not show_stats:
        return
    msg = f"    [{tag}] start ctx={num_ctx} pred={num_predict}"
    with _STREAM_LOCK:
        if mode == "raw":
            sys.stderr.write(msg + "\n")
        else:
            print(msg, file=sys.stderr)
        sys.stderr.flush()


def _emit_done(tag, elapsed, stats, mode, show_stats):
    tok = stats.get("eval_count", 0)
    prompt_tok = stats.get("prompt_eval_count", 0)
    eval_ns = stats.get("eval_duration_ns", 0) or 0
    peval_ns = stats.get("prompt_eval_duration_ns", 0) or 0
    load_s = stats.get("load_duration_ns", 0) / 1e9
    # Real generation speed: tokens / eval time (excludes prompt eval & load)
    eval_tps = (tok / (eval_ns / 1e9)) if eval_ns > 0 else 0.0
    # Real prompt eval speed: prompt tokens / prompt eval time
    peval_tps = (prompt_tok / (peval_ns / 1e9)) if peval_ns > 0 else 0.0
    parts = []
    if prompt_tok:
        if peval_tps > 0:
            parts.append(f"prompt={prompt_tok}tok@{peval_tps:.0f}tok/s")
        else:
            parts.append(f"prompt={prompt_tok}tok")
    parts.append(f"eval={tok}tok@{eval_tps:.1f}tok/s")
    parts.append(f"wall={elapsed:.1f}s")
    if load_s > 1.0:
        parts.append(f"cold-load={load_s:.1f}s")
    line = f"    [{tag}] done: " + " | ".join(parts)
    with _STREAM_LOCK:
        if mode == "raw":
            sys.stderr.write("\n" + line + "\n")
        else:
            print(line, file=sys.stderr)
        sys.stderr.flush()

    # v3.4 — think-mode leak warning (should never fire when think=False
    # is honoured). Surfaced separately so it's not lost in stats noise.
    think_tokens = stats.get("think_tokens_seen", 0)
    if think_tokens:
        warn = (f"    [{tag}] ⚠️ think LEAKED: {think_tokens} reasoning "
                f"token(s) received despite think={_FORCED_THINK}. "
                f"Ollama ignored the flag — upgrade server or check the "
                f"model family.")
        with _STREAM_LOCK:
            print(warn, file=sys.stderr)
            sys.stderr.flush()


# ============================================================
# Ollama client
# ============================================================
def _build_payload(model, prompt, num_ctx, num_predict,
                   keep_alive, extra_options, stream):
    # v3.4 — hard guard: `think` is an invariant, not an option.
    # Ollama reads `think` top-level; anything inside `options` is ignored
    # or rejected. Reject early so nobody thinks they've toggled it.
    if extra_options and "think" in extra_options:
        raise ValueError(
            "`think` is forced to False and cannot be overridden via "
            "extra_options; it is set top-level in the payload.")
    options = {
        "temperature": 0.15,
        "top_p": 0.9,
        "top_k": 20,
        "repeat_penalty": 1.05,
        "num_ctx": num_ctx,
        "num_predict": num_predict,
    }
    if DEFAULT_NUM_GPU is not None:
        try:    options["num_gpu"] = int(DEFAULT_NUM_GPU)
        except: pass
    if extra_options:
        options.update(extra_options)
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": stream,
        "keep_alive": keep_alive,
        "options": options,
        # v3.4 — single source of truth; never a literal here.
        "think": _FORCED_THINK,
    }
    if DEFAULT_STOP:
        payload["options"]["stop"] = [s for s in DEFAULT_STOP.split("\\n") if s]
    return payload


def ollama_chat(host, model, prompt, num_ctx, num_predict, timeout,
                keep_alive="30m", extra_options=None):
    payload = _build_payload(model, prompt, num_ctx, num_predict,
                              keep_alive, extra_options, stream=False)
    r = requests.post(host.rstrip("/") + "/api/chat",
                      json=payload, timeout=timeout)
    r.raise_for_status()
    msg = r.json().get("message", {}) or {}
    # v3.4 — defensive: if the server ignored think=False, warn loudly.
    thinking = msg.get("thinking", "") or ""
    if thinking:
        print(f"    [⚠️ think] non-stream response contained "
              f"{len(thinking)} reasoning chars despite "
              f"think={_FORCED_THINK}", file=sys.stderr, flush=True)
    return msg.get("content", "") or ""


def ollama_chat_stream(host, model, prompt, num_ctx, num_predict, timeout,
                       keep_alive="30m", extra_options=None, cb=None):
    payload = _build_payload(model, prompt, num_ctx, num_predict,
                              keep_alive, extra_options, stream=True)
    r = requests.post(host.rstrip("/") + "/api/chat",
                      json=payload, timeout=timeout, stream=True)
    r.raise_for_status()
    buf = []
    stats = {}
    think_tokens_seen = 0  # v3.4 — count any leaked reasoning tokens
    try:
        for line in r.iter_lines():
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" in obj:
                raise requests.exceptions.RequestException(
                    f"Ollama error: {obj['error']}")
            if obj.get("done"):
                stats = {
                    "eval_count": obj.get("eval_count", 0),
                    "eval_duration_ns": obj.get("eval_duration", 0),
                    "prompt_eval_count": obj.get("prompt_eval_count", 0),
                    "prompt_eval_duration_ns": obj.get("prompt_eval_duration", 0),
                    "total_duration_ns": obj.get("total_duration", 0),
                    "load_duration_ns": obj.get("load_duration", 0),
                }
                if think_tokens_seen:
                    stats["think_tokens_seen"] = think_tokens_seen
                break
            msg = obj.get("message", {}) or {}
            # v3.4 — detect and count thinking tokens (should be empty).
            thk = msg.get("thinking", "") or ""
            if thk:
                think_tokens_seen += 1
            tok = msg.get("content", "")
            if tok:
                buf.append(tok)
                if cb is not None:
                    cb(tok)
    finally:
        r.close()
    return "".join(buf), stats


def call_with_retry(host, model, prompt, num_ctx, num_predict, timeout,
                    retries=2, tag="", keep_alive="30m",
                    extra_options=None, stream=False, stream_cb=None,
                    stream_mode="quiet", show_stats=False):
    last = None
    for attempt in range(retries + 1):
        try:
            _emit_start(tag, stream_mode, num_ctx, num_predict, show_stats)
            t0 = time.monotonic()
            if stream:
                content, stats = ollama_chat_stream(
                    host, model, prompt, num_ctx, num_predict, timeout,
                    keep_alive=keep_alive, extra_options=extra_options,
                    cb=stream_cb,
                )
            else:
                content = ollama_chat(
                    host, model, prompt, num_ctx, num_predict, timeout,
                    keep_alive=keep_alive, extra_options=extra_options,
                )
                stats = {}
            elapsed = time.monotonic() - t0
            _emit_done(tag, elapsed, stats, stream_mode, show_stats)
            return content
        except requests.exceptions.RequestException as e:
            last = e
            if attempt < retries:
                w = 2 ** attempt
                print(f"    [!] {tag} retry {attempt+1}/{retries} in {w}s: {e}",
                      file=sys.stderr, flush=True)
                time.sleep(w)
    raise last  # type: ignore


# ============================================================
# Prompt builders
# ============================================================
def _framework_hints_block(frameworks: list) -> str:
    if not frameworks:
        return ""
    lines = ["FRAMEWORK-SPECIFIC FOCUS:"]
    for f in frameworks:
        if f in FRAMEWORK_HINTS:
            lines.append(f"- {f}: {FRAMEWORK_HINTS[f]}")
    return "\n".join(lines) if len(lines) > 1 else ""


def _prescan_for_range(prescan_data: dict, start: int, end: int) -> dict:
    return {
        "dangers": [d for d in prescan_data["dangers"]
                    if start <= d["line"] <= end],
        "secrets": [s for s in prescan_data["secrets"]
                    if start <= s["line"] <= end],
    }


def build_chunk_prompt(args, chunk: Chunk, total: int,
                       prescan_data: dict) -> str:
    chunk_hits = _prescan_for_range(prescan_data, chunk.start_line,
                                     chunk.end_line)
    hints = _format_prescan_hints(chunk.text, chunk_hits["dangers"],
                                   chunk_hits["secrets"])
    if args.line_numbers:
        chunk_body = number_lines(chunk.text, chunk.start_line)
    else:
        chunk_body = chunk.text
    return BASE_ANALYSIS_TMPL.format(
        ftype_upper=args.ftype.upper(),
        path=args.path, ftype=args.ftype,
        idx1=chunk.idx + 1, total=total,
        start_line=chunk.start_line, end_line=chunk.end_line,
        total_lines=prescan_data["line_count"],
        type_hints=TYPE_HINTS.get(args.ftype, ""),
        framework_hints=_framework_hints_block(args.frameworks),
        severity_rubric=SEVERITY_RUBRIC,
        evidence_rules=EVIDENCE_RULES,
        toc=args.toc_text or "(none)",
        hints=hints or "",
        chunk=chunk_body,
    )


def build_hot_chunk_prompt(args, chunk: Chunk, prescan_data: dict) -> str:
    chunk_hits = _prescan_for_range(prescan_data, chunk.start_line,
                                     chunk.end_line)
    hits = _format_prescan_hints(chunk.text, chunk_hits["dangers"],
                                  chunk_hits["secrets"])
    if args.line_numbers:
        chunk_body = number_lines(chunk.text, chunk.start_line)
    else:
        chunk_body = chunk.text
    return HOT_CHUNK_PROMPT.format(
        path=args.path, ftype=args.ftype,
        start_line=chunk.start_line, end_line=chunk.end_line,
        framework_hints=_framework_hints_block(args.frameworks),
        hits=hits or "(none)",
        chunk=chunk_body,
    )


# ============================================================
# Adaptive sizing
# ============================================================
def _adaptive_ctx(prompt_chars: int, num_predict: int,
                  min_ctx: int = 2048, floor: int = 512) -> int:
    est_prompt_tokens = prompt_chars // 3
    needed = est_prompt_tokens + num_predict + 512
    return max(min_ctx, (needed + floor - 1) // floor * floor)


# ============================================================
# Analysis orchestration
# ============================================================
def analyze_one_chunk(args, chunk: Chunk, total: int,
                      prescan_data: dict) -> str:
    prompt = build_chunk_prompt(args, chunk, total, prescan_data)
    num_ctx = args.num_ctx
    if args.adaptive_ctx:
        num_ctx = _adaptive_ctx(len(prompt), args.num_predict)
    tag = f"chunk {chunk.idx+1}/{total}"
    mode = _resolve_stream_mode(args)
    cb = _make_stream_cb(mode, tag, args.stream_dir)
    try:
        return call_with_retry(
            args.host, args.model, prompt,
            num_ctx, args.num_predict, args.timeout,
            tag=tag, keep_alive=args.keep_alive,
            stream=(mode != "quiet"), stream_cb=cb,
            stream_mode=mode, show_stats=args.stats,
        )
    finally:
        if cb is not None and hasattr(cb, "_fh"):
            try: cb._fh.close()
            except Exception: pass


def hot_pass(args, chunk: Chunk, prescan_data: dict) -> str:
    prompt = build_hot_chunk_prompt(args, chunk, prescan_data)
    num_ctx = args.num_ctx
    num_predict = max(args.num_predict, 3072)
    if args.adaptive_ctx:
        num_ctx = _adaptive_ctx(len(prompt), num_predict)
    tag = f"HOT {chunk.idx+1}"
    mode = _resolve_stream_mode(args)
    cb = _make_stream_cb(mode, tag, args.stream_dir)
    try:
        return call_with_retry(
            args.host, args.model, prompt,
            num_ctx, num_predict, args.timeout,
            tag=tag, keep_alive=args.keep_alive,
            stream=(mode != "quiet"), stream_cb=cb,
            stream_mode=mode, show_stats=args.stats,
        )
    finally:
        if cb is not None and hasattr(cb, "_fh"):
            try: cb._fh.close()
            except Exception: pass


def synthesize(args, partials: list) -> str:
    joined = "\n\n---CHUNK SEPARATOR---\n\n".join(
        f"[CHUNK {i+1}]\n{p}" for i, p in enumerate(partials))
    prompt = SYNTHESIS_PROMPT + joined
    num_ctx = args.num_ctx
    if args.adaptive_ctx:
        num_ctx = _adaptive_ctx(len(prompt), args.num_predict)
    mode = _resolve_stream_mode(args)
    cb = _make_stream_cb(mode, "synthesis", args.stream_dir)
    try:
        return call_with_retry(
            args.host, args.model, prompt,
            num_ctx, args.num_predict, args.timeout,
            tag="synthesis", keep_alive=args.keep_alive,
            stream=(mode != "quiet"), stream_cb=cb,
            stream_mode=mode, show_stats=args.stats,
        )
    finally:
        if cb is not None and hasattr(cb, "_fh"):
            try: cb._fh.close()
            except Exception: pass


def run_analysis(args, chunks: list, prescan_data: dict) -> str:
    total = len(chunks)
    results = [None] * total
    t_start = time.monotonic()

    if args.parallel > 1 and total > 1:
        print(f"    -> parallel pass: {total} chunks, "
              f"workers={args.parallel}", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=args.parallel) as ex:
            futs = {
                ex.submit(analyze_one_chunk, args, c, total, prescan_data): c
                for c in chunks
            }
            for fut in as_completed(futs):
                c = futs[fut]
                try:
                    results[c.idx] = fut.result()
                except Exception as e:
                    print(f"    [!] chunk {c.idx+1} failed: {e}",
                          file=sys.stderr)
                    results[c.idx] = f"## NOTES\n(chunk {c.idx+1} failed: {e})"
    else:
        for c in chunks:
            try:
                results[c.idx] = analyze_one_chunk(args, c, total, prescan_data)
            except Exception as e:
                print(f"    [!] chunk {c.idx+1} failed: {e}",
                      file=sys.stderr)
                results[c.idx] = f"## NOTES\n(chunk {c.idx+1} failed: {e})"

    hot_threshold = max(3, args.hot_threshold)
    hot_chunks = [c for c in chunks if c.danger_count >= hot_threshold]
    if hot_chunks:
        print(f"    -> hot pass on {len(hot_chunks)} chunk(s) "
              f"(>= {hot_threshold} signals)", file=sys.stderr)
        for c in hot_chunks:
            try:
                deep = hot_pass(args, c, prescan_data)
                results[c.idx] = (results[c.idx] or "") + \
                    "\n\n### DEEP DIVE (hot chunk)\n" + deep
            except Exception as e:
                print(f"    [!] hot pass {c.idx+1} failed: {e}",
                      file=sys.stderr)

    if total == 1 or args.skip_synthesis:
        if total > 1:
            print(f"    -> skip-synthesis: concatenating {total} chunks",
                  file=sys.stderr)
        return "\n\n---CHUNK SEPARATOR---\n\n".join(r or "" for r in results)

    print(f"    -> synthesizing {total} chunks", file=sys.stderr)
    out = synthesize(args, results)
    print(f"    -> analysis total: {time.monotonic()-t_start:.1f}s",
          file=sys.stderr)
    return out


# ============================================================
# Post-processing
# ============================================================
def parse_sections(text: str) -> dict:
    sections = {k: "" for k in SECTION_ORDER}
    current = None
    for line in text.splitlines():
        m = re.match(r"^#{2,3}\s+(.+?)\s*$", line)
        if m:
            header = m.group(1).strip().upper()
            matched = None
            for k in SECTION_ORDER:
                if k.upper() == header:
                    matched = k
                    break
            if matched:
                current = matched
                continue
        if current:
            sections[current] += line + "\n"
    return sections


def strip_not_exploitable_blocks(text: str) -> tuple:
    """Remove VULNERABILITIES blocks the LLM itself declared not exploitable."""
    if not text:
        return text, 0
    removed = [0]

    def _scrub(section: str) -> str:
        blocks = re.split(r"(?=\*\*Severity[:*\s]*)", section)
        out = []
        for b in blocks:
            if not b.strip():
                continue
            window = b[:800].lower()
            if any(k in window for k in (
                "not exploitable", "is not exploitable",
                "no xss vector", "no user-input", "no user input",
                "not a vulnerability", "not vulnerable",
                "no exploitable", "no user-controlled",
                "no user-controllable",
            )) or re.search(r"\*\*is it exploitable[^\n]*\*\*\s*no\b",
                            window):
                if not re.search(r"\b(exploitable|vulnerable)[^\n]*"
                                 r"\b(?:but|however|if)\b", window):
                    removed[0] += 1
                    continue
            out.append(b)
        return "".join(out)

    parts = re.split(r"(?m)^(##\s+.+)$", text)
    rebuilt = []
    in_vulns = False
    for i, p in enumerate(parts):
        if i % 2 == 1:
            in_vulns = p.strip().upper().startswith("## VULNERABILITIES")
            rebuilt.append(p)
        elif in_vulns:
            scrubbed = _scrub(p)
            rebuilt.append(scrubbed if scrubbed.strip() else "(none)\n")
        else:
            rebuilt.append(p)
    return "".join(rebuilt), removed[0]


def dedup_vulnerabilities(text: str) -> str:
    if not text:
        return text
    out_lines, seen = [], set()
    in_vulns = False
    for line in text.splitlines():
        s = line.strip()
        if s.upper().startswith("## VULNERABILITIES"):
            in_vulns = True
            out_lines.append(line)
            continue
        if s.startswith("## ") and not s.upper().startswith("## VULNERABILITIES"):
            in_vulns = False
        if in_vulns and s.startswith("- "):
            parts = re.split(r"\s+—\s+", s, maxsplit=2)
            sev_m = re.match(r"-\s*\*\*(\w+)\*\*\s*(.+)", parts[0])
            if sev_m:
                sev = sev_m.group(1)
                typ = sev_m.group(2).strip().lower()
                line_ref = ""
                if len(parts) >= 2:
                    m2 = re.search(r"`L(\d+)", parts[1])
                    if m2:
                        line_ref = m2.group(1)
                key = (sev, typ, line_ref)
                if key in seen:
                    continue
                seen.add(key)
        out_lines.append(line)
    return "\n".join(out_lines)


LINE_REF_RE = re.compile(r"`L(\d{1,5}):\s*([^`]{3,240})`")


def verify_line_refs(analysis_text: str, file_lines: list) -> tuple:
    report = []

    def _repl(m):
        n = int(m.group(1))
        quote = m.group(2).strip()
        key = re.split(r"\.\.\.|\(\?\)", quote)[0].strip()[:60]
        key_norm = re.sub(r"\s+", " ", key)
        if n < 1 or n > len(file_lines):
            report.append(f"- L{n:04d}: OUT OF RANGE — `{quote[:60]}`")
            return f"`L{n}: {quote}` ⚠️OUT-OF-RANGE"
        actual = re.sub(r"\s+", " ", file_lines[n - 1]).strip()
        if not key_norm or key_norm in actual:
            return m.group(0)
        for delta in (-1, 1, -2, 2):
            j = n + delta - 1
            if 0 <= j < len(file_lines):
                adj = re.sub(r"\s+", " ", file_lines[j]).strip()
                if key_norm in adj:
                    report.append(f"- L{n:04d}: moved to L{n+delta:04d}")
                    return f"`L{n+delta}: {quote}`"
        report.append(f"- L{n:04d}: NOT IN FILE — `{quote[:60]}` "
                      f"(actual: `{actual[:60]}`)")
        return f"`L{n}: {quote}` ⚠️UNVERIFIED"

    cleaned = LINE_REF_RE.sub(_repl, analysis_text)
    return cleaned, report


def format_analysis(path, sha, size, ftype, model, n_chunks,
                    sections, prescan_data, frameworks, total_lines) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = [
        HEADER_DELIM,
        f"FILE:   {path}",
        f"SHA256: {sha}",
        f"SIZE:   {size}",
        f"TYPE:   {ftype}",
        f"MODEL:  {model}",
        f"DATE:   {ts}",
        f"CHUNKS: {n_chunks}",
        f"LINES:  {total_lines}",
        f"FRAMEWORKS: {', '.join(frameworks) or 'none'}",
        f"INLINE-SCRIPTS: {prescan_data.get('inline_scripts', 0)}",
        f"EVENT-HANDLERS: {prescan_data.get('event_handlers', 0)} "
        f"({prescan_data.get('safe_handlers', 0)} safe)",
        HEADER_DELIM, "",
    ]
    body = []
    for k in SECTION_ORDER:
        body.append(f"## {k}")
        section_text = (sections.get(k) or "").strip() or "(none)"
        if k == "VULNERABILITIES":
            section_text = dedup_vulnerabilities(
                f"## VULNERABILITIES\n{section_text}").split("\n", 1)[-1]
        body.append(section_text)
        body.append("")
    body.append("## PRESCAN (regex evidence — independent of the LLM)")
    body.append(prescan_markdown(prescan_data))
    return "\n".join(header + body)


# ============================================================
# Header cache
# ============================================================
def read_existing_header(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    header = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            if f.readline().strip() != HEADER_DELIM:
                return {}
            for line in f:
                line = line.rstrip("\n")
                if line.strip() == HEADER_DELIM:
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    header[k.strip()] = v.strip()
    except Exception:
        return {}
    return header


# ============================================================
# Main per-file pipeline
# ============================================================
def process_file(path: str, args) -> tuple:
    if not os.path.isfile(path):
        return ("error", f"not a file: {path}")

    analysis_path = path + ANALYSIS_SUFFIX
    sha = sha256_of(path)
    size = os.path.getsize(path)

    if not args.force and os.path.exists(analysis_path):
        if read_existing_header(analysis_path).get("SHA256") == sha:
            return ("skipped", f"already analyzed: {analysis_path}")

    try:
        text = extract_text(path)
    except Exception as e:
        return ("error", f"{path}: {e}")
    if not text.strip():
        return ("error", f"{path}: empty after extraction")

    ftype = detect_type(path, text)
    # Auto-full: large files (>80KB) or PDFs benefit from hot-pass+synthesis
    if not getattr(args, "full", False) and (
            size > 80 * 1024 or ftype == "pdf"):
        if getattr(args, "lite", False):
            print(f"  [auto] {ftype} {size}B -> disabling lite (heavy analysis)")
            args.lite = False
    if getattr(args, "lite", False):
        # Bigger chunks = fewer calls, faster; rely on grep for detail
        args.chunk_size = max(args.chunk_size, 20000)
    prescan_data = prescan(text, ftype)
    frameworks = prescan_data["frameworks"]

    chunks = chunk_text(text, args.chunk_size, ftype)
    annotate_chunks_with_dangers(chunks, prescan_data)

    toc_text = build_file_toc(ftype, text) if args.toc else ""

    n = len(chunks)
    summary = (f"  -> {path}: {size}B / {len(text)} chars / {ftype} / "
               f"{n} chunk(s) / "
               f"{len(prescan_data['dangers'])} danger, "
               f"{len(prescan_data['secrets'])} secret hit(s)")
    if frameworks:
        summary += f" / fw: {','.join(frameworks)}"
    if ftype == "html":
        safe = prescan_data.get("safe_handlers", 0)
        susp = prescan_data["event_handlers"] - safe
        summary += (f" / inline-js: {prescan_data['inline_scripts']} blocks, "
                    f"handlers {safe} safe / {susp} susp")
    print(summary)

    args.path, args.ftype = path, ftype
    args.frameworks = frameworks
    args.toc_text = toc_text

    try:
        combined = run_analysis(args, chunks, prescan_data)
    except Exception as e:
        return ("error", f"{path}: analysis failed: {e}")

    file_lines = text.splitlines()
    combined_verified, integrity_report = verify_line_refs(combined, file_lines)

    # Safety net: drop not-exploitable blocks from VULNERABILITIES
    combined_verified, n_fp = strip_not_exploitable_blocks(combined_verified)
    if n_fp:
        print(f"    -> filtered {n_fp} non-exploitable block(s)",
              file=sys.stderr)

    sections = parse_sections(combined_verified)
    output = format_analysis(
        path, sha, size, ftype, args.model, n,
        sections, prescan_data, frameworks,
        total_lines=prescan_data["line_count"],
    )

    if integrity_report:
        output += (
            "\n\n## INTEGRITY REPORT (L#### verification)\n"
            f"_{len(integrity_report)} citation(s) flagged. "
            "Review manually before trusting._\n\n"
            + "\n".join(integrity_report)
            + "\n"
        )

    tmp = analysis_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(output)
    os.replace(tmp, analysis_path)

    flagged = f", {len(integrity_report)} ref-flags" if integrity_report else ""
    return ("ok", f"analyzed -> {analysis_path} "
                  f"({len(output)}B, {n} chunk(s){flagged})")


# ============================================================
# CLI
# ============================================================
def main():
    ap = argparse.ArgumentParser(
        description="Analyze files for pentest findings with Ollama (v3.4).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SPEED (no quality loss):
  --parallel N + env OLLAMA_NUM_PARALLEL=N     parallel chunks
  --keep-alive 30m + env OLLAMA_KEEP_ALIVE=30m  keep model hot
  --warmup                                      preload once
  --adaptive-ctx                                size num_ctx to prompt
  --skip-synthesis                              fast path for 2-3 chunks

OLLAMA SERVER ENV (recommended):
  OLLAMA_FLASH_ATTENTION=1     ~ +20-40% on modern GPUs
  OLLAMA_KV_CACHE_TYPE=q8_0    halves KV-cache VRAM
  OLLAMA_NUM_GPU=99            all layers on GPU

STREAMING (debug):
  -S / --stream                 live tokens to stderr
  --stream-mode auto|raw|offs|dir|quiet
  --stream-dir DIR              save each chunk's raw output to DIR/
  --stats                       print per-call tok/s and durations

NOTE: think mode is FORCED OFF (_FORCED_THINK = False).
  Reasoning models (qwen3, deepseek-r1, ...) do not leak CoT into the
  report and do not burn num_predict on hidden tokens.
        """,
    )
    ap.add_argument("files", nargs="+")
    ap.add_argument("-r", "--force", action="store_true")
    ap.add_argument("-m", "--model", default=DEFAULT_MODEL)
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK)
    ap.add_argument("--num-ctx", type=int, default=DEFAULT_NUM_CTX)
    ap.add_argument("--num-predict", type=int, default=DEFAULT_NUM_PRED)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--parallel", type=int, default=DEFAULT_PARALLEL)
    ap.add_argument("--hot-threshold", type=int, default=3)
    ap.add_argument("--keep-alive", default=DEFAULT_KEEPALIVE)
    ap.add_argument("--warmup", action="store_true")
    ap.add_argument("--adaptive-ctx", action="store_true")
    ap.add_argument("--skip-synthesis", action="store_true")
    ap.add_argument("--toc", dest="toc", action="store_true", default=True)
    ap.add_argument("--no-toc", dest="toc", action="store_false")
    ap.add_argument("--line-numbers", dest="line_numbers",
                    action="store_true", default=True)
    ap.add_argument("--no-line-numbers", dest="line_numbers",
                    action="store_false")
    ap.add_argument("-S", "--stream", action="store_true")
    ap.add_argument("--stream-mode",
                    choices=["auto", "raw", "offs", "dir", "quiet"],
                    default="auto")
    ap.add_argument("--stream-dir", default=None)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--lite", action="store_true", default=True,
                    help="LITE mode (DEFAULT): no hot-pass, no synthesis, larger chunks")
    ap.add_argument("--full", action="store_true",
                    help="Disable lite: enables hot-pass and synthesis")
    args = ap.parse_args()
    # --full explicitly disables lite
    if args.full:
        args.lite = False

    # v3.4 — refuse to run if the invariant has been tampered with.
    if _FORCED_THINK is not False:
        sys.exit(f"[!] invariant violated: _FORCED_THINK must be False, "
                 f"got {_FORCED_THINK!r}")

    if args.stream_dir and args.stream_mode == "auto":
        args.stream_mode = "dir"
    if args.stream and args.parallel > 1 and args.stream_mode == "raw":
        print("[!] raw stream with parallel>1 will interleave; "
              "consider --stream-mode offs", file=sys.stderr)

    try:
        requests.get(args.host.rstrip("/") + "/api/tags",
                     timeout=5).raise_for_status()
    except Exception as e:
        sys.exit(f"[!] cannot reach Ollama at {args.host}: {e}")

    if not args.quiet:
        print(f"[analyzer] host={args.host} model={args.model} "
              f"chunk={args.chunk_size} parallel={args.parallel} "
              f"toc={args.toc} lines={args.line_numbers} "
              f"stream={_resolve_stream_mode(args)} "
              f"keep_alive={args.keep_alive} "
              f"adaptive_ctx={args.adaptive_ctx} "
              f"think={_FORCED_THINK} (forced)")

    if args.warmup:
        print("[analyzer] warming up model...", file=sys.stderr, flush=True)
        try:
            t0 = time.monotonic()
            call_with_retry(
                args.host, args.model, "ok",
                num_ctx=512, num_predict=1, timeout=args.timeout,
                tag="warmup", keep_alive=args.keep_alive,
                stream=True, stream_cb=None, stream_mode="quiet",
                show_stats=args.stats,
            )
            print(f"[analyzer] warmup done in {time.monotonic()-t0:.1f}s",
                  file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[!] warmup failed (continuing): {e}",
                  file=sys.stderr, flush=True)

    ok = skip = err = 0
    for path in args.files:
        try:
            status, msg = process_file(path, args)
        except KeyboardInterrupt:
            print("\n[!] interrupted"); return 1
        except Exception as e:
            status, msg = "error", f"{path}: unexpected: {e}"
        prefix = {"ok": "[+]", "skipped": "[=]", "error": "[!]"}[status]
        print(f"{prefix} {msg}")
        ok += status == "ok"
        skip += status == "skipped"
        err += status == "error"

    if not args.quiet:
        print(f"\n[analyzer] done: {ok} analyzed, {skip} skipped, "
              f"{err} errors")
    return 0 if err == 0 else 1


if __name__ == "__main__":
    sys.exit(main())