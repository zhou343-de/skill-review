#!/usr/bin/env python3
"""
Automated skill review tool.
Runs structural, quality, and security checks on a skill directory.

Usage:
    python review_skill.py <skill-directory> [--json] [--security-only]
"""

import base64
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
except ModuleNotFoundError:
    yaml = None

MAX_NAME_LEN = 64
MAX_DESC_LEN = 1024
MAX_BODY_LINES = 500
EXTRANEOUS_FILES = {"README.md", "INSTALLATION_GUIDE.md", "CHANGELOG.md", "QUICK_REFERENCE.md", "CONTRIBUTING.md"}
ALLOWED_FM_KEYS = {"name", "description", "license", "allowed-tools", "metadata"}
SCRIPT_EXTS = {".py", ".sh", ".js", ".ts", ".bash", ".rb", ".pl"}
DOC_EXTS = {".md", ".txt", ".rst"}
CRED_DIRS = {".ssh", ".aws", ".gnupg", ".config/gcloud", ".azure"}
CRED_FILE_PATTERNS = [
    r"(?<!\w)\.env(?:\.|$)", r"\.pem$", r"\.key(?:\.|$)", r"id_rsa", r"id_ed25519",
    r"(?<![/\w])credentials(?:\.|$)", r"\.netrc$", r"\.npmrc$", r"\.pypirc$",
    r"\.keystore$",
]
EXFIL_DOMAINS = [
    "requestbin", "webhook.site", "hookbin", "pipedream",
    "ngrok.io", "burpcollaborator", "interact.sh", "canarytokens",
    "oast.fun", "oast.pro", "oast.live", "oast.online",
    "dnslog.cn", "ceye.io", "log4j",
]
ENCODED_EXEC_PATTERNS = [
    r"eval\s*\(", r"exec\s*\(", r"subprocess\.(?:call|run|Popen)\s*\(",
    r"os\.system\s*\(", r"__import__\s*\(",
    r"child_process", r"spawn\s*\(", r"execSync\s*\(",
]
NETWORK_CALL_PATTERNS = [
    r"curl\s+.*-X\s*POST", r"curl\s+.*--data", r"curl\s+.*-d\s",
    r"wget\s+.*--post", r"requests\.post\s*\(", r"urllib.*urlopen\s*\(",
    r"fetch\s*\([^)]*method:\s*['\"]POST", r"\.send\s*\(",
    r"XMLHttpRequest", r"axios\.post",
]
PRIVILEGE_PATTERNS = [
    r"\bsudo\b", r"chmod\s+777", r"chown\s+root",
    r"setuid", r"setgid",
]
SYSTEM_MODIFY_PATTERNS = [
    r"/etc/(?:passwd|shadow|sudoers|hosts|crontab)",
    r"systemctl\s+(?:enable|start|restart)", r"launchctl\s+load",
    r"crontab\s+-", r"at\s+now",
    r"iptables\s+-[FD]", r"ufw\s+disable", r"setenforce\s+0",
]
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+(?:instructions|prompts|rules|constraints)",
    r"disregard\s+(?:all\s+)?(?:previous|above|prior|your)\s+(?:instructions|prompts|rules)",
    r"forget\s+(?:all\s+)?(?:previous|above|your)\s+(?:instructions|rules)",
    r"you\s+are\s+now\s+(?:a|an|the)\s+(?:DAN|jailbreak|unrestricted|evil|malicious)",
    r"new\s+instructions?\s*[:=]",
    r"override\s+(?:safety|system|all)\s+(?:instructions|rules|guidelines)",
    r"bypass\s+(?:safety|content|system)\s+(?:filter|policy|check|restriction)",
    r"pretend\s+(?:you|that)\s+(?:are|have)\s+no\s+(?:restrictions|rules|limitations|guidelines)",
    r"act\s+as\s+(?:if|though)\s+you\s+(?:have|were)\s+no\s+(?:restrictions|rules|limitations)",
    r"do\s+not\s+(?:follow|obey)\s+(?:the\s+)?(?:safety|content|system)\s+(?:rules|guidelines|policies)",
    r"system\s*prompt\s*[:=]",
    r"\[system\]\s*[:=]", r"\[INST\]\s*<<SYS>>",
]
ZERO_WIDTH_CHARS = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2061\u2062\u2063\ufeff\u00ad]")
HIDDEN_HTML_PATTERNS = [
    r"display\s*:\s*none", r"visibility\s*:\s*hidden",
    r"color\s*:\s*#fff(?:fff)?", r"font-size\s*:\s*0",
    r"opacity\s*:\s*0", r"position\s*:\s*absolute\s*;\s*left\s*:\s*-9999",
]
TYPOSQUAT_PACKAGES = [
    "reqeusts", "reqeust", "requets", "beutifulsoup", "beatifulsoup",
    "pandsa", "numpi", "mattplotlib", "scikitlearn", "sklear",
    "lodahs", "loda", "uent", "reques",
]


class Finding:
    def __init__(self, severity: str, message: str, location: str = "", category: str = "structure"):
        self.severity = severity  # "fail", "warn", "info"
        self.message = message
        self.location = location
        self.category = category  # "structure" or "security"

    def to_dict(self):
        d = {"severity": self.severity, "message": self.message, "category": self.category}
        if self.location:
            d["location"] = self.location
        return d

    def __str__(self):
        icon = {"fail": "❌", "warn": "⚠️", "info": "ℹ️"}[self.severity]
        loc = f" ({self.location})" if self.location else ""
        return f"{icon} [{self.severity.upper()}]{loc} {self.message}"


def extract_frontmatter(content: str) -> tuple[Optional[str], Optional[int]]:
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "\n".join(lines[1:i]), i + 1
    return None, None


def parse_frontmatter(text: str) -> Optional[dict]:
    if yaml:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else None
        except Exception:
            return None
    parsed = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            parsed[k.strip()] = v.strip().strip('"').strip("'")
    return parsed or None


# ─── Structure checks ───────────────────────────────────────────────

def check_frontmatter(fm: dict, findings: list):
    name = fm.get("name", "")
    if not name:
        findings.append(Finding("fail", "Missing 'name' in frontmatter"))
    else:
        if not isinstance(name, str):
            findings.append(Finding("fail", f"'name' must be a string, got {type(name).__name__}"))
        else:
            name = name.strip()
            if not re.match(r"^[a-z0-9-]+$", name):
                findings.append(Finding("fail", f"Name '{name}' must be hyphen-case (lowercase, digits, hyphens)"))
            if name.startswith("-") or name.endswith("-") or "--" in name:
                findings.append(Finding("fail", f"Name '{name}' cannot start/end with hyphen or have consecutive hyphens"))
            if len(name) > MAX_NAME_LEN:
                findings.append(Finding("fail", f"Name too long ({len(name)} chars, max {MAX_NAME_LEN})"))

    desc = fm.get("description", "")
    if not desc:
        findings.append(Finding("fail", "Missing 'description' in frontmatter"))
    else:
        if not isinstance(desc, str):
            findings.append(Finding("fail", f"'description' must be a string, got {type(desc).__name__}"))
        else:
            desc = desc.strip()
            if len(desc) > MAX_DESC_LEN:
                findings.append(Finding("fail", f"Description too long ({len(desc)} chars, max {MAX_DESC_LEN})"))
            if "<" in desc or ">" in desc:
                findings.append(Finding("fail", "Description contains angle brackets (< or >)"))
            if len(desc) < 50:
                findings.append(Finding("warn", f"Description is short ({len(desc)} chars). Include 'when to use' context"))
            trigger_keywords = ["use when", "triggers on", "use for", "when the user", "when asked", "when you need"]
            if not any(kw in desc.lower() for kw in trigger_keywords):
                findings.append(Finding("warn", "Description lacks 'when to use' triggering context"))

    unexpected = set(fm.keys()) - ALLOWED_FM_KEYS
    if unexpected:
        findings.append(Finding("warn", f"Non-standard frontmatter keys: {', '.join(sorted(unexpected))}"))


def check_body(body: str, body_start: int, findings: list):
    if not body.strip():
        findings.append(Finding("fail", "SKILL.md body is empty"))
        return

    lines = body.splitlines()
    if len(lines) > MAX_BODY_LINES:
        findings.append(Finding("warn", f"Body is {len(lines)} lines (max {MAX_BODY_LINES}). Consider splitting into references/"))

    for i, line in enumerate(lines):
        if re.match(r"^#{1,3}\s+when\s+to\s+use", line, re.IGNORECASE):
            findings.append(Finding("warn", f"Line {body_start + i + 1}: 'When to Use' section in body — move to description", f"line {body_start + i + 1}"))
            break

    bad_patterns = [
        (r"\byou should\b", "Use imperative form instead of 'you should'"),
        (r"\bthe user should\b", "Use imperative form instead of 'the user should'"),
        (r"\bplease note\b", "Remove filler phrase 'please note'"),
        (r"\bit is important\b", "Remove filler phrase 'it is important'"),
        (r"\bas mentioned above\b", "Remove filler phrase 'as mentioned above'"),
    ]
    for pattern, msg in bad_patterns:
        for i, line in enumerate(lines):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding("info", f"Line {body_start + i + 1}: {msg}", f"line {body_start + i + 1}"))
                break


def check_files(skill_path: Path, body: str, findings: list):
    all_files = []
    for f in skill_path.rglob("*"):
        if f.is_file() and ".git" not in f.parts:
            all_files.append(f.relative_to(skill_path))

    for f in all_files:
        if f.name in EXTRANEOUS_FILES and f.parent == Path("."):
            findings.append(Finding("fail", f"Extraneous file: {f}"))

    for f in all_files:
        if (skill_path / f).is_symlink():
            findings.append(Finding("fail", f"Symlink detected: {f}"))

    scripts_dir = skill_path / "scripts"
    if scripts_dir.exists():
        for f in scripts_dir.iterdir():
            if f.is_file():
                ext = f.suffix.lower()
                if ext not in SCRIPT_EXTS and ext != "":
                    findings.append(Finding("warn", f"scripts/{f.name}: non-executable extension '{ext}'"))
                if ext in {".py", ".sh", ".bash"}:
                    try:
                        text = f.read_text()
                        first_line = text.splitlines()[0] if text else ""
                        if not first_line.startswith("#!"):
                            findings.append(Finding("warn", f"scripts/{f.name}: missing shebang line"))
                    except Exception:
                        pass
                try:
                    if not (f.stat().st_mode & stat.S_IXUSR):
                        findings.append(Finding("info", f"scripts/{f.name}: not executable (chmod +x)"))
                except Exception:
                    pass

    refs_dir = skill_path / "references"
    if refs_dir.exists():
        for f in refs_dir.iterdir():
            if f.is_file():
                ext = f.suffix.lower()
                if ext not in DOC_EXTS:
                    findings.append(Finding("warn", f"references/{f.name}: non-document extension '{ext}'"))
                try:
                    content = f.read_text()
                    if len(content.splitlines()) > 100 and not re.search(r"^#\s+.*contents|^##\s+", content, re.MULTILINE):
                        findings.append(Finding("info", f"references/{f.name}: >100 lines, consider adding a TOC"))
                except Exception:
                    pass

    for f in all_files:
        if f == Path("SKILL.md"):
            continue
        if str(f) not in body and f.name not in body:
            findings.append(Finding("warn", f"File '{f}' not referenced in SKILL.md body"))


# ─── Security checks ────────────────────────────────────────────────

def _read_file_safe(path: Path, max_bytes: int = 500_000) -> str:
    try:
        data = path.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def check_prompt_injection(content: str, rel_path: str, findings: list):
    """Detect prompt injection / override attempts in text content."""
    # Skip binary-like content
    if "\x00" in content[:1000]:
        return

    for pattern in PROMPT_INJECTION_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            # Get surrounding context for the report
            start = max(0, m.start() - 20)
            end = min(len(content), m.end() + 20)
            snippet = content[start:end].replace("\n", " ").strip()
            findings.append(Finding("fail",
                f"Prompt injection pattern: \"{snippet}\"",
                rel_path, "security"))
            break  # One match per pattern per file

    # Check for zero-width characters (potential hidden text)
    zw_matches = ZERO_WIDTH_CHARS.findall(content)
    if len(zw_matches) > 5:  # A few might be legitimate (RTL markers)
        findings.append(Finding("fail",
            f"Zero-width characters detected ({len(zw_matches)} occurrences) — possible hidden instructions",
            rel_path, "security"))

    # Check for hidden HTML patterns in markdown
    for pattern in HIDDEN_HTML_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding("fail",
                f"Hidden content pattern: {pattern}",
                rel_path, "security"))
            break


def check_data_exfiltration(content: str, rel_path: str, findings: list):
    """Detect scripts that send data to external endpoints."""
    lower = content.lower()

    # Check for exfil domains
    for domain in EXFIL_DOMAINS:
        if domain.lower() in lower:
            findings.append(Finding("fail",
                f"Reference to known exfiltration/interaction domain: {domain}",
                rel_path, "security"))
            break

    # Check for network POST patterns combined with sensitive data access
    # Only flag when BOTH network POST AND env var access co-occur (file read alone is too common in docs)
    has_network_post = any(re.search(p, content, re.IGNORECASE) for p in NETWORK_CALL_PATTERNS)
    has_env_access = bool(re.search(r"os\.environ|process\.env|ENV\[|getenv", content, re.IGNORECASE))

    if has_network_post and has_env_access:
        findings.append(Finding("fail",
            "Script combines network POST with environment variable access — possible data exfiltration",
            rel_path, "security"))
    elif has_network_post and rel_path.rsplit(".", 1)[-1].lower() in {"py", "sh", "bash", "js", "ts"}:
        # In executable scripts, flag POST + file read
        has_file_read = bool(re.search(r"open\s*\(|readFile|readFileSync|subprocess.*cat|os\.popen", content))
        if has_file_read:
            findings.append(Finding("fail",
                "Script combines network POST with file read — possible data exfiltration",
                rel_path, "security"))

    # DNS exfiltration patterns
    # Only match in scripts, not docs where "dig" / "host" are discussed casually
    is_script = rel_path.rsplit(".", 1)[-1].lower() in {"py", "sh", "bash", "js", "ts", "rb", "pl"} if "." in rel_path else False
    if is_script:
        if re.search(r"\bnslookup\b|\bdig\s+\S|socket\.gethostbyname|socket\.getaddrinfo", content, re.IGNORECASE):
            if re.search(r"\$\{|%s|format\(|\.join\(|encode|base64", content):
                findings.append(Finding("fail",
                    "DNS query with dynamic data construction — possible DNS exfiltration",
                    rel_path, "security"))

    # curl piped to bash (only flag in executable scripts, not in markdown docs where it's usually install instructions)
    if re.search(r"curl\s+.*\|\s*(?:ba)?sh|wget\s+.*\|\s*(?:ba)?sh", content, re.IGNORECASE):
        is_script = rel_path.rsplit(".", 1)[-1].lower() in {"py", "sh", "bash", "js", "ts", "rb", "pl"} if "." in rel_path else False
        if is_script:
            findings.append(Finding("fail",
                "curl/wget piped to shell — supply chain risk",
                rel_path, "security"))
        else:
            findings.append(Finding("warn",
                "curl/wget piped to shell in docs — verify this is an intentional install instruction",
                rel_path, "security"))


def check_credential_access(content: str, rel_path: str, findings: list):
    """Detect attempts to read credentials or secrets."""
    # Access to known credential directories
    for cred_dir in CRED_DIRS:
        if cred_dir in content:
            findings.append(Finding("fail",
                f"Accesses credential directory: ~/{cred_dir}",
                rel_path, "security"))
            break

    # Access to credential file patterns
    for pattern in CRED_FILE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding("warn",
                f"Possible credential file access: {pattern}",
                rel_path, "security"))
            break

    # Environment variable harvesting — only flag direct secret access, not config vars
    # Matches: process.env.API_KEY, os.environ["GITHUB_TOKEN"], getenv("SECRET")
    # Does NOT match: process.env.SHERPA_ONNX_TOKENS_FILE (config, not a secret)
    # The negative lookahead (?!S) prevents matching TOKENS/TOKEN_FILE as config vars
    env_secret = r"(?:API_?KEY|TOKEN(?!S)|SECRET|PASSWORD)"
    env_suffix = r"(?:[_A-Z]\w*)?"  # optional suffix like _FILE, _ID
    env_patterns = [
        rf"os\.environ\[.*['\"][\w+_]*?{env_secret}{env_suffix}['\"]",
        rf"os\.environ\.get\(.*['\"][\w+_]*?{env_secret}{env_suffix}['\"]",
        rf"os\.getenv\(.*['\"][\w+_]*?{env_secret}{env_suffix}['\"]",
        rf"process\.env\[(?:['\"]|\s*['\"]?)[\w+_]*?{env_secret}{env_suffix}",
        rf"process\.env\.[\w+_]*?{env_secret}{env_suffix}\b",
        rf"ENV\[.*['\"][\w+_]*?{env_secret}{env_suffix}['\"]",
        rf"getenv\(.*['\"][\w+_]*?{env_secret}{env_suffix}['\"]",
    ]
    for pattern in env_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding("fail",
                "Reads sensitive environment variables (API_KEY/TOKEN/SECRET/PASSWORD)",
                rel_path, "security"))
            break


def check_obfuscation(content: str, rel_path: str, findings: list):
    """Detect obfuscated or encoded payloads."""
    # Very long single lines (potential obfuscation)
    # Use extract_frontmatter to skip frontmatter reliably (handles nested --- in code blocks)
    _, body_start = extract_frontmatter(content)
    start_line = body_start if body_start is not None else 0
    for i, line in enumerate(content.splitlines()):
        if i < start_line:
            continue  # Skip frontmatter
        stripped = line.strip()
        if len(line) > 500 and not stripped.startswith("#"):
            if not re.match(r"^\s*\|", line) and "http" not in line[:100]:
                findings.append(Finding("warn",
                    f"Line {i+1}: unusually long ({len(line)} chars) — possible obfuscation",
                    f"{rel_path}:{i+1}", "security"))
                break

    # Base64 blobs > 200 chars (excluding comments and URLs)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
    for m in b64_pattern.finditer(content):
        blob = m.group()
        try:
            decoded = base64.b64decode(blob).decode("utf-8", errors="replace")
            if any(kw in decoded.lower() for kw in ["curl", "wget", "exec", "eval", "import", "require", "bash", "sh "]):
                findings.append(Finding("fail",
                    f"Base64 blob decodes to command content: \"{decoded[:80]}...\"",
                    rel_path, "security"))
                break
        except Exception:
            pass

    # Excessive chr()/String.fromCharCode patterns
    # Match 5+ occurrences of chr(), fromCharCode, or \xHH separated by non-alphanumeric chars
    chr_pattern = re.compile(r"(?:chr\s*\(|String\.fromCharCode|\\x[0-9a-f]{2})(?:[^a-zA-Z0-9]*(?:chr\s*\(|String\.fromCharCode|\\x[0-9a-f]{2})){4,}", re.IGNORECASE)
    if chr_pattern.search(content):
        findings.append(Finding("warn",
            "Character-by-character string construction — possible obfuscation",
            rel_path, "security"))

    # eval/exec of dynamic strings
    for pattern in ENCODED_EXEC_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            after = content[m.end():m.end()+100].lstrip()
            # Skip if it's a plain string literal (eval("print('hi')") is less risky)
            if after and after[0] in ('"', "'"):
                continue
            # Flag if argument is a variable, function call, or expression
            if re.search(r"[a-zA-Z_\$]|\(", after[:50]):
                findings.append(Finding("warn",
                    f"Dynamic code execution: {pattern}",
                    rel_path, "security"))
                break


def check_supply_chain(content: str, rel_path: str, findings: list):
    """Detect risky dependency installation patterns."""
    # pip/npm install from git URLs or untrusted sources
    risky_install = [
        (r"pip\s+install\s+.*git\+", "pip install from git URL"),
        (r"pip\s+install\s+.*https?://", "pip install from URL"),
        (r"npm\s+install\s+.*github:", "npm install from GitHub shorthand"),
        (r"npm\s+install\s+.*git\+", "npm install from git URL"),
        (r"cargo\s+install\s+.*--git", "cargo install from git"),
    ]
    for pattern, desc in risky_install:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding("warn", f"{desc} — verify source trustworthiness", rel_path, "security"))
            break

    # Typosquatted packages
    for pkg in TYPOSQUAT_PACKAGES:
        if re.search(rf"\b{re.escape(pkg)}\b", content, re.IGNORECASE):
            findings.append(Finding("fail",
                f"Possible typosquatted package: '{pkg}'",
                rel_path, "security"))
            break

    # PATH modification
    if re.search(r"PATH\s*=\s*['\"]|export\s+PATH|sys\.path\.(?:insert|append)", content):
        findings.append(Finding("warn",
            "Modifies PATH — verify this doesn't shadow system tools",
            rel_path, "security"))


def check_privilege_escalation(content: str, rel_path: str, findings: list):
    """Detect privilege escalation or system modification attempts."""
    for pattern in PRIVILEGE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding("warn",
                f"Privilege escalation pattern: {pattern}",
                rel_path, "security"))
            break

    for pattern in SYSTEM_MODIFY_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(Finding("warn",
                f"System modification pattern: {pattern}",
                rel_path, "security"))
            break

    # SSH key injection
    if re.search(r"authorized_keys|ssh-rsa\s|ssh-ed25519\s", content):
        findings.append(Finding("fail",
            "SSH key manipulation — possible backdoor",
            rel_path, "security"))

    # User creation
    if re.search(r"\buseradd\b|\badduser\b|\bnet\s+user\s+.*\s+/add", content, re.IGNORECASE):
        findings.append(Finding("fail",
            "User creation command — verify necessity",
            rel_path, "security"))


def check_binary_payloads(skill_path: Path, findings: list):
    """Check for suspicious binary files or embedded payloads."""
    BINARY_EXTS = {".bin", ".exe", ".dll", ".so", ".dylib", ".dat", ".payload"}
    for f in skill_path.rglob("*"):
        if f.is_file() and f.suffix.lower() in BINARY_EXTS:
            findings.append(Finding("warn",
                f"Binary file in skill: {f.relative_to(skill_path)} — verify purpose",
                _rel(f, skill_path), "security"))

        # Check for base64-encoded executables in non-script files
        if f.is_file() and f.suffix.lower() in {".md", ".txt", ".json", ".yaml", ".yml"}:
            content = _read_file_safe(f, 100_000)
            # Look for PK (ZIP/EXE), ELF, or Mach-O magic bytes in base64
            for magic_b64 in ["UEsDB", "f0VMRg", "TVqQA", "H4sIA"]:
                if magic_b64 in content and len(content) > len(magic_b64) + 200:
                    findings.append(Finding("warn",
                        f"Possible embedded binary (base64 magic bytes) in {_rel(f, skill_path)}",
                        _rel(f, skill_path), "security"))
                    break


def run_security_checks(skill_path: Path, findings: list):
    """Run all security checks across every file in the skill."""
    all_files = []
    for f in skill_path.rglob("*"):
        if f.is_file() and ".git" not in f.parts:
            all_files.append(f)

    # Check all files
    text_extensions = {".md", ".txt", ".py", ".sh", ".js", ".ts", ".bash",
                       ".rb", ".pl", ".json", ".yaml", ".yml", ".toml",
                       ".cfg", ".ini", ".conf", ".html", ".htm", ".xml",
                       ".css", ".env", ".dockerfile", ""}

    for f in all_files:
        rel = _rel(f, skill_path)

        # Check filename for credential patterns
        for pattern in CRED_FILE_PATTERNS:
            if re.search(pattern, f.name, re.IGNORECASE):
                findings.append(Finding("fail",
                    f"Suspicious filename: {f.name} (matches credential pattern)",
                    rel, "security"))
                break

        # Skip large/binary files for content analysis
        if f.suffix.lower() not in text_extensions:
            continue

        content = _read_file_safe(f, 200_000)
        if not content or "\x00" in content[:500]:
            continue

        check_prompt_injection(content, rel, findings)
        check_data_exfiltration(content, rel, findings)
        check_credential_access(content, rel, findings)
        check_obfuscation(content, rel, findings)
        check_supply_chain(content, rel, findings)
        check_privilege_escalation(content, rel, findings)

    check_binary_payloads(skill_path, findings)


# ─── Scoring ─────────────────────────────────────────────────────────

def compute_grade(findings: list) -> tuple[str, str]:
    """Structure grade based on non-security findings."""
    struct_finds = [f for f in findings if f.category == "structure"]
    fails = sum(1 for f in struct_finds if f.severity == "fail")
    warns = sum(1 for f in struct_finds if f.severity == "warn")

    if fails == 0 and warns <= 1:
        return "A", "Excellent — minimal or no issues"
    elif fails == 0 and warns <= 4:
        return "B", "Good — a few improvements recommended"
    elif fails == 0:
        return "C", "Fair — several improvements recommended"
    elif fails <= 2:
        return "D", "Needs work — critical issues found"
    else:
        return "F", "Poor — multiple critical issues"


def compute_security_grade(findings: list) -> tuple[str, str]:
    """Security grade based on security findings."""
    sec_finds = [f for f in findings if f.category == "security"]
    fails = sum(1 for f in sec_finds if f.severity == "fail")
    warns = sum(1 for f in sec_finds if f.severity == "warn")

    if fails == 0 and warns == 0:
        return "A", "Clean — no suspicious patterns"
    elif fails == 0 and warns <= 2:
        return "B", "Minor concerns — review recommended"
    elif fails == 0:
        return "C", "Multiple warnings — manual review needed"
    elif fails == 1:
        return "D", "Security issue found"
    else:
        return "F", "🚨 Multiple security issues — do NOT install"


def final_grade(struct_grade: str, sec_grade: str) -> str:
    """Final grade = lower (worse) of structure and security."""
    order = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
    return sec_grade if order[sec_grade] >= order[struct_grade] else struct_grade


# ─── Output ──────────────────────────────────────────────────────────

def review_skill_to_dict(skill_path: Path) -> dict:
    """Run full review and return structured dict (for use by other scripts)."""
    findings: list[Finding] = []
    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        missing = {"severity": "fail", "message": "SKILL.md not found", "category": "structure"}
        return {"skill": skill_path.name, "structure_grade": "F", "security_grade": "F", "final_grade": "F", "findings": [missing], "summary": {"fail": 1, "warn": 0, "info": 0, "security_fails": 0, "security_warns": 0}}

    content = skill_md.read_text(encoding="utf-8")
    fm_text, body_start = extract_frontmatter(content)

    if fm_text is not None:
        fm = parse_frontmatter(fm_text)
        if fm:
            check_frontmatter(fm, findings)
        else:
            findings.append(Finding("fail", "Could not parse frontmatter YAML", category="structure"))
    else:
        findings.append(Finding("fail", "Invalid or missing frontmatter", category="structure"))

    body = "\n".join(content.splitlines()[body_start:]) if body_start is not None else content
    check_body(body, body_start or 0, findings)
    check_files(skill_path, body, findings)
    run_security_checks(skill_path, findings)

    sg, _ = compute_grade(findings)
    secg, _ = compute_security_grade(findings)
    return {
        "skill": skill_path.name,
        "structure_grade": sg,
        "security_grade": secg,
        "final_grade": final_grade(sg, secg),
        "summary": {
            "fail": sum(1 for f in findings if f.severity == "fail"),
            "warn": sum(1 for f in findings if f.severity == "warn"),
            "info": sum(1 for f in findings if f.severity == "info"),
            "security_fails": sum(1 for f in findings if f.severity == "fail" and f.category == "security"),
            "security_warns": sum(1 for f in findings if f.severity == "warn" and f.category == "security"),
        },
        "findings": [f.to_dict() for f in findings],
    }


def review_skill(skill_path: Path, as_json: bool = False, security_only: bool = False):
    findings: list[Finding] = []

    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        findings.append(Finding("fail", "SKILL.md not found", category="structure"))
        if as_json:
            print(json.dumps({"grade": "F", "findings": [f.to_dict() for f in findings]}))
        else:
            print("❌ SKILL.md not found")
        return

    content = skill_md.read_text(encoding="utf-8")
    fm_text, body_start = extract_frontmatter(content)

    if not security_only:
        if fm_text is None:
            findings.append(Finding("fail", "Invalid or missing frontmatter", category="structure"))
        else:
            fm = parse_frontmatter(fm_text)
            if fm is None:
                findings.append(Finding("fail", "Could not parse frontmatter YAML", category="structure"))
            else:
                check_frontmatter(fm, findings)

        body = "\n".join(content.splitlines()[body_start:]) if body_start is not None else content
        check_body(body, body_start or 0, findings)
        check_files(skill_path, body, findings)

    # Always run security checks
    run_security_checks(skill_path, findings)

    struct_grade, struct_desc = compute_grade(findings)
    sec_grade, sec_desc = compute_security_grade(findings)
    final = final_grade(struct_grade, sec_grade) if not security_only else sec_grade

    if as_json:
        result = {
            "skill": skill_path.name,
            "structure_grade": struct_grade,
            "security_grade": sec_grade,
            "final_grade": final,
            "security_flag": sec_grade in ("D", "F"),
            "summary": {
                "fail": sum(1 for f in findings if f.severity == "fail"),
                "warn": sum(1 for f in findings if f.severity == "warn"),
                "info": sum(1 for f in findings if f.severity == "info"),
                "security_fails": sum(1 for f in findings if f.severity == "fail" and f.category == "security"),
                "security_warns": sum(1 for f in findings if f.severity == "warn" and f.category == "security"),
            },
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(result, indent=2))
    else:
        sec_flag = " 🚨 SECURITY" if sec_grade in ("D", "F") else ""
        print(f"## Skill Review: `{skill_path.name}`{sec_flag}\n")
        if security_only:
            print(f"**Security: {sec_grade}** — {sec_desc}\n")
        else:
            print(f"**Structure: {struct_grade}** | **Security: {sec_grade}** | **Final: {final}**{sec_flag}\n")

        sec_finds = [f for f in findings if f.category == "security"]
        struct_finds = [f for f in findings if f.category == "structure"]

        if sec_finds:
            print("### 🔒 Security Findings\n")
            sec_fails = [f for f in sec_finds if f.severity == "fail"]
            sec_warns = [f for f in sec_finds if f.severity == "warn"]
            if sec_fails:
                print("#### ❌ Critical (exploit risk)\n")
                for f in sec_fails:
                    print(f"- [ ] {f}")
                print()
            if sec_warns:
                print("#### ⚠️ Suspicious (needs review)\n")
                for f in sec_warns:
                    print(f"- [ ] {f}")
                print()

        if not security_only and struct_finds:
            print("### 📋 Structure Findings\n")
            s_fails = [f for f in struct_finds if f.severity == "fail"]
            s_warns = [f for f in struct_finds if f.severity == "warn"]
            s_infos = [f for f in struct_finds if f.severity == "info"]
            if s_fails:
                print("#### ❌ Failures (must fix)\n")
                for f in s_fails:
                    print(f"- [ ] {f}")
                print()
            if s_warns:
                print("#### ⚠️ Warnings (should fix)\n")
                for f in s_warns:
                    print(f"- [ ] {f}")
                print()
            if s_infos:
                print("#### ℹ️ Info (nice to have)\n")
                for f in s_infos:
                    print(f"- [ ] {f}")
                print()

        if not findings:
            print("### ✅ All clear — no issues found!\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python review_skill.py <skill-directory> [--json] [--security-only]")
        sys.exit(1)

    path = Path(sys.argv[1])
    json_mode = "--json" in sys.argv
    sec_only = "--security-only" in sys.argv

    if not path.exists():
        print(f"Error: {path} does not exist")
        sys.exit(1)

    review_skill(path, json_mode, sec_only)
