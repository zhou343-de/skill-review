# Skill Review Checklist

Complete checklist for manual or automated skill auditing. Each item has a severity, rationale, and example.

## Frontmatter

### ✅ Required fields

- [ ] **`name` exists** (fail) — Skill identity. Must be hyphen-case, lowercase, digits, hyphens only, ≤64 chars.
  - Good: `pdf-editor`, `gh-address-comments`
  - Bad: `PDF Editor`, `my_skill`, `-leading`

- [ ] **`description` exists** (fail) — Primary triggering mechanism. This is how the agent decides to load the skill.

- [ ] **No unexpected keys** (fail) — Only `name`, `description`, `license`, `allowed-tools`, `metadata` are allowed.

### ✅ Description quality

- [ ] **≥50 characters** (warn) — Too short = poor triggering. The agent needs enough signal to match user intent.

- [ ] **≤1024 characters** (fail) — Hard limit from the spec.

- [ ] **No angle brackets** (fail) — `<` and `>` break YAML parsing.

- [ ] **Includes "when to use" context** (warn) — The description should list concrete trigger phrases or scenarios.
  - Good: "Use when a user asks to rotate, merge, split, or extract text from PDF files. Also triggers on 'edit this PDF'."
  - Bad: "A skill for PDF processing."

- [ ] **Describes what the skill does AND when to use it** (warn) — Both dimensions matter for triggering.

## Body

### ✅ Structure

- [ ] **Body exists** (fail) — Empty body after frontmatter means no instructions.

- [ ] **≤500 lines** (warn) — Context window is shared. Split into references/ if longer.

- [ ] **No "When to Use" section in body** (warn) — This belongs in the description. Body is only loaded AFTER triggering.

### ✅ Writing style

- [ ] **Imperative/infinitive form** (warn) — "Run the script" not "You should run the script" or "The user runs the script".

- [ ] **No filler phrases** (info) — "Please note that", "It is important to", "As mentioned above" → cut them.

- [ ] **Concise examples over verbose explanations** (info) — Show, don't tell.

### ✅ Content organization

- [ ] **References to bundled resources are discoverable** (warn) — If `references/api.md` exists, SKILL.md should mention it and say when to read it.

- [ ] **No duplicate content** (warn) — Same info in body AND a reference file → pick one.

- [ ] **Progressive disclosure used for >300 line bodies** (warn) — Split domain-specific or variant-specific content into references/.

## File organization

### ✅ Extraneous files

- [ ] **No README.md** (fail) — Skills don't need user-facing READMEs.
- [ ] **No INSTALLATION_GUIDE.md** (fail) — Auxiliary docs, not needed.
- [ ] **No CHANGELOG.md** (fail) — Not needed for agent consumption.
- [ ] **No QUICK_REFERENCE.md** (fail) — Redundant with SKILL.md body.
- [ ] **No other non-essential docs** (warn) — Anything not directly supporting the skill's function.

### ✅ Directory structure

- [ ] **`scripts/` contains only executables** (warn) — .py, .sh, .js, .ts. Not .md or data files.
- [ ] **`references/` contains only docs** (warn) — .md files. Not scripts or binaries.
- [ ] **`assets/` contains output resources** (warn) — Templates, images, fonts. Not docs or scripts.
- [ ] **No empty directories** (warn) — Remove unused dirs.
- [ ] **No symlinks** (fail) — Security restriction; packaging rejects them.
- [ ] **Each subdir file referenced from SKILL.md** (warn) — Orphaned files waste space and confuse agents.

## Scripts quality

- [ ] **Shebang line present** (warn) — `#!/usr/bin/env python3` or `#!/usr/bin/env bash` at line 1.
- [ ] **`if __name__` guard** (warn) — For Python scripts, prevents execution on import.
- [ ] **No hardcoded secrets** (fail) — API keys, tokens, passwords must not appear in scripts.
- [ ] **No hardcoded absolute paths** (warn) — `/Users/john/...` won't work elsewhere. Use relative paths or parameters.
- [ ] **Executable permission set** (warn) — `chmod +x` so the agent can run directly.

## Reference files quality

- [ ] **Table of contents for files >100 lines** (info) — Helps the agent preview scope.
- [ ] **Well-structured with headers** (info) — Enables grep/search for specific sections.
- [ ] **No massive monolithic references** (warn) — Split by domain/variant for targeted loading.

## Cross-cutting concerns

- [ ] **Skill name matches directory name** (warn) — `skill-name/SKILL.md` should have `name: skill-name`.
- [ ] **No TODO/placeholder content** (warn) — `TODO`, `FIXME`, `PLACEHOLDER` left in published skills.
- [ ] **Consistent formatting** (info) — Headers, code blocks, lists follow a consistent pattern.
- [ ] **No broken links** (warn) — Internal links to references/ files should resolve.

---

## Security audit

All files in the skill directory are scanned. Security findings are categorized separately from structure findings.

### Prompt injection

- [ ] **No "ignore previous instructions" patterns** (fail) — Variants like "disregard all", "forget your rules", "you are now DAN".
- [ ] **No system prompt override attempts** (fail) — "new instructions:", "override safety", "[system]:".
- [ ] **No zero-width characters** (fail) — `\u200b`, `\u200c`, `\u200d`, `\ufeff` used to hide text.
- [ ] **No hidden HTML** (fail) — `display:none`, `visibility:hidden`, `font-size:0`, `opacity:0`, white-on-white.

### Data exfiltration

- [ ] **No exfil domain references** (fail) — webhook.site, requestbin, ngrok, burpcollaborator, interact.sh, etc.
- [ ] **No POST + env/file access combos** (fail) — Script reads env vars or files AND sends data via POST.
- [ ] **No DNS exfiltration** (fail) — DNS queries with dynamically constructed data.
- [ ] **No curl-pipe-to-shell** (fail) — `curl ... | bash` or `wget ... | sh`.

### Credential harvesting

- [ ] **No access to ~/.ssh, ~/.aws, etc.** (fail) — Reading credential directories.
- [ ] **No sensitive env var harvesting** (fail) — Reading TOKEN, KEY, SECRET, PASSWORD from environment.
- [ ] **No suspicious filenames** (fail) — `.env`, `.pem`, `id_rsa`, `credentials` files in the skill.

### Obfuscation

- [ ] **No base64 blobs that decode to commands** (fail) — Base64 that decodes to curl, exec, eval, etc.
- [ ] **No excessive chr()/fromCharCode patterns** (warn) — Character-by-character string construction.
- [ ] **No dynamic eval/exec** (warn) — `eval(variable)`, `exec(function())` with non-literal arguments.
- [ ] **No suspiciously long lines** (warn) — Lines >500 chars (excluding frontmatter, markdown tables, URLs).

### Supply chain

- [ ] **No pip/npm from git URLs** (warn) — `pip install git+https://...`.
- [ ] **No typosquatted packages** (fail) — `reqeusts`, `beutifulsoup`, `numpi`, etc.
- [ ] **No PATH shadowing** (warn) — Scripts that modify PATH.

### Privilege escalation

- [ ] **No sudo/root operations** (warn) — `sudo`, `chmod 777`, `chown root`.
- [ ] **No system file modification** (fail) — `/etc/passwd`, `authorized_keys`, systemd/launchd.
- [ ] **No firewall/SELinux disabling** (fail) — `ufw disable`, `setenforce 0`, `iptables -F`.
- [ ] **No user creation** (fail) — `useradd`, `adduser`.

### Embedded binaries

- [ ] **No suspicious binary files** (warn) — `.exe`, `.dll`, `.so`, `.bin` in skill directory.
- [ ] **No base64-encoded executables in docs** (warn) — Magic bytes (PK, ELF, Mach-O) in .md/.txt files.
