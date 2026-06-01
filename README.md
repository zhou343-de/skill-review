<div align="center">

# 🛡️ Skill Review

### OpenClaw Skill Security Gatekeeper

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-yellow.svg)](https://python.org)
[![Security Scanner](https://img.shields.io/badge/Security-Scanner-red.svg)](#security-audit)

**Automated security auditing and quality review for OpenClaw AgentSkills.**

*Detects prompt injection, data exfiltration, credential harvesting, obfuscated payloads, and supply chain attacks — before they run.*

[English](#english) · [中文](#中文)

---

</div>

<a name="english"></a>

## 🇬🇧 English

### Why This Exists

OpenClaw skills are powerful — they can read files, execute scripts, access the network, and interact with your system. But that power comes with risk. A malicious skill could:

- 🔓 **Steal credentials** — SSH keys, API tokens, cloud credentials
- 🕵️ **Exfiltrate data** — POST your files to an attacker's server
- 🧠 **Inject prompts** — Override the agent's safety rules with hidden instructions
- 📦 **Poison dependencies** — Install backdoored packages via typosquatting
- 👻 **Hide payloads** — Use zero-width characters, base64 encoding, or steganography

**Skill Review** is a security firewall that scans skills *before* they're trusted, catching these patterns automatically.

### Features

| Category | What It Detects |
|----------|----------------|
| **Prompt Injection** | "Ignore previous instructions", zero-width hidden text, `display:none` content |
| **Data Exfiltration** | POST + env var/file access combos, exfil domains (webhook.site, ngrok, etc.) |
| **Credential Harvesting** | Access to `~/.ssh`, `~/.aws`, sensitive env vars (TOKEN/KEY/SECRET) |
| **Code Obfuscation** | Base64→command payloads, `chr()` chains, dynamic `eval`/`exec` |
| **Supply Chain** | `curl|bash`, typosquatted packages, pip/npm from untrusted git URLs |
| **Privilege Escalation** | `sudo`, SSH key injection, user creation, firewall disabling |
| **Structure Quality** | Frontmatter validation, progressive disclosure, file organization |

### Quick Start

```bash
# Scan a single skill
python3 scripts/review_skill.py /path/to/skill

# Security-only scan
python3 scripts/review_skill.py /path/to/skill --security-only

# JSON output for automation
python3 scripts/review_skill.py /path/to/skill --json

# Scan all installed skills and build trust registry
python3 scripts/scan_all.py /app/skills --force

# Manually approve a blocked skill
python3 scripts/scan_all.py /app/skills --approve skill-name --reason "trusted source"
```

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    Skill Review Gatekeeper               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  SKILL.md │───▶│  Frontmatter │───▶│  Structure   │  │
│  │  Scanner  │    │  Validation  │    │  Analysis    │  │
│  └──────────┘    └──────────────┘    └──────────────┘  │
│       │                                             │   │
│       ▼                                             ▼   │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Script  │───▶│   Security   │───▶│    Grade     │  │
│  │  Scanner │    │   Checks     │    │   A/B/C/D/F  │  │
│  └──────────┘    └──────────────┘    └──────────────┘  │
│       │                                     │           │
│       ▼                                     ▼           │
│  ┌──────────┐                        ┌──────────────┐  │
│  │  Trust   │◀───────────────────────│  Decision    │  │
│  │ Registry │                        │  Engine      │  │
│  └──────────┘                        └──────────────┘  │
│                                                         │
│  Grade A/B → ✅ Auto-approve                            │
│  Grade C   → ⚠️ Approve with warnings                   │
│  Grade D/F → 🚫 Block, report to user                   │
└─────────────────────────────────────────────────────────┘
```

### Grading System

Skills receive **two independent grades** — the final grade is the *lower* (worse) of the two:

| Grade | Structure | Security |
|-------|-----------|----------|
| **A** | 0 fails, ≤1 warn | 0 security issues |
| **B** | 0 fails, 2–4 warns | 0 fails, 1–2 warns |
| **C** | 0 fails, 5+ warns | 0 fails, 3+ warns |
| **D** | 1–2 fails | 1 security fail |
| **F** | 3+ fails | 2+ security fails |

### Trust Registry

Located at `~/.openclaw/skill-trust-registry.json`, the registry tracks:

```json
{
  "version": 1,
  "skills": {
    "my-skill": {
      "signature": "a1b2c3d4e5f6g7h8",
      "security_grade": "A",
      "structure_grade": "B",
      "approved": true,
      "override": false,
      "reviewed_at": "2026-06-01T21:00:00+0800"
    }
  },
  "last_scan": "2026-06-01T21:00:00+0800"
}
```

Skills are automatically re-reviewed when their file signature changes.

### Security Self-Assessment

> **"Quis custodiet ipsos custodes?"** — Who watches the watchmen?

This tool scans itself. Here's the honest result:

```
Structure: A | Security: F | Final: F 🚨
```

**Why?** Because the scanner's own source code and documentation *necessarily* contain the patterns it detects — strings like `"ignore all previous instructions"`, `"webhook.site"`, `"~/.ssh"`, `eval(`, `curl|bash`, etc. These are **by design**, not vulnerabilities.

The trust registry has a manual override for exactly this case:

```bash
python3 scripts/scan_all.py --approve skill-review \
  --reason "System-level gatekeeper — self-approved"
```

**This is a feature, not a bug.** A security scanner that couldn't detect its own patterns would be incomplete.

---

<a name="中文"></a>

## 🇨🇳 中文

### 为什么需要这个

OpenClaw 的 Skill 功能强大——可以读取文件、执行脚本、访问网络、操作系统。但能力越大，风险越大。一个恶意 Skill 可以：

- 🔓 **窃取凭证** — SSH 密钥、API Token、云服务凭证
- 🕵️ **外泄数据** — 把你的文件 POST 到攻击者的服务器
- 🧠 **注入提示词** — 用隐藏指令覆盖 Agent 的安全规则
- 📦 **投毒依赖** — 通过拼写错误的包名安装后门
- 👻 **隐藏载荷** — 用零宽字符、Base64 编码或隐写术藏匿恶意代码

**Skill Review** 是一道安全防火墙，在 Skill 被信任之前自动扫描，捕获这些模式。

### 功能特性

| 类别 | 检测内容 |
|------|----------|
| **提示词注入** | "忽略之前的指令"、零宽字符隐藏文本、`display:none` 隐藏内容 |
| **数据外泄** | POST + 环境变量/文件读取组合、外传域名（webhook.site、ngrok 等） |
| **凭证窃取** | 访问 `~/.ssh`、`~/.aws`、敏感环境变量（TOKEN/KEY/SECRET） |
| **代码混淆** | Base64 解码为命令、`chr()` 拼接、动态 `eval`/`exec` |
| **供应链攻击** | `curl\|bash`、拼写错误的包名、从不受信任的 git URL 安装 |
| **权限提升** | `sudo`、注入 SSH 密钥、创建用户、禁用防火墙 |
| **结构质量** | Frontmatter 验证、渐进式披露、文件组织规范 |

### 快速上手

```bash
# 扫描单个 Skill
python3 scripts/review_skill.py /path/to/skill

# 仅安全扫描
python3 scripts/review_skill.py /path/to/skill --security-only

# JSON 输出（便于自动化）
python3 scripts/review_skill.py /path/to/skill --json

# 扫描所有已安装 Skill 并构建信任注册表
python3 scripts/scan_all.py /app/skills --force

# 手动批准被拦截的 Skill
python3 scripts/scan_all.py /app/skills --approve skill-name --reason "可信来源"
```

### 工作流程

```
┌─────────────────────────────────────────────────────────┐
│                  Skill Review 安全门禁                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  SKILL.md │───▶│  Frontmatter │───▶│  结构分析    │  │
│  │  扫描器   │    │  校验        │    │              │  │
│  └──────────┘    └──────────────┘    └──────────────┘  │
│       │                                             │   │
│       ▼                                             ▼   │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  脚本    │───▶│   安全检查   │───▶│   评级       │  │
│  │  扫描器  │    │              │    │  A/B/C/D/F   │  │
│  └──────────┘    └──────────────┘    └──────────────┘  │
│       │                                     │           │
│       ▼                                     ▼           │
│  ┌──────────┐                        ┌──────────────┐  │
│  │  信任    │◀───────────────────────│  决策引擎    │  │
│  │  注册表  │                        │              │  │
│  └──────────┘                        └──────────────┘  │
│                                                         │
│  A/B 级 → ✅ 自动放行                                    │
│  C 级   → ⚠️ 谨慎放行，通知用户                          │
│  D/F 级 → 🚫 拦截，报告用户                              │
└─────────────────────────────────────────────────────────┘
```

### 评级体系

每个 Skill 获得**两个独立评级**——最终评级取两者中较低的：

| 等级 | 结构评级 | 安全评级 |
|------|----------|----------|
| **A** | 0 失败，≤1 警告 | 0 安全问题 |
| **B** | 0 失败，2–4 警告 | 0 失败，1–2 警告 |
| **C** | 0 失败，5+ 警告 | 0 失败，3+ 警告 |
| **D** | 1–2 失败 | 1 安全失败 |
| **F** | 3+ 失败 | 2+ 安全失败 |

### 信任注册表

位于 `~/.openclaw/skill-trust-registry.json`，记录每个 Skill 的：

```json
{
  "version": 1,
  "skills": {
    "my-skill": {
      "signature": "a1b2c3d4e5f6g7h8",
      "security_grade": "A",
      "structure_grade": "B",
      "approved": true,
      "override": false,
      "reviewed_at": "2026-06-01T21:00:00+0800"
    }
  }
}
```

当 Skill 的文件签名变更时，自动重新审查。

### 安全自证

> **"谁来监视监视者？"**

这个工具会扫描自己。以下是诚实的结果：

```
结构: A | 安全: F | 最终: F 🚨
```

**为什么？** 因为扫描器自身的源代码和文档*必然*包含它要检测的模式——比如 `"ignore all previous instructions"`、`"webhook.site"`、`"~/.ssh"`、`eval(`、`curl|bash` 等。这是**设计如此**，不是漏洞。

信任注册表提供手动覆盖机制：

```bash
python3 scripts/scan_all.py --approve skill-review \
  --reason "系统级门禁 Skill — 自我批准"
```

**这是特性，不是缺陷。** 一个连自身模式都检测不了的安全扫描器，才是不完整的。

---

<div align="center">

### 📁 Project Structure

```
skill-review/
├── SKILL.md                        # Gatekeeper protocol & review process
├── README.md                       # This file
├── LICENSE                         # MIT License
├── scripts/
│   ├── review_skill.py             # Single skill scanner (530+ lines)
│   └── scan_all.py                 # Batch scanner & trust registry manager
└── references/
    └── checklist.md                # Complete security audit checklist
```

### 🤝 Contributing

Contributions welcome. Run the scanner on your own skill first:

```bash
python3 scripts/review_skill.py your-skill/
```

### 📄 License

MIT — use it, fork it, make it better.

---

*Built for the [OpenClaw](https://github.com/openclaw/openclaw) ecosystem.*

</div>
