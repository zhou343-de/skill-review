#!/usr/bin/env python3
"""
Skill gatekeeper — scan all installed skills and maintain a trust registry.

Usage:
    python scan_all.py <skills-dir> [<skills-dir2> ...] [--registry <path>] [--json] [--force]

Produces a trust registry JSON file that tracks:
- Which skills have been reviewed
- Their security grade
- Whether they are approved for use

When run with --force, re-reviews all skills. Without --force, only reviews
new or modified skills (based on file mtime).
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

# Add parent script dir to path for imports
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from review_skill import review_skill_to_dict


DEFAULT_REGISTRY = Path.home() / ".openclaw" / "skill-trust-registry.json"


def file_hash(path: Path) -> str:
    """Quick hash of a file's contents."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except Exception:
        return ""


def skill_signature(skill_path: Path) -> str:
    """Hash of all files in a skill directory for change detection."""
    parts = []
    for f in sorted(skill_path.rglob("*")):
        if f.is_file() and ".git" not in f.parts:
            parts.append(f"{f.relative_to(skill_path)}:{file_hash(f)}")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def load_registry(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {"version": 1, "skills": {}, "last_scan": None}


def save_registry(registry: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2))


def discover_skills(dirs: list[Path]) -> dict[str, Path]:
    """Discover all skill directories from given paths."""
    skills = {}
    for d in dirs:
        if not d.exists():
            continue
        for item in sorted(d.iterdir()):
            if item.is_dir() and (item / "SKILL.md").exists():
                skills[item.name] = item
    return skills


def scan_all(skills_dirs: list[Path], registry_path: Path, force: bool = False, as_json: bool = False):
    registry = load_registry(registry_path)
    all_skills = discover_skills(skills_dirs)

    if not all_skills:
        print("No skills found.")
        return

    results = []
    reviewed = 0
    skipped = 0

    for name, path in all_skills.items():
        sig = skill_signature(path)
        existing = registry["skills"].get(name)

        # Skip if already reviewed with same signature and not forced
        if not force and existing and existing.get("signature") == sig:
            skipped += 1
            results.append({
                "name": name,
                "status": "cached",
                "security_grade": existing.get("security_grade", "?"),
                "approved": existing.get("approved", False),
            })
            continue

        # Review the skill
        result = review_skill_to_dict(path)
        reviewed += 1

        sec_grade = result.get("security_grade", "F")
        struct_grade = result.get("structure_grade", "F")
        sec_fails = result.get("summary", {}).get("security_fails", 0)
        approved = sec_fails == 0  # Auto-approve only if zero security fails

        # Preserve user overrides
        was_overridden = existing.get("override", False) if existing else False
        override_reason = existing.get("override_reason") if existing else None

        registry["skills"][name] = {
            "signature": sig,
            "security_grade": sec_grade,
            "structure_grade": struct_grade,
            "approved": approved or was_overridden,
            "override": was_overridden,
            "override_reason": override_reason,
            "security_fails": sec_fails,
            "security_warns": result.get("summary", {}).get("security_warns", 0),
            "findings_count": len(result.get("findings", [])),
            "reviewed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "path": str(path),
        }

        results.append({
            "name": name,
            "status": "reviewed",
            "security_grade": sec_grade,
            "structure_grade": struct_grade,
            "approved": approved or was_overridden,
            "security_fails": sec_fails,
        })

    registry["last_scan"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    save_registry(registry, registry_path)

    if as_json:
        output = {
            "registry_path": str(registry_path),
            "total": len(all_skills),
            "reviewed": reviewed,
            "skipped": skipped,
            "approved": sum(1 for r in results if r.get("approved")),
            "blocked": sum(1 for r in results if not r.get("approved")),
            "skills": results,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"## Skill Trust Registry\n")
        print(f"**Scanned:** {len(all_skills)} skills | **Reviewed:** {reviewed} | **Cached:** {skipped}")
        print(f"**Registry:** `{registry_path}`\n")

        approved = [r for r in results if r.get("approved")]
        blocked = [r for r in results if not r.get("approved")]

        if blocked:
            print(f"### 🚨 Blocked ({len(blocked)})\n")
            for r in blocked:
                grade = r.get("security_grade", "?")
                print(f"- **{r['name']}** — Security: {grade} ({r.get('security_fails', '?')} critical issues)")
            print()

        if approved:
            print(f"### ✅ Approved ({len(approved)})\n")
            for r in approved:
                grade = r.get("security_grade", "A")
                print(f"- **{r['name']}** — Security: {grade}")
            print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Skill gatekeeper — scan and approve skills")
    parser.add_argument("dirs", nargs="+", help="Skill directories to scan")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY), help="Registry file path")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--force", action="store_true", help="Re-review all skills")
    parser.add_argument("--approve", metavar="SKILL", help="Manually approve a blocked skill")
    parser.add_argument("--reason", default="user trusts source", help="Reason for manual approval")
    args = parser.parse_args()

    registry_path = Path(args.registry)

    if args.approve:
        registry = load_registry(registry_path)
        if args.approve in registry.get("skills", {}):
            registry["skills"][args.approve]["approved"] = True
            registry["skills"][args.approve]["override"] = True
            registry["skills"][args.approve]["override_reason"] = args.reason
            save_registry(registry, registry_path)
            print(f"✅ Manually approved '{args.approve}': {args.reason}")
        else:
            print(f"Skill '{args.approve}' not in registry. Run a scan first.")
        sys.exit(0)

    dirs = [Path(d) for d in args.dirs]
    scan_all(dirs, registry_path, args.force, args.json)
