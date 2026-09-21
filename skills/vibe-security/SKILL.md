---
name: vibe-security
description: Security guard and automated remediation skill for AI-generated code. Scans projects across frontend, backend, database, network, cicd, and observability layers, detects vulnerabilities, and safely plans and applies auto-fixes.
---

# Vibe Security - Agent Action Protocol (AAP) Skill

This skill guides AI agents (Antigravity, Gemini CLI, Claude Code, Cursor, Copilot) in auditing codebases, detecting security vulnerabilities, explaining risks, and safely remediating issues using the Vibe Security engine.

## Agent Action Protocol (AAP) Workflow

When performing security audits or reviewing AI-generated code, follow this 5-stage loop:

```mermaid
graph TD
    A[1. Scan & Profile] --> B[2. Triage & Classify]
    B --> C[3. Plan & Preview Fix]
    C --> D[4. Safe Apply]
    D --> E[5. Verify & Report]
```

### Stage 1: Scan & Profile
- Run `scan_project` via MCP or `vibe-security scan .` via CLI.
- Detect project primary language and active frameworks (e.g. Next.js, Express, Django).
- If scanning after recent changes, pass `baselinePath: ".vibe-security-baseline.json"` to focus solely on newly introduced findings.

### Stage 2: Triage & Classify
- Sort findings by severity: `CRITICAL` -> `HIGH` -> `MEDIUM` -> `LOW` -> `INFO`.
- Identify findings that are marked as auto-fixable (`fix` present).
- For complex vulnerabilities, inspect detailed threat models and remediation guides using `get_rule_detail(ruleId)`.

### Stage 3: Plan & Preview Fix (Dry-Run)
- **NEVER** apply blind changes without inspection.
- Call `apply_fix` with `dryRun: true` (or `vibe-security scan . --fix --dry-run`).
- Present the unified diff to the user or review policy.
- For issues without automated patches, use the remediation steps from the rule definition to construct a minimal, non-breaking patch.

### Stage 4: Safe Apply
- Once verified or approved, call `apply_fix` with `dryRun: false` (or `vibe-security scan . --fix`).
- Limit fixes to specific rules or files using `ruleIds: ["FE-001"]` or `file: "src/api/auth.ts"`.

### Stage 5: Verify & Report
- Re-run `scan_file` or `scan_project` to ensure:
  1. The target vulnerability is resolved.
  2. No regression or new finding was introduced.
- Confirm `Security.md` has been updated with the latest audit summary.

---

## MCP Tools Reference

| MCP Tool | Purpose | Key Arguments |
| :--- | :--- | :--- |
| `scan_project` | Full project vulnerability scan | `rootDir`, `layers`, `languages`, `ruleIds`, `baselinePath`, `includeFixes` |
| `scan_file` | Single file fast check | `filePath`, `layers`, `ruleIds` |
| `list_rules` | List available rules and layers | `layer` |
| `get_rule_detail` | Detailed remediation & threat specs | `ruleId` |
| `apply_fix` | Preview or apply automated patches | `rootDir`, `ruleIds`, `file`, `dryRun` (default `true`) |

---

## CLI Reference

```bash
# Scan full project (generates Security.md)
vibe-security scan .

# Preview automated fixes without modifying disk
vibe-security scan . --fix --dry-run

# Apply automated fixes
vibe-security scan . --fix

# CI SARIF generation for GitHub Code Scanning
vibe-security scan . --format sarif -o vibe-security.sarif

# Update baseline for regression checks
vibe-security baseline update
```
