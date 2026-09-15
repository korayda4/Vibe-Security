# Usage

## Install

### From GitHub

```json
{
  "mcpServers": {
    "vibe-security": { "command": "npx", "args": ["-y", "github:korayda4/Vibe-Security"] }
  }
}
```

### From npm

```json
{
  "mcpServers": {
    "vibe-security": { "command": "npx", "args": ["-y", "vibe-security"] }
  }
}
```

### Bootstrap a project

```bash
npx -y vibe-security init
```

Drops `.vibe-security.json`, slash command, and Copilot instructions.

## Slash command

```
/securityCheck                  full scan, writes Security.md
/securityCheck --frontend       only frontend layer
/securityCheck --fix            preview + apply auto-fixes
/securityCheck --baseline       only NEW findings
/securityCheck --rule BE-004    single rule
/securityCheck --format sarif   SARIF output for CI
```

## CLI

```bash
vibe-security scan [path] [options]

Options:
  --format <markdown|json|sarif|junit|compact>
  --output, -o <path>
  --fix | --dry-run
  --baseline <path> | --update-baseline
  --layers <frontend,backend,network,database,cicd,observability>
  --rules <FE-001,BE-004>
  --watch, -w
  --no-fail
```

Subcommands: `scan`, `list`, `init`, `baseline update`.

## Configuration (`.vibe-security.json`)

```json
{
  "rules": { "FE-006": { "enabled": false } },
  "ignore": ["**/vendor/**"],
  "output": { "format": "sarif", "path": "vibe-security.sarif" },
  "baseline": ".vibe-security-baseline.json",
  "layers": ["backend", "database"]
}
```

## CI/CD

### GitHub Actions (SARIF + baseline)

```yaml
- run: npx -y vibe-security scan . --format sarif --output vibe-security.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vibe-security.sarif }
```

Full workflow: [`examples/github-actions.yml`](../examples/github-actions.yml).

### Baseline strategy

```bash
# main branch (snapshot all known findings)
vibe-security scan . --update-baseline --no-fail

# PR branch (only new findings)
vibe-security scan . --baseline .vibe-security-baseline.json
```

## MCP tools

| Tool | Purpose |
|---|---|
| `scan_project` | Full scan, returns summary + profile, writes Security.md |
| `scan_file` | Single file |
| `list_rules` | All rules (filter by layer / language) |
| `get_rule_detail` | Full description + remediation for one rule |

## Suppress a finding

Use the `.vibe-security.json` config to disable rules project-wide:

```json
{ "rules": { "FE-006": { "enabled": false } } }
```

Per-rule inline disable is on the Phase 3 roadmap.

## Performance

| Project size | Time |
|---|---|
| 500 files | ~200 ms |
| 5,000 files | ~1.5 s |
| 50,000 files | ~15 s |

## Compatibility

- Node.js 18+
- Claude Code (CLI), VS Code Anthropic Claude extension, Cursor, Continue.dev
- GitHub Copilot Workspace (MCP preview)
- Standalone CLI / CI
