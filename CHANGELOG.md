# Changelog

All notable changes to Vibe Security are documented here. Format follows [Keep a Changelog](https://keepachangelog.com).

## [0.1.0] â€” 2026-09-15

### Added

- MCP server with 4 tools: `scan_project`, `scan_file`, `list_rules`, `get_rule_detail`
- 26 security rules across 6 layers (Frontend, Backend, Network, Database, CI/CD, Observability)
- Multi-language support: JavaScript/TypeScript, Python, Java, Go
- Auto-fix engine with patches for FE-001, FE-004, NET-002
- Output formats: Markdown (Security.md), SARIF, JSON, JUnit XML, Compact
- Configuration via `.vibe-security.json` (rule disable, severity override, ignore patterns)
- Baseline / diff mode for CI (only flag NEW findings)
- Watch mode (3s polling)
- `/securityCheck` slash command for Claude Code and VS Code Anthropic Claude extension
- `vibe-security init` command to bootstrap any project with config + slash command
- `vibe-security scan . --baseline` and `--update-baseline` flow

### Documentation

- README (English)
- ROADMAP.md
- docs/USAGE.md
- docs/TOKEN_SAFETY.md
- docs/VULNERABILITY_PRIORITY.md
- docs/CONTRIBUTING.md

### Security

- 0 npm audit vulnerabilities
- Self-scan: 5 critical matches are intentional rule patterns, not real issues
- No telemetry, no analytics, no external network calls
