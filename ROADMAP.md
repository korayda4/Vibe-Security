# Roadmap

## Vision

Vibe Security is the default security layer for AI Vibe Coders. When someone writes `/securityCheck` in Claude Code or VS Code, Vibe Security runs automatically, finds what's wrong, explains it, and patches what can be patched.

**Why an MCP server, not an external API?** The AI is already on the Claude side. Vibe Security is the rule engine, context provider, and fix generator. No API keys, no extra cost.

## Status

| Phase | Status | Scope |
|---|---|---|
| 1 — Core MVP | ✅ | MCP server, 36 rules, 8 languages, 6 layers |
| 2 — Ecosystem | ✅ | Auto-fix, SARIF/JSON/JUnit, baseline diff, /securityCheck, init command, project profile, smart detection |
| 3 — Quality | ⏳ | AST-based scanner (tree-sitter), false-positive reduction, data-flow analysis |
| 4 — AI-augmented | ⏳ | Custom rule DSL, plugin system, deeper Claude-driven review |

## Versioning

We follow [Semantic Versioning](https://semver.org/):

- `0.x.y` — pre-1.0 development, breaking changes allowed between minor versions
- `1.0.0` — first stable release
- `x.0.0` — breaking changes
- `x.y.0` — new features, backward-compatible
- `x.y.z` — bug fixes

## Release cadence

- **Patch releases** as needed for bug fixes and security patches
- **Minor releases** roughly monthly with new rules and features
- **Major releases** only with deliberate breaking-change announcements (MIGRATION.md will be provided)

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## What is next (Phase 3 backlog)

- tree-sitter AST scanner (replaces regex, reduces false positives)
- TypeScript JSX data-flow for XSS detection
- Inline suppression: `// vibe-security-disable-next-line RULE_ID`
- Custom rule DSL (JSON / YAML) for community rules
- HTML / PDF report formats
- PR automation: open a PR with the Security.md on every release
