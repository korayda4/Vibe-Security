# Changelog

All notable changes to Vibe Security are documented here. Format follows [Keep a Changelog](https://keepachangelog.com). The project adheres to [Semantic Versioning](https://semver.org).

## [1.3.1] — 2026-09-21

### Added

- **On-the-fly Pre-Build Auto-Patching** — `check-build` now supports `--fix` and `--auto-patch`. Auto-fixable vulnerabilities are patched on-the-fly during pre-build; if all blocking flaws are resolved, the build proceeds cleanly without halting.
- **Self-Healing Build Scripts** — `vibe-security init` now injects `"prebuild": "vibe-security check-build --fix"` into host `package.json` files for zero-friction self-healing builds.
- **Internal Pre-Build Guard** — added `"prebuild": "tsx src/cli.ts check-build src/ --fix"` to ensure internal builds are continuously gated and verified.
- **MCP `check_build` Auto-Patching** — enhanced `check_build` tool with `fix` and `dryRun` parameters, allowing AI agents to heal vulnerabilities in a single step.

## [1.3.0] — 2026-09-21

### Added

- **Automated Pre-Build Gate (`check-build` / `SecurityCheckBuild`)** — automated pre-build gatekeeper that enforces a 3-tier verdict:
  - `SUCCESS`: Clean project, 0 blocking flaws (Exit 0, build proceeds).
  - `WARNING`: Non-blocking issues detected (medium/low/lint) (Exit 0, warnings displayed prominently).
  - `SECURITY_VULNERABILITY`: Critical or High vulnerabilities found (Exit 1, **build halted**).
- **Auto-injected `prebuild` Hook** — `vibe-security init` now automatically wires `"prebuild": "vibe-security check-build"` into the host project's `package.json`, preventing unsafe builds out-of-the-box.
- **`check_build` MCP Tool** — allows AI agents to verify build readiness and self-heal vulnerabilities before triggering deployments.
- **Dual Workflow Agent Action Protocol (AAP)** — `SKILL.md` updated with strict separation between automated build gating (`SecurityCheckBuild`) and interactive research/remediation (`SecurityCheck`).
- **Language Quality & Lint Rules (`LINT-001` - `LINT-005`)** — detects empty catch blocks, floating promises, TypeScript `any` bypasses, and common syntax traps across frontend and backend code.
- **Target Folder & Detailed Scanning** — `--dir` / `--path` and `--detailed` options for surgical, component-level scanning.

## [1.2.0] — 2026-09-21

### Added

- **Programmatic Library API** — `src/index.ts` exports `scan`, `applyFixes`, `getAllRules`, `detectLanguage`, `readBaseline`, `writeSecurityReport`, and TypeScript definitions for programmatic use via `npm i`.
- **Standalone MCP Server Binary** — `vibe-security-mcp` binary (`dist/mcp.js`), decoupling library imports from stdio MCP server execution.
- **`apply_fix` MCP Tool** — enables AI agents to preview unified diffs (`dryRun: true`) and apply security patches via MCP.
- **Agent Action Protocol (AAP) Skill** — `skills/vibe-security/SKILL.md` standard for Antigravity, Gemini CLI, Claude Code, and Cursor.
- **UNIQUE Vibe-Coding Rules (`AI-001` - `AI-004`)** — detects client-side LLM SDK key leaks, Supabase `SERVICE_ROLE_KEY` client leaks, Next.js Server Action auth bypasses, and Prompt Injection sinks.
- **Automated Fix Patches** — added auto-fix patches for `AI-001` (client LLM leaks) and `OBS-001` (stack trace disclosure).
- **Multi-Environment Init** — `vibe-security init` now sets up `.agents/skills/` and `.cursor/rules/` alongside Claude Code and VS Code.

### Changed

- **False Positive Elimination in `BE-004`** — removed broad matching on benign MongoDB operators (`$gt`, `$lt`, `$ne`), keeping accurate NoSQL injection detection without noise.
- **Line-Invariant Baseline Tracking** — `findingFingerprint` now tolerates line insertions and code shifts without falsely re-flagging baseline findings.
- **Modular MCP Tool Architecture** — tool handlers moved to dedicated modules under `src/tools/` (SOLID Single Responsibility).
- **Package Publishing Metadata** — added `publishConfig: { access: "public" }`, `types`, and modern `"exports"` map to `package.json`.

## [1.1.0] — 2026-09-17

### Added

- Scan results now expose file and rule execution errors instead of presenting partial scans as clean.
- Security reports include a scan warnings section when analysis is incomplete.

### Changed

- Auto-fixes are grouped per file, preserving multiple fixes in one write operation.
- Auto-fixes reject path traversal and symlink targets outside the scan root.
- Explicit CLI layer and language filters take precedence over configuration defaults.
- CLI options can be used without providing a positional scan path.
- Invalid configuration files fail clearly instead of being silently ignored.

## [1.0.0] — 2026-09-16

### Added

- Stable npm and MCP release for AI coding assistants.
- Language filtering for targeted frontend and backend scans.
- Per-file and global finding caps for predictable scans on large projects.
- Redaction of token-shaped values in finding snippets before they reach reports or AI tools.

### Changed

- Updated MCP and SARIF runtime metadata to `1.0.0`.
- Translated remaining runtime-facing text to English.
- Synchronized package and lockfile release metadata.

## [0.3.0] — 2026-09-15

### Added

- **Framework auto-detection** — React, Next.js, Vue.js, Angular, Svelte, Express, Fastify, NestJS, Django, Flask, FastAPI, Rails, Sinatra, Laravel, Symfony, WordPress, Spring, ASP.NET Core, Blazor, Actix, Axum, Gin, Fiber, CMake. Reads `package.json`, `composer.json`, `Gemfile`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `*.csproj`, `*.sln`, `CMakeLists.txt`.
- **C / C++ / C# / .NET support** — added `.c`, `.cpp`, `.h`, `.hpp`, `.cs`, `.csproj`, `.sln`, `CMakeLists.txt` detection.
- **Smart language detection v2** — shebang (`#!/usr/bin/env python3`) + syntax sniffing (def, fn, fun, package main) for files without extension.
- **Project profile output** — primary language, detected languages, file counts, applicable rules, and detected frameworks.
- **Published on npm** as `@korayda4/vibe-security` (scoped, public).

### Changed

- **README rewritten** — 6.3 KB. Action-focused. Frontend and Backend technologies explicitly listed with the Vibe Coding security philosophy: "Plan → Test → Find → Explain → Fix".
- **All docs translated to English and simplified** — CONTRIBUTING.md, ROADMAP.md, USAGE.md, TOKEN_SAFETY.md, VULNERABILITY_PRIORITY.md.
- **Package renamed to scoped** — `@korayda4/vibe-security` (the unscoped name was taken).
- **Contact email** — `koraydemirmc@gmail.com` (real address) in package.json and SECURITY.md.
- **Author block** in package.json with name, email, GitHub URL.
- **`prepublishOnly` hook** runs lint + test before publish.

### Total

- **36 rules** (was 26 in 0.1.0)
- **10 languages** (JS/TS, Python, Java, Kotlin, Go, Rust, Ruby, PHP, C/C++, C#/.NET)
- **~25 frameworks** auto-detected
- **19 tests** (was 16 in 0.1.0), all passing
- **0 npm audit vulnerabilities**

## [0.2.0] — 2026-09-15

### Added

- 4 new languages: Rust, Ruby, PHP, Kotlin
- 10 new rules (RS-*, RB-*, PHP-*, KT-*)
- Smart language detection: extension + shebang + syntax sniffing
- Project profile in scan output

## [0.1.0] — 2026-09-15

### Added

- MCP server with 4 tools: `scan_project`, `scan_file`, `list_rules`, `get_rule_detail`
- 26 security rules across 6 layers
- Multi-language support: JavaScript/TypeScript, Python, Java, Go
- Auto-fix engine with patches for FE-001, FE-004, NET-002
- Output formats: Markdown (Security.md), SARIF, JSON, JUnit XML, Compact
- Configuration via `.vibe-security.json`
- Baseline / diff mode for CI
- Watch mode (3s polling)
- `/securityCheck` slash command
- `vibe-security init` command
