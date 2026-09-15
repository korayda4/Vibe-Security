# Changelog

All notable changes to Vibe Security are documented here. Format follows [Keep a Changelog](https://keepachangelog.com). The project adheres to [Semantic Versioning](https://semver.org).

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
