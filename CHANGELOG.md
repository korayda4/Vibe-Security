# Changelog

All notable changes to Vibe Security are documented here. Format follows [Keep a Changelog](https://keepachangelog.com). The project adheres to [Semantic Versioning](https://semver.org).

## [0.3.0] — 2026-09-15

### Added

- **Framework detection** — auto-detects React, Next.js, Vue.js, Angular, Svelte, Express, Fastify, NestJS, Django, Flask, FastAPI, Rails, Sinatra, Laravel, Symfony, WordPress, Spring, ASP.NET Core, Blazor, Actix, Axum, Gin, Fiber, CMake. Reads `package.json`, `composer.json`, `Gemfile`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `*.csproj`, `*.sln`, `CMakeLists.txt`.
- **C / C++ support** — added `.c`, `.cpp`, `.h`, `.hpp`, `CMakeLists.txt` detection.
- **.NET / C# support** — added `.cs`, `.csproj`, `.sln` detection.
- **Smart language detection v2** — shebang (`#!/usr/bin/env python3`), syntax sniffing (def, fn, fun, package main, etc.) for files without extension.
- **Project profile output** — primary language, all detected languages, file counts, applicable rules, and now detected frameworks.

### Changed

- **README simplified** — 14.7 KB → 7.5 KB. Action-focused. Now lists 8 languages and ~25 frameworks explicitly.
- **All docs translated to English** — CONTRIBUTING.md, ROADMAP.md, USAGE.md, TOKEN_SAFETY.md, VULNERABILITY_PRIORITY.md are now concise English.
- **Contact email** — `koraydemirmc@gmail.com` (real address) in package.json and SECURITY.md.
- **TypeScript types** — Language union extended with `kotlin`, `rust`, `ruby`, `php`; Framework type added.

### Total

- **36 rules** (was 26 in 0.1.0)
- **8 code languages + C/C++/.NET** support
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
