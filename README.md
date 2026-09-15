# Vibe Security

> **Security guard for AI Vibe Coders.** Type `/securityCheck` in Claude Code or VS Code — the AI scans your project, writes `Security.md`, and ships auto-fix patches for the most common mistakes.

[![MCP](https://img.shields.io/badge/MCP-stdio-blue?style=flat-square)](https://modelcontextprotocol.io)
[![npm](https://img.shields.io/npm/v/vibe-security?style=flat-square)](https://www.npmjs.com/package/vibe-security)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](https://nodejs.org)

---

## Install (one command)

```bash
npx -y vibe-security init
```

This drops the slash command, MCP config, and Copilot instructions into your project. Restart Claude Code / VS Code.

That's it. Now `/securityCheck` works.

---

## Use

```
/securityCheck                  full project scan, writes Security.md
/securityCheck --frontend       only frontend layer
/securityCheck --fix            preview + apply auto-fixes
/securityCheck --baseline       only NEW findings vs baseline
/securityCheck --rule BE-004    single rule
```

Or just ask Claude:

> "Run a security scan on this project."
> "Any IDOR or SQL injection in the backend?"
> "Explain FE-001 in detail."

---

## Supported Languages & Frameworks

Vibe Security auto-detects language (file extension + shebang + syntax sniff) and detects frameworks from package manifests.

### Languages (8)

| Language | Detection | Extensions |
|---|---|---|
| **JavaScript / TypeScript** | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts`, `.tsx` | All Node + browser |
| **Python** | `.py`, `.pyi`, `#!/usr/bin/env python3` | Python 3.x |
| **Java** | `.java` | Java 8+ |
| **Kotlin** | `.kt`, `.kts` | Kotlin / Android |
| **Go** | `.go` | Go 1.18+ |
| **Rust** | `.rs` | Rust 2018+ |
| **Ruby** | `.rb`, `Gemfile`, `#!/usr/bin/env ruby` | Ruby 3.x |
| **PHP** | `.php` | PHP 8+ |
| **C / C++** | `.c`, `.cpp`, `.h`, `.hpp`, `CMakeLists.txt` | C11+ / C++17+ |
| **C# / .NET** | `.cs`, `.csproj`, `.sln` | .NET 6+ |

### Frameworks (auto-detected)

**Frontend:** React · Next.js · Vue.js · Angular · Svelte
**Backend (JS/TS):** Express · Fastify · NestJS
**Backend (Python):** Django · Flask · FastAPI
**Backend (Ruby):** Rails · Sinatra
**Backend (PHP):** Laravel · Symfony · WordPress
**Backend (Java):** Spring
**Backend (.NET):** ASP.NET Core · Blazor
**Backend (Rust):** Actix · Axum
**Backend (Go):** Gin · Fiber
**Build:** CMake

Detection sources: `package.json`, `composer.json`, `Gemfile`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `*.csproj`, `*.sln`, `CMakeLists.txt`.

The MCP server reports detected frameworks so the model knows what context to focus on.

---

## What it finds (36 rules × 6 layers)

| Layer | Examples |
|---|---|
| **Frontend** | XSS, cookie flags, public env leaks, source maps, clickjacking |
| **Backend** | IDOR, weak hashing, JWT, SQL injection, mass assignment, rate limit, file upload, token in URL, long-lived tokens |
| **Network** | Missing headers, CORS wildcard, TLS downgrade |
| **Database** | Over-privileged user, unencrypted PII |
| **CI/CD** | Dependencies, hardcoded secrets, Dockerfile |
| **Observability** | PII in logs, stack trace in response, missing handlers |

Every finding cites **CWE** + **OWASP** + concrete remediation. Three rules ship **auto-fix** patches.

Full rule catalog: [`docs/VULNERABILITY_PRIORITY.md`](docs/VULNERABILITY_PRIORITY.md).

---

## Attack vectors covered

XSS (CWE-79) · SQL/NoSQL injection (CWE-89) · BOLA/IDOR (CWE-639) · CSRF (CWE-352) · Broken auth (CWE-287) · Sensitive data exposure (CWE-200) · Cryptographic failures (OWASP A02) · Security misconfiguration (OWASP A05) · SSRF (CWE-918) · File upload (CWE-434) · Rate-limit bypass (CWE-307) · Vulnerable dependencies (OWASP A06) · Software supply chain (CWE-1357) · Insufficient logging (OWASP A09) · Mass assignment (CWE-915) · Path traversal (CWE-22) · DoS / ReDoS (CWE-400).

---

## Configuration

`.vibe-security.json`:

```json
{
  "rules": { "FE-006": { "enabled": false } },
  "ignore": ["**/vendor/**"],
  "output": { "format": "sarif" }
}
```

---

## CI/CD

```yaml
- run: npx -y vibe-security scan . --format sarif --output vibe-security.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vibe-security.sarif }
```

Baseline for PR-only-new-findings:

```bash
vibe-security scan . --update-baseline --no-fail    # main branch
vibe-security scan . --baseline .vibe-security-baseline.json    # PR branch
```

Full GitHub Actions: [`examples/github-actions.yml`](examples/github-actions.yml).

---

## How it works with your AI

Vibe Security is a **specialist skill** the AI calls when security comes up.

```
User: "/securityCheck this project"
    │
    ▼
Claude / Copilot gets MCP tool catalog
  • scan_project: file walker + 36 rules + reporter
  • scan_file:    single-file fast iteration
  • list_rules:   "what rules exist for Python?"
  • get_rule_detail: "explain FE-001 in detail"
    │
    ▼
Project profile returned:
  Primary language: TypeScript
  Frameworks detected: React, Next.js, Express
  Languages: TypeScript, Python, Dockerfile, YAML
  Applicable rules: 36 of 36
    │
    ▼
Findings → model fixes and explains
Security.md written to YOUR project root
```

Works with: Claude Code (CLI), VS Code Anthropic Claude extension, Cursor, Continue.dev.

---

## Performance

| Project size | Time |
|---|---|
| 500 files | ~200 ms |
| 5,000 files | ~1.5 s |
| 50,000 files | ~15 s |

---

## Compatibility

| Platform | Status |
|---|---|
| Claude Code | ✅ |
| VS Code Anthropic Claude extension | ✅ |
| Cursor | ✅ |
| Continue.dev | ✅ |
| Standalone CLI / CI | ✅ |

Node.js 18+.

---

## More

- [`docs/USAGE.md`](docs/USAGE.md) — every flag, every output format
- [`docs/TOKEN_SAFETY.md`](docs/TOKEN_SAFETY.md) — JWT, refresh tokens, rotation
- [`docs/VULNERABILITY_PRIORITY.md`](docs/VULNERABILITY_PRIORITY.md) — clusters by priority
- [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) — add a new rule
- [`ROADMAP.md`](ROADMAP.md) — phases and what is next

---

## License

MIT — see [`LICENSE`](LICENSE).
