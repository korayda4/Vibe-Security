# Vibe Security

> **Security guard for AI Vibe Coders.** A Model Context Protocol (MCP) server that scans your project across six security layers, writes `Security.md` to the root, and ships auto-fix patches for the most common mistakes.

<p align="left">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-stdio-blue?style=flat-square" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img alt="Node" src="https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square" />
  <img alt="Rules" src="https://img.shields.io/badge/rules-26-blueviolet?style=flat-square" />
  <img alt="Languages" src="https://img.shields.io/badge/languages-4-orange?style=flat-square" />
</p>

---

## Why Vibe Security?

AI assistants (Claude Code, VS Code Anthropic Claude extension, Cursor, Continue.dev) generate code fast. They sometimes forget security. Vibe Security is a **specialist skill** that the AI can invoke — it scans, explains, and fixes.

- **No external API.** The AI is already on the Claude side. Vibe Security is the rule engine and context provider.
- **One slash command.** Type `/securityCheck` and the scan runs.
- **Real fixes.** Some rules ship with auto-fix patches (`--fix`); the rest tell you exactly what to change.

---

## Install

### From GitHub (no npm publish required)

```bash
# Claude Code — ~/.claude/mcp_servers.json
{
  "mcpServers": {
    "vibe-security": { "command": "npx", "args": ["-y", "github:korayda4/Vibe-Security"] }
  }
}

# VS Code Anthropic Claude extension — .vscode/settings.json
{
  "mcp.servers": {
    "vibe-security": { "command": "npx", "args": ["-y", "github:korayda4/Vibe-Security"] }
  }
}
```

### From npm (after publish)

```json
{ "command": "npx", "args": ["-y", "vibe-security"] }
```

### Project bootstrap

Run this in any project to copy the slash command, MCP config, and Copilot instructions:

```bash
npx -y github:korayda4/Vibe-Security init
```

Creates:

- `.vibe-security.json` — project config
- `.claude/commands/securityCheck.md` — Claude Code slash command
- `.vscode/settings.json` — VS Code MCP config
- `.github/instructions/security-check.instructions.md` — Copilot instructions

---

## Usage

### Slash command

```
/securityCheck                  # full scan, writes Security.md
/securityCheck --frontend       # only frontend layer
/securityCheck --fix            # apply auto-fixes (dry-run by default)
/securityCheck --baseline       # show only NEW findings vs baseline
/securityCheck --rule BE-004    # run a single rule
```

### Natural language

> "Scan this project for security issues."
> "Are there any IDOR or SQL injection in the backend?"
> "Explain FE-001 in detail."

### CLI

```bash
npx -y github:korayda4/Vibe-Security scan .                       # Markdown report
npx -y github:korayda4/Vibe-Security scan . --format sarif        # GitHub Code Scanning
npx -y github:korayda4/Vibe-Security scan . --fix --dry-run       # preview fixes
npx -y github:korayda4/Vibe-Security scan . --watch               # live re-scan
npx -y github:korayda4/Vibe-Security list                         # list all rules
npx -y github:korayda4/Vibe-Security baseline update              # snapshot current findings
```

### What `Security.md` looks like in your project

When you run `vibe-security scan .` in any project, a `Security.md` file is **generated at runtime** at your project's root. It contains:

- Executive summary table (counts by severity)
- Findings grouped by layer (Frontend, Backend, Network, Database, CI/CD, Observability)
- Each finding shows: rule ID, severity, CWE / OWASP reference, file:line, code snippet, **detailed remediation** (the fix to apply)
- "How to fix" footer with workflow guidance

**Important:** `Security.md` is **not** part of this repo. It's auto-generated in *your* project. See a sample here: [`docs/SECURITY_REPORT.example.md`](docs/SECURITY_REPORT.example.md).

`.gitignore` ships with this pattern so the generated file never accidentally gets committed:

```
Security.md
Security-*.md
.vibe-security-baseline.json
```

---

## Supported Languages

Vibe Security scans source code in four languages out of the box, with rules adapted to each ecosystem's idioms:

| Language | Files | What it covers |
|---|---|---|
| **JavaScript / TypeScript** | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.mts`, `.cts`, `.tsx` | React, Next.js, Express, NestJS, Vite, Webpack, Node.js APIs, TypeScript types |
| **Python** | `.py`, `.pyi` | Flask, Django, FastAPI, raw SQLAlchemy, f-string injection, hashlib misuse, JWT (PyJWT) |
| **Java** | `.java` | Spring `@ModelAttribute`, JDBC queries, MessageDigest, JWT libs |
| **Go** | `.go` | Gin, net/http, `md5.Sum`, `jwt.SigningMethodNone`, `c.BindJSON`, `filepath.Join` |

Each rule is tagged with the `languages` it applies to, so a Python-only project doesn't waste cycles on JavaScript patterns.

---

## Attack Vectors Covered

Vibe Security protects against 26 categorized threats across 6 layers. Each finding cites the relevant **CWE**, **OWASP**, and remediation guidance.

### Cross-Site Scripting (XSS) — CWE-79
Stored, reflected, and DOM-based XSS via `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, `outerHTML`, `insertAdjacentHTML`. Auto-fix wraps values with `DOMPurify.sanitize`.

### SQL & NoSQL Injection — CWE-89
String-concatenation SQL queries, f-string SQL in Python, `+` SQL in Java/Go, NoSQL `$where` / `$function` / `$regex` operator injection.

### Broken Object-Level Authorization (BOLA / IDOR) — CWE-639
`findUnique({ where: { id } })` without ownership check, `findByPk`, `getById` patterns that skip the `ownerId` filter.

### Insecure Direct Object Reference — OWASP API1:2023
Same family as BOLA — covers Spring `@ModelAttribute`, FastAPI / Django `ModelForm`, Go `c.BindJSON`.

### Cross-Site Request Forgery (CSRF) — CWE-352
Detected via missing SameSite / CSRF token checks; covered by FE-002 cookie flags and FE-005 frame-ancestors.

### Broken Authentication — CWE-287, OWASP A07
JWT `alg: none`, weak HMAC secrets, missing expiry, tokens in URLs, tokens in localStorage, long-lived sessions, weak password hashing (MD5/SHA1/SHA256).

### Sensitive Data Exposure — CWE-200, OWASP A02
Public env vars with secrets (`NEXT_PUBLIC_*`, `REACT_APP_*`), source maps in production, hardcoded secrets in source.

### Cryptographic Failures — OWASP A02
Weak hashing (MD5, SHA-1, SHA-256), TLS downgrade, missing HSTS, missing CSP.

### Security Misconfiguration — OWASP A05
CORS wildcard, missing security headers (CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy), clickjacking, source map exposure, over-privileged DB user, Dockerfile running as root, `latest` tag, `ADD` from URL.

### Server-Side Request Forgery (SSRF) — CWE-918
Detected via unrestricted URL patterns in fetch / HTTP clients.

### File Upload Vulnerabilities — CWE-434
Multer diskStorage with `originalname`, Flask `file.save(originalname)`, Spring `transferTo`, Go `filepath.Join` with user input.

### Rate-Limiting Bypass / Brute Force — CWE-307
Missing rate limit on `/login`, `/signup`, `/reset-password`, `/verify-otp`, `/2fa`.

### Vulnerable & Outdated Components — OWASP A06
Missing lockfile, missing audit script, `FROM latest`, `pip install` without `--require-hashes`.

### Software Supply Chain — OWASP A06, CWE-1357
Hardcoded tokens, missing dependency audit, base-image latest.

### Insufficient Logging & Monitoring — OWASP A09
Stack traces in HTTP responses, PII in logs (`console.log(password)`, `logger.info(token)`), missing global `unhandledRejection` / `uncaughtException` handlers.

### Insecure Design (Mass Assignment) — CWE-915, OWASP A04
`prisma.user.create({ data: req.body })`, `ModelForm.save()`, Go `c.BindJSON(struct)`.

### Path Traversal — CWE-22
Detected in Go via `filepath.Join` with user-controlled filenames.

### Denial of Service (ReDoS / Resource Exhaustion) — CWE-400
Detected via unbounded query patterns (covered by missing rate limit + missing pagination checks).

---

## Features

| Feature | Description |
|---|---|
| **MCP server** | Standard `@modelcontextprotocol/sdk` stdio transport — Claude Code, VS Code Anthropic Claude extension, Cursor, Continue.dev |
| **`/securityCheck` slash command** | One-line trigger; AI calls `scan_project` automatically |
| **26 rules × 6 layers** | Frontend, Backend, Network, Database, CI/CD, Observability |
| **4 languages** | JavaScript/TypeScript, Python, Java, Go |
| **Auto-fix** | Patches for `FE-001` (XSS → DOMPurify), `FE-004` (source maps off), `NET-002` (CORS whitelist) |
| **5 output formats** | Markdown (`Security.md`), SARIF (GitHub Code Scanning), JSON, JUnit XML, Compact |
| **Configuration** | `.vibe-security.json` — rule disable, severity override, ignore patterns |
| **Baseline / diff mode** | Snapshot known findings, only flag new ones in CI |
| **Watch mode** | Live re-scan on file changes (3s polling) |
| **`init` command** | Bootstraps any project with config + slash command |
| **CWE + OWASP references** | Every finding cites the relevant weakness and category |
| **Zero npm audit vulnerabilities** | Audited via `npm audit` |
| **Zero external network calls** | Pure local scan; no telemetry, no analytics |

---

## What it scans — 26 rules in detail

### Frontend (6 rules)

| ID | Severity | What it detects | Auto-fix |
|---|---|---|---|
| `FE-001` | high | `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, `outerHTML`, `insertAdjacentHTML` | ✅ `DOMPurify.sanitize()` |
| `FE-002` | high | `document.cookie` write, `Set-Cookie` without HttpOnly, token in localStorage / sessionStorage | — |
| `FE-003` | critical | `NEXT_PUBLIC_*` / `REACT_APP_*` / `VITE_*` with SECRET / KEY / TOKEN | — |
| `FE-004` | medium | `productionBrowserSourceMaps: true`, Vite `build.sourcemap = true` | ✅ flip to `false` |
| `FE-005` | medium | Missing `X-Frame-Options` / CSP `frame-ancestors` in Next.js config | — |
| `FE-006` | high | `eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)` | — |

### Backend & API (9 rules)

| ID | Severity | What it detects | Auto-fix |
|---|---|---|---|
| `BE-001` | high | `findUnique`, `findFirst`, `findOne`, `findByPk`, `getById` without ownership check (IDOR) | — |
| `BE-002` | critical | `md5`, `sha1`, `sha256`, plain-text password compare | — |
| `BE-003` | critical | JWT `alg: none`, weak secret (< 256-bit), `jwt.decode` without `verify` | — |
| `BE-004` | critical | SQL/NoSQL injection via string concatenation (JS, Python f-string, Java `+`, Go `+`) | — |
| `BE-005` | high | `prisma.user.create({ data: req.body })`, Spring `@ModelAttribute`, Go `c.BindJSON(struct)` | — |
| `BE-006` | medium | Missing rate limit on `/login`, `/signup`, `/reset-password`, `/verify-otp`, `/2fa` | — |
| `BE-007` | high | Multer `diskStorage` with `originalname`, Flask `file.save(originalname)`, Spring `transferTo` | — |
| `BE-008` | high | Token in URL: `req.query.token`, `fetch('... ?api_key=')`, path params | — |
| `BE-009` | high | Long-lived token: `expiresIn: '365d'`, no expiry, session `maxAge > 24h` | — |

### Network & Infrastructure (3 rules)

| ID | Severity | What it detects | Auto-fix |
|---|---|---|---|
| `NET-001` | medium | Missing CSP / HSTS / X-Content-Type-Options / Referrer-Policy / Permissions-Policy in Next.js config | — |
| `NET-002` | high | CORS `Access-Control-Allow-Origin: *`, `cors({ origin: '*' })`, origin reflection | ✅ specific origin |
| `NET-003` | high | TLS 1.0/1.1 in Nginx `ssl_protocols` | — |

### Database (2 rules)

| ID | Severity | What it detects | Auto-fix |
|---|---|---|---|
| `DB-001` | high | DB user with DROP / ALTER / GRANT / SUPERUSER | — |
| `DB-002` | high | Plain-text PII columns (`nationalId`, `creditCard`, `cvv`, `ssn`), DB connection without SSL | — |

### CI/CD & DevOps (3 rules)

| ID | Severity | What it detects | Auto-fix |
|---|---|---|---|
| `CI-001` | medium | Missing lockfile / audit script in `package.json` | — |
| `CI-002` | critical | Hardcoded secret — AWS key, Stripe key, GitHub PAT, JWT, private key | — |
| `CI-003` | medium | Dockerfile: no `USER`, `FROM :latest`, `ADD <URL>` | — |

### Observability (2 rules)

| ID | Severity | What it detects | Auto-fix |
|---|---|---|---|
| `OBS-001` | medium | PII in logs (`console.log(password)`), stack trace in HTTP response | — |
| `OBS-002` | medium | Missing `process.on('unhandledRejection')` / `uncaughtException` handler | — |

---

## Configuration

`.vibe-security.json`:

```json
{
  "rules": {
    "FE-006": { "enabled": false },
    "OBS-002": { "severity": "low" }
  },
  "ignore": ["**/vendor/**", "**/test/**"],
  "output": { "format": "sarif", "path": "vibe-security.sarif" },
  "baseline": ".vibe-security-baseline.json",
  "layers": ["backend", "database"]
}
```

---

## CI/CD

### GitHub Actions (SARIF + baseline)

```yaml
- run: npx -y github:korayda4/Vibe-Security scan . --format sarif --output vibe-security.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vibe-security.sarif }
```

Full example with baseline: [`examples/github-actions.yml`](examples/github-actions.yml).

### GitLab CI (JUnit)

```yaml
security-scan:
  script: npx -y github:korayda4/Vibe-Security scan . --format junit --output vibe-security.xml
  artifacts: { reports: { junit: vibe-security.xml } }
```

### Baseline strategy

```bash
# First run (main branch): snapshot all known findings
vibe-security scan . --update-baseline --no-fail

# Subsequent runs (PRs): show only new findings
vibe-security scan . --baseline .vibe-security-baseline.json
```

---

## MCP tools

Exposed to AI agents via Model Context Protocol:

| Tool | Purpose |
|---|---|
| `scan_project` | Full scan, writes Security.md, returns summary |
| `scan_file` | Single file scan (fast iteration) |
| `list_rules` | List all rules (filter by layer) |
| `get_rule_detail` | Get full description, threat, remediation for a rule |

---

## Compatibility

| Platform | Status |
|---|---|
| Claude Code (CLI) | ✅ |
| VS Code Anthropic Claude extension | ✅ |
| Cursor | ✅ |
| Continue.dev | ✅ |
| GitHub Copilot Workspace | ⚠️ MCP preview |
| Standalone CLI / CI | ✅ |

Requires Node.js 18+.

---

## Performance

| Project size | Time |
|---|---|
| 500 files | ~200 ms |
| 5,000 files | ~1.5 s |
| 50,000 files (monorepo) | ~15 s |

Memory footprint: ~80 MB at peak.

---

## Security of Vibe Security itself

- 0 npm audit vulnerabilities
- No external network calls — pure local scan
- No telemetry, no analytics, no data leaves your machine
- Source audited via self-scan
- See [`docs/VULNERABILITY_PRIORITY.md`](docs/VULNERABILITY_PRIORITY.md) for the security roadmap

---

## Development

```bash
git clone https://github.com/korayda4/Vibe-Security.git
cd Vibe-Security
npm install
npm run build
npm test         # 16 tests
npm start        # stdio MCP server
```

Add a new rule: [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

---

## Documentation

- [`ROADMAP.md`](ROADMAP.md) — phases, status, future plans
- [`docs/USAGE.md`](docs/USAGE.md) — every flag, every output format
- [`docs/TOKEN_SAFETY.md`](docs/TOKEN_SAFETY.md) — JWT, refresh tokens, sessions, rotation
- [`docs/VULNERABILITY_PRIORITY.md`](docs/VULNERABILITY_PRIORITY.md) — clusters by priority
- [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) — adding rules, code style

---

## License

MIT — see [`LICENSE`](LICENSE).
