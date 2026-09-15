# Vibe Security Kullanim Kilavuzu

## Kurulum yollari

### A) GitHub repo'dan direkt (npm publish oncesi)

```json
{
  "mcpServers": {
    "vibe-security": {
      "command": "npx",
      "args": ["-y", "github:korayda4/Vibe-Security"]
    }
  }
}
```

Bu komut GitHub'daki son commit'i indirir, `npm install` calistirir, `dist/index.js`'i MCP server olarak baslatir. npm publish gerektirmez.

### B) npm'den (yayinlandiktan sonra)

```json
{
  "mcpServers": {
    "vibe-security": {
      "command": "npx",
      "args": ["-y", "vibe-security"]
    }
  }
}
```

### C) Lokal klon (gelistirme)

```json
{
  "mcpServers": {
    "vibe-security": {
      "command": "node",
      "args": ["/path/to/vibe-security/dist/index.js"]
    }
  }
}
```

## Slash command kurulumu

`npx -y github:korayda4/Vibe-Security init` projeye su dosyalari kopyalar:

- `.vibe-security.json` â€” config
- `.claude/commands/securityCheck.md` â€” Claude Code slash command
- `.vscode/settings.json` â€” VS Code Anthropic Claude extension MCP config
- `.github/instructions/security-check.instructions.md` â€” Copilot instructions

Sonra Claude Code veya VS Code'u yeniden baslatin (veya VS Code icin `Reload Window`).

## Hizli baslangic

```bash
# 1. Proje kokunde tarama yap
npx -y github:korayda4/Vibe-Security scan .

# 2. Sonuclari incele
cat Security.md

# 3. Auto-fix dene (dry-run)
npx -y github:korayda4/Vibe-Security scan . --fix --dry-run

# 4. CI icin SARIF
npx -y github:korayda4/Vibe-Security scan . --format sarif --output vibe-security.sarif
```

## Claude Code ile `/securityCheck`

`.claude/mcp_servers.json` yukle, sonra projede:

```
/securityCheck
/securityCheck --frontend
/securityCheck --fix
/securityCheck --rule BE-004
```

Argumanlar slash command tarafindan parse edilir ve MCP tool'una aktarilir.

## VS Code Anthropic Claude extension ile

`.vscode/settings.json` yukle, VS Code'u yeniden baslat, sonra:

1. Claude extension chat panelini ac
2. `/securityCheck` yaz
3. Sonuclar chat'te ve workspace kokunde `Security.md` olarak gelir

## CLI komutlari

### `scan`

```bash
vibe-security scan [path] [options]

Options:
  --format <markdown|json|sarif|junit|compact>
  --output, -o <path>
  --fix
  --dry-run
  --baseline <path>
  --update-baseline
  --layers <frontend,backend,network,database,cicd,observability>
  --rules <FE-001,BE-004>
  --watch, -w
  --no-fail
```

### `list`

26 kuralin tamamini ID, severity, layer ile listeler.

### `init`

`.vibe-security.json` + slash command + VS Code / Copilot instructions dosyalarini projeye kopyalar.

### `baseline update`

Mevcut tum bulgulari baseline'a yazar.

## Config dosyasi

`.vibe-security.json`:
```json
{
  "rules": {
    "OBS-002": { "severity": "low" },
    "FE-006": { "enabled": false }
  },
  "ignore": ["**/vendor/**", "**/test/**"],
  "output": {
    "format": "sarif",
    "path": "vibe-security.sarif"
  },
  "baseline": ".vibe-security-baseline.json",
  "autoFix": false
}
```

## CI/CD

### GitHub Actions

```yaml
- run: npx -y github:korayda4/Vibe-Security scan . --format sarif --output vibe-security.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vibe-security.sarif }
```

`examples/github-actions.yml`'da baseline + diff + SARIF upload tam ornegi var.

### GitLab CI

```yaml
security-scan:
  script:
    - npx -y github:korayda4/Vibe-Security scan . --format junit --output vibe-security.xml
  artifacts:
    reports:
      junit: vibe-security.xml
```

### Baseline stratejisi

```bash
# Ilk kurulumda (main branch push'unda)
vibe-security scan . --update-baseline --no-fail

# Sonraki taramalarda (PR'larda)
vibe-security scan . --baseline .vibe-security-baseline.json
# Sadece yeni bulgulari raporlar
```

## MCP tools (AI ajanlari icin)

| Tool | Aciklama |
| --- | --- |
| `scan_project` | Tum projeyi tara, ozet + Security.md |
| `scan_file` | Tek dosya tarama |
| `list_rules` | Tum kurallari listele |
| `get_rule_detail` | Bir kuralin tam detaylari |

## False positive?

`.vibe-security.json`:
```json
{ "rules": { "FE-006": { "enabled": false } } }
```

## Performans

- ~500 dosyalik orta olcekli proje: ~200ms
- Buyuk monorepo (10K+ dosya): ~3s
- Watch modu: 3s polling

## Bilinen sinirlar

- Regex-based â€” bazi durumlarda AST daha iyi olurdu
- TypeScript JSX sema analizi yok
- Go/Python'da bazi kurallar icin ornek pattern az
- Tarayici extension / Service Worker context'leri taranmaz
