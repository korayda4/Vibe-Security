# Vibe Security Implementation Plan / Roadmap

Bu dokuman Vibe Security projesinin **neyi**, **niye**, **hangi sira ile** yaptigini belgeler. Token safety ve tum guvenlik islevleri bu plana gore insa edilir.

## Vizyon

AI Vibe Coder'lar icin **varsayilan secenek** haline gelen bir security katmani. Claude Code veya VS Code Anthropic Claude extension'a `/securityCheck` yazildiginda otomatik devreye giren, hatalari acikca soyleyen ve duzelten bir "guvenlik muhendisi skill" i.

**Temel prensip:** AI sadece Claude tarafinda zaten var â€” biz kural motoru + context + fix ureteciyiz. AI'in verdigi yanlislari yakalayan, dogrulari oneren bir "guvenlik uzmanligi modulu."

## Tasarim kararlari

| Karar | Tercih | Gerekce |
|---|---|---|
| External API kullan | âŒ Hayir | AI Claude tarafinda zaten var, ek API = ek bagimlilik + ucret |
| MCP server olarak calis | âœ… Evet | Claude Code / VS Code extension dogal destegi |
| Regex-based scanner | âœ… MVP | Hizli, deterministic, kolay genisletilebilir |
| AST-based scanner | Faz 3 | False positive'leri azaltmak icin |
| Multi-language destegi | âœ… Evet | JS/TS, Python, Java, Go â€” buyuk kitle |
| Custom rule DSL | Faz 3 | Topluluk katkilari icin |

## Faz durumlari

### Faz 1 â€” Core MVP âœ… TAMAMLANDI
**Hedef:** Calisan bir MCP server, temel guvenlik kontrolleri.

| Ozellik | Durum |
|---|---|
| MCP stdio server (4 tool) | âœ… |
| 26 kural, 6 katman | âœ… |
| Multi-language (JS/TS, Python, Java, Go) | âœ… |
| File walker + language detection | âœ… |
| Security.md reporter | âœ… |
| CLI (`scan`, `list`) | âœ… |
| 16/16 unit test | âœ… |
| MCP stdio smoke test | âœ… |

### Faz 2 â€” Ecosystem-ready âœ… TAMAMLANDI
**Hedef:** Gercek projelerde kullanilabilir, CI/CD entegre edilebilir.

| Ozellik | Durum |
|---|---|
| `/securityCheck` slash command (Claude Code) | âœ… |
| VS Code Anthropic Claude extension config | âœ… |
| GitHub-direct install (`npx -y github:...`) | âœ… |
| `vibe-security init` komutu | âœ… |
| Auto-fix engine (FE-001, FE-004, NET-002) | âœ… |
| `--fix` / `--dry-run` modlari | âœ… |
| SARIF output (GitHub Code Scanning) | âœ… |
| JSON / JUnit / Compact output | âœ… |
| `.vibe-security.json` config (rule disable, severity override, ignore) | âœ… |
| Baseline / diff mode | âœ… |
| Watch mode (polling) | âœ… |
| Token safety kurallari (BE-003, BE-008, BE-009, FE-002) | âœ… |

### Faz 3 â€” Quality & Scale (sonraki iterasyon)
**Hedef:** False positive azaltma, daha akilli tespit, topluluk katkilari.

| Ozellik | Oncelik | Notlar |
|---|---|---|
| tree-sitter entegrasyonu (AST-based) | YÃ¼ksek | Regex yerine gercek syntax agaci |
| TypeScript JSX sema analizi | YÃ¼ksek | XSS tespitinde data-flow |
| Data-flow analysis (taint tracking) | YÃ¼ksek | Source-to-sink takibi ile SQLi / XSS kesin tespit |
| Custom rule DSL (JSON/YAML) | Orta | Topluluk kendi kurallarini ekleyebilsin |
| Inline ignore: `// vibe-security-disable-next-line RULE_ID` | Orta | False positive suppression |
| SARIF baseline mode (sadece yeni bulgular GitHub'a) | Orta | CI entegrasyonu kolaylastirir |
| HTML / PDF / docx report | DÃ¼ÅŸÃ¼k | Alternatif formatlar |
| Plugin sistemi (npm paket olarak kurallar) | DÃ¼ÅŸÃ¼k | Topluluk ekosistemi |

### Faz 4 â€” AI-Augmented (uzun vade)
**Hedef:** Statik kurallarin otesine gecmek.

| Ozellik | Oncelik | Notlar |
|---|---|---|
| Claude-driven deep analysis (opsiyonel) | DÃ¼ÅŸÃ¼k | Kullanici isterse MCP tool olarak "explain" cagirilabilir |
| Auto-fix patch validation (test calistirma) | DÃ¼ÅŸÃ¼k | Fix sonrasi test kosmak |
| Pull request automation | DÃ¼ÅŸÃ¼k | Bulgu + fix'i otomatik PR acma |
| Multi-repo org-wide tarama | DÃ¼ÅŸÃ¼k | Monorepo + birden fazla repo |

## Her fazda token safety

Token guvenligi **surekli odak noktasi**. Her fazda:

- **Faz 1:** JWT (BE-003), localStorage token (FE-002) â€” temel
- **Faz 2:** URL'de token (BE-008), uzun omurlu token (BE-009) â€” genis kapsam
- **Faz 3:** Data-flow ile token leak tespiti (env â†’ log, response â†’ log)
- **Faz 4:** OAuth refresh token rotation, secret manager entegrasyonu kontrolu

Detayli token guvenligi: [`docs/TOKEN_SAFETY.md`](docs/TOKEN_SAFETY.md)

## Katki sureci

Topluluk katkilari `docs/CONTRIBUTING.md`'da belgelenen yontemle yapilir:

1. Yeni kural PR'i (en yaygin katki)
2. Mevcut kural iyilestirme (false positive azaltma)
3. Yeni dil destegi (ornek: Rust, Ruby)
4. DokÃ¼man / ornek

Her PR `npm test` + `npm run lint` gecmek zorunda.

## Olcum hedefleri

| Metrik | Hedef | Durum |
|---|---|---|
| False positive orani (bilinen proje) | < %10 | â³ |
| Tarama hizi (1000 dosya) | < 1s | â³ |
| Kural sayisi | 30+ | â³ |
| Desteklenen dil | 4+ | âœ… (JS/TS, Python, Java, Go) |
| Test coverage | > %80 | â³ |
| CI'da kullanici sayisi | 100+ | â³ |

## Lisans & yonetim

- MIT lisans
- Koray Demir tarafindan baslatildi
- Topluluk katkilari PR ile
- Guvenlik acigi bildirimi: security@korayda4.dev (ornek)

---

**Son guncelleme:** 2026-09-15 â€” Faz 2 tamamlandi, Faz 3 icin 5 PR backlog hazir.
