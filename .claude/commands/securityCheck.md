---
description: Run Vibe Security scan on the current project and report findings
---

Bu projeyi gÃ¼venlik aÃ§Ä±sÄ±ndan tara.

AÅŸaÄŸÄ±daki araÃ§larÄ± (MCP tools) sÄ±rayla kullan:

1. **`mcp__vibe-security__scan_project`** â€” TÃ¼m projeyi tara. `rootDir` parametresini geÃ§erli Ã§alÄ±ÅŸma dizinine ayarla.
2. EÄŸer kullanÄ±cÄ± argÃ¼man verdiyse (`$ARGUMENTS`):
   - `--frontend` / `--backend` / `--network` / `--database` / `--cicd` / `--observability` â†’ `layers` parametresini filtrele
   - `--fix` â†’ bulgular iÃ§in auto-fix patch Ã¶nerisi istemek Ã¼zere `mcp__vibe-security__get_rule_detail` ile kural detaylarÄ±nÄ± Ã§ek, kullanÄ±cÄ±ya uygulama planÄ± sun
   - `--baseline` â†’ `mcp__vibe-security__scan_project` Ã§Ä±ktÄ±sÄ±nÄ± mevcut baseline ile karÅŸÄ±laÅŸtÄ±r, sadece yenileri raporla
   - `--rule <id>` â†’ sadece o kuralÄ± Ã§alÄ±ÅŸtÄ±r (`ruleIds` parametresi)
   - `--json` â†’ JSON Ã§Ä±ktÄ± iste, tablo formatÄ± kullanma

3. BulgularÄ± **kritik â†’ yÃ¼ksek â†’ orta â†’ dÃ¼ÅŸÃ¼k** sÄ±rasÄ±yla Ã¶zetle.
4. **Ä°lk 3 bulgu** iÃ§in somut fix Ã¶nerisi yaz (kod Ã¶rneÄŸi ile).
5. Security.md dosyasÄ± zaten MCP tarafÄ±ndan yazÄ±ldÄ±. KullanÄ±cÄ±ya dosya yolunu ve toplam bulgu sayÄ±sÄ±nÄ± gÃ¶ster.

Yapma:
- BulgularÄ± gizleme veya kÃ¼Ã§Ã¼mseme.
- Emin olmadÄ±ÄŸÄ±n fix Ã¶nerisi verme; bunun yerine kuralÄ±n dokÃ¼mantasyonuna yÃ¶nlendir.
- Scan Ã§alÄ±ÅŸtÄ±rmadan Ã¶nce kullanÄ±cÄ±ya soru sorma; doÄŸrudan tara.
