# Vibe Security'a Katki Rehberi

AI Vibe Coder ekosistemi icin ortak bir security katmani insa ediyoruz. PR'lar, yeni kurallar, kural iyilestirmeleri ve dil destegi cok degerli.

## Yeni kural ekleme

En etkili katki: yeni bir guvenlik kurali.

### 1. Kural dosyasi

Uygun katman altinda:

```
src/engine/rules/<katman>/<konu>.ts
```

Mevcut katmanlar: `frontend`, `backend`, `network`, `database`, `cicd`, `observability`.

### 2. Kural sablonu

```typescript
import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'XX-NNN',                         // Katman kodu + uc hane
  title: 'Kisa, anlasilir baslik',
  layer: 'frontend',
  severity: 'high',
  description: 'Zaafiyetin ne oldugunu acikla (1-2 cumle).',
  threat: 'Saldiri vektoru ve olasilik (1 cumle).',
  remediation: 'Adim adim fix talimati (numarali).',
  references: [
    'https://owasp.org/...',
  ],
  cwe: 'CWE-XXX',
  owasp: 'A0X:2021 ...',
  languages: ['typescript', 'javascript'],

  check: (ctx) => {
    const findings = [];
    for (const m of ctx.source.matchAll(/senin-regex/g)) {
      if (m.index === undefined) continue;
      const { line } = lineColumnFromIndex(ctx.source, m.index);
      findings.push({
        id: `${rule.id}-${ctx.relativePath}-${line}`,
        ruleId: rule.id,
        title: rule.title,
        layer: rule.layer,
        severity: rule.severity,
        file: ctx.relativePath,
        match: { snippet: snippetAt(ctx.source, line), line, column: m.index },
        description: rule.description,
        impact: rule.threat,
        remediation: rule.remediation,
        references: rule.references,
        cwe: rule.cwe,
        owasp: rule.owasp,
        fix: {                              // Opsiyonel auto-fix
          find: 'eski kod',
          replace: 'yeni kod',
          description: 'Bu ne yapar',
        },
      });
    }
    return findings;
  },
};

export default rule;
```

### 3. Kayit

`<katman>/index.ts`'e ekleyin:

```typescript
import yeniKural from './yeni-konu.js';

export const rules = {
  // ...mevcut kurallar
  yeniKural,
};
```

### 4. Test

1. `test/fixtures/vulnerable-app/` altinda kuralinizi tetikleyen bir ornek ekleyin
2. `test/test.ts`'e bir assertion ekleyin
3. `npm test` ile dogrulayin

## PR checklist

- [ ] Kural calistirildiginda false positive uretmiyor (en azindan yaygin pattern'lerde)
- [ ] Severity, layer ve languages dogru ayarlanmis
- [ ] Description, threat, remediation anlasilir Turkce/Ingilizce
- [ ] Referanslar (OWASP, CWE, resmi docs) eklenmis
- [ ] Auto-fix varsa, `--fix --dry-run` ile dosyayi degistirmedigi dogrulanmis
- [ ] Yeni test fixture + assertion eklenmis
- [ ] `npm test` ve `npm run lint` temiz

## Gelistirme ortami

```bash
npm install
npm run dev      # tsc --watch
npm test         # test runner
node dist/cli.js scan .   # manual tarama
```

## Code style

- TypeScript strict mode
- ESM modulleri (`.js` extension'lari ile)
- Functional, yan etkisiz kurallar (sadece `check` fonksiyonu)
- Her kural izole, bagimsiz test edilebilir
- CWE ve OWASP referansi zorunlu

## Iletisim

- Issues: GitHub Issues
- Discussions: GitHub Discussions
- Discord: (yakinda)

Lisans: MIT â€” katkilarinizla proje yeserir.
