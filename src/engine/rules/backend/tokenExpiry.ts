import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-009',
  title: 'Long-lived token — missing or excessive expiry',
  layer: 'backend',
  severity: 'high',
  description:
    'JWT access token\'larinda `expiresIn` claim yoksa veya asiri uzunsa (30 gun+) token sizdirildiginda sonsuza kadar gecerli kalir. Ayni sekilde session cookie maxAge > 24 saat veya "remember me" tarzi kalici oturumlar kontrolsuzse saldırganin eline gecmis token ile yapacagi hasar sinirsiz olur.',
  threat:
    'Stolen token remains valid indefinitely → no logout, no password reset can revoke access',
  remediation:
    '1) **Access token** icin `expiresIn: \'15m\'` veya daha kisa (5m). ' +
    '2) **Refresh token** icin 7-30 gun + her kullanimda rotation + revocation store (Redis). ' +
    '3) `jwt.sign()`\'de mutlaka `expiresIn` veya `exp` belirt, default davranisa guvenme. ' +
    '4) `jwt.verify()`\'de `maxAge` veya explicit `exp` kontrolu yap. ' +
    '5) `req.session.cookie.maxAge` 24 saatten fazla olmasin. ' +
    '6) "Remember me" icin ayri, rotation\'lu, revocation\'lu token uret. ' +
    '7) Tum sizdirilmis token\'lar icin blacklist / revocation list tut.',
  references: [
    'https://datatracker.ietf.org/doc/html/rfc8725#section-3.12',
    'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-expiration',
    'https://auth0.com/docs/secure/tokens/access-tokens/access-token-lifetime',
  ],
  cwe: 'CWE-613',
  owasp: 'A07:2021 Identification and Authentication Failures',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const findings = [];
const longExpiry = [
      /expiresIn\s*:\s*['"`](?:30d|60d|90d|365d|1y|'none'|"none"|0|null|undefined)['"`]/gi,
      /expiresIn\s*:\s*['"`]\d{4,}\s*d['"`]/gi, // >999 gun
      /jwt\.sign\s*\([^)]*\)\s*;(?![^]*expiresIn)/g, // expiresIn yok
      /pyjwt\.encode\s*\([^)]*\)\s*(?![^]*exp)/g,
      /new\s+UnsecuredJWT\s*\([^)]*\)/g,
    ];

    for (const re of longExpiry) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-e`,
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
        });
      }
    }
const longSession = [
      /maxAge\s*:\s*\d{2,}\s*\*\s*60\s*\*\s*60\s*\*\s*1000/g, // > 24 saat
      /cookie\s*:\s*\{[^}]*maxAge\s*:\s*\d{8,}/g, // cok buyuk sayi (ms olarak)
    ];

    for (const re of longSession) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-s`,
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
        });
      }
    }

    return findings;
  },
};

export default rule;
