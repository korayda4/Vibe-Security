import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-009',
  title: 'Long-lived token — missing or excessive expiry',
  layer: 'backend',
  severity: 'high',
  description:
    'JWT access tokens with no `expiresIn` claim, or with excessively long lifetimes (30+ days), remain valid forever once leaked. The same goes for session cookies with `maxAge > 24h` or uncontrolled "remember me" tokens -- a stolen token can then cause unlimited damage.',
  threat:
    'Stolen token remains valid indefinitely -- no logout, no password reset can revoke access',
  remediation:
    '1) For **access tokens** use `expiresIn: \'15m\'` or shorter (5m). ' +
    '2) For **refresh tokens** use 7-30 days + rotation on every use + a revocation store (Redis). ' +
    '3) Always specify `expiresIn` (or `exp`) in `jwt.sign()` -- never rely on the library default. ' +
    '4) In `jwt.verify()`, enforce `maxAge` or an explicit `exp` check. ' +
    '5) Keep `req.session.cookie.maxAge` under 24 hours. ' +
    '6) For "Remember me", issue a separate token with rotation and revocation. ' +
    '7) Maintain a blacklist / revocation list for any leaked tokens.',
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
