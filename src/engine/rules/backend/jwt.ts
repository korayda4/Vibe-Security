import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-003',
  title: 'Insecure JWT configuration (alg: none / weak secret / no verify)',
  layer: 'backend',
  severity: 'critical',
  description:
    'JWT token uretimi veya dogrulamasi yapilirken `alg: none`, zayif HMAC secret, hardcoded secret veya `verify` atlama gibi hatalar yapildiginda saldirgan imzayi atlayip kendi token\'ini uretebilir.',
  threat: 'Authentication bypass → full account takeover',
  remediation:
    '1) **Asla `alg: none`** kullanmayin; her zaman explicit `algorithms: [\'RS256\']` veya `[\'HS256\']` whitelist edin. ' +
    '2) HMAC secret\'i en az 256-bit (32 byte) random uretin, **asla** commit\'lemeyin. Asimetrik (RS256/ES256) tercih edin. ' +
    '3) `jwt.verify()` her zaman cagirin, payload\'i dogrudan kabul etmeyin. ' +
    '4) `exp`, `iss`, `aud` claim\'lerini dogrulayin. ' +
    '5) Access token\'i 15 dakika ile sinirlayin, refresh token icin rotation + revocation store kullanin. ' +
    '6) `Authorization: Bearer` basligini okuyun, query string\'de token tasimalarini reddedin.',
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
    'https://datatracker.ietf.org/doc/html/rfc8725',
    'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
  ],
  cwe: 'CWE-347',
  owasp: 'A02:2021 Cryptographic Failures',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const patterns: RegExp[] = [
      /algorithm\s*[:=]\s*['"`]none['"`]/gi,
      /algorithms\s*:\s*\[\s*['"`]none['"`]\s*\]/g,
      /jwt\.sign\s*\([^)]*['"`\s]none['"`\s]/gi,
      /jwt\.decode\s*\([^)]*\)/g, // decode without verify
      /['"`]secret['"`]\s*[:=]\s*['"`][a-zA-Z0-9_\-]{1,31}['"`]/g, // short hardcoded secret
      /JWT_SECRET\s*[:=]\s*['"`][^'"`\n]{1,15}['"`]/g,
      /verify\s*:\s*false/gi,
      /verify=False/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
