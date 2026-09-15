import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-003',
  title: 'Insecure JWT configuration (alg: none / weak secret / no verify)',
  layer: 'backend',
  severity: 'critical',
  description:
    'When JWT tokens are issued or verified with mistakes such as `alg: none`, a weak HMAC secret, a hardcoded secret, or skipped verification, attackers can bypass the signature and forge their own tokens.',
  threat: 'Authentication bypass -- full account takeover',
  remediation:
    '1) **Never use `alg: none`**; always whitelist an explicit `algorithms: [\'RS256\']` or `[\'HS256\']`. ' +
    '2) Generate HMAC secrets with at least 256 bits (32 bytes) of randomness and **never** commit them. Prefer asymmetric algorithms (RS256/ES256). ' +
    '3) Always call `jwt.verify()`; never trust a decoded payload directly. ' +
    '4) Validate the `exp`, `iss`, and `aud` claims. ' +
    '5) Limit access tokens to ~15 minutes; use rotation + a revocation store for refresh tokens. ' +
    '6) Read tokens from the `Authorization: Bearer` header; reject tokens passed via query string.',
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
