import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'FE-002',
  title: 'Insecure cookie attributes (HttpOnly / Secure / SameSite)',
  layer: 'frontend',
  severity: 'high',
  description:
    'JWT, session, or sensitive tokens set via document.cookie or via Set-Cookie without HttpOnly / Secure / SameSite flags can be stolen via XSS or MITM.',
  threat: 'Session hijacking, token theft, account takeover',
  remediation:
    'Set sensitive cookies server-side with HttpOnly (blocks JS), Secure (HTTPS-only), SameSite=Lax or Strict (CSRF mitigation). ' +
    'Store tokens in server-side cookies, not localStorage or sessionStorage. ' +
    "Avoid document.cookie for reading or writing tokens in the frontend.",
  references: [
    'https://owasp.org/www-community/HttpOnly',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies',
    'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
  ],
  cwe: 'CWE-1004',
  owasp: 'A07:2021 Identification and Authentication Failures',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const findings = [];
    const patterns: RegExp[] = [
      /document\.cookie\s*=/g,
      /Set-Cookie\s*:\s*[^;\n]+(?![;\n]*HttpOnly)/gi,
      /localStorage\.setItem\s*\(\s*['"][^'"]*(token|jwt|session|auth|api[_-]?key)/gi,
      /sessionStorage\.setItem\s*\(\s*['"][^'"]*(token|jwt|session|auth|api[_-]?key)/gi,
    ];

    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
