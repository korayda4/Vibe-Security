import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'NET-001',
  title: 'Missing HTTP security headers (CSP, HSTS, nosniff, referrer-policy, permissions-policy)',
  layer: 'network',
  severity: 'medium',
  description:
    'HTTP response\'larinda `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` veya `Permissions-Policy` basliklari yoksa tarayici tabanli saldiri yuzeyi acilir: XSS, MIME sniffing, bilgi sizintisi, yetenek istismari.',
  threat: 'XSS escalation, MIME sniffing, MITM downgrade, information leakage, feature abuse',
  remediation:
    'Asagidaki header\'lari TUM response\'lara ekleyin: ' +
    '`Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'` ' +
    '`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` ' +
    '`X-Content-Type-Options: nosniff` ' +
    '`Referrer-Policy: strict-origin-when-cross-origin` ' +
    '`Permissions-Policy: camera=(), microphone=(), geolocation=()` ' +
    'Next.js: `next.config.js` headers; Nginx: `add_header ... always`; Express: `helmet()` middleware\'i.',
  references: [
    'https://owasp.org/www-project-secure-headers/',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers',
    'https://securityheaders.com/',
    'https://helmetjs.github.io/',
  ],
  cwe: 'CWE-693',
  owasp: 'A05:2021 Security Misconfiguration',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const isConfig =
      /next\.config\.(js|mjs|ts)$/i.test(ctx.relativePath) ||
      /vercel\.json$/i.test(ctx.relativePath) ||
      /_headers$/i.test(ctx.relativePath) ||
      /server\.(ts|js)$/i.test(ctx.relativePath) ||
      /nginx\.conf$/i.test(ctx.relativePath) ||
      /middleware\.(ts|js)$/i.test(ctx.relativePath);

    if (!isConfig) return [];

    const requiredHeaders = [
      'content-security-policy',
      'strict-transport-security',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy',
    ];

    const missing = requiredHeaders.filter(
      (h) => !new RegExp(h, 'i').test(ctx.source)
    );

    if (missing.length === 0) return [];
const findings = [];
    const re = /headers\s*\(\s*\)\s*[:=]/g;
    findings.push(...grepRule(rule, ctx, re));
    return findings;
  },
};

export default rule;
