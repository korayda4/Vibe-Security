import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'FE-005',
  title: 'Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)',
  layer: 'frontend',
  severity: 'medium',
  description:
    'HTTP response\'unda `X-Frame-Options` veya `Content-Security-Policy: frame-ancestors` direktifi yoksa sayfa saldirgan kontrolundeki bir iframe icinde acilabilir. UI Redressing (clickjacking) ile kullanici istemedigi islemleri yaptirilabilir.',
  threat: 'UI redressing, clickjacking → unauthorized clicks (payment, settings change)',
  remediation:
    'Tum HTML response\'larina sunlardan birini ekleyin: ' +
    '`Content-Security-Policy: frame-ancestors \'none\'` (en guclu, modern), veya ' +
    '`X-Frame-Options: DENY` (eski browser destegi). ' +
    'Sadece kendi origin\'inizden iframe kabul edecekseniz: `frame-ancestors \'self\'`. ' +
    'Next.js: middleware veya `next.config.js` headers\'tan ayarlayin. Nginx: `add_header X-Frame-Options "DENY" always;`.',
  references: [
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
    'https://owasp.org/www-community/attacks/Clickjacking',
  ],
  cwe: 'CWE-1021',
  owasp: 'A05:2021 Security Misconfiguration',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const isConfig =
      /next\.config\.(js|mjs|ts)$/i.test(ctx.relativePath) ||
      /vercel\.json$/i.test(ctx.relativePath) ||
      /_headers$/i.test(ctx.relativePath) ||
      /nginx\.conf$/i.test(ctx.relativePath) ||
      /server\.ts$/i.test(ctx.relativePath) ||
      /server\.js$/i.test(ctx.relativePath);

    if (!isConfig) return [];

    const hasFrameAncestors = /frame-ancestors\s+/i.test(ctx.source);
    const hasXFrameOptions = /X-Frame-Options\s*:/i.test(ctx.source);

    if (hasFrameAncestors || hasXFrameOptions) return [];

    const findings = [];
    findings.push(...grepRule(rule, ctx, /\basync\s+headers\s*\(/g));
    return findings;
  },
};

export default rule;
