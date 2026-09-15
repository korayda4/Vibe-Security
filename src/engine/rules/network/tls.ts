import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'NET-003',
  title: 'Insecure transport — TLS downgrade or missing HTTPS enforcement',
  layer: 'network',
  severity: 'high',
  description:
    'TLS 1.0/1.1 destegi aciksa veya HTTP→HTTPS yonlendirmesi yoksa, ag seviyesi MITM saldirilari ile hassas veri sizdirilabilir.',
  threat: 'Man-in-the-middle, credential interception, session theft',
  remediation:
    '1) TLS 1.2+ zorunlu tutun; TLS 1.0/1.1\'i devre disi birakin. ' +
    '2) `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. ' +
    '3) Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. ' +
    '4) Tum HTTP isteklerini 301 ile HTTPS\'e yonlendirin. ' +
    '5) Sertifika otomasyonu icin Let\'s Encrypt + certbot veya cloud provider ACM kullanin. ' +
    '6) HSTS preload listesi icin basvuru yapin.',
  references: [
    'https://wiki.mozilla.org/Security/Server_Side_TLS',
    'https://datatracker.ietf.org/doc/html/rfc6797',
  ],
  cwe: 'CWE-319',
  owasp: 'A02:2021 Cryptographic Failures',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const isConfig =
      /nginx\.conf$/i.test(ctx.relativePath) ||
      /next\.config\.(js|mjs|ts)$/i.test(ctx.relativePath) ||
      /server\.(ts|js)$/i.test(ctx.relativePath);

    if (!isConfig) return [];

    const findings = [];
const tlsPattern = /ssl_protocols\s+([^;\n]+)/g;
    for (const m of ctx.source.matchAll(tlsPattern)) {
      if (m[1] && /TLSv1\.0|TLSv1\.1|SSLv[23]/.test(m[1])) {
        findings.push(...grepRule(rule, ctx, tlsPattern));
        break;
      }
    }
    return findings;
  },
};

export default rule;
