import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'NET-002',
  title: 'Overly permissive CORS (wildcard or origin reflection)',
  layer: 'network',
  severity: 'high',
  description:
    '`Access-Control-Allow-Origin: *` veya gelen `Origin` header\'inin dogrudan yansitilmasi, baska origin\'lerin API\'nize erismesine izin verir. Kimlik bilgisi (credentials) ile birlikteyse cross-origin veri hirsizligina yol acar.',
  threat: 'Cross-origin data theft, CSRF, credential exfiltration',
  remediation:
    '1) Wildcard (`*`) KULLANMAYIN. ' +
    '2) Explicit bir whitelist tanimlayin: `const allowed = [\'https://app.example.com\', \'https://admin.example.com\']`. ' +
    '3) Origin kontrolu yapip eslesiyorsa `Access-Control-Allow-Origin: <specific-origin>` donun. ' +
    '4) Credentials ile birlikte `*` ASLA calismaz; gerekirse `Access-Control-Allow-Credentials: true` + explicit origin use. ' +
    '5) Preflight icin `Access-Control-Allow-Methods` ve `Access-Control-Allow-Headers`\'i da kisitlayin. ' +
    '6) Express: `cors({ origin: allowed, credentials: true })`.',
  references: [
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
    'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing',
  ],
  cwe: 'CWE-942',
  owasp: 'A05:2021 Security Misconfiguration',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const isServerFile =
      /(?:server|app|main|index)\.(?:ts|js|tsx|jsx|mjs|cjs)$/i.test(ctx.relativePath) ||
      /\/api\//i.test(ctx.relativePath) ||
      /routes?\//i.test(ctx.relativePath);

    if (!isServerFile) return [];

    const findings = [];
const wildcard = /Access-Control-Allow-Origin['"`\s]*,?\s*['"`]\*['"`]/gi;
    for (const m of ctx.source.matchAll(wildcard)) {
      if (m.index === undefined) continue;
      const { line } = lineColumnFromIndex(ctx.source, m.index);
      findings.push({
        id: `${rule.id}-${ctx.relativePath}-${line}-w`,
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
        fix: {
          find: m[0],
          replace: m[0].replace(/['"`]\*['"`]/, "'https://yourdomain.com'"),
          description: 'Wildcard yerine explicit origin whitelist kullan (kendi domain\'ini yaz)',
        },
      });
    }
const reflect = /origin\s*:\s*req\.headers\.origin/g;
    for (const m of ctx.source.matchAll(reflect)) {
      if (m.index === undefined) continue;
      const { line } = lineColumnFromIndex(ctx.source, m.index);
      findings.push({
        id: `${rule.id}-${ctx.relativePath}-${line}-r`,
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
const corsOrigin = /origin\s*:\s*['"`]\*['"`]/g;
    for (const m of ctx.source.matchAll(corsOrigin)) {
      if (m.index === undefined) continue;
      const { line } = lineColumnFromIndex(ctx.source, m.index);
      findings.push({
        id: `${rule.id}-${ctx.relativePath}-${line}-c`,
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
        fix: {
          find: "origin: '*'",
          replace: "origin: ['https://yourdomain.com']",
          description: 'cors()\'a whitelist array\'i ver',
        },
      });
    }

    return findings;
  },
};

export default rule;
