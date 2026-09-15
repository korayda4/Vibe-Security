import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-001',
  title: 'Potential IDOR / BOLA — ownership not verified',
  layer: 'backend',
  severity: 'high',
  description:
    '`GET /api/resource/:id`, `app.get(\'/users/:id\')` gibi endpoint\'lerde, ID\'nin varligi kontrol edilse bile o kaynagin gercek sahibinin istegi yapan kullanici olup olmadigi sorgulanmiyor. Saldirgan baska kullanicilarin verilerine erisebilir (BOLA — Broken Object Level Authorization, OWASP API #1).',
  threat: 'Unauthorized data access → account takeover, data breach, privacy violation',
  remediation:
    'Her resource erisiminden once sunucu tarafinda suni sorgu ekleyin: ' +
    '`await db.resource.findFirst({ where: { id, ownerId: session.userId } })`. ' +
    'Ya da policy tabanli bir authz katmani kullanin (CASL, Oso, cerbos). ' +
    'Sadece `findUnique({ where: { id } })` ile cekmek YETERSIZ. ' +
    'Listeleme endpoint\'lerinde `where` filtresine her zaman `ownerId` ekleyin. ' +
    'Audit log ile anomalileri izleyin.',
  references: [
    'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
    'https://owasp.org/www-project-api-security/',
  ],
  cwe: 'CWE-639',
  owasp: 'A01:2021 Broken Access Control',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
// This is a coarse heuristic — false positives are accepted in static analysis.
    const suspiciousPatterns: RegExp[] = [
      /findUnique\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*[:=]/g,
      /findFirst\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*[:=]/g,
      /findOne\s*\(\s*\{\s*where\s*:\s*\{\s*id\s*[:=]/gi,
      /findByPk\s*\(/g,
      /getById\s*\(/g,
      /\.find\s*\(\s*\{\s*id\s*[:=]/g,
    ];

    const findings = [];
    for (const re of suspiciousPatterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
