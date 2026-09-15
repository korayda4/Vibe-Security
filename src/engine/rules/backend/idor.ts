import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-001',
  title: 'Potential IDOR / BOLA — ownership not verified',
  layer: 'backend',
  severity: 'high',
  description:
    'On endpoints like `GET /api/resource/:id` or `app.get(\'/users/:id\')`, even when the ID\'s existence is checked, the code never verifies that the requesting user is the actual owner of that resource. Attackers can therefore access other users\' data (BOLA -- Broken Object Level Authorization, OWASP API #1).',
  threat: 'Unauthorized data access -- account takeover, data breach, privacy violation',
  remediation:
    'Before returning any resource, add an ownership check on the server side: ' +
    '`await db.resource.findFirst({ where: { id, ownerId: session.userId } })`. ' +
    'Or use a policy-based authorization layer (CASL, Oso, Cerbos). ' +
    'Fetching with only `findUnique({ where: { id } })` is INSUFFICIENT. ' +
    'Always include `ownerId` in the `where` filter of list endpoints. ' +
    'Monitor anomalies via audit logs.',
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
