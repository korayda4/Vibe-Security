import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-005',
  title: 'Mass assignment — input not validated against DTO',
  layer: 'backend',
  severity: 'high',
  description:
    'Passing `req.body` or `request.json()` directly to the ORM (e.g. `prisma.user.create({ data: req.body })`) is open to mass-assignment attacks. Attackers can inject fields such as `role: "admin"`, `isAdmin: true`, or `balance: 99999`.',
  threat: 'Privilege escalation, data tampering, business logic bypass',
  remediation:
    '1) Define an explicit DTO schema with **Zod / Joi / class-validator**. ' +
    '2) Reject any field not in the schema via `.strict()`. ' +
    '3) Pass only the validated fields to the ORM: `prisma.user.create({ data: parsed.data })`. ' +
    '4) Avoid patterns like `Object.assign(user, req.body)` or spreads `{...req.body, ...overrides}`. ' +
    '5) Update endpoints should default to PATCH (per-field) instead of PUT (full replace).',
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html',
    'https://zod.dev/',
  ],
  cwe: 'CWE-915',
  owasp: 'A04:2021 Insecure Design',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/\.(?:create|update|upsert)\s*\(\s*\{\s*data\s*:\s*(?:req\.body|request\.body|request\.json\(\)|input|body)/gi,
      /\.(?:create|update|upsert)\s*\(\s*(?:req\.body|request\.body|request\.json\(\)|input|body)\b/gi,
/@ModelAttribute\s+\w+\s+\w+/g,
/(?:ModelForm|form\.save)\(\)/g,
/c\.BindJSON\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
