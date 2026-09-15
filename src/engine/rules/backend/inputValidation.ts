import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-005',
  title: 'Mass assignment — input not validated against DTO',
  layer: 'backend',
  severity: 'high',
  description:
    '`req.body` veya `request.json()`\'i dogrudan ORM\'a vermek (prisma.user.create({ data: req.body })) mass assignment saldirisina aciktir. Saldirgan `role: "admin"`, `isAdmin: true`, `balance: 99999` gibi alanlari enjekte edebilir.',
  threat: 'Privilege escalation, data tampering, business logic bypass',
  remediation:
    '1) **Zod / Joi / class-validator** ile explicit DTO semasi tanimlayin. ' +
    '2) Schema\'da olmayan alanlari `.strict()` ile reddedin. ' +
    '3) Sadece schema\'da tanimli alanlari ORM\'a gecirin: `prisma.user.create({ data: parsed.data })`. ' +
    '4) `Object.assign(user, req.body)` veya spread `{...req.body, ...overrides}` yapilarindan kacinin. ' +
    '5) Default olarak tum update endpointleri "PUT yerine PATCH" ile alan-bazli olmali.',
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
