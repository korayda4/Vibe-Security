import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-004',
  title: 'SQL / NoSQL injection via string concatenation',
  layer: 'backend',
  severity: 'critical',
  description:
    'When SQL queries or NoSQL filters are built via string concatenation or template literals, user input can be injected into the query structure. ' +
    'Examples: `query: "SELECT * FROM users WHERE id = " + req.params.id` or `db.users.find({ $where: req.body.filter })`.',
  threat: 'Data breach, authentication bypass, remote code execution (DB-specific), full DB compromise',
  remediation:
    '1) Use **parameterized queries** / prepared statements: `db.query(\'SELECT * FROM users WHERE id = $1\', [id])`. ' +
    '2) ORMs (Prisma, TypeORM, Sequelize, SQLAlchemy) parameterize automatically. ' +
    '3) Never build SQL via string concatenation. ' +
    '4) NoSQL: NEVER pass user input to operators like `$where`, `$function`, or `$regex`; use an explicit whitelist. ' +
    '5) Even when using stored procedures, never build SQL dynamically inside them. ' +
    '6) Validate all user input first (Zod, Joi, class-validator).',
  references: [
    'https://owasp.org/www-community/attacks/SQL_Injection',
    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
    'https://owasp.org/www-project-top-ten/2017/A1_2017-Injection',
  ],
  cwe: 'CWE-89',
  owasp: 'A03:2021 Injection',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+[^;\n]*['"`]\s*\+\s*(req\.|request\.|input|params|body|query)/gi,
      /\$\{[^}]*(req\.|request\.|input|params|body|query)[^}]*\}\s*['"`]\s*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/gi,
/f['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{[^}]*(?:request|input|args|params)/gi,
      /['"`](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^'"`]*['"`]\s*%\s*\(/g,
      /(?:createQuery|createNativeQuery)\s*\([^)]*\+[^)]*(?:request|param)/g,
      /\$where\s*:\s*(?:['"`][^'"`]*\$\{|(?:req\.|request\.|input|params|body|query|\+))/gi,
      /\.(?:find|findOne|countDocuments|deleteOne|updateOne)\s*\(\s*(?:req\.query|req\.body)\s*\)/g,
      /\$(?:where|function)\s*:\s*(?:function|\([^)]*\)\s*=>)/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
