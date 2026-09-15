import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-004',
  title: 'SQL / NoSQL injection via string concatenation',
  layer: 'backend',
  severity: 'critical',
  description:
    'SQL sorgulari veya NoSQL filtreleri string concatenation / template literals ile olusturuldugunda, kullanici girdisi sorgu yapisina enjekte edilebilir. ' +
    'Senaryolar: `query: "SELECT * FROM users WHERE id = " + req.params.id` veya `db.users.find({ $where: req.body.filter })` gibi.',
  threat: 'Data breach, authentication bypass, remote code execution (DB-specific), full DB compromise',
  remediation:
    '1) **Parametrik sorgular** / prepared statements kullanin: `db.query(\'SELECT * FROM users WHERE id = $1\', [id])`. ' +
    '2) ORM (Prisma, TypeORM, Sequelize, SQLAlchemy) otomatik parameterize eder. ' +
    '3) String concatenation ile SQL asla olusturmayin. ' +
    '4) NoSQL: `$where`, `$function`, `$regex` gibi operatorlari kullanici girdisinden GEÇMEYIN; explicit whitelist kullanin. ' +
    '5) Stored procedure kullaniyorsaniz bile icindeki SQL\'i dinamik olusturmayin. ' +
    '6) Tum user input\'u once validate edin (Zod, Joi, class-validator).',
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
/\$(?:where|function|regex|ne|gt|lt)\s*:/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
