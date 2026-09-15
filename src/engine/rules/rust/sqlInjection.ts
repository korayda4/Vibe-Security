import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'RS-002',
  title: 'Rust: SQL/NoSQL injection via string concatenation',
  layer: 'backend',
  severity: 'critical',
  description:
    'Using `format!` or string concatenation to build SQL queries lets attackers inject SQL via untrusted input. While sqlx and diesel parameterize by default, raw `query_as` / `sqlx::query` with concatenation bypasses that protection.',
  threat: 'Database exfiltration, authentication bypass, data destruction',
  remediation:
    '1) Use sqlx::query with bind parameters: `query("SELECT * FROM users WHERE id = $1").bind(id)`. ' +
    '2) Diesel: `users.filter(id.eq(&given_id)).first(&conn)`. ' +
    '3) SeaORM / SQLAlchemy: parameter binding via `.bind()` or placeholder. ' +
    '4) NEVER use `format!("SELECT ... WHERE id = {}", user_input)`. ' +
    '5) For complex dynamic queries, build with sqlx::QueryBuilder and `.push_bind`.',
  references: [
    'https://docs.rs/sqlx/latest/sqlx/struct.Query.html',
    'https://github.com/launchbadge/sqlx-secure-ext',
    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
  ],
  cwe: 'CWE-89',
  owasp: 'A03:2021 Injection',
  languages: ['rust'],
  check: (ctx) => {
    const patterns = [
      /format!\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP)[^'"`]*\{\s*\w+/gi,
      /format!\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^'"`]*\{\s*\w+/gi,
      /\.exec\(\s*format!\(/g,
    ];
    const findings = [];
    for (const re of patterns) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}`,
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
    }
    return findings;
  },
};

export default rule;
