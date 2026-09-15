import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'RB-001',
  title: 'Ruby: SQL injection via string interpolation',
  layer: 'backend',
  severity: 'critical',
  description:
    'Ruby on Rails ActiveRecord parameterizes queries by default. However, raw `where("...")` with string interpolation, `sanitize_sql` with concatenation, or find_by_sql bypass that protection.',
  threat: 'Database exfiltration, authentication bypass, data destruction',
  remediation:
    '1) Use ActiveRecord: `User.where(email: params[:email])` — auto-parameterized. ' +
    '2) For raw SQL: `where("email = ?", params[:email])` with `?` placeholders. ' +
    '3) Use `sanitize_sql_array` for IN clauses: `where("id IN (?)", ids)`. ' +
    '4) Hash conditions: `where("name = :name", name: input)` — named placeholders. ' +
    "5) NEVER use string interpolation in raw SQL: where(\"email = '#{params[:email]}'\") is vulnerable.",
  references: [
    'https://guides.rubyonrails.org/security.html#sql-injection',
    'https://api.rubyonrails.org/classes/ActiveRecord/Sanitization/ClassMethods.html',
    'https://owasp.org/www-community/attacks/SQL_Injection',
  ],
  cwe: 'CWE-89',
  owasp: 'A03:2021 Injection',
  languages: ['ruby'],
  check: (ctx) => {
    const findings = [];
    const patterns = [
      /where\s*\(\s*["'][^"']*#\{[^}]*(?:params|request|input|params\[|@user\.input)/g,
      /find_by_sql\s*\(\s*["'][^"']*#\{/g,
      /execute\s*\(\s*["'][^"']*#\{/g,
      /sanitize_sql\s*\(\s*["'][^"']*#\{/g,
    ];
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
