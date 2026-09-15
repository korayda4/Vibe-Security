import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'KT-001',
  title: 'Kotlin: SQL injection via string template in JPA/JDBC',
  layer: 'backend',
  severity: 'critical',
  description:
    'Kotlin string templates (`"SELECT * FROM users WHERE id = $id"`) and string concatenation passed to JPA native queries or JDBC allow SQL injection. Spring Data JPA with `@Query` parameterizes via `?1` / `:name`; raw concatenation bypasses that.',
  threat: 'Database exfiltration, authentication bypass, data destruction',
  remediation:
    '1) Use Spring Data JPA: `@Query("SELECT u FROM User u WHERE u.email = :email") fun findByEmail(@Param("email") email: String)`. ' +
    '2) For native queries: `@Query(value = "SELECT * FROM users WHERE id = ?1", nativeQuery = true)`. ' +
    '3) For raw JDBC: `PreparedStatement` with `?` placeholders, never `String.format` or `+`. ' +
    '4) Use `org.springframework.jdbc.core.namedparam.MapSqlParameterSource` for named parameters. ' +
    '5) NEVER use `"SELECT * FROM users WHERE id = $id"` with string templates.',
  references: [
    'https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#jpa.query-methods.at-query',
    'https://kotlinlang.org/docs/reference/java-interop.html#string-templates',
  ],
  cwe: 'CWE-89',
  owasp: 'A03:2021 Injection',
  languages: ['kotlin'],
  check: (ctx) => {
    const findings = [];
    const patterns = [
      /["']SELECT[^"']*\$[a-zA-Z]/gi,
      /["']INSERT[^"']*\$[a-zA-Z]/gi,
      /["']UPDATE[^"']*\$[a-zA-Z]/gi,
      /["']DELETE[^"']*\$[a-zA-Z]/gi,
      /createNativeQuery\s*\(\s*["'][^"']*\$/g,
      /@Query\s*\(\s*["'][^"']*\$/g,
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
