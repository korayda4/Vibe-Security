import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'DB-001',
  title: 'Overly privileged database user (DROP, ALTER, GRANT granted to app user)',
  layer: 'database',
  severity: 'high',
  description:
    'When the application DB user holds DROP, ALTER, GRANT, or superuser privileges, a SQL injection lets the attacker wipe or modify the entire database schema.',
  threat: 'Mass data destruction, ransomware-grade attack, full DB compromise',
  remediation:
    '1) Grant the app DB user ONLY the privileges it needs (SELECT, INSERT, UPDATE, DELETE). ' +
    '2) Do NOT grant DROP, ALTER, GRANT, or CREATE. ' +
    '3) Use a separate migration user (used in CI/CD, NOT in the app runtime). ' +
    '4) Postgres: `ALTER USER app_user NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION`. ' +
    '5) For read-only endpoints, use a dedicated read-only user. ' +
    '6) Do NOT put `superuser=yes` or `root` in the connection string.',
  references: [
    'https://en.wikipedia.org/wiki/Principle_of_least_privilege',
    'https://www.postgresql.org/docs/current/sql-grant.html',
    'https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html',
  ],
  cwe: 'CWE-269',
  owasp: 'A01:2021 Broken Access Control',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'yaml'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/GRANT\s+(ALL|ALL\s+PRIVILEGES|SUPERUSER|CREATE|DROP|ALTER)\b/gi,
      /SUPERUSER\b/gi,
      /NOSUPERUSER\s*=\s*false/gi,
/(?:postgres|mysql|mariadb):\/\/[^:]+:([^@]+)@[^\/]+\/(?:[^?]+\?)?[^"\s]*superuser/gi,
      /(?:postgres|mysql|mariadb):\/\/[^:]+:([^@]+)@[^\/]+\/(?:[^?]+\?)?[^"\s]*root/gi,
      /GRANT\s+OPTION/gi,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
