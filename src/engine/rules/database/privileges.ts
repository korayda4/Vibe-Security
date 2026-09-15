import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'DB-001',
  title: 'Overly privileged database user (DROP, ALTER, GRANT granted to app user)',
  layer: 'database',
  severity: 'high',
  description:
    'Uygulama DB baglanti kullanicisi DROP, ALTER, GRANT veya superuser yetkilerine sahipse, SQL injection durumunda saldırıgın tum veritabanini silmesi veya sema degistirmesi mumkun.',
  threat: 'Mass data destruction, ransomware-grade attack, full DB compromise',
  remediation:
    '1) App DB user\'ina SADECE gereken yetkileri verin (SELECT, INSERT, UPDATE, DELETE). ' +
    '2) DROP, ALTER, GRANT, CREATE yetkilerini vermeyin. ' +
    '3) Migration\'lar icin ayri bir migration user (CI/CD\'de kullanilan, app\'te OLMAYAN). ' +
    '4) Postgres: `ALTER USER app_user NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION`. ' +
    '5) Read-only endpointler icin ayri read-only user kullanin. ' +
    '6) Baglanti string\'inde `superuser=yes` veya `root` KULLANMAYIN.',
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
