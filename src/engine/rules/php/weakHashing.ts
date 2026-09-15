import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'PHP-003',
  title: 'PHP: weak password hashing (md5 / sha1 / sha256)',
  layer: 'backend',
  severity: 'critical',
  description:
    'Using `md5()`, `sha1()`, or `sha256()` for password hashing is broken — modern hardware cracks these in seconds. Use `password_hash($password, PASSWORD_BCRYPT)` or `PASSWORD_ARGON2ID`.',
  threat: 'Mass credential disclosure if database leaks',
  remediation:
    '1) Use `password_hash($pw, PASSWORD_BCRYPT, ["cost" => 12])` for bcrypt (PHP 5.5+). ' +
    '2) Or `password_hash($pw, PASSWORD_ARGON2ID)` for Argon2id (PHP 7.2+). ' +
    '3) Verify with `password_verify($pw, $hash)`. ' +
    '4) NEVER use `md5`, `sha1`, `sha256`, `hash("md5", ...)` for passwords. ' +
    '5) For legacy hashes, rehash on next successful login: if (password_verify(...)) { $new = password_hash(...) }.',
  references: [
    'https://www.php.net/manual/en/function.password-hash.php',
    'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
  ],
  cwe: 'CWE-916',
  owasp: 'A02:2021 Cryptographic Failures',
  languages: ['php'],
  check: (ctx) => {
    const findings = [];
    const patterns = [
      /\bmd5\s*\(\s*\$_/gi,
      /\bsha1\s*\(\s*\$_/gi,
      /\bsha256\s*\(\s*\$_/gi,
      /\bhash\s*\(\s*['"`](?:md5|sha1|sha256)['"`]/gi,
    ];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
