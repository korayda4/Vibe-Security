import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-002',
  title: 'Weak password hashing (MD5 / SHA-1 / SHA-256 / plain text)',
  layer: 'backend',
  severity: 'critical',
  description:
    'Passwords stored as MD5, SHA1, SHA256, or plain text are trivially cracked the moment a database leaks. Modern GPUs can try billions of MD5 hashes per second.',
  threat: 'Mass credential disclosure, credential stuffing on other services',
  remediation:
    'Hash passwords with **Argon2id** or **bcrypt (work factor >= 12)**. ' +
    'Use a unique salt per user (Argon2/bcrypt handles this automatically). ' +
    'Use constant-time comparison when verifying logins. ' +
    'Require minimum 12-character passwords + check against a breached-password list (e.g. HIBP) on signup. ' +
    'Roll out MFA broadly. Re-hash any legacy hashes immediately.',
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
    'https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md',
    'https://auth0.com/blog/hashing-in-action-understanding-bcrypt-and-argon2/',
  ],
  cwe: 'CWE-916',
  owasp: 'A02:2021 Cryptographic Failures',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/(?:createHash|hashlib\.\w+|MessageDigest\.getInstance)\s*\(\s*['"`](md5|sha1|sha-1|sha256|sha-256)['"`]/gi,
      /['"`](md5|sha1|sha-1|sha256|sha-256)['"`]\s*\)/g,
      /\bmd5\s*\(/gi,
      /\bsha1\s*\(/gi,
      /\bsha256\s*\(/gi,
/password\s*[:=]\s*req\.body\.(password|passwd|pwd)/gi,
      /\bpassword\s*=\s*['"`][^'"`]+['"`]\s*[;\n]/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
