import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-002',
  title: 'Weak password hashing (MD5 / SHA-1 / SHA-256 / plain text)',
  layer: 'backend',
  severity: 'critical',
  description:
    'Parolalar MD5, SHA1, SHA256 veya duz metin olarak saklandiginda, veritabani sizintisinda aninda kirilabilir. Modern GPU\'lar MD5\'i saniyede milyarlarca kez deneyebilir.',
  threat: 'Mass credential disclosure, credential stuffing on other services',
  remediation:
    'Parolalari **Argon2id** veya **bcrypt (work factor >= 12)** ile hashleyin. ' +
    'Her kullanici icin unique salt (Argon2/bcrypt otomatik ekler). ' +
    'Login sirasinda constant-time comparison kullanin. ' +
    'Yeni uyelikte minimum 12 karakter sifre zorunlulugu + zayif sifre listesi (HIBP). ' +
    'MFA\'yi yayginlastirin. Mevcut legacy hashleri acil olarak yeniden hashleyin.',
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
