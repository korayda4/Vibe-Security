import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'DB-002',
  title: 'Sensitive data not encrypted at rest (PII / payment / health)',
  layer: 'database',
  severity: 'high',
  description:
    'TC kimlik, kredi karti, saglik verisi, parolalar gibi PII alanlari duz metin (plain text) ile saklaniyorsa fiziksel veya yedek sizintisinda aninda okunabilir hale gelir.',
  threat: 'GDPR / KVKK / PCI-DSS violation, identity theft, regulatory fines',
  remediation:
    '1) In-transit: tum baglantilari **TLS 1.2+** ile sifreleyin. Baglanti string\'inde `sslmode=require` veya `ssl=true`. ' +
    '2) At-rest: kritik kolonlari uygulama seviyesinde **AES-256-GCM** ile sifreleyin (deterministic olmayan, random IV). ' +
    '3) Veya TDE / column-level encryption (pgcrypto, AWS RDS encryption, MongoDB CSFLE). ' +
    '4) KMS / Vault ile key\'leri yonetin, kodda saklamayin. ' +
    '5) Backup\'lar da sifrelenmis olmali. ' +
    '6) PCI scope\'a giren veriler icin tokenization (Stripe, Adyen) kullanin, ham PAN\'i ASLA saklamayin.',
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
    'https://www.postgresql.org/docs/current/encryption-options.html',
    'https://www.pcisecuritystandards.org/',
  ],
  cwe: 'CWE-311',
  owasp: 'A02:2021 Cryptographic Failures',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/(?:nationalId|tckimlik|ssn|socialSecurityNumber|creditCard|cardNumber|cvv|pan|tc_kimlik)\s*[:=]\s*['"`]?String['"`]?/gi,
      /(?:nationalId|tckimlik|ssn|socialSecurityNumber|creditCard|cardNumber|cvv|pan)\s+(?:String|VARCHAR|TEXT)/g,
/(?:postgres|mysql|mongodb):\/\/[^@\s]+@/gi,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
