import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'DB-002',
  title: 'Sensitive data not encrypted at rest (PII / payment / health)',
  layer: 'database',
  severity: 'high',
  description:
    'PII fields such as national IDs, credit card numbers, health data, or passwords stored as plain text become immediately readable the moment a disk or backup leaks.',
  threat: 'GDPR / KVKK / PCI-DSS violation, identity theft, regulatory fines',
  remediation:
    '1) In transit: encrypt all connections with **TLS 1.2+**. Set `sslmode=require` or `ssl=true` in connection strings. ' +
    '2) At rest: encrypt sensitive columns at the application layer with **AES-256-GCM** (non-deterministic, random IV). ' +
    '3) Or use TDE / column-level encryption (pgcrypto, AWS RDS encryption, MongoDB CSFLE). ' +
    '4) Manage keys via KMS / Vault -- never store keys in code. ' +
    '5) Backups must also be encrypted. ' +
    '6) For data in PCI scope, use tokenization (Stripe, Adyen); NEVER store raw PANs.',
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
