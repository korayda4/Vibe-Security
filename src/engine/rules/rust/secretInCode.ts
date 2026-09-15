import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'RS-003',
  title: 'Rust: hardcoded secret / credential',
  layer: 'cicd',
  severity: 'critical',
  description:
    'Hardcoded API keys, database passwords, JWT secrets, or private keys in Rust source code or `.env` files. Once committed to Git, they are public.',
  threat: 'Cloud account takeover, financial fraud, lateral movement',
  remediation:
    '1) Move all secrets to environment variables + secret manager (Vault, AWS Secrets Manager). ' +
    '2) Use `std::env::var("API_KEY")` with proper error handling. ' +
    '3) Add `dotenvy` only for local development; never commit `.env`. ' +
    '4) Add `git-secrets` or `gitleaks` pre-commit hook. ' +
    '5) If a secret leaked, rotate immediately.',
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    'https://github.com/YoyoFate/secretfinder-rs',
  ],
  cwe: 'CWE-798',
  owasp: 'A05:2021 Security Misconfiguration',
  languages: ['rust'],
  check: (ctx) => {
    const patterns = [
      /AKIA[0-9A-Z]{16}/g,
      /sk_live_[0-9a-zA-Z]{24,}/g,
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      /(?:SECRET|API_KEY|PASSWORD|TOKEN|PRIVATE_KEY)\s*:\s*&?\[\s*u?8\s*\][\s\S]{0,200}=\s*["'][a-zA-Z0-9_\-/+=]{20,}["']/g,
    ];
    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
