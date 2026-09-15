import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'CI-002',
  title: 'Hardcoded secret / credential in source',
  layer: 'cicd',
  severity: 'critical',
  description:
    'Storing sensitive values such as API keys, private keys, DB passwords, OAuth secrets, or AWS access keys in source code or in `.env` files means they leak into the Git repository.',
  threat: 'Cloud takeover, financial fraud, data breach, lateral movement',
  remediation:
    '1) Manage all secrets with **Vault / AWS Secrets Manager / GCP Secret Manager / Doppler**. ' +
    '2) Install **gitleaks** or **trufflehog** as a pre-commit hook. ' +
    '3) Add `.env`, `.env.local`, `*.pem`, `*.key` to `.gitignore`. ' +
    '4) `.env.example` should contain only key names, with empty values. ' +
    '5) Inject secrets in CI via environment variables (GitHub Actions secrets, GitLab CI variables, etc.). ' +
    '6) If a secret has been committed, rotate it IMMEDIATELY; it stays in the Git history forever.',
  references: [
    'https://github.com/gitleaks/gitleaks',
    'https://github.com/trufflesecurity/trufflehog',
    'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
  ],
  cwe: 'CWE-798',
  owasp: 'A05:2021 Security Misconfiguration',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'yaml', 'dockerfile'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/AKIA[0-9A-Z]{16}/g,
/api[_-]?key\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})['"`]/gi,
/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
/(?:password|passwd|pwd|secret)\s*[:=]\s*['"`]([^'"`\s]{6,})['"`]/gi,
/sk_live_[0-9a-zA-Z]{24,}/g,
/gh[pousr]_[0-9a-zA-Z]{36,}/g,
/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
