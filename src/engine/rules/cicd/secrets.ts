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
  languages: [
    'javascript',
    'typescript',
    'python',
    'java',
    'kotlin',
    'go',
    'rust',
    'ruby',
    'php',
    'yaml',
    'json',
    'toml',
    'dockerfile',
    'unknown',
  ],
  check: (ctx) => {
    const baseName = ctx.relativePath.split('/').pop()?.toLowerCase() ?? '';
    if (
      baseName.includes('.example') ||
      baseName.includes('.template') ||
      baseName.includes('.sample') ||
      baseName.includes('.dist')
    ) {
      return [];
    }

    const patterns: RegExp[] = [
      /AKIA[0-9A-Z]{16}/g,
      /api[_-]?key\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{20,})['"`]/gi,
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
      /(?:password|passwd|pwd|secret)\s*[:=]\s*['"`]([^'"`\s]{6,})['"`]/gi,
      /sk_live_[0-9a-zA-Z]{24,}/g,
      /gh[pousr]_[0-9a-zA-Z]{36,}/g,
      /github_pat_[0-9a-zA-Z_]{82}/g,
      /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
      /sk-(?:proj-)?[a-zA-Z0-9_\-]{32,}/g,
      /sk-ant-[a-zA-Z0-9_\-]{20,}/g,
      /AIzaSy[a-zA-Z0-9_\-]{33}/g,
      /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis(?:s)?|amqps?):\/\/[^\s'"`:@/]+:[^@\s'"`/]{4,}@[^\s'"`/]+/gi,
      /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/g,
      /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{50,}/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
