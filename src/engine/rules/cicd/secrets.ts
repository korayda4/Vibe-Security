import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'CI-002',
  title: 'Hardcoded secret / credential in source',
  layer: 'cicd',
  severity: 'critical',
  description:
    'API key, private key, DB password, OAuth secret, AWS access key gibi hassas degerlerin kaynak kodunda veya .env dosyasinda duz metin bulunmasi, Git reposuna sizmasi demektir.',
  threat: 'Cloud takeover, financial fraud, data breach, lateral movement',
  remediation:
    '1) Tum secret\'lari **Vault / AWS Secrets Manager / GCP Secret Manager / Doppler** ile yonetin. ' +
    '2) Pre-commit hook olarak **gitleaks** veya **trufflehog** kurun. ' +
    '3) `.gitignore`\'a `.env`, `.env.local`, `*.pem`, `*.key` ekleyin. ' +
    '4) `.env.example` sadece anahtar isimlerini icersin, degerler bos olmali. ' +
    '5) CI ortaminda secret\'lari environment variable olarak inject edin (GitHub Actions secrets, GitLab CI variables). ' +
    '6) Bir secret commit olduysa HEMEN rotate edin; Git history\'de kalir.',
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
