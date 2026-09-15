import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'FE-003',
  title: 'Sensitive value exposed via public env prefix',
  layer: 'frontend',
  severity: 'critical',
  description:
    'Public env prefixes (NEXT_PUBLIC_, REACT_APP_, VITE_, GATSBY_, EXPO_PUBLIC_) are bundled into the client at build time. Any secret read via these prefixes (API key, DB connection string) is exposed to every visitor.',
  threat: 'Secret / API key disclosure, full backend compromise',
  remediation:
    '1) Do NOT define sensitive keys with public prefixes — use API_KEY instead of NEXT_PUBLIC_API_KEY. ' +
    '2) Public env should only carry public data (API URL, feature flags). ' +
    "3) Read secrets server-side via process.env.SECRET_NAME in route / API handlers. " +
    '4) Wire gitleaks or trufflehog as a pre-commit hook in CI.',
  references: [
    'https://nextjs.org/docs/basic-features/environment-variables#exposing-environment-variables-to-the-browser',
    'https://create-react-app.dev/docs/adding-custom-environment-variables/',
    'https://vitejs.dev/guide/env-and-mode.html',
  ],
  cwe: 'CWE-200',
  owasp: 'A05:2021 Security Misconfiguration',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const findings = [];
    const patterns: RegExp[] = [
      /^(NEXT_PUBLIC|REACT_APP|VITE_|GATSBY_|EXPO_PUBLIC_)[A-Z0-9_]*(SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY|PRIVATE|CREDENTIAL|AUTH)/gim,
      /process\.env\.(NEXT_PUBLIC|REACT_APP|VITE_|GATSBY_|EXPO_PUBLIC_)[A-Z0-9_]*(SECRET|KEY|TOKEN|PASSWORD|API[_-]?KEY|PRIVATE|CREDENTIAL|AUTH)/g,
    ];

    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
