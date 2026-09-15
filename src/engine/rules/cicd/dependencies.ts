import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'CI-001',
  title: 'Dependency hygiene — missing lockfile, audit, or pinning',
  layer: 'cicd',
  severity: 'medium',
  description:
    'When a lockfile (package-lock.json / yarn.lock / poetry.lock / go.sum) is missing, dependency versions resolve non-deterministically (supply-chain risk). Without an audit script, known CVEs slip in silently.',
  threat: 'Software supply chain attack, dependency confusion, known CVE exploitation',
  remediation:
    '1) Always commit the lockfile -- do NOT add it to `.gitignore`. ' +
    '2) In CI, run `npm audit --audit-level=high`, `pip-audit`, `govulncheck`, `snyk test`, or `dependabot`. ' +
    '3) Use minimal container bases (`distroless`, `alpine`) and a **non-root** user. ' +
    '4) Build with `npm ci` (forces the lockfile). ' +
    '5) Configure Renovate / Dependabot to open security PRs automatically. ' +
    '6) Define an `audit` script in `package.json`.',
  references: [
    'https://docs.npmjs.com/cli/v10/commands/npm-audit',
    'https://github.com/pypa/pip-audit',
    'https://github.com/govulncheck/govulncheck',
  ],
  cwe: 'CWE-1357',
  owasp: 'A06:2021 Vulnerable and Outdated Components',
  languages: ['javascript', 'typescript', 'python', 'go', 'json'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/^(\s*)\}\s*$/gm,
/pip\s+install\s+(?!.*--require-hashes)/g,
      /npm\s+install\s+(?!.*--ignore-scripts)/g,
/FROM\s+[^:\n]+:latest/g,
    ];

    if (/(?:package\.json|requirements\.txt|pyproject\.toml|go\.mod)$/i.test(ctx.relativePath)) {
      const hasAudit = /"audit"|pip-audit|snyk|dependabot|renovate/i.test(ctx.source);
      if (!hasAudit && /(?:package\.json)$/i.test(ctx.relativePath)) {
        return grepRule(rule, ctx, /"scripts"\s*:\s*\{/g);
      }
    }

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
