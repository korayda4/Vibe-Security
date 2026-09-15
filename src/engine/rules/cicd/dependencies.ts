import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'CI-001',
  title: 'Dependency hygiene — missing lockfile, audit, or pinning',
  layer: 'cicd',
  severity: 'medium',
  description:
    'Lockfile (package-lock.json / yarn.lock / poetry.lock / go.sum) eksikse bagimlilik versiyonlari tekrarlanamaz sekilde cozumlenir (tedarik zinciri riski). Audit script\'i yoksa CVE\'ler sessizce slider.',
  threat: 'Software supply chain attack, dependency confusion, known CVE exploitation',
  remediation:
    '1) Lockfile\'i her zaman commit\'leyin ve `.gitignore`\'a ALMAYIN. ' +
    '2) CI\'da `npm audit --audit-level=high`, `pip-audit`, `govulncheck`, `snyk test`, `dependabot` calistirin. ' +
    '3) Container imajlarinda minimal taban (`distroless`, `alpine`) ve **non-root** user kullanin. ' +
    '4) `npm ci` ile build yapin (lockfile\'a zorlar). ' +
    '5) Renovate / Dependabot ile guvenlik PR\'leri otomatik acilsin. ' +
    '6) `package.json` `scripts.audit` tanimlayin.',
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
