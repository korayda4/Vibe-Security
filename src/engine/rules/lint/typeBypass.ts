import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, matchAll, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'LINT-003',
  title: 'Compiler type-safety suppression (@ts-ignore / @ts-nocheck / as any)',
  layer: 'lint',
  severity: 'low',
  description:
    'Suppressing TypeScript compiler checks using `@ts-ignore`, `@ts-nocheck`, or coercing objects to `as any` removes compile-time verification. In security-sensitive code (authentication, input handling, permissions), this leads to runtime undefined errors, property confusion, and type injection bugs.',
  threat:
    'Runtime type errors, bypass of schema validation contracts, undefined property dereferencing in production.',
  remediation:
    '1) Declare proper TypeScript interfaces or types instead of coercing to `any`.\n' +
    '2) Use type narrowing (e.g. `typeof`, `instanceof`, or Zod schemas) instead of `@ts-ignore`.\n' +
    '3) If external library types are missing, use `unknown` and validate fields explicitly.',
  references: [
    'https://typescript-eslint.io/rules/ban-ts-comment/',
    'https://typescript-eslint.io/rules/no-explicit-any/',
  ],
  cwe: 'CWE-843',
  owasp: 'A04:2021 Insecure Design',
  languages: ['typescript'],
  check: (ctx) => {
    const patterns = [
      /\/\/\s*@ts-ignore\b/g,
      /\/\/\s*@ts-nocheck\b/g,
      /\bas\s+any\b/g,
    ];

    const findings = [];
    for (const re of patterns) {
      for (const m of matchAll(re, ctx.source)) {
        if (m.index === undefined) continue;
        const { line, column } = lineColumnFromIndex(ctx.source, m.index);

        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
          ruleId: rule.id,
          title: rule.title,
          layer: rule.layer,
          severity: rule.severity,
          file: ctx.relativePath,
          match: { snippet: snippetAt(ctx.source, line), line, column },
          description: rule.description,
          impact: rule.threat,
          remediation: rule.remediation,
          references: rule.references,
          cwe: rule.cwe,
          owasp: rule.owasp,
        });
      }
    }
    return findings;
  },
};

export default rule;
