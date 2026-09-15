import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'FE-006',
  title: 'Dangerous dynamic code execution (eval / Function / setTimeout string)',
  layer: 'frontend',
  severity: 'high',
  description:
    'Executing dynamic code via `eval()`, `new Function()`, `setTimeout(string, ...)`, or `setInterval(string, ...)` can lead to RCE or XSS when the input is not strictly controlled.',
  threat: 'Remote code execution, XSS, injection chain',
  remediation:
    'If you need dynamic behavior, prefer `JSON.parse` or a safe DSL parser. ' +
    'Avoid `eval` and the `Function` constructor entirely. ' +
    'Always pass function references (not strings) to `setTimeout` / `setInterval`. ' +
    'Do NOT enable `unsafe-eval` in your CSP header.',
  references: [
    'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!',
    'https://owasp.org/www-community/attacks/Code_Injection',
  ],
  cwe: 'CWE-95',
  owasp: 'A03:2021 Injection',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const patterns: RegExp[] = [
      /\beval\s*\(/g,
      /\bnew\s+Function\s*\(/g,
      /setTimeout\s*\(\s*['"`]/g,
      /setInterval\s*\(\s*['"`]/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
