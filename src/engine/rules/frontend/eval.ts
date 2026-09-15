import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'FE-006',
  title: 'Dangerous dynamic code execution (eval / Function / setTimeout string)',
  layer: 'frontend',
  severity: 'high',
  description:
    '`eval()`, `new Function()`, `setTimeout(string, ...)` veya `setInterval(string, ...)` ile dinamik kod calistirmak, kullanici girdisi kontrolsuzce yurutulurse RCE veya XSS ile sonuclanabilir.',
  threat: 'Remote code execution, XSS, injection chain',
  remediation:
    'Dinamik koda ihtiyac varsa JSON.parse veya guvenli bir DSL parser kullanin. ' +
    '`eval`, `Function` constructor\'dan tamamen kacinin. ' +
    '`setTimeout` / `setInterval`\'a her zaman fonksiyon referansi verin, string vermeyin. ' +
    'CSP header\'larinda `unsafe-eval` eklemeyin.',
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
