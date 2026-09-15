import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'KT-002',
  title: 'Kotlin: XSS via kotlinx.html raw text or unsafe HTML',
  layer: 'frontend',
  severity: 'high',
  description:
    '` kotlinx.html` DSL escapes HTML by default, but `unsafe { +userInput }` (the unary plus operator on TextBuilder) or `rawText(userInput)` inserts raw HTML — XSS.',
  threat: 'Reflected / Stored XSS → session hijack, account takeover',
  remediation:
    '1) Use plain DSL: `p { text(userInput) }` — auto-escapes. ' +
    '2) NEVER use `unsafe { +userInput }` or `rawText(userInput)` with user-controlled input. ' +
    '3) For rich text, sanitize first via OWASP Java HTML Sanitizer. ' +
    '4) Set Content-Security-Policy header for defense in depth. ' +
    '5) Server-side render: always escape on output.',
  references: [
    'https://github.com/Kotlin/kotlinx.html',
    'https://owasp.org/www-community/attacks/xss/',
  ],
  cwe: 'CWE-79',
  owasp: 'A03:2021 Injection',
  languages: ['kotlin'],
  check: (ctx) => {
    const findings = [];
    const patterns = [
      /unsafe\s*\{\s*\+/g,
      /rawText\s*\(\s*[^)]*request/gi,
      /rawText\s*\(\s*[^)]*input/gi,
    ];
    for (const re of patterns) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}`,
          ruleId: rule.id,
          title: rule.title,
          layer: rule.layer,
          severity: rule.severity,
          file: ctx.relativePath,
          match: { snippet: snippetAt(ctx.source, line), line, column: m.index },
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
