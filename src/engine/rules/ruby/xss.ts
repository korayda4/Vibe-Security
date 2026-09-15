import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'RB-003',
  title: 'Ruby: XSS via raw / html_safe in views',
  layer: 'frontend',
  severity: 'high',
  description:
    'In Rails, `<%= ... %>` escapes HTML by default. However `<%= raw ... %>` or `<%== ... %>` (or `html_safe` in controllers) bypasses escaping and renders raw HTML — XSS.',
  threat: 'Stored / Reflected XSS → session hijack, account takeover, data exfiltration',
  remediation:
    '1) NEVER use `<%= raw user_input %>` or `<%== user_input %>`. ' +
    '2) Use `<%= user_input %>` which auto-escapes. ' +
    '3) For rich text, sanitize via `sanitize(user_input)` or a gem like `loofah` / `sanitize`. ' +
    '4) In controllers, NEVER call `.html_safe` on user-controlled data. ' +
    '5) Set `Content-Security-Policy` headers to add defense in depth.',
  references: [
    'https://guides.rubyonrails.org/security.html#cross-site-scripting-xss',
    'https://owasp.org/www-community/attacks/xss/',
  ],
  cwe: 'CWE-79',
  owasp: 'A03:2021 Injection',
  languages: ['ruby'],
  check: (ctx) => {
    const findings = [];
    const patterns = [
      /<%=\s*raw\s+/g,
      /<%==\s*/g,
      /<%=\s*\w+\.html_safe\s*%>/g,
      /\.html_safe\s*(?:!|\b)/g,
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
