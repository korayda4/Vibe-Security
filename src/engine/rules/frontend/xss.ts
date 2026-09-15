import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'FE-001',
  title: 'Unsafe DOM injection (innerHTML / dangerouslySetInnerHTML)',
  layer: 'frontend',
  severity: 'high',
  description:
    'User-controlled or external data rendered via element.innerHTML or React dangerouslySetInnerHTML enables XSS (Cross-Site Scripting). Attackers inject HTML/JS to steal sessions, exfiltrate data, or take over the page.',
  threat: 'Stored / Reflected XSS → account takeover, session hijack, data exfiltration, malware distribution',
  remediation:
    "1) Use textContent or the framework's safe binding (React JSX, Vue {{ }}, Angular interpolation). " +
    '2) If rich text is required, sanitize with DOMPurify.sanitize(). ' +
    "3) If user HTML must render, enforce server-side CSP to block inline scripts. " +
    '4) Avoid eval(), document.write(), Function() constructor.',
  references: [
    'https://owasp.org/www-community/attacks/xss/',
    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    'https://github.com/cure53/DOMPurify',
  ],
  cwe: 'CWE-79',
  owasp: 'A03:2021 Injection',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const findings = [];
    const patterns: RegExp[] = [
      /\.innerHTML\s*=/g,
      /dangerouslySetInnerHTML\s*=\s*\{/g,
      /document\.write\s*\(/g,
      /\.outerHTML\s*=/g,
      /insertAdjacentHTML\s*\(/g,
    ];

    for (const re of patterns) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);

        let fix;
        if (re.source.includes('dangerouslySetInnerHTML')) {
          const snippet = snippetAt(ctx.source, line, 3);
          const dsihMatch = snippet.match(
            /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*([^}]+)\s*\}\s*\}/
          );
          if (dsihMatch) {
            const expr = dsihMatch[1].trim();
            fix = {
              find: `dangerouslySetInnerHTML={{ __html: ${expr} }}`,
              replace: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(${expr}) }}`,
              description: 'Sanitize with DOMPurify (npm i dompurify @types/dompurify)',
            };
          }
        }

        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-${m[0].length}`,
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
          fix,
        });
      }
    }
    return findings;
  },
};

export default rule;
