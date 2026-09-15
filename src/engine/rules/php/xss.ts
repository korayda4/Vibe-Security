import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'PHP-002',
  title: 'PHP: XSS via echo of unescaped input',
  layer: 'frontend',
  severity: 'high',
  description:
    '`echo $_GET["..."]` or `print $user_input` renders raw user input as HTML. Attackers inject `<script>` tags for session hijacking. The same applies to Laravel `{{ ... }}` raw output and Symfony `{{ var|raw }}`.',
  threat: 'Reflected / Stored XSS → account takeover, session hijack, data exfiltration',
  remediation:
    '1) Use `htmlspecialchars($input, ENT_QUOTES, "UTF-8")` before echo: `echo htmlspecialchars($_GET["q"])`. ' +
    '2) Laravel: `{{ $input }}` auto-escapes; `{{!! $input !!}}` is raw (avoid). ' +
    '3) Use Twig auto-escape; avoid `|raw` filter on user input. ' +
    '4) Set `Content-Security-Policy` header. ' +
    '5) Use a templating engine that escapes by default (Twig, Blade).',
  references: [
    'https://www.php.net/manual/en/function.htmlspecialchars.php',
    'https://laravel.com/docs/blade#displaying-data',
    'https://owasp.org/www-community/attacks/xss/',
  ],
  cwe: 'CWE-79',
  owasp: 'A03:2021 Injection',
  languages: ['php'],
  check: (ctx) => {
    const findings = [];
    const patterns = [
      /\b(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/g,
      /\b(?:echo|print)\s+\$this->input->/g,
      /\{\{!!\s+[^}]+\s+!!\}\}/g,
      /\{\{[^}]+\s*\|\s*raw\s*\}\}/g,
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
