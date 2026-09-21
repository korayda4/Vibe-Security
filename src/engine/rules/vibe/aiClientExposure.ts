import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'AI-001',
  title: 'Client-side LLM SDK instantiation (dangerouslyAllowBrowser / Exposed AI Key)',
  layer: 'frontend',
  severity: 'critical',
  description:
    'Instantiating OpenAI, Anthropic, or other LLM SDKs directly in client-side code (especially with dangerouslyAllowBrowser: true) exposes your paid private API keys to any user via browser devtools or bundle scraping.',
  threat:
    'Full API key compromise, account credit exhaustion, unauthorized LLM usage, data exfiltration from organization model access.',
  remediation:
    '1) Never instantiate LLM clients in frontend code.\n' +
    '2) Create a backend API route (e.g. /api/chat or Next.js route handler) that securely holds the API key in server-side environment variables.\n' +
    '3) Forward client chat requests through your authenticated backend endpoint.',
  references: [
    'https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety',
    'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
  ],
  cwe: 'CWE-798',
  owasp: 'A07:2021 Identification and Authentication Failures',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const findings = [];
    const patterns = [
      /dangerouslyAllowBrowser\s*:\s*true/g,
      /new\s+(?:OpenAI|Anthropic|GoogleGenerativeAI|MistralClient)\s*\(\s*\{[^}]*apiKey\s*:\s*['"`][A-Za-z0-9_\-]{20,}['"`]/gi,
    ];

    for (const re of patterns) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);
        let fix;

        if (m[0].includes('dangerouslyAllowBrowser')) {
          fix = {
            find: m[0],
            replace: '// REMOVED: Move LLM call to backend route (e.g. /api/chat)',
            description: 'Remove dangerouslyAllowBrowser and migrate LLM call to backend route handler',
          };
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
