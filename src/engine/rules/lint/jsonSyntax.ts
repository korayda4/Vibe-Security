import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'LINT-004',
  title: 'Malformed JSON configuration or data file (SyntaxError)',
  layer: 'lint',
  severity: 'high',
  description:
    'The JSON file contains invalid syntax (such as trailing commas, single quotes, unquoted keys, or unescaped characters). Malformed JSON breaks configuration loaders, causes immediate deployment failures, and halts CI/CD build scripts.',
  threat:
    'Fatal deployment crashes, broken dependency trees, failure to load security configurations or environment policies.',
  remediation:
    '1) Remove any trailing commas: standard JSON does not permit trailing commas after objects or arrays.\n' +
    '2) Ensure all keys and string values are enclosed in double quotes ("), never single quotes (\').\n' +
    '3) Validate the JSON file using a strict JSON linter or `node -e "JSON.parse(fs.readFileSync(...))"`.',
  references: [
    'https://www.json.org/json-en.html',
    'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse',
  ],
  cwe: 'CWE-20',
  owasp: 'A04:2021 Insecure Design',
  languages: ['json'],
  check: (ctx) => {
    if (ctx.language !== 'json' && !ctx.relativePath.endsWith('.json')) {
      return [];
    }

    // Skip empty files
    if (!ctx.source.trim()) {
      return [];
    }

    try {
      JSON.parse(ctx.source);
      return [];
    } catch (err) {
      const msg = (err as Error).message;
      let line = 1;
      let column = 0;

      // Extract error position if provided by V8
      const posMatch = msg.match(/position\s+(\d+)/i);
      const lineMatch = msg.match(/line\s+(\d+)\s+column\s+(\d+)/i);

      if (lineMatch) {
        line = parseInt(lineMatch[1], 10);
        column = parseInt(lineMatch[2], 10);
      } else if (posMatch) {
        const pos = parseInt(posMatch[1], 10);
        const loc = lineColumnFromIndex(ctx.source, pos);
        line = loc.line;
        column = loc.column;
      }

      return [
        {
          id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
          ruleId: rule.id,
          title: `${rule.title} - ${msg}`,
          layer: rule.layer,
          severity: rule.severity,
          file: ctx.relativePath,
          match: {
            snippet: snippetAt(ctx.source, line),
            line,
            column,
          },
          description: `Invalid JSON syntax: ${msg}`,
          impact: rule.threat,
          remediation: rule.remediation,
          references: rule.references,
          cwe: rule.cwe,
          owasp: rule.owasp,
        },
      ];
    }
  },
};

export default rule;
