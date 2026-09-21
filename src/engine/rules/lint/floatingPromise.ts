import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, matchAll, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'LINT-002',
  title: 'Floating asynchronous operation without await or .catch()',
  layer: 'lint',
  severity: 'medium',
  description:
    'Calling asynchronous database queries, encryption, or network calls without `await` or `.catch()` causes floating promises. This can lead to unhandled promise rejections, race conditions, or route handlers completing before changes are saved.',
  threat:
    'Data inconsistency, unhandled promise rejections crashing Node processes, race conditions where mutations finish after response is sent.',
  remediation:
    '1) Prepend `await` to asynchronous database and auth calls: `await prisma.user.update(...)`.\n' +
    '2) If executing in the background, attach a `.catch(err => ...)` handler.\n' +
    '3) Ensure the enclosing function is marked `async`.',
  references: [
    'https://typescript-eslint.io/rules/no-floating-promises/',
    'https://nodejs.org/api/process.html#event-unhandledrejection',
  ],
  cwe: 'CWE-391',
  owasp: 'A04:2021 Insecure Design',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    // Check for async calls without await on the statement
    const pattern =
      /^[ \t]*(?!(?:await|return|void|const|let|var)\b)(?:prisma\.[a-zA-Z0-9_]+\.(?:create|update|delete|upsert|deleteMany|updateMany)|db\.(?:query|execute|run|mutate)|bcrypt\.hash)\s*\([^)]*\)(?!\s*\.(?:then|catch))\s*;/gm;

    const findings = [];
    for (const m of matchAll(pattern, ctx.source)) {
      if (m.index === undefined) continue;
      const { line, column } = lineColumnFromIndex(ctx.source, m.index);
      const trimmed = m[0].trim();

      const fix = {
        find: m[0],
        replace: m[0].replace(trimmed, `await ${trimmed}`),
        description: 'Prepend await to floating asynchronous call',
      };

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
        fix,
      });
    }
    return findings;
  },
};

export default rule;
