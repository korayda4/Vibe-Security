import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, matchAll, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'LINT-001',
  title: 'Empty catch or swallowed exception (silent failure)',
  layer: 'lint',
  severity: 'medium',
  description:
    'Catching an error or exception without logging, handling, or rethrowing it silently swallows critical runtime failures. This blinds security monitoring, conceals authentication/authorization aborts, and leads to unpredictable application states.',
  threat:
    'Hidden crashes, unhandled security exceptions, silent failure of critical validation logic, and blind observability.',
  remediation:
    '1) Always log the caught error with sufficient context: `console.error("Operation failed:", err)`.\n' +
    '2) Rethrow the error if the function cannot safely recover: `throw err`.\n' +
    '3) In Python, avoid `except: pass`; log with `logger.exception()`.\n' +
    '4) In Go, never ignore `if err != nil { }`; return or log the error.',
  references: [
    'https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging%2526Monitoring',
    'https://cwe.mitre.org/data/definitions/390.html',
  ],
  cwe: 'CWE-390',
  owasp: 'A09:2021 Security Logging and Monitoring Failures',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'kotlin', 'php', 'ruby'],
  check: (ctx) => {
    const patterns: RegExp[] = [
      // JS / TS / Java / Kotlin / PHP empty catch
      /catch\s*(?:\([^)]*\))?\s*\{\s*\}/g,
      // Python empty except with pass or ellipsis
      /except(?:\s+[a-zA-Z0-9_,\s]+)?:\s*(?:pass|\.\.\.)/g,
      // Go empty error check
      /if\s+err\s*!=\s*nil\s*\{\s*\}/g,
      // Ruby empty rescue
      /rescue(?:\s+[\w:]+)?\s*(?:\r?\n\s*end|\s+nil\b)/g,
    ];

    const findings = [];
    for (const re of patterns) {
      for (const m of matchAll(re, ctx.source)) {
        if (m.index === undefined) continue;
        const { line, column } = lineColumnFromIndex(ctx.source, m.index);

        let fix;
        if (m[0].includes('catch') && (ctx.language === 'javascript' || ctx.language === 'typescript')) {
          fix = {
            find: m[0],
            replace: `catch (err) {\n    console.error('Unhandled error:', err);\n    throw err;\n  }`,
            description: 'Log and rethrow swallowed error',
          };
        }

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
    }
    return findings;
  },
};

export default rule;
