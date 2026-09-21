import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, matchAll, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'LINT-005',
  title: 'Unclosed resource or file descriptor without context manager',
  layer: 'lint',
  severity: 'medium',
  description:
    'Opening files or streams without a context manager (`with` in Python, `try-finally` / `using` in TS/C#, `defer` in Go) leaves file descriptors open. Under high concurrency, this exhausts operating system file handles (EMFILE/ENFILE) and triggers denial of service.',
  threat:
    'File descriptor exhaustion, memory leaks, OS file handle starvation, crash under load.',
  remediation:
    '1) In Python, always use context managers: `with open(...) as f:`.\n' +
    '2) In Node.js / TypeScript, use `fs.promises.readFile()` or ensure `stream.on("close")` handlers are registered.\n' +
    '3) In Go, immediately defer file closing: `f, err := os.Open(...); if err == nil { defer f.Close() }`.',
  references: [
    'https://cwe.mitre.org/data/definitions/775.html',
    'https://docs.python.org/3/tutorial/inputoutput.html#reading-and-writing-files',
  ],
  cwe: 'CWE-775',
  owasp: 'A04:2021 Insecure Design',
  languages: ['python', 'javascript', 'typescript', 'go'],
  check: (ctx) => {
    const findings = [];

    if (ctx.language === 'python') {
      // Look for f = open(...) without with statement
      const pyPattern = /^[ \t]*[a-zA-Z0-9_]+\s*=\s*open\s*\([^)]+\)(?!\s*\.(?:read|write|close))/gm;
      for (const m of matchAll(pyPattern, ctx.source)) {
        if (m.index === undefined) continue;
        const { line, column } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
          ruleId: rule.id,
          title: rule.title,
          layer: rule.layer,
          severity: rule.severity,
          file: ctx.relativePath,
          match: { snippet: snippetAt(ctx.source, line), line, column },
          description: 'Python open() called without `with` context manager.',
          impact: rule.threat,
          remediation: rule.remediation,
          references: rule.references,
          cwe: rule.cwe,
          owasp: rule.owasp,
        });
      }
    } else if (ctx.language === 'javascript' || ctx.language === 'typescript') {
      const jsPattern = /fs\.openSync\s*\([^)]+\)/g;
      for (const m of matchAll(jsPattern, ctx.source)) {
        if (m.index === undefined) continue;
        const { line, column } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
          ruleId: rule.id,
          title: rule.title,
          layer: rule.layer,
          severity: rule.severity,
          file: ctx.relativePath,
          match: { snippet: snippetAt(ctx.source, line), line, column },
          description: 'fs.openSync descriptor may leak if not closed in try/finally block.',
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
