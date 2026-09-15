import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'RS-001',
  title: 'Rust: unwrap() / expect() / panic! in production code',
  layer: 'backend',
  severity: 'medium',
  description:
    'Calling .unwrap(), .expect(), or panic!() in production code causes a panic (crash) on unexpected states. In a web handler or critical path this leads to DoS via attacker-controlled input.',
  threat: 'Denial of service via panic on untrusted input; information disclosure from stack trace',
  remediation:
    '1) Use proper error handling with `Result<T, E>` and the `?` operator. ' +
    '2) For invariant assertions, document why the value cannot fail; consider `debug_assert!` for non-critical checks. ' +
    '3) Wrap input parsing in dedicated `try_from` / `parse` and return HTTP 400. ' +
    '4) Catch panics at the boundary (e.g. actix_web::middleware::panic_handler, tower_http::catch_panic). ' +
    '5) Add a global catch_unwind or tokio::spawn wrapper for resilience.',
  references: [
    'https://doc.rust-lang.org/book/ch09-00-error-handling.html',
    'https://github.com/tokio-rs/axum/blob/main/examples/testing-errors/src/main.rs',
  ],
  cwe: 'CWE-754',
  owasp: 'A04:2021 Insecure Design',
  languages: ['rust'],
  check: (ctx) => {
    const patterns = [
      /\.unwrap\(\)/g,
      /\.expect\([^)]*\)/g,
      /\bpanic!\(/g,
      /unimplemented!\(/g,
      /todo!\(/g,
    ];
    const findings = [];
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
