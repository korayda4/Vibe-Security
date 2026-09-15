import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'OBS-001',
  title: 'Sensitive data exposed via logs (PII / stack trace / console.log in prod)',
  layer: 'observability',
  severity: 'medium',
  description:
    'Log\'a parola, kart numarasi, token, session cookie veya user kimlik bilgisi basilmasi, log toplayici sizintisinda GDPR/KVKK ihlali olusturur. Stack trace\'in production response\'una donmesi bilgi ifshasidir.',
  threat: 'PII leakage via logs, information disclosure via error responses, compliance violation',
  remediation:
    '1) Production response\'larinda ASLA stack trace / `error.stack` / ic detay donmeyin. Generic 500 + correlation id. ' +
    '2) Log\'a PII gondermeden once redact edin (`***-mask`). ' +
    '3) Parola, token, CVV, PAN gibi alanlari logger\'a gecmeyin. ' +
    '4) Merkezi log (ELK, Datadog, Sentry) ile PII redaction rules kurun. ' +
    '5) Anomali tespiti icin SIEM (Splunk, Sentinel) ile alerting. ' +
    '6) `console.log` production\'da birakilabilir ama debug amacli PII tasimamali.',
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html',
    'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
  ],
  cwe: 'CWE-532',
  owasp: 'A09:2021 Security Logging and Monitoring Failures',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/console\.log\s*\([^)]*(?:password|passwd|pwd|token|secret|api[_-]?key|cvv|cardNumber|ssn|tcKimlik)/gi,
      /logger?\.(?:info|debug|warn)\s*\([^)]*(?:password|passwd|pwd|token|secret|api[_-]?key|cvv|cardNumber|ssn|tcKimlik)/gi,
/res\.(?:send|json)\s*\(\s*\{\s*[^}]*error\s*:\s*err\.stack/gi,
      /res\.(?:send|json)\s*\(\s*err\.stack/gi,
/print\s*\(\s*[^)]*(?:password|secret|token|api[_-]?key)/gi,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
