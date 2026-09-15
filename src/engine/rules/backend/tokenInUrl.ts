import type { Rule } from '../../../types.js';
import { grepRule, lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-008',
  title: 'Token transmitted in URL (query string or path)',
  layer: 'backend',
  severity: 'high',
  description:
    'When an access token, API key, session ID, or any other sensitive token is carried in the URL query string (`?token=...`) or path (`/users/:token/...`), it leaks into server access logs, reverse proxy logs, browser history, the Referer header, and screenshots. It also opens the door to chained attacks (e.g. OWASP API3:2023 - Broken Object Property Level Authorization).',
  threat:
    'Token leakage via logs/history/referer -- session hijack, account takeover, lateral movement',
  remediation:
    '1) ALWAYS send tokens in the **Authorization: Bearer** header (not in the query string or path). ' +
    '2) Never send long-lived secrets such as API keys to the client; use a server-side proxy instead. ' +
    '3) When the frontend calls the API, use `fetch(url, { headers: { Authorization: \'Bearer \' + token } })`. ' +
    '4) Add an Express middleware that hard-rejects tokens in URLs: `app.use((req, res, next) => { if (req.query.token) return res.status(400).send(\'token in URL\'); next(); })`. ' +
    '5) Strip the query string from reverse proxy / Nginx access log formats. ' +
    '6) If a token really must appear in a URL (e.g. a download link), use a one-time, short-TTL signed URL.',
  references: [
    'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/',
    'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/598.html',
  ],
  cwe: 'CWE-598',
  owasp: 'A07:2021 Identification and Authentication Failures',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const findings = [];
const queryToken = [
      /req\.query\.(?:token|api_?key|apikey|access_?token|session)/gi,
      /request\.GET\[['"](?:token|api_?key|apikey|access_?token|session)['"]\]/g,
      /c\.Query\s*\(\s*['"`](?:token|api_?key|apikey|access_?token|session)/gi,
      /request\.query_params\.get\s*\(\s*['"`](?:token|api_?key|apikey)/gi,
    ];

    for (const re of queryToken) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-q`,
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
const fetchWithToken = [
      /fetch\s*\(\s*[`'"](?:[^`'"]*)\$\{[^}]*(?:token|api_?key|apikey|secret)[^}]*\}/gi,
      /fetch\s*\(\s*[`'"][^`'"]*\?(?:[^`'"]*)\$\{[^}]*(?:token|api_?key|apikey|secret)/gi,
      /axios\.(?:get|post)\s*\(\s*[`'"](?:[^`'"]*)\$\{[^}]*(?:token|api_?key|apikey|secret)/gi,
      /requests\.(?:get|post)\s*\(\s*[`'"]f?(?:[^`'"]*)\{[^}]*(?:token|api_?key|apikey|secret)/gi,
    ];

    for (const re of fetchWithToken) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-f`,
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
const pathParam = [
      /\/:\s*(?:token|api_?key|apikey|secret)\b/gi,
      /\/<(?:\w+:)?(?:token|api_?key|apikey|secret)>/gi,
      /\/\{(?:token|api_?key|apikey|secret)\}/gi,
    ];

    for (const re of pathParam) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const { line } = lineColumnFromIndex(ctx.source, m.index);
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-p`,
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
