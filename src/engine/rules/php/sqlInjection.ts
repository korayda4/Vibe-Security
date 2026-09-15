import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'PHP-001',
  title: 'PHP: SQL injection via string concatenation',
  layer: 'backend',
  severity: 'critical',
  description:
    'PHP mysqli / PDO queries built via string concatenation or interpolation allow attackers to inject SQL through any user-controlled parameter.',
  threat: 'Database exfiltration, authentication bypass, data destruction, full server compromise',
  remediation:
    '1) Use PDO prepared statements: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id])`. ' +
    '2) Use mysqli prepared: `$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?"); $stmt->bind_param("i", $id)`. ' +
    '3) For Eloquent / Laravel query builder: `User::where("id", $id)->first()`. ' +
    '4) NEVER use `"SELECT * FROM users WHERE id = $id"` or `.="..."`. ' +
    '5) For variable table/column names: validate against an allowlist.',
  references: [
    'https://www.php.net/manual/en/pdo.prepared-statements.php',
    'https://www.php.net/manual/en/mysqli.quickstart.prepared-statements.php',
    'https://owasp.org/www-community/attacks/SQL_Injection',
  ],
  cwe: 'CWE-89',
  owasp: 'A03:2021 Injection',
  languages: ['php'],
  check: (ctx) => {
    const findings = [];
    const patterns = [
      /\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/g,
      /\$this->input->get\(/g,
      /\bquery\s*\(\s*["'][^"']*["']\s*\.\s*\$_/gi,
      /->query\s*\(\s*["'][^"']*["']\s*\.\s*\$_/gi,
      /->prepare\s*\(\s*["'][^"']*["']\s*\.\s*\$_/gi,
      /mysqli_query\s*\(\s*[^,]+,\s*["'][^"']*["']\s*\.\s*\$_/gi,
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
