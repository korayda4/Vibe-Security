import path from 'node:path';
import type { Finding, FixPatch, Rule, RuleContext } from '../../../types.js';
import { lineColumnFromIndex, snippetAt } from '../_helpers.js';

const BENIGN_VALUES = new Set([
  'your_api_key',
  'your_api_key_here',
  'your_secret_key',
  'your_password',
  'change_me',
  'changeme',
  'placeholder',
  'example',
  'dummy',
  'sample',
  'todo',
  'test',
  'test_key',
  'xxx',
  'xxxx',
  '123456',
  'insert_here',
  'replace_me',
  'fake',
  'mock',
  'none',
  'null',
  'undefined',
  'false',
  'true',
]);

function isBenignPlaceholder(val: string): boolean {
  const clean = val.trim().toLowerCase();
  if (clean.length < 8) return true;
  if (BENIGN_VALUES.has(clean)) return true;
  if (/^(?:your[_-]?(?:api[_-]?)?key|change[_-]?me|my[_-]?secret|dummy|example|placeholder)/i.test(clean)) return true;
  if (/^\${?[A-Z0-9_]+}?$/.test(val.trim())) return true; // Interpolated env var like ${DB_PASS}
  if (/^process\.env\./.test(val.trim()) || /^os\.environ/.test(val.trim())) return true;
  return false;
}

function extractVarAssignmentFix(lineText: string, secretValue: string, isPython: boolean): FixPatch | undefined {
  const varMatch = lineText.match(/(?:const|let|var|export\s+const)\s+([A-Za-z0-9_]+)\s*=\s*(['"`])/);
  if (varMatch) {
    const varName = varMatch[1];
    const quote = varMatch[2];
    const prefix = varMatch[0].split('=')[0];
    const hasSemicolon = lineText.includes(`${varMatch[0]}${secretValue}${quote};`);
    const findStr = hasSemicolon ? `${varMatch[0]}${secretValue}${quote};` : `${varMatch[0]}${secretValue}${quote}`;
    const semi = hasSemicolon ? ';' : '';
    return {
      find: findStr,
      replace: isPython
        ? `${prefix}= os.environ.get('${varName}', '')`
        : `${prefix}= process.env.${varName} || ''${semi}`,
      description: `Extract ${varName} to .env and reference via environment variable`,
    };
  }
  return undefined;
}

const rule: Rule = {
  id: 'AI-005',
  title: 'Hardcoded secret, API key, or credential outside of .env',
  layer: 'backend',
  severity: 'critical',
  description:
    'Detects private API keys (OpenAI, Anthropic, Gemini, Stripe, etc.), database connection strings with embedded passwords, secret webhooks, and credentials hardcoded in source code or committed .env files instead of being safely stored in gitignored .env files.',
  threat:
    'Severe credential exposure, unauthorized API usage & billing spikes, complete database takeover, private webhook hijacking, permanent Git repository leak.',
  remediation:
    '1) Move secret values into your local .env file (e.g. SERVICE_API_KEY=your_key).\n' +
    '2) Ensure .env, .env.local, .env.production are listed in .gitignore.\n' +
    '3) Access the secret via environment variables (process.env.SERVICE_API_KEY in Node/TS, or os.environ.get("SERVICE_API_KEY") in Python).\n' +
    '4) Never commit active credentials to version control.',
  references: [
    'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
    'https://12factor.net/config',
    'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
  ],
  cwe: 'CWE-798',
  owasp: 'A07:2021 Identification and Authentication Failures',
  languages: [
    'javascript',
    'typescript',
    'python',
    'java',
    'kotlin',
    'go',
    'rust',
    'ruby',
    'php',
    'json',
    'yaml',
    'toml',
    'unknown',
  ],
  check: (ctx: RuleContext): Finding[] => {
    const findings: Finding[] = [];
    const baseName = path.basename(ctx.relativePath).toLowerCase();

    // Skip example/template/sample env files which legitimately contain placeholder variable names
    if (
      baseName.includes('.example') ||
      baseName.includes('.template') ||
      baseName.includes('.sample') ||
      baseName.includes('.dist')
    ) {
      return [];
    }

    const isEnvFile = baseName === '.env' || baseName.startsWith('.env.');
    const isPython = ctx.language === 'python';

    // 1. High-precision AI and LLM API keys
    const aiKeyPatterns: Array<{ re: RegExp; name: string }> = [
      { re: /\b(sk-(?:proj-)?[a-zA-Z0-9_\-]{32,})\b/g, name: 'OpenAI API key' },
      { re: /\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b/g, name: 'Anthropic API key' },
      { re: /\b(AIza[0-9A-Za-z-_]{30,35})\b/g, name: 'Google Gemini / Cloud API key' },
      { re: /\b(hf_[a-zA-Z0-9]{34,})\b/g, name: 'HuggingFace API token' },
      { re: /\b(gsk_[a-zA-Z0-9]{40,})\b/g, name: 'Groq API key' },
      { re: /\b(pcsk_[a-zA-Z0-9_\-]{30,})\b/g, name: 'Pinecone API key' },
      { re: /\b(r8_[a-zA-Z0-9]{37})\b/g, name: 'Replicate API token' },
    ];

    for (const { re, name } of aiKeyPatterns) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const matchedKey = m[1];
        if (isBenignPlaceholder(matchedKey)) continue;

        const { line, column } = lineColumnFromIndex(ctx.source, m.index);
        const lineText = ctx.lines[line - 1] ?? '';
        const fix = !isEnvFile ? extractVarAssignmentFix(lineText, matchedKey, isPython) : undefined;

        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
          ruleId: rule.id,
          title: `${rule.title} (${name})`,
          layer: rule.layer,
          severity: rule.severity,
          file: ctx.relativePath,
          match: { snippet: snippetAt(ctx.source, line), line, column },
          description: `Found hardcoded ${name}. Move this credential to .env and reference it via environment variables.`,
          impact: rule.threat,
          remediation: rule.remediation,
          references: rule.references,
          cwe: rule.cwe,
          owasp: rule.owasp,
          fix,
        });
      }
    }

    // 2. Database Connection Strings with embedded credentials
    const dbUriPattern =
      /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis(?:s)?|amqps?):\/\/[^\s'"`:@/]+:([^@\s'"`/]{4,})@[^\s'"`/]+/gi;

    for (const m of ctx.source.matchAll(dbUriPattern)) {
      if (m.index === undefined) continue;
      const password = m[1];
      if (isBenignPlaceholder(password)) continue;

      const { line, column } = lineColumnFromIndex(ctx.source, m.index);
      findings.push({
        id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
        ruleId: rule.id,
        title: `${rule.title} (Database URI with embedded password)`,
        layer: rule.layer,
        severity: rule.severity,
        file: ctx.relativePath,
        match: { snippet: snippetAt(ctx.source, line), line, column },
        description:
          'Found hardcoded database connection string with plaintext password. Move DATABASE_URL to .env.',
        impact: 'Full database compromise, table dropping, and sensitive data extraction.',
        remediation: rule.remediation,
        references: rule.references,
        cwe: 'CWE-798',
        owasp: rule.owasp,
      });
    }

    // 3. SaaS, Cloud & Webhook Secrets
    const saasPatterns: Array<{ re: RegExp; name: string }> = [
      { re: /\b(AKIA[0-9A-Z]{16})\b/g, name: 'AWS Access Key ID' },
      { re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b/g, name: 'Stripe Live Secret Key' },
      { re: /\b(whsec_[0-9a-zA-Z]{24,})\b/g, name: 'Stripe Webhook Secret' },
      { re: /\b(gh[pousr]_[0-9a-zA-Z]{36})\b/g, name: 'GitHub Personal Access Token' },
      { re: /\b(github_pat_[0-9a-zA-Z_]{82})\b/g, name: 'GitHub Fine-Grained Token' },
      {
        re: /(https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24})/g,
        name: 'Slack Incoming Webhook URL',
      },
      {
        re: /(https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{50,})/g,
        name: 'Discord Webhook URL',
      },
      { re: /\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b/g, name: 'SendGrid API Key' },
      { re: /\b(AC[a-zA-Z0-9]{32})\b/g, name: 'Twilio Account SID' },
    ];

    for (const { re, name } of saasPatterns) {
      for (const m of ctx.source.matchAll(re)) {
        if (m.index === undefined) continue;
        const matched = m[1];
        if (isBenignPlaceholder(matched)) continue;

        const { line, column } = lineColumnFromIndex(ctx.source, m.index);
        const lineText = ctx.lines[line - 1] ?? '';
        const fix = !isEnvFile ? extractVarAssignmentFix(lineText, matched, isPython) : undefined;

        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
          ruleId: rule.id,
          title: `${rule.title} (${name})`,
          layer: rule.layer,
          severity: rule.severity,
          file: ctx.relativePath,
          match: { snippet: snippetAt(ctx.source, line), line, column },
          description: `Found hardcoded ${name}. Move this private secret to .env.`,
          impact: rule.threat,
          remediation: rule.remediation,
          references: rule.references,
          cwe: rule.cwe,
          owasp: rule.owasp,
          fix,
        });
      }
    }

    // 4. Generic variable assignments (e.g. const JWT_SECRET = "...")
    if (!isEnvFile) {
      const varAssignPattern =
        /(?:const|let|var|export\s+const)\s+([A-Z0-9_]*(?:API_KEY|SECRET|PASSWORD|AUTH_TOKEN|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*(['"`])([^'"`\r\n]{10,})\2/g;

      for (const m of ctx.source.matchAll(varAssignPattern)) {
        if (m.index === undefined) continue;
        const varName = m[1];
        const quote = m[2];
        const val = m[3];

        if (isBenignPlaceholder(val)) continue;
        const { line, column } = lineColumnFromIndex(ctx.source, m.index);
        // Avoid duplicate finding if specific key pattern already captured this line
        if (findings.some((f) => f.match.line === line)) continue;

        const fullMatch = m[0];
        let fix: FixPatch | undefined;
        if (isPython) {
          fix = {
            find: fullMatch,
            replace: fullMatch.replace(`${quote}${val}${quote}`, `os.environ.get('${varName}', '')`),
            description: `Extract ${varName} to .env and reference via os.environ.get`,
          };
        } else {
          fix = {
            find: fullMatch,
            replace: fullMatch.replace(`${quote}${val}${quote}`, `process.env.${varName} || ''`),
            description: `Extract ${varName} to .env and reference via process.env`,
          };
        }

        findings.push({
          id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
          ruleId: rule.id,
          title: `${rule.title} (${varName})`,
          layer: rule.layer,
          severity: rule.severity,
          file: ctx.relativePath,
          match: { snippet: snippetAt(ctx.source, line), line, column },
          description: `Variable '${varName}' contains a hardcoded secret string. Move this value to .env.`,
          impact: rule.threat,
          remediation: rule.remediation,
          references: rule.references,
          cwe: rule.cwe,
          owasp: rule.owasp,
          fix,
        });
      }
    } else {
      // 5. If this is a committed .env file (and findings exist inside it), add a file-level notice
      if (findings.length > 0) {
        findings.push({
          id: `${rule.id}-${ctx.relativePath}-committed-env`,
          ruleId: rule.id,
          title: 'Committed .env file with active secrets detected in repository',
          layer: 'cicd',
          severity: 'critical',
          file: ctx.relativePath,
          match: { snippet: `File: ${ctx.relativePath}`, line: 1, column: 0 },
          description:
            `The environment file '${ctx.relativePath}' contains active secrets and is present in the repository. ` +
            'Add this file to .gitignore immediately and rotate any exposed keys.',
          impact: 'Permanent leak of production secrets to Git history, public repository clones, and CI logs.',
          remediation: '1) Add .env to .gitignore.\n2) Run git rm --cached .env to unstage it.\n3) Rotate all compromised secrets.',
          references: rule.references,
          cwe: 'CWE-798',
          owasp: rule.owasp,
        });
      }
    }

    return findings;
  },
};

export default rule;
