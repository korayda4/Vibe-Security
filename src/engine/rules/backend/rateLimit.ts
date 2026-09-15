import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-006',
  title: 'Missing rate limiting / throttling on sensitive endpoints',
  layer: 'backend',
  severity: 'medium',
  description:
    'Without rate limiting on endpoints such as login, signup, password reset, or OTP verification, brute-force, credential stuffing, and denial-of-service become trivial.',
  threat: 'Brute force, credential stuffing, OTP enumeration, denial of service, scraping',
  remediation:
    '1) Use **express-rate-limit**, **rate-limiter-flexible**, or **slowapi** (Python). ' +
    '2) Apply two layers: IP-based AND user/token-based. ' +
    '3) For login endpoints, cap at ~5 attempts per 15 minutes per IP+user. ' +
    '4) Slow failed attempts with exponential backoff. ' +
    '5) After 5 failures, temporarily lock the account and notify the user. ' +
    '6) Add CAPTCHA or Turnstile on sensitive flows. ' +
    '7) Apply a global rate limit at the edge (Cloudflare, API Gateway).',
  references: [
    'https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks',
    'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling',
  ],
  cwe: 'CWE-307',
  owasp: 'A07:2021 Identification and Authentication Failures',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const isServerFile =
      /(?:server|app|main|index|routes)\.(?:ts|js|py|go|java)$/i.test(ctx.relativePath) ||
      /\/routes?\//i.test(ctx.relativePath) ||
      /\/api\//i.test(ctx.relativePath);

    if (!isServerFile) return [];

    const hasRateLimit =
      /rate[-_]?limit|rateLimit|throttle|bruteforce|slowapi|express-rate-limit/i.test(ctx.source);

    if (hasRateLimit) return [];

    const authRoutes = [
      /\bapp\.(?:post|put|get)\s*\(\s*['"`](?:\/api)?\/?(?:login|signin|signup|register|auth|reset-?password|forgot-?password|verify-?otp|2fa)/gi,
      /@app\.route\s*\(\s*['"`](?:\/api)?\/?(?:login|signin|signup|register|auth|reset-?password|forgot-?password)/gi,
      /router\.post\s*\(\s*['"`](?:\/api)?\/?(?:login|signin|signup|register|auth|reset-?password|forgot-?password)/gi,
    ];

    const findings = [];
    for (const re of authRoutes) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
