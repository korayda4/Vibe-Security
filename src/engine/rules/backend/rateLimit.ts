import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-006',
  title: 'Missing rate limiting / throttling on sensitive endpoints',
  layer: 'backend',
  severity: 'medium',
  description:
    'Login, signup, password reset, OTP dogrulama gibi endpointlerde rate limiting yoksa brute-force, credential stuffing ve DoS kolaylastirilir.',
  threat: 'Brute force, credential stuffing, OTP enumeration, denial of service, scraping',
  remediation:
    '1) **express-rate-limit**, **rate-limiter-flexible**, **slowapi** (Python) kullanin. ' +
    '2) IP bazli + user/token bazli iki katman uygulayin. ' +
    '3) Login endpointleri icin 5 deneme / 15 dakika cap\'i koyun. ' +
    '4) Exponential backoff ile basarisiz denemeleri yavaslatin. ' +
    '5) 5 basarisiz denemede account\'u gecici kilitleyin + kullaniciya bildirim gonderin. ' +
    '6) Captcha veya Turnstile ekleyin. ' +
    '7) Edge seviyesinde (Cloudflare, API Gateway) global limit ekleyin.',
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
