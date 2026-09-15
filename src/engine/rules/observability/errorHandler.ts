import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'OBS-002',
  title: 'Unhandled promise rejection / missing global error handler',
  layer: 'observability',
  severity: 'medium',
  description:
    'Node.js servislerinde `process.on(\'unhandledRejection\')` ve `process.on(\'uncaughtException\')` handler\'lari yoksa process crash\'ler sessizce olur, security event\'leri kaybolur, monitoring bos kalir.',
  threat: 'Silent crashes, missed security signals, denial of service via uncaught errors',
  remediation:
    'Production\'da mutlaka global handler kurun: ' +
    '`process.on(\'unhandledRejection\', (err) => { logger.error(err); metrics.increment(\'unhandled_rejection\'); })` ve ' +
    '`process.on(\'uncaughtException\', (err) => { logger.fatal(err); process.exit(1); })`. ' +
    'Express icin en sonda `app.use((err, req, res, next) => { ... })` error middleware. ' +
    'Worker queue\'larda failed job\'lari retry queue\'ya yonlendirin.',
  references: [
    'https://nodejs.org/api/process.html#warning-using-uncaughtexception-correctly',
    'https://expressjs.com/en/guide/error-handling.html',
  ],
  cwe: 'CWE-754',
  owasp: 'A09:2021 Security Logging and Monitoring Failures',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const isServerEntry = /(?:server|app|main|index)\.(?:ts|js)$/i.test(ctx.relativePath);
    if (!isServerEntry) return [];

    const hasUnhandled = /unhandledRejection|uncaughtException/.test(ctx.source);
    if (hasUnhandled) return [];

    const findings = [];
    findings.push(...grepRule(rule, ctx, /listen\s*\(\s*\d+/g));
    return findings;
  },
};

export default rule;
