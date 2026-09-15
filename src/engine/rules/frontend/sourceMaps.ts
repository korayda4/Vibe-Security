import type { Rule } from '../../../types.js';
import { lineColumnFromIndex, snippetAt } from '../_helpers.js';

const rule: Rule = {
  id: 'FE-004',
  title: 'Source maps published in production',
  layer: 'frontend',
  severity: 'medium',
  description:
    'Publishing .js.map files in production output exposes source code (component names, comments, internal architecture) to anyone. Attackers can reverse engineer and discover sensitive internals (URLs, developer notes).',
  threat: 'Source code disclosure, architecture reconnaissance, intellectual property leak',
  remediation:
    '1) Next.js: set productionBrowserSourceMaps: false. ' +
    '2) Vite: set build.sourcemap = false or upload to Sentry / Datadog. ' +
    '3) Webpack: use devtool: false or hidden-source-map, then upload to Sentry. ' +
    '4) Block *.map access at CDN/Nginx: location ~* \\.map$ { deny all; }',
  references: [
    'https://nextjs.org/docs/advanced-features/source-maps',
    'https://webpack.js.org/configuration/devtool/',
    'https://docs.sentry.io/platforms/javascript/sourcemaps/',
  ],
  cwe: 'CWE-540',
  owasp: 'A05:2021 Security Misconfiguration',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const findings = [];

    const nextPattern = /productionBrowserSourceMaps\s*:\s*true/g;
    for (const m of ctx.source.matchAll(nextPattern)) {
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
        fix: {
          find: 'productionBrowserSourceMaps: true',
          replace: 'productionBrowserSourceMaps: false',
          description: 'Disable production source maps',
        },
      });
    }

    const vitePattern = /build\.sourcemap\s*=\s*['"]?true/g;
    for (const m of ctx.source.matchAll(vitePattern)) {
      if (m.index === undefined) continue;
      const { line } = lineColumnFromIndex(ctx.source, m.index);
      findings.push({
        id: `${rule.id}-${ctx.relativePath}-${line}-vite`,
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
        fix: {
          find: 'build.sourcemap = true',
          replace: 'build.sourcemap = false',
          description: 'Disable Vite sourcemap generation',
        },
      });
    }

    return findings;
  },
};

export default rule;
