import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'CI-003',
  title: 'Insecure Dockerfile (root user, latest tag, ADD with URL)',
  layer: 'cicd',
  severity: 'medium',
  description:
    'Dockerfile\'da `USER` belirtilmemisse konteyner root olarak calisir; `latest` tag tekrarlanamaz; `ADD` URL\'den dosya cekmek MITM\'e aciktir.',
  threat: 'Container escape, root privilege escalation, unpredictable builds, supply chain',
  remediation:
    '1) `FROM <image>:<pinned-version>` kullanin (digest\'e pinleyin: `@sha256:...`). ' +
    '2) `USER nonroot:nonroot` veya specific UID ile calistirin. ' +
    '3) `COPY` kullanin; sadece gerekli dosyalari kopyalayin. `ADD <url>` kullanmayin (curl/wget ile indirip checksum dogrulayin). ' +
    '4) Multi-stage build ile build tool\'lari final imaja sokmayin. ' +
    '5) Minimal taban (`gcr.io/distroless/*`, `alpine`) kullanin. ' +
    '6) `.dockerignore` ile secret / node_modules / .git\'i disarida birakin.',
  references: [
    'https://docs.docker.com/develop/dev-best-practices/',
    'https://snyk.io/learn/docker-security/',
    'https://github.com/hadolint/hadolint',
  ],
  cwe: 'CWE-250',
  owasp: 'A05:2021 Security Misconfiguration',
  languages: ['dockerfile'],
  check: (ctx) => {
    const findings = [];
    const lines = ctx.lines;

    const hasUser = /^USER\s+/m.test(ctx.source);
    const hasLatest = /FROM\s+\S+:latest\b/.exec(ctx.source);
    const hasAddUrl = /^ADD\s+https?:\/\//m.test(ctx.source);

    if (!hasUser) {
      findings.push(...grepRule(rule, ctx, /^FROM\s+/gm));
    }
    if (hasLatest) {
      findings.push(...grepRule(rule, ctx, /FROM\s+\S+:latest\b/g));
    }
    if (hasAddUrl) {
      findings.push(...grepRule(rule, ctx, /^ADD\s+https?:\/\//gm));
    }
    return findings;
  },
};

export default rule;
