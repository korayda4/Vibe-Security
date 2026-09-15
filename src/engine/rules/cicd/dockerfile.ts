import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'CI-003',
  title: 'Insecure Dockerfile (root user, latest tag, ADD with URL)',
  layer: 'cicd',
  severity: 'medium',
  description:
    'If a Dockerfile does not declare a `USER` directive, the container runs as root. The `latest` tag makes builds non-reproducible, and `ADD`ing from a URL exposes the build to MITM attacks.',
  threat: 'Container escape, root privilege escalation, unpredictable builds, supply chain',
  remediation:
    '1) Use `FROM <image>:<pinned-version>` (pin by digest: `@sha256:...`). ' +
    '2) Run as `USER nonroot:nonroot` or with a specific UID. ' +
    '3) Use `COPY` and copy only what you need; never `ADD <url>` (download with curl/wget and verify the checksum instead). ' +
    '4) Use multi-stage builds so build tools never reach the final image. ' +
    '5) Use minimal bases (`gcr.io/distroless/*`, `alpine`). ' +
    '6) Use `.dockerignore` to keep secrets, `node_modules`, and `.git` out of the build context.',
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
