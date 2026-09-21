import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'AI-003',
  title: "Next.js Server Action with direct DB mutation missing authentication/authorization check",
  layer: 'backend',
  severity: 'high',
  description:
    "Next.js Server Actions ('use server') are public HTTP POST endpoints accessible by anyone on the internet. Mutating databases (delete, update, insert) inside server actions without verifying the caller's session/identity allows unauthorized arbitrary data modification.",
  threat:
    'Unauthenticated data manipulation, privilege escalation, IDOR / BOLA bypass via direct action invocation.',
  remediation:
    '1) Always retrieve the authenticated user session (e.g. auth(), getServerSession(), or supabase.auth.getUser()) at the top of every Server Action.\n' +
    '2) Verify that the authenticated user owns or has permission to mutate the target resource.\n' +
    '3) Validate inputs with schema libraries like Zod.',
  references: [
    'https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations#security',
    'https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html',
  ],
  cwe: 'CWE-862',
  owasp: 'A01:2021 Broken Access Control',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    // Only check if file contains 'use server' directive
    if (!ctx.source.includes("'use server'") && !ctx.source.includes('"use server"')) {
      return [];
    }

    // Flag server action mutation patterns where session/auth is not checked
    const hasAuthCheck =
      /auth\(\)|getServerSession|getUser|currentUser|requireAuth|verifySession/i.test(ctx.source);
    if (hasAuthCheck) {
      return [];
    }

    const mutationPattern =
      /(?:prisma\.[a-zA-Z0-9_]+\.(?:delete|update|create|upsert|deleteMany|updateMany)|db\.(?:delete|update|insert)|query\s*\(\s*['"`](?:DELETE|UPDATE|INSERT))/gi;

    return grepRule(rule, ctx, mutationPattern);
  },
};

export default rule;
