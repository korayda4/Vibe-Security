import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'AI-002',
  title: 'Supabase SERVICE_ROLE_KEY exposed in client code or public environment',
  layer: 'frontend',
  severity: 'critical',
  description:
    'The Supabase SERVICE_ROLE_KEY bypasses all Row Level Security (RLS) policies and grants full superadmin access to the database. Exposing it with NEXT_PUBLIC_ or in frontend bundles allows any user to read, modify, or drop any database table.',
  threat:
    'Total database takeover, Row Level Security (RLS) bypass, complete data breach and table tampering.',
  remediation:
    '1) Use ONLY the public SUPABASE_ANON_KEY (or NEXT_PUBLIC_SUPABASE_ANON_KEY) in client-side code.\n' +
    '2) Keep SUPABASE_SERVICE_ROLE_KEY strictly in server-side environment variables without NEXT_PUBLIC_ prefix.\n' +
    '3) Ensure Row Level Security (RLS) is enabled on every table.',
  references: [
    'https://supabase.com/docs/guides/api/api-keys#service_role-secret',
    'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
  ],
  cwe: 'CWE-200',
  owasp: 'A01:2021 Broken Access Control',
  languages: ['javascript', 'typescript'],
  check: (ctx) => {
    const patterns = [
      /NEXT_PUBLIC_[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*/gi,
      /createClient\s*\([^,]+,\s*(?:process\.env\.)?NEXT_PUBLIC_[A-Z0-9_]*SERVICE_ROLE/gi,
      /createClient\s*\([^,]+,\s*['"`]eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+['"`]\s*,\s*\{[^}]*auth\s*:\s*\{[^}]*persistSession\s*:\s*false/gi,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
