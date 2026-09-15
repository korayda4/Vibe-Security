# Contributing

Thanks for your interest in improving Vibe Security.

## Add a new rule

Each rule lives in `src/engine/rules/<layer>/<topic>.ts`. Pick a free ID (e.g. `BE-010`).

```ts
import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-010',
  title: 'Short, clear title',
  layer: 'backend',
  severity: 'high',
  description: 'One paragraph — what the rule detects and why.',
  threat: 'Attack vector and likelihood.',
  remediation: 'Step-by-step fix instructions.',
  references: ['https://owasp.org/...', 'https://cwe.mitre.org/...'],
  cwe: 'CWE-XXX',
  owasp: 'A0X:2021 ...',
  languages: ['typescript', 'python'],
  check: (ctx) => grepRule(rule, ctx, /your-pattern/g),
};

export default rule;
```

Register it in `src/engine/rules/<layer>/index.ts`:

```ts
import newRule from './newRule.js';
export const rules = { /* ... */ newRule };
```

## Add a new language

1. Add the language to the `Language` union in `src/types.ts`.
2. Add extension/filename/shebang/syntax patterns in `src/engine/language.ts`.
3. Create rule files in `src/engine/rules/<layer>/` with `languages: ['yourlang']`.
4. Add a test fixture file in `test/fixtures/vulnerable-app/`.
5. Add an assertion in `test/test.ts`.
6. Update the `Supported Languages` table in `README.md`.

## Pull request checklist

- [ ] `npm test` passes
- [ ] `npm run lint` passes
- [ ] `npm run build` clean
- [ ] Test fixture added for new rules
- [ ] CWE / OWASP fields populated
- [ ] No secrets / tokens / PII in code or fixtures
- [ ] Docs updated if user-facing behavior changed

## Commit message format

```
<type>(<scope>): <subject>

<optional body>
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`.
Scopes: `rules`, `scanner`, `output`, `mcp`, `integrations`, `docs`.

Examples:

```
feat(rules): add PHP SQL injection rule
fix(scanner): skip node_modules with absolute path
docs: clarify auto-fix workflow
```

## Code style

- TypeScript strict mode, ESM, `.js` extensions on imports
- Functional, side-effect-free rules
- One rule per file
- Tests via `node --test`

## License

By contributing, you agree that your contributions will be licensed under MIT.
