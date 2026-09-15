## What

A short description of what this PR changes.

## Why

Link to the issue / roadmap item this addresses.

## Checklist

- [ ] Tests added or updated (`npm test`)
- [ ] `npm run lint` passes
- [ ] `npm run build` clean
- [ ] If a new rule: fixture added to `test/fixtures/vulnerable-app/` and assertion in `test/test.ts`
- [ ] If a new rule: `cwe` and `owasp` fields populated
- [ ] No secrets / tokens / PII introduced
- [ ] Docs updated if behavior changed

## Test plan

```bash
npm test
npm run scan -- test/fixtures/vulnerable-app
```

## Screenshots / sample output

If the rule adds a finding or changes rendering, paste the relevant snippet.
