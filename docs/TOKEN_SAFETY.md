# Token Safety

How AI Vibe Coders should handle every token type — short and actionable.

## Token types

| Token | Lifetime | Storage | Rule |
|---|---|---|---|
| **Access (JWT)** | 5–15 min | Server-side cookie (HttpOnly + Secure + SameSite) or memory | `BE-009` |
| **Refresh** | 7–30 days, rotate every use | Server-side cookie, revocation store | `FE-002` |
| **Session ID** | 24 h sliding | Server-side cookie (HttpOnly + Secure + SameSite) | `FE-002` |
| **API key / service token** | 90-day rotation | Vault / AWS Secrets Manager / Doppler — never in code | `CI-002` |
| **OAuth bearer** | 1 h access, 30 d refresh | Access: memory; refresh: server-side cookie | `BE-003`, `BE-008` |
| **CSRF** | Per session or per request | Hidden form field + server-side validation | manual check |

## Critical errors (with auto-detection)

### 1. Token in URL — `BE-008`

```javascript
const token = req.query.token;
fetch(`https://api.example.com/data?api_key=${API_KEY}`);
```

**Fix:** Use `Authorization: Bearer <token>` header. Block query-string tokens at the proxy.

### 2. No expiry / too long — `BE-009`

```javascript
jwt.sign({ userId: 1 }, SECRET, { expiresIn: '365d' });
jwt.sign({ userId: 1 }, SECRET); // no expiresIn at all
```

**Fix:** `expiresIn: '15m'` for access, `7d` for refresh (with rotation). Always call `jwt.verify()` with `maxAge` or explicit `exp` check.

### 3. Token in localStorage — `FE-002`

```javascript
localStorage.setItem('jwt', token);
```

**Fix:** Set tokens via server cookie with `HttpOnly`, `Secure`, `SameSite=Strict`, `maxAge: 15*60*1000`.

### 4. JWT `alg: none` / weak secret — `BE-003`

```javascript
jwt.verify(token, '', { algorithms: ['none'] });
const SECRET = 'my-secret-12';
const payload = jwt.decode(token); // not verify
```

**Fix:** Use `RS256` (asymmetric) or `HS256` with a 256-bit random secret. Always `verify()`, never `decode()`.

### 5. Hardcoded secret — `CI-002`

```javascript
const STRIPE_KEY = 'sk_live_abc123...';
```

**Fix:** `process.env.STRIPE_KEY` from a secret manager. Add `gitleaks` pre-commit hook.

## Rotation strategy

```javascript
async function rotateRefreshToken(oldToken) {
  const stored = await db.refreshTokens.findOne({ token: oldToken, revoked: false });
  if (!stored) {
    // Token reuse → invalidate ALL sessions for this user
    await db.refreshTokens.updateMany({ userId: stored.userId }, { revoked: true });
    throw new Error('Token reuse detected');
  }
  stored.revoked = true;
  await stored.save();
  const newRefresh = crypto.randomBytes(32).toString('hex');
  await db.refreshTokens.create({ token: newRefresh, userId: stored.userId });
  const access = jwt.sign({ userId: stored.userId }, SECRET, { expiresIn: '15m' });
  return { access, refresh: newRefresh };
}
```

## Storage decision tree

```
Token needs JavaScript access?
├── No  → HttpOnly cookie (most secure)
└── Yes → Memory-only state (lost on refresh)
         │
         └── Survive refresh?
             ├── No  → Memory-only
             └── Yes → Cookie with SameSite=Strict (no localStorage)
```

## Incident response

1. **Rotate** the leaked token immediately
2. **Revoke** all sessions for the affected user
3. **Audit** the access log to scope the impact
4. **Find** the leak source (log, error, Git history)
5. **Notify** the user
6. **Post-mortem** to prevent recurrence

## References

- OWASP API Security Top 10 — API2:2023 Broken Authentication
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 8725 — JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
