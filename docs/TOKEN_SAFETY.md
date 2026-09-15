# Token Safety â€” Vibe Security Kapsamli Rehber

Bu dokuman AI Vibe Coder'larin urettigi kodda **token guvenligi** ile ilgili tum riskleri ve dogru pratikleri toplar. Vibe Security asagidaki kurallarla bu riskleri otomatik tespit eder:

| Kural | Tespit ettigi |
|---|---|
| `FE-002` | localStorage/sessionStorage'da token, cookie HttpOnly/Secure/SameSite eksik |
| `BE-003` | JWT `alg: none`, zayif secret, imzasiz kullanim |
| `BE-008` | Token'in URL query string veya path'te tasinmasi |
| `BE-009` | JWT/oturum token'da expiry (exp) claim yok veya cok uzun omurlu |
| `CI-002` | Hardcoded secret/token kaynak kod veya `.env`'de |

---

## 1. Token turleri ve dogru kullanim

### Access Token
- **Nedir:** API'ye istek yaparken kullanilan kisa omurlu token (genelde JWT).
- **Omur:** 5-15 dakika. Asla saatler/gunler olmamali.
- **Saklama:** Server-side cookie (HttpOnly + Secure + SameSite=Strict) veya memory-only frontend state.
- **Vibe Security kontrolu:** `BE-009` (omur kontrolu).

### Refresh Token
- **Nedir:** Access token'in omru bitince yenisini almak icin kullanilan uzun omurlu token.
- **Omur:** 7-30 gun, **rotasyon zorunlu** (her kullanÄ±mda yenilenmeli).
- **Saklama:** Server-side cookie (HttpOnly + Secure), **asla** JavaScript'ten erisilebilir Olmamali.
- **Vibe Security kontrolu:** `FE-002`.

### Session ID (server-side session)
- **Nedir:** Sunucuda tutulan oturumun referansi.
- **Omur:** Oturum boyunca (genelde 24 saat, sliding window).
- **Saklama:** Cookie (HttpOnly + Secure + SameSite).
- **Vibe Security kontrolu:** `FE-002`.

### API Key / Service Token
- **Nedir:** Servisler arasinda kimlik dogrulamak icin kullanilan kalici token.
- **Omur:** Belirsiz; rotasyon 90 gunde bir ZORUNLU.
- **Saklama:** Vault / AWS Secrets Manager / Doppler. **ASLA** kod veya .env.
- **Vibe Security kontrolu:** `CI-002`.

### OAuth Bearer Token
- **Nedir:** OAuth 2.0 akisinda alinan access/refresh token.
- **Omur:** Access 1 saat, refresh 30 gun (RFC 6749 oneri).
- **Saklama:** Access â†’ memory; refresh â†’ server-side cookie.
- **Vibe Security kontrolu:** `BE-003`, `BE-008`.

### CSRF Token
- **Nedir:** Cross-site request forgery'ye karsi tek kullanÄ±mlÄ±k token.
- **Omur:** Oturum boyunca veya tek istek.
- **Saklama:** Hidden form field + server-side dogrulama.
- **Vibe Security kontrolu:** Manuel kontrol (gelecek kural).

---

## 2. EN KRITIK hatalar ve ornekler

### 2.1 Token URL'de tasimak (BE-008)

```javascript
// âŒ YANLIS â€” token URL'de, sunucu loglarinda, browser history'de gorunur
app.get('/api/data', (req, res) => {
  const token = req.query.token; // URL'den okuma
  verifyToken(token);
});

// âŒ YANLIS â€” token path'te
app.get('/api/users/:token/profile', ...);

// âŒ YANLIS â€” 3rd party servise token URL'de gondermek
fetch(`https://api.example.com/data?api_key=${API_KEY}`);
```

```javascript
// âœ… DOGRU â€” Authorization header
fetch('/api/data', {
  headers: { Authorization: `Bearer ${token}` }
});

// âœ… DOGRU â€” Server-side proxy ile API key tasimak (client'da gormemek)
app.get('/api/proxy', (req, res) => {
  fetch('https://api.example.com/data', {
    headers: { 'X-API-Key': process.env.API_KEY } // server-only
  });
});
```

**Neden kritik:**
- URL'ler sunucu access log'larina, browser history'e, referer header'ina yazilir
- Reverse proxy'ler URL'leri loglar
- Screenshot/ekran paylasiminda token ifsa olur
- OWASP API3:2023 Broken Object Property Level Authorization ile zincir saldirilar

### 2.2 Long-lived token, expiry yok (BE-009)

```javascript
// âŒ YANLIS â€” token 1 yil geÃ§erli
jwt.sign({ userId: 1 }, SECRET, { expiresIn: '365d' });

// âŒ YANLIS â€” exp yok
jwt.sign({ userId: 1 }, SECRET); // no expiry

// âŒ YANLIS â€” exp kontrol etmeden kabul etmek
const decoded = jwt.decode(token); // verify degil decode!
if (decoded.userId) { /* yetki ver */ }
```

```javascript
// âœ… DOGRU â€” kisa omur
jwt.sign({ userId: 1 }, SECRET, { expiresIn: '15m' });

// âœ… DOGRU â€” verify ile okuma + expiry kontrolu
const decoded = jwt.verify(token, SECRET, {
  algorithms: ['HS256'],
  maxAge: '15m',
});
if (decoded.exp < Math.floor(Date.now() / 1000)) throw new Error('expired');
```

**Neden kritik:**
- Sizdirilmis token sonsuza kadar gecerli kalir
- Kullanici sifre degisse bile eski token calisir
- Logout gercek bir logout degildir (token hÃ¢lÃ¢ gecerli)

### 2.3 localStorage'da token (FE-002)

```javascript
// âŒ YANLIS â€” XSS ile calinabilir
localStorage.setItem('jwt', token);
const token = localStorage.getItem('jwt');

// âŒ YANLIS â€” Sadece Secure yok, SameSite yok
res.cookie('session', token, { httpOnly: true });
```

```javascript
// âœ… DOGRU â€” server-side cookie, tum flag'ler
res.cookie('session', token, {
  httpOnly: true,   // JS erisimi yok
  secure: true,     // sadece HTTPS
  sameSite: 'strict', // CSRF korumasi
  maxAge: 15 * 60 * 1000, // 15 dakika
  path: '/',
  domain: '.example.com',
});

// âœ… DOGRU â€” Frontend'de token memory-only (sayfa yenileyince sifirlanir)
let authToken: string | null = null;
export function setToken(t: string) { authToken = t; }
```

### 2.4 JWT alg: none veya zayif secret (BE-003)

```javascript
// âŒ YANLIS â€” alg: none, saldirgan imzayi atlar
jwt.verify(token, '', { algorithms: ['none'] });

// âŒ YANLIS â€” 12 karakter secret
const SECRET = 'my-secret-12';

// âŒ YANLIS â€” decode yerine verify kullanmamak
const payload = jwt.decode(token); // imza kontrolsuz!
```

```javascript
// âœ… DOGRU â€” RS256 (asimetrik), en az 256-bit secret veya key pair
const publicKey = fs.readFileSync('public.pem');
jwt.verify(token, publicKey, { algorithms: ['RS256'] });

// âœ… DOGRU â€” HS256 + guclu secret
const SECRET = crypto.randomBytes(64).toString('hex'); // 128 hex char
jwt.verify(token, SECRET, { algorithms: ['HS256'] });
```

### 2.5 Hardcoded secret (CI-002)

```javascript
// âŒ YANLIS â€” token koda gomulu
const STRIPE_KEY = 'sk_live_abc123...';

// âŒ YANLIS â€” .env Git'e commitlenmis
// .env
JWT_SECRET=mysecret
```

```javascript
// âœ… DOGRU â€” environment variable + secret manager
const STRIPE_KEY = process.env.STRIPE_KEY; // Vault'tan gelir
```

---

## 3. Token rotation stratejisi

Her token turu icin **zorunlu rotasyon** politikasi:

| Token | Rotasyon | Nasil |
|---|---|---|
| Access (JWT) | Surekli (kisa omur) | 15 dk + refresh |
| Refresh | Her kullanim | Rotation + revocation store (Redis'te blacklist) |
| Session ID | Login'de | Yeniden olustur (regenerate) |
| API Key | 90 gunde bir | Vault rotate + grace period |
| OAuth access | Auto (kisa omur) | Provider tarafindan |
| OAuth refresh | 30 gunde bir | Kullanici onayli re-auth |

**Refresh token rotation ornegi:**

```javascript
async function rotateRefreshToken(oldToken) {
  const stored = await db.refreshTokens.findOne({ token: oldToken, revoked: false });
  if (!stored) {
    // Token reuse tespit â€” tum session'i iptal et
    await db.refreshTokens.updateMany(
      { userId: stored.userId },
      { revoked: true }
    );
    throw new Error('Token reuse detected');
  }

  // Eski token'i iptal et
  stored.revoked = true;
  await stored.save();

  // Yeni token uret
  const newRefresh = crypto.randomBytes(32).toString('hex');
  await db.refreshTokens.create({ token: newRefresh, userId: stored.userId });

  // Yeni access token
  const access = jwt.sign({ userId: stored.userId }, SECRET, { expiresIn: '15m' });

  return { access, refresh: newRefresh };
}
```

---

## 4. Token saklama matris karar agaci

```
Token'i nereye koyacagim?
â”‚
â”œâ”€ Client tarafinda saklamam gerekiyor mu?
â”‚  â”œâ”€ Hayir â†’ Server-only (env var, Vault)
â”‚  â””â”€ Evet â†’ Client tarafi icin devam et
â”‚
â”œâ”€ JavaScript'ten erisim gerekli mi?
â”‚  â”œâ”€ Hayir â†’ HttpOnly cookie (en guvenli)
â”‚  â””â”€ Evet â†’ Memory-only state veya sessionStorage
â”‚
â”œâ”€ Sayfa yenileyince korunmali mi?
â”‚  â”œâ”€ Hayir â†’ Memory-only (en dusuk risk)
â”‚  â””â”€ Evet â†’ Cookie veya sessionStorage (kisitli sure)
â”‚
â””â”€ Cross-site isteklerde gonderilecek mi?
   â”œâ”€ Hayir â†’ SameSite=Strict
   â””â”€ Evet â†’ SameSite=Lax + CSRF token
```

---

## 5. Incident response â€” token sizdirildiginda

1. **HEMEN rotate** â€” sizdirilmis tokeni gecersiz kil, yenisini uret
2. **Tum session'lari revoke et** â€” kullanicinin tum aktif oturumlarini sonlandir
3. **Audit log kontrol et** â€” token ne zaman, nerede, kim tarafindan kullanildi
4. **Sizma noktasini bul** â€” log, error, monitoring, git history
5. **Kullanici bilgilendir** â€” email/in-app notification
6. **Post-mortem** â€” neden oldu, nasil engellenir

---

## 6. Vibe Security'in token kurallari calisma sekli

Scanner asagidaki pattern'leri **statik olarak** yakalar. Tam kapsamli tespit icin **data-flow analysis** Faz 3'te gelecek (tree-sitter tabanli).

| Kural | Statik tespit | Data-flow gerekli |
|---|---|---|
| `FE-002` localStorage token | âœ… | âŒ |
| `BE-003` JWT alg=none | âœ… | âŒ |
| `BE-008` token in URL | âœ… | âŒ |
| `BE-009` token expiry yok | âœ… (expireIn yok) | Kismen |
| `CI-002` hardcoded secret | âœ… (regex) | âŒ |

**Limitler:**
- Runtime token handling taranmaz (memory'de tutulan token)
- Encrypted/obfuscated token'lari yakalayamaz
- Multi-file data flow (A dosyasindaki secret â†’ B dosyasinda kullanilmasi) sadece kismen

---

## 7. Daha fazla referans

- OWASP API Security Top 10 â€” API2:2023 Broken Authentication
- OWASP CheatSheet: [JSON Web Token for Java](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- OWASP CheatSheet: [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- RFC 8725 â€” JSON Web Token Best Current Practices
- Auth0: [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- OWASP ASVS (Application Security Verification Standard) â€” V3 Session Management, V4 Access Control, V6 Cryptography
