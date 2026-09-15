/**
 * Test fixture — bilinen zaafiyetleri olan ornek React component.
 * Tarayicinin bunlari dogru yakalamasi bekleniyor.
 */

import { useEffect, useState } from 'react';
import express from 'express';
import jwt from 'jsonwebtoken';

const SECRET = 'my-super-secret-key-123'; // BE-002: weak, hardcoded

function UserComment({ html }: { html: string }) {
  // FE-001: XSS
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

function LegacyDashboard() {
  // FE-002: token in localStorage
  const token = localStorage.getItem('jwt');
  const [user, setUser] = useState<{ balance: number } | null>(null);

  useEffect(() => {
    // FE-006: eval
    eval(`fetchUserData(${token})`);
  }, [token]);

  return (
    <div
      // FE-001: innerHTML
      ref={(el) => {
        if (el) el.innerHTML = `<h1>Welcome ${user?.name}</h1>`;
      }}
    />
  );
}

function loginHandler(req: express.Request, res: express.Response) {
  // BE-003: alg: none
  const token = jwt.sign({ userId: 1 }, SECRET, { algorithm: 'none' as any });
  res.json({ token });
}

function callbackHandler(req: express.Request, res: express.Response) {
  // BE-008: token in URL query
  const token = req.query.token;
  verifyAndUseToken(token);

  // BE-008: token ile fetch URL'de
  const apiKey = process.env.SECRET_API_KEY;
  fetch(`https://api.example.com/data?api_key=${apiKey}`);

  // BE-009: long-lived token, 365 gun
  const longToken = jwt.sign({ userId: 1 }, SECRET, { expiresIn: '365d' });
  res.json({ token: longToken });
}

const app = express();

// NET-002: CORS wildcard
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

app.post('/api/login', (req, res) => {
  // BE-004: SQL injection
  const query = `SELECT * FROM users WHERE email = '${req.body.email}' AND password = '${req.body.password}'`;
  db.query(query, (err: any, rows: any) => {
    if (err) {
      // OBS-001: stack trace exposed
      return res.send({ error: err.stack });
    }
    // BE-002: plain text password compare
    if (rows[0].password === req.body.password) {
      res.json({ token });
    }
  });
});

app.get('/api/users/:id', async (req, res) => {
  // BE-001: IDOR — no ownership check
  const user = await db.user.findUnique({ where: { id: req.params.id } });
  res.json(user);
});

app.post('/api/users', async (req, res) => {
  // BE-005: mass assignment
  const user = await db.user.create({ data: req.body });
  res.json(user);
});

const db = {
  query: (_q: string, _cb: any) => {},
  user: {
    findUnique: async (_args: any) => null,
    create: async (_args: any) => null,
  },
};

export default app;
