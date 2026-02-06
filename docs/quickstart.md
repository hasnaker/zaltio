# Zalt.io Quickstart

**5 dakikada auth entegrasyonu**

---

## 1. Realm Al

Her proje için bir realm gerekli. Admin'den realm ID al veya oluştur.

```
Örnek: clinisyn, hsd-crm, hsd-erp
```

---

## 2. Backend'de Token Doğrulama

### Node.js / Express

```bash
npm install jsonwebtoken jwks-rsa
```

```typescript
// middleware/auth.ts
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const client = jwksClient({
  jwksUri: 'https://api.zalt.io/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 600000
});

function getKey(header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) {
  client.getSigningKey(header.kid, (err, key) => {
    callback(err, key?.getPublicKey());
  });
}

export function verifyToken(token: string): Promise<any> {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, {
      issuer: 'https://api.zalt.io',
      audience: 'https://api.zalt.io',
      algorithms: ['RS256']
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}

// Express middleware
export async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }
  
  try {
    req.user = await verifyToken(token);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}
```

---

## 3. Frontend'de Login

### React / Next.js

```typescript
// lib/auth.ts
const API = 'https://api.zalt.io';
const REALM = 'your-realm-id';

export async function login(email: string, password: string) {
  const res = await fetch(`${API}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ realm_id: REALM, email, password })
  });
  
  const data = await res.json();
  
  // MFA gerekli mi?
  if (data.mfa_required) {
    return { mfaRequired: true, mfaSessionId: data.mfa_session_id };
  }
  
  // Token'ları sakla
  localStorage.setItem('access_token', data.tokens.access_token);
  localStorage.setItem('refresh_token', data.tokens.refresh_token);
  
  return { user: data.user };
}

export async function verifyMFA(mfaSessionId: string, code: string) {
  const res = await fetch(`${API}/v1/auth/mfa/login/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfa_session_id: mfaSessionId, code })
  });
  
  const data = await res.json();
  
  localStorage.setItem('access_token', data.tokens.access_token);
  localStorage.setItem('refresh_token', data.tokens.refresh_token);
  
  return { user: data.user };
}

export function getToken() {
  return localStorage.getItem('access_token');
}

export async function refreshToken() {
  const refresh = localStorage.getItem('refresh_token');
  if (!refresh) throw new Error('No refresh token');
  
  const res = await fetch(`${API}/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refresh })
  });
  
  const data = await res.json();
  
  localStorage.setItem('access_token', data.tokens.access_token);
  localStorage.setItem('refresh_token', data.tokens.refresh_token);
  
  return data.tokens;
}

export function logout() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
}
```

---

## 4. API İstekleri

```typescript
// lib/api.ts
import { getToken, refreshToken } from './auth';

export async function apiRequest(path: string, options: RequestInit = {}) {
  const token = getToken();
  
  const res = await fetch(`https://your-api.com${path}`, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });
  
  // Token expired - refresh and retry
  if (res.status === 401) {
    await refreshToken();
    return apiRequest(path, options);
  }
  
  return res.json();
}
```

---

## 5. Kullanıcı Kaydı

```typescript
export async function register(email: string, password: string, profile?: any) {
  const res = await fetch(`${API}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      realm_id: REALM,
      email,
      password,
      profile
    })
  });
  
  return res.json();
}
```

---

## Checklist

- [ ] Realm ID al
- [ ] Backend'de JWT doğrulama ekle
- [ ] Frontend'de login/logout implement et
- [ ] Token refresh logic ekle
- [ ] MFA flow'u handle et (opsiyonel)

---

## Sonraki Adımlar

- [MFA Kurulumu](./guides/mfa-setup.md)
- [WebAuthn/Passkeys](./guides/webauthn.md)
- [Error Handling](./reference/error-codes.md)
