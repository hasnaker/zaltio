# MFA Kurulumu

**TOTP (Authenticator App) entegrasyonu**

---

## Genel Bakış

Zalt.io TOTP tabanlı MFA destekler. Google Authenticator, Authy, 1Password gibi uygulamalarla çalışır.

**SMS MFA yok** - SS7 güvenlik açığı nedeniyle desteklenmez.

---

## 1. MFA Setup Flow

```
Kullanıcı → Setup İste → QR Kod Al → Uygulamada Tara → Kod Doğrula → MFA Aktif
```

### Frontend Implementation

```typescript
// lib/mfa.ts
const API = 'https://api.zalt.io';

// 1. MFA Setup başlat
export async function setupMFA(accessToken: string) {
  const res = await fetch(`${API}/v1/auth/mfa/setup`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    }
  });
  
  return res.json();
  // Returns: { secret, otpauth_url, message }
}

// 2. QR kod göster (otpauth_url kullan)
// qrcode kütüphanesi ile:
import QRCode from 'qrcode';

export async function generateQRCode(otpauthUrl: string): Promise<string> {
  return QRCode.toDataURL(otpauthUrl);
}

// 3. Kodu doğrula ve MFA'yı aktifleştir
export async function verifyMFASetup(accessToken: string, code: string) {
  const res = await fetch(`${API}/v1/auth/mfa/verify`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ code })
  });
  
  return res.json();
  // Returns: { message, backup_codes, warning }
}
```

### React Component

```tsx
// components/MFASetup.tsx
import { useState } from 'react';
import { setupMFA, generateQRCode, verifyMFASetup } from '@/lib/mfa';

export function MFASetup({ accessToken }: { accessToken: string }) {
  const [step, setStep] = useState<'start' | 'scan' | 'verify' | 'done'>('start');
  const [qrCode, setQrCode] = useState('');
  const [secret, setSecret] = useState('');
  const [code, setCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState('');

  async function handleSetup() {
    try {
      const data = await setupMFA(accessToken);
      setSecret(data.secret);
      const qr = await generateQRCode(data.otpauth_url);
      setQrCode(qr);
      setStep('scan');
    } catch (err) {
      setError('Setup failed');
    }
  }

  async function handleVerify() {
    try {
      const data = await verifyMFASetup(accessToken, code);
      setBackupCodes(data.backup_codes);
      setStep('done');
    } catch (err) {
      setError('Invalid code');
    }
  }

  if (step === 'start') {
    return (
      <button onClick={handleSetup}>
        MFA Aktifleştir
      </button>
    );
  }

  if (step === 'scan') {
    return (
      <div>
        <h3>Authenticator Uygulamasında Tara</h3>
        <img src={qrCode} alt="QR Code" />
        <p>Manuel giriş: {secret}</p>
        <button onClick={() => setStep('verify')}>Taradım, Devam</button>
      </div>
    );
  }

  if (step === 'verify') {
    return (
      <div>
        <h3>6 Haneli Kodu Gir</h3>
        <input
          type="text"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          maxLength={6}
          placeholder="000000"
        />
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <button onClick={handleVerify}>Doğrula</button>
      </div>
    );
  }

  return (
    <div>
      <h3>✅ MFA Aktif</h3>
      <p>Backup kodlarını güvenli bir yere kaydet:</p>
      <ul>
        {backupCodes.map((code, i) => (
          <li key={i}><code>{code}</code></li>
        ))}
      </ul>
      <p>⚠️ Bu kodlar bir daha gösterilmeyecek!</p>
    </div>
  );
}
```

---

## 2. MFA Login Flow

MFA aktif kullanıcılar login olduğunda:

```
Login → mfa_required: true → MFA Kod Gir → Token Al
```

### Implementation

```typescript
// lib/auth.ts
export async function login(email: string, password: string) {
  const res = await fetch(`${API}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ realm_id: REALM, email, password })
  });
  
  const data = await res.json();
  
  if (data.mfa_required) {
    // MFA gerekli - session ID'yi sakla
    return {
      mfaRequired: true,
      mfaSessionId: data.mfa_session_id,
      allowedMethods: data.allowed_methods // ['totp', 'webauthn']
    };
  }
  
  // MFA yok - direkt token
  return { tokens: data.tokens, user: data.user };
}

export async function verifyMFALogin(mfaSessionId: string, code: string) {
  const res = await fetch(`${API}/v1/auth/mfa/login/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfa_session_id: mfaSessionId, code })
  });
  
  return res.json();
  // Returns: { tokens, user, used_backup_code }
}
```

---

## 3. MFA Devre Dışı Bırakma

```typescript
export async function disableMFA(accessToken: string, code: string) {
  const res = await fetch(`${API}/v1/auth/mfa/disable`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ code })
  });
  
  return res.json();
}
```

---

## 4. Backup Codes

- 8 adet tek kullanımlık kod
- Authenticator erişimi kaybolduğunda kullanılır
- Login'de normal kod yerine backup code girilebilir
- Kullanılan kod bir daha çalışmaz

```typescript
// Backup code ile login
const result = await verifyMFALogin(mfaSessionId, 'BACKUP-CODE-HERE');
if (result.used_backup_code) {
  // Kullanıcıyı uyar: "Backup kod kullandınız, yeni kodlar oluşturun"
}
```

---

## API Endpoints

| Method | Path | Auth | Açıklama |
|--------|------|------|----------|
| POST | `/v1/auth/mfa/setup` | Bearer | Setup başlat |
| POST | `/v1/auth/mfa/verify` | Bearer | Setup doğrula |
| POST | `/v1/auth/mfa/disable` | Bearer | MFA kapat |
| POST | `/v1/auth/mfa/login/verify` | - | Login MFA doğrula |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/v1/auth/mfa/*/verify` | 5 / dakika |
| `/v1/auth/mfa/login/verify` | 5 / dakika |

---

## Sonraki Adımlar

- [WebAuthn/Passkeys](./webauthn.md) - Phishing-proof MFA
- [Error Codes](../reference/error-codes.md)
