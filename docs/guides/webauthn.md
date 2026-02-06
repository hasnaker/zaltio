# WebAuthn / Passkeys

**Phishing-proof authentication**

---

## Genel Bakış

WebAuthn, FIDO2 standardına dayalı passwordless/MFA çözümüdür. Passkeys olarak da bilinir.

**Avantajları:**
- Phishing-proof (domain-bound)
- Evilginx2 gibi proxy saldırılarına karşı koruma
- Touch ID, Face ID, Windows Hello desteği
- Hardware key desteği (YubiKey)

**Healthcare realm'lerde zorunlu** - HIPAA compliance için.

---

## 1. Credential Kayıt Flow

```
Kullanıcı → Options Al → Browser Prompt → Verify → Credential Kaydedildi
```

### Frontend Implementation

```typescript
// lib/webauthn.ts
const API = 'https://api.zalt.io';

// 1. Registration options al
export async function getRegisterOptions(accessToken: string) {
  const res = await fetch(`${API}/v1/auth/webauthn/register/options`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    }
  });
  
  return res.json();
}

// 2. Browser credential oluştur
export async function createCredential(options: any) {
  // Base64URL decode helper
  const decode = (str: string) => 
    Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  
  const publicKeyOptions: PublicKeyCredentialCreationOptions = {
    challenge: decode(options.challenge),
    rp: options.rp,
    user: {
      id: decode(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName
    },
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    attestation: options.attestation,
    authenticatorSelection: options.authenticatorSelection
  };
  
  const credential = await navigator.credentials.create({
    publicKey: publicKeyOptions
  }) as PublicKeyCredential;
  
  return credential;
}

// 3. Credential'ı verify et
export async function verifyRegistration(accessToken: string, credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAttestationResponse;
  
  // Base64URL encode helper
  const encode = (buffer: ArrayBuffer) => 
    btoa(String.fromCharCode(...new Uint8Array(buffer)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  
  const res = await fetch(`${API}/v1/auth/webauthn/register/verify`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: encode(response.clientDataJSON),
        attestationObject: encode(response.attestationObject)
      }
    })
  });
  
  return res.json();
}
```

### React Component

```tsx
// components/WebAuthnSetup.tsx
import { useState } from 'react';
import { getRegisterOptions, createCredential, verifyRegistration } from '@/lib/webauthn';

export function WebAuthnSetup({ accessToken }: { accessToken: string }) {
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [error, setError] = useState('');

  async function handleSetup() {
    setStatus('loading');
    
    try {
      // 1. Options al
      const options = await getRegisterOptions(accessToken);
      
      // 2. Browser prompt
      const credential = await createCredential(options);
      
      // 3. Verify
      await verifyRegistration(accessToken, credential);
      
      setStatus('success');
    } catch (err: any) {
      setError(err.message || 'Setup failed');
      setStatus('error');
    }
  }

  if (status === 'success') {
    return <p>✅ Passkey kaydedildi!</p>;
  }

  return (
    <div>
      <button onClick={handleSetup} disabled={status === 'loading'}>
        {status === 'loading' ? 'Bekleniyor...' : 'Passkey Ekle'}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
}
```

---

## 2. Authentication Flow

MFA login sırasında WebAuthn kullanımı:

```typescript
// lib/webauthn.ts

// 1. Authentication options al
export async function getAuthOptions(mfaSessionId: string) {
  const res = await fetch(`${API}/v1/auth/webauthn/authenticate/options`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfa_session_id: mfaSessionId })
  });
  
  return res.json();
}

// 2. Browser assertion al
export async function getAssertion(options: any) {
  const decode = (str: string) => 
    Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  
  const publicKeyOptions: PublicKeyCredentialRequestOptions = {
    challenge: decode(options.challenge),
    timeout: options.timeout,
    rpId: options.rpId,
    allowCredentials: options.allowCredentials?.map((c: any) => ({
      id: decode(c.id),
      type: c.type,
      transports: c.transports
    }))
  };
  
  const assertion = await navigator.credentials.get({
    publicKey: publicKeyOptions
  }) as PublicKeyCredential;
  
  return assertion;
}

// 3. Verify ve token al
export async function verifyAuthentication(mfaSessionId: string, assertion: PublicKeyCredential) {
  const response = assertion.response as AuthenticatorAssertionResponse;
  
  const encode = (buffer: ArrayBuffer) => 
    btoa(String.fromCharCode(...new Uint8Array(buffer)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  
  const res = await fetch(`${API}/v1/auth/webauthn/authenticate/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      mfa_session_id: mfaSessionId,
      id: assertion.id,
      rawId: encode(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: encode(response.clientDataJSON),
        authenticatorData: encode(response.authenticatorData),
        signature: encode(response.signature),
        userHandle: response.userHandle ? encode(response.userHandle) : null
      }
    })
  });
  
  return res.json();
  // Returns: { tokens, user }
}
```

---

## 3. Credential Yönetimi

### Credential Listele

```typescript
export async function listCredentials(accessToken: string) {
  const res = await fetch(`${API}/v1/auth/webauthn/credentials`, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  
  return res.json();
  // Returns: { credentials: [{ id, name, created_at, last_used }] }
}
```

### Credential Sil

```typescript
export async function deleteCredential(accessToken: string, credentialId: string) {
  const res = await fetch(`${API}/v1/auth/webauthn/credentials/${credentialId}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  
  return res.json();
}
```

---

## API Endpoints

| Method | Path | Auth | Açıklama |
|--------|------|------|----------|
| POST | `/v1/auth/webauthn/register/options` | Bearer | Kayıt options |
| POST | `/v1/auth/webauthn/register/verify` | Bearer | Kayıt doğrula |
| POST | `/v1/auth/webauthn/authenticate/options` | - | Auth options |
| POST | `/v1/auth/webauthn/authenticate/verify` | - | Auth doğrula |
| GET | `/v1/auth/webauthn/credentials` | Bearer | Credential listele |
| DELETE | `/v1/auth/webauthn/credentials/{id}` | Bearer | Credential sil |

---

## Browser Support

| Browser | Durum |
|---------|-------|
| Chrome 67+ | ✅ |
| Firefox 60+ | ✅ |
| Safari 14+ | ✅ |
| Edge 79+ | ✅ |
| Mobile Safari | ✅ (iOS 14+) |
| Chrome Android | ✅ |

### Feature Detection

```typescript
function isWebAuthnSupported(): boolean {
  return !!(
    window.PublicKeyCredential &&
    typeof window.PublicKeyCredential === 'function'
  );
}

// Platform authenticator (Touch ID, Face ID, Windows Hello)
async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}
```

---

## Healthcare Realm Zorunluluğu

Clinisyn gibi healthcare realm'lerde WebAuthn zorunludur:

```typescript
// Login response
{
  "mfa_required": true,
  "webauthn_required": true,  // ← Healthcare realm
  "allowed_methods": ["webauthn"]  // TOTP yok
}
```

---

## Sonraki Adımlar

- [MFA Setup](./mfa-setup.md) - TOTP alternatifi
- [JWT Claims](../reference/jwt-claims.md)
