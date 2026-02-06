# Clinisyn x Zalt.io - Sık Karşılaşılan Hatalar

## 🔴 RATE_LIMITED

**Hata Mesajı:**
```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Too many login attempts. Please try again later.",
    "details": { "retry_after": 900 }
  }
}
```

**Sebep:** 15 dakika içinde 5'ten fazla başarısız login denemesi.

**Çözüm:**
1. `retry_after` süresini bekleyin (saniye cinsinden)
2. Kullanıcıya "Şifrenizi mi unuttunuz?" seçeneği sunun
3. CAPTCHA ekleyin (önerilir)

**Önleme:**
```typescript
// Frontend'de login denemelerini sayın
let attempts = 0;
const MAX_ATTEMPTS = 3;

async function login(email, password) {
  if (attempts >= MAX_ATTEMPTS) {
    showCaptcha();
    return;
  }
  // ... login logic
  attempts++;
}
```

---

## 🔴 INVALID_CREDENTIALS

**Hata Mesajı:**
```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password"
  }
}
```

**Sebep:** Email veya şifre yanlış.

**Önemli:** Güvenlik nedeniyle "email bulunamadı" veya "şifre yanlış" ayrımı yapılmaz.

**Çözüm:**
1. Email formatını kontrol edin
2. Caps Lock açık mı kontrol edin
3. Şifre sıfırlama önerisi sunun

---

## 🔴 INVALID_TOKEN

**Hata Mesajı:**
```json
{
  "error": {
    "code": "INVALID_TOKEN",
    "message": "Invalid access token"
  }
}
```

**Sebep:** 
- Token süresi dolmuş (15 dakika)
- Token formatı bozuk
- Token revoke edilmiş

**Çözüm:**
```typescript
// Token yenileme mantığı
async function apiCall(endpoint, options) {
  let response = await fetch(endpoint, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`
    }
  });
  
  if (response.status === 401) {
    // Token yenile
    const refreshed = await refreshTokens();
    if (refreshed) {
      // Tekrar dene
      response = await fetch(endpoint, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${newAccessToken}`
        }
      });
    } else {
      // Login sayfasına yönlendir
      redirectToLogin();
    }
  }
  
  return response;
}
```

---

## 🔴 TOKEN_EXPIRED

**Hata Mesajı:**
```json
{
  "error": {
    "code": "TOKEN_EXPIRED",
    "message": "Access token has expired"
  }
}
```

**Sebep:** Access token 15 dakikalık süresini doldurmuş.

**Çözüm:** Refresh token ile yeni token alın:
```typescript
const response = await fetch('https://api.zalt.io/refresh', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ refresh_token: storedRefreshToken })
});

const { tokens } = await response.json();
// Yeni tokenları kaydet
```

---

## 🔴 REALM_NOT_FOUND

**Hata Mesajı:**
```json
{
  "error": {
    "code": "REALM_NOT_FOUND",
    "message": "Authentication service unavailable"
  }
}
```

**Sebep:** Yanlış realm_id kullanılmış.

**Çözüm:** 
- Clinisyn için realm_id: `clinisyn`
- Büyük/küçük harf duyarlı

---

## 🔴 MFA_REQUIRED

**Hata Mesajı:**
```json
{
  "mfa_required": true,
  "mfa_session_id": "xxx",
  "available_methods": ["totp", "webauthn"]
}
```

**Sebep:** Kullanıcının MFA'sı aktif.

**Çözüm:**
```typescript
if (response.mfa_required) {
  // MFA sayfasına yönlendir
  redirectToMFA({
    sessionId: response.mfa_session_id,
    methods: response.available_methods
  });
}
```

---

## 🔴 WEBAUTHN_NOT_SUPPORTED

**Hata Mesajı:**
```json
{
  "error": {
    "code": "WEBAUTHN_NOT_SUPPORTED",
    "message": "WebAuthn is not supported on this device"
  }
}
```

**Sebep:** Tarayıcı veya cihaz WebAuthn desteklemiyor.

**Çözüm:**
```typescript
// WebAuthn desteğini kontrol et
if (window.PublicKeyCredential) {
  // WebAuthn kullanılabilir
  showPasskeyOption();
} else {
  // Alternatif MFA göster (TOTP)
  showTOTPOption();
}
```

---

## 🔴 CORS Hatası

**Hata Mesajı:**
```
Access to fetch at 'https://api.zalt.io/login' from origin 'http://localhost:3000' 
has been blocked by CORS policy
```

**Sebep:** Development ortamında CORS.

**Çözüm:**
1. Production'da sorun yok (*.clinisyn.com izinli)
2. Development için proxy kullanın:

```javascript
// next.config.js
module.exports = {
  async rewrites() {
    return [
      {
        source: '/api/auth/:path*',
        destination: 'https://api.zalt.io/:path*'
      }
    ];
  }
};
```

---

## 🔴 Network Error

**Hata Mesajı:**
```
TypeError: Failed to fetch
```

**Sebep:** 
- İnternet bağlantısı yok
- API erişilemiyor
- SSL sertifika sorunu

**Çözüm:**
```typescript
try {
  const response = await fetch('https://api.zalt.io/login', options);
} catch (error) {
  if (error.name === 'TypeError') {
    // Network hatası
    showOfflineMessage();
    // Retry logic
    setTimeout(() => retryLogin(), 5000);
  }
}
```

---

## 📞 Destek

Çözülemeyen sorunlar için:
- **Email:** support@zalt.io
- **Slack:** #clinisyn-support
- **Status:** https://status.zalt.io
