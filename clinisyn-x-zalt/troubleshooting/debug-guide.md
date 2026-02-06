# Clinisyn x Zalt.io - Debug Rehberi

## 🔍 API Durumunu Kontrol Et

```bash
# Health check
curl -s https://api.zalt.io/health | jq .

# Beklenen çıktı:
{
  "status": "healthy",
  "version": "1.0.0",
  "region": "eu-central-1",
  "components": [
    { "name": "dynamodb", "status": "healthy" },
    { "name": "secretsManager", "status": "healthy" },
    { "name": "lambda", "status": "healthy" }
  ]
}
```

## 🔐 Token Doğrulama

### JWT Decode (jwt.io kullanmadan)
```bash
# Access token'ı decode et
echo "YOUR_ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Beklenen payload:
{
  "sub": "user-id",
  "realm_id": "clinisyn",
  "email": "user@clinisyn.com",
  "iat": 1706345678,
  "exp": 1706346578,
  "type": "access",
  "iss": "https://api.zalt.io",
  "aud": "https://api.zalt.io"
}
```

### Token Süresini Kontrol Et
```javascript
function isTokenExpired(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return Date.now() >= payload.exp * 1000;
  } catch {
    return true;
  }
}
```

## 🧪 Manuel Test Komutları

### 1. Login Test
```bash
curl -s -X POST https://api.zalt.io/login \
  -H "Content-Type: application/json" \
  -d '{
    "realm_id": "clinisyn",
    "email": "YOUR_EMAIL",
    "password": "YOUR_PASSWORD"
  }' | jq .
```

### 2. Token Refresh Test
```bash
curl -s -X POST https://api.zalt.io/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }' | jq .
```

### 3. Authenticated Request Test
```bash
curl -s -X GET https://api.zalt.io/v1/auth/webauthn/credentials \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" | jq .
```

### 4. JWKS Doğrulama
```bash
curl -s https://api.zalt.io/.well-known/jwks.json | jq .

# Public key'i al
curl -s https://api.zalt.io/.well-known/jwks.json | jq -r '.keys[0].n'
```

## 📊 Response Time Kontrolü

```bash
# Login response time
time curl -s -X POST https://api.zalt.io/login \
  -H "Content-Type: application/json" \
  -d '{"realm_id":"clinisyn","email":"test@test.com","password":"test"}' \
  -o /dev/null -w "%{time_total}s\n"

# Beklenen: < 2 saniye
```

## 🔄 Rate Limit Durumu

Rate limit'e takıldıysanız:
```bash
# Retry-After header'ını kontrol et
curl -s -I -X POST https://api.zalt.io/login \
  -H "Content-Type: application/json" \
  -d '{"realm_id":"clinisyn","email":"test@test.com","password":"wrong"}' \
  | grep -i retry-after
```

## 🐛 Browser Console Debug

```javascript
// Network isteklerini logla
const originalFetch = window.fetch;
window.fetch = async (...args) => {
  console.log('🌐 Request:', args[0], args[1]);
  const response = await originalFetch(...args);
  console.log('📥 Response:', response.status, response.statusText);
  return response;
};

// Token durumunu kontrol et
function debugTokens() {
  const accessToken = localStorage.getItem('zalt_access_token');
  const refreshToken = localStorage.getItem('zalt_refresh_token');
  
  console.log('Access Token:', accessToken ? 'Present' : 'Missing');
  console.log('Refresh Token:', refreshToken ? 'Present' : 'Missing');
  
  if (accessToken) {
    const payload = JSON.parse(atob(accessToken.split('.')[1]));
    console.log('Token Expires:', new Date(payload.exp * 1000));
    console.log('Is Expired:', Date.now() >= payload.exp * 1000);
  }
}
```

## 📱 Mobile Debug (React Native)

```javascript
// Flipper veya React Native Debugger kullanın
import { LogBox } from 'react-native';

// Network isteklerini logla
global.XMLHttpRequest = global.originalXMLHttpRequest || global.XMLHttpRequest;

// Fetch interceptor
const originalFetch = global.fetch;
global.fetch = async (url, options) => {
  console.log(`[FETCH] ${options?.method || 'GET'} ${url}`);
  const start = Date.now();
  try {
    const response = await originalFetch(url, options);
    console.log(`[FETCH] ${response.status} in ${Date.now() - start}ms`);
    return response;
  } catch (error) {
    console.error(`[FETCH ERROR] ${error.message}`);
    throw error;
  }
};
```

## 🔧 Yaygın Sorunlar ve Çözümler

### Token Storage Sorunu
```javascript
// Secure storage kullanın
import * as SecureStore from 'expo-secure-store';

// ❌ Yanlış
localStorage.setItem('token', accessToken);

// ✅ Doğru (Web)
// HttpOnly cookie kullanın

// ✅ Doğru (Mobile)
await SecureStore.setItemAsync('accessToken', accessToken);
```

### CORS Preflight Hatası
```javascript
// OPTIONS request başarısız oluyorsa
// Backend'de CORS ayarlarını kontrol edin

// Geçici çözüm (development only):
// Proxy kullanın
```

### SSL Certificate Hatası
```bash
# Sertifikayı kontrol et
openssl s_client -connect api.zalt.io:443 -servername api.zalt.io

# Sertifika zincirini doğrula
curl -vI https://api.zalt.io/health 2>&1 | grep -A 5 "SSL certificate"
```

## 📞 Destek İçin Gerekli Bilgiler

Destek talebi açarken şunları ekleyin:

1. **Request ID** (her response'da var)
2. **Timestamp** (UTC)
3. **Endpoint** (örn: /login)
4. **HTTP Status Code**
5. **Error Code** (örn: RATE_LIMITED)
6. **Platform** (Web/iOS/Android)
7. **Browser/App Version**

```json
{
  "request_id": "abc123-def456",
  "timestamp": "2026-01-27T06:00:00Z",
  "endpoint": "POST /login",
  "status": 429,
  "error_code": "RATE_LIMITED",
  "platform": "Web",
  "browser": "Chrome 120"
}
```
