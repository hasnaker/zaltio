# Tediyat - Zalt.io Troubleshooting Rehberi

**Versiyon:** 1.0.0  
**Tarih:** 28 Ocak 2026

---

## Sık Karşılaşılan Hatalar ve Çözümleri

### 1. Kimlik Doğrulama Hataları

#### 1.1 "Invalid credentials" Hatası

**Hata:**
```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid credentials"
  }
}
```

**Olası Nedenler:**
- Email veya şifre yanlış
- Email büyük/küçük harf farkı (email'ler lowercase'e dönüştürülür)
- Kullanıcı bu realm'de kayıtlı değil

**Çözüm:**
```typescript
// Email'i lowercase yapın
const email = userInput.email.toLowerCase().trim();

// Şifreyi kontrol edin (boşluk var mı?)
const password = userInput.password.trim();
```

#### 1.2 "Account locked" Hatası

**Hata:**
```json
{
  "error": {
    "code": "ACCOUNT_LOCKED",
    "message": "Account is temporarily locked",
    "details": {
      "unlock_at": "2026-01-28T11:00:00Z",
      "remaining_seconds": 900
    }
  }
}
```

**Neden:** 5 başarısız giriş denemesi

**Çözüm:**
- 15 dakika bekleyin
- Veya şifre sıfırlama yapın (`/password-reset/request`)

#### 1.3 "Token expired" Hatası

**Hata:**
```json
{
  "error": {
    "code": "TOKEN_EXPIRED",
    "message": "Access token has expired"
  }
}
```

**Çözüm:**
```typescript
// Refresh token ile yenileyin
try {
  const response = await fetch('https://api.zalt.io/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: storedRefreshToken })
  });
  
  if (response.ok) {
    const { tokens } = await response.json();
    // Yeni token'ları kaydet
    saveTokens(tokens);
  } else {
    // Refresh token da geçersiz, tekrar login gerekli
    redirectToLogin();
  }
} catch (error) {
  redirectToLogin();
}
```

---

### 2. Rate Limit Hataları

#### 2.1 "Rate limited" Hatası

**Hata:**
```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Too many login attempts. Please try again later.",
    "details": {
      "retry_after": 900
    }
  }
}
```

**Rate Limit Değerleri:**

| Endpoint | Limit | Süre |
|----------|-------|------|
| `/login` | 5 deneme | 15 dakika |
| `/register` | 3 deneme | 1 saat |
| `/password-reset/request` | 3 deneme | 1 saat |
| `/mfa/verify` | 5 deneme | 1 dakika |
| Genel API | 100 istek | 1 dakika |

**Çözüm:**
```typescript
// Retry-After header'ını kullanın
const retryAfter = response.headers.get('Retry-After');
const waitSeconds = parseInt(retryAfter) || 900;

// Kullanıcıya bilgi verin
showMessage(`Lütfen ${Math.ceil(waitSeconds / 60)} dakika sonra tekrar deneyin.`);

// Otomatik retry (opsiyonel)
setTimeout(() => {
  retryRequest();
}, waitSeconds * 1000);
```

**Önleme:**
```typescript
// Debounce kullanın
import { debounce } from 'lodash';

const debouncedLogin = debounce(async (credentials) => {
  await login(credentials);
}, 1000);

// Form submit'te
form.onSubmit = () => debouncedLogin(credentials);
```

---

### 3. Multi-Tenant Hataları

#### 3.1 "Not a member" Hatası

**Hata:**
```json
{
  "error": {
    "code": "NOT_MEMBER",
    "message": "User is not a member of this tenant"
  }
}
```

**Neden:** Kullanıcı bu şirkete üye değil

**Çözüm:**
```typescript
// Login sonrası tenant listesini kontrol edin
const { tenants } = await login(credentials);

// Kullanıcının üye olduğu şirketleri gösterin
const memberTenants = tenants.filter(t => t.role !== null);

if (memberTenants.length === 0) {
  showMessage('Henüz bir şirkete üye değilsiniz.');
}
```

#### 3.2 "Tenant not found" Hatası

**Hata:**
```json
{
  "error": {
    "code": "TENANT_NOT_FOUND",
    "message": "Tenant not found"
  }
}
```

**Olası Nedenler:**
- Yanlış tenant_id
- Şirket silinmiş
- Typo

**Çözüm:**
```typescript
// Tenant ID'yi doğrulayın
const validTenantId = tenantId.startsWith('tnt_') ? tenantId : `tnt_${tenantId}`;

// Veya tenant listesinden seçin
const tenants = await getTenants();
const selectedTenant = tenants.find(t => t.id === tenantId);

if (!selectedTenant) {
  showError('Şirket bulunamadı');
}
```

#### 3.3 "Cannot remove owner" Hatası

**Hata:**
```json
{
  "error": {
    "code": "CANNOT_REMOVE_OWNER",
    "message": "Cannot remove the owner from the tenant"
  }
}
```

**Çözüm:**
1. Önce ownership'i başka birine transfer edin
2. Sonra eski owner'ı çıkarabilirsiniz

```typescript
// Ownership transfer
await transferOwnership(tenantId, newOwnerId);

// Sonra eski owner'ı çıkar
await removeMember(tenantId, oldOwnerId);
```

---

### 4. Davet (Invitation) Hataları

#### 4.1 "Invitation expired" Hatası

**Hata:**
```json
{
  "error": {
    "code": "INVITATION_EXPIRED",
    "message": "This invitation has expired"
  }
}
```

**Neden:** Davet 7 günden eski

**Çözüm:**
```typescript
// Yeni davet gönder
await createInvitation({
  tenant_id: tenantId,
  email: userEmail,
  role: 'accountant'
});

showMessage('Yeni davet gönderildi.');
```

#### 4.2 "Already a member" Hatası

**Hata:**
```json
{
  "error": {
    "code": "ALREADY_MEMBER",
    "message": "User is already a member of this tenant"
  }
}
```

**Çözüm:**
```typescript
// Davet göndermeden önce kontrol edin
const members = await getMembers(tenantId);
const existingMember = members.find(m => m.email === inviteEmail);

if (existingMember) {
  showMessage('Bu kullanıcı zaten üye. Rolünü değiştirmek ister misiniz?');
} else {
  await createInvitation({ email: inviteEmail, role: selectedRole });
}
```

---

### 5. MFA (2FA) Hataları

#### 5.1 "MFA required" Durumu

**Yanıt:**
```json
{
  "mfa_required": true,
  "mfa_session_id": "mfa_sess_abc123",
  "mfa_methods": ["totp"],
  "expires_in": 300
}
```

**Çözüm:**
```typescript
const loginResult = await login(credentials);

if (loginResult.mfa_required) {
  // MFA ekranına yönlendir
  setMfaSessionId(loginResult.mfa_session_id);
  navigateTo('/mfa-verify');
}

// MFA doğrulama
const verifyResult = await verifyMfa({
  mfa_session_id: mfaSessionId,
  code: userEnteredCode
});
```

#### 5.2 "Invalid MFA code" Hatası

**Hata:**
```json
{
  "error": {
    "code": "MFA_INVALID_CODE",
    "message": "Invalid MFA code"
  }
}
```

**Olası Nedenler:**
- Yanlış kod
- Kod süresi dolmuş (30 saniye)
- Cihaz saati yanlış

**Çözüm:**
```typescript
// Kullanıcıya bilgi verin
showError('Kod geçersiz. Lütfen kontrol edin:');
showInfo('• Kodun 30 saniye içinde girilmesi gerekir');
showInfo('• Cihazınızın saatinin doğru olduğundan emin olun');

// Retry sayısını takip edin
if (retryCount >= 5) {
  showError('Çok fazla deneme. Lütfen 1 dakika bekleyin.');
}
```

#### 5.3 MFA Session Expired

**Hata:**
```json
{
  "error": {
    "code": "MFA_SESSION_EXPIRED",
    "message": "MFA session has expired"
  }
}
```

**Neden:** 5 dakika içinde MFA kodu girilmedi

**Çözüm:**
```typescript
// Tekrar login yapın
showMessage('Oturum süresi doldu. Lütfen tekrar giriş yapın.');
navigateTo('/login');
```

---

### 6. Validasyon Hataları

#### 6.1 "Weak password" Hatası

**Hata:**
```json
{
  "error": {
    "code": "WEAK_PASSWORD",
    "message": "Password does not meet requirements",
    "details": {
      "requirements": [
        "At least 8 characters",
        "At least one uppercase letter",
        "At least one lowercase letter",
        "At least one number"
      ],
      "missing": ["uppercase", "number"]
    }
  }
}
```

**Çözüm:**
```typescript
// Frontend'de şifre validasyonu
function validatePassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('En az 8 karakter olmalı');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('En az 1 büyük harf olmalı');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('En az 1 küçük harf olmalı');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('En az 1 rakam olmalı');
  }
  
  return { valid: errors.length === 0, errors };
}
```

#### 6.2 "Email already exists" Hatası

**Hata:**
```json
{
  "error": {
    "code": "EMAIL_ALREADY_EXISTS",
    "message": "A user with this email already exists"
  }
}
```

**Çözüm:**
```typescript
// Kullanıcıya seçenek sunun
showMessage('Bu email zaten kayıtlı.');
showButton('Giriş Yap', () => navigateTo('/login'));
showButton('Şifremi Unuttum', () => navigateTo('/forgot-password'));
```

---

### 7. Network ve Bağlantı Hataları

#### 7.1 CORS Hatası

**Hata (Browser Console):**
```
Access to fetch at 'https://api.zalt.io/login' from origin 'https://myapp.com' 
has been blocked by CORS policy
```

**Neden:** Origin izin listesinde değil

**Çözüm:**
1. Zalt.io admin'e origin eklenmesini isteyin
2. Development için `http://localhost:3000` zaten izinli

#### 7.2 Network Timeout

**Çözüm:**
```typescript
// Timeout ile fetch
const controller = new AbortController();
const timeoutId = setTimeout(() => controller.abort(), 30000);

try {
  const response = await fetch(url, {
    ...options,
    signal: controller.signal
  });
  clearTimeout(timeoutId);
  return response;
} catch (error) {
  if (error.name === 'AbortError') {
    showError('Bağlantı zaman aşımına uğradı. Lütfen tekrar deneyin.');
  }
  throw error;
}
```

#### 7.3 SSL/TLS Hatası

**Neden:** HTTPS kullanılmıyor

**Çözüm:**
```typescript
// Her zaman HTTPS kullanın
const API_URL = 'https://api.zalt.io';  // ✅
// const API_URL = 'http://api.zalt.io';  // ❌ YANLIŞ
```

---

### 8. Token Yönetimi Sorunları

#### 8.1 Token Storage Best Practices

```typescript
// ❌ YANLIŞ - XSS'e açık
localStorage.setItem('access_token', token);

// ✅ DOĞRU - Memory'de tut
let accessToken: string | null = null;

function setAccessToken(token: string) {
  accessToken = token;
}

function getAccessToken(): string | null {
  return accessToken;
}

// ✅ DOĞRU - httpOnly cookie (backend set etmeli)
// Cookie otomatik olarak gönderilir
```

#### 8.2 Token Refresh Race Condition

**Problem:** Birden fazla istek aynı anda token yenilemeye çalışıyor

**Çözüm:**
```typescript
let refreshPromise: Promise<Tokens> | null = null;

async function refreshTokenSafely(): Promise<Tokens> {
  // Zaten refresh yapılıyorsa, aynı promise'i döndür
  if (refreshPromise) {
    return refreshPromise;
  }
  
  refreshPromise = doRefreshToken();
  
  try {
    const tokens = await refreshPromise;
    return tokens;
  } finally {
    refreshPromise = null;
  }
}
```

---

### 9. Webhook Sorunları

#### 9.1 Signature Verification Failed

**Neden:** Yanlış secret veya payload manipulation

**Çözüm:**
```typescript
// Raw body kullanın (parsed değil)
app.post('/webhooks/zalt', 
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const signature = req.headers['x-zalt-signature'];
    const payload = req.body.toString();  // Raw string
    
    if (!verifySignature(payload, signature, WEBHOOK_SECRET)) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
    
    const event = JSON.parse(payload);
    handleEvent(event);
    res.status(200).json({ received: true });
  }
);
```

#### 9.2 Webhook Timeout

**Neden:** İşlem 30 saniyeden uzun sürüyor

**Çözüm:**
```typescript
// Hemen 200 dönün, işlemi async yapın
app.post('/webhooks/zalt', async (req, res) => {
  // Hemen acknowledge
  res.status(200).json({ received: true });
  
  // Async işle
  setImmediate(async () => {
    try {
      await processWebhookEvent(req.body);
    } catch (error) {
      console.error('Webhook processing failed:', error);
      // Retry queue'ya ekle
      await addToRetryQueue(req.body);
    }
  });
});
```

---

### 10. Debug İpuçları

#### 10.1 Request ID Kullanımı

Her hata yanıtında `request_id` bulunur:

```json
{
  "error": {
    "code": "...",
    "message": "...",
    "request_id": "req_abc123xyz"
  }
}
```

Destek talebi açarken bu ID'yi paylaşın.

#### 10.2 Logging Best Practices

```typescript
// İstek logla (sensitive data olmadan!)
console.log('API Request:', {
  method: 'POST',
  url: '/login',
  // ❌ password: credentials.password,  // ASLA!
  email: credentials.email,
  timestamp: new Date().toISOString()
});

// Hata logla
console.error('API Error:', {
  code: error.code,
  message: error.message,
  request_id: error.request_id,
  timestamp: new Date().toISOString()
});
```

#### 10.3 Health Check

```typescript
// API durumunu kontrol edin
async function checkApiHealth(): Promise<boolean> {
  try {
    const response = await fetch('https://api.zalt.io/health');
    const data = await response.json();
    return data.status === 'healthy';
  } catch {
    return false;
  }
}
```

---

## Destek

Çözülemeyen sorunlar için:

1. **Request ID**'yi not edin
2. **Hata mesajı**nın tam metnini kopyalayın
3. **Hangi endpoint**'e istek attığınızı belirtin
4. **Ne zaman** oluştuğunu yazın

Email: **dev@zalt.io**

---

*Bu rehber Zalt.io v1.0.0 için hazırlanmıştır.*
