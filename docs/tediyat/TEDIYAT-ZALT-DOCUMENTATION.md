# Tediyat - Zalt.io Entegrasyon Dokümantasyonu

**Versiyon:** 1.0.0  
**Tarih:** 28 Ocak 2026  
**API Base URL:** `https://api.zalt.io`  
**Realm ID:** `tediyat`

---

## İçindekiler

1. [Genel Bakış](#1-genel-bakış)
2. [Kimlik Doğrulama Akışları](#2-kimlik-doğrulama-akışları)
3. [Multi-Tenant (Şirket) Yapısı](#3-multi-tenant-şirket-yapısı)
4. [API Endpoint'leri](#4-api-endpointleri)
5. [Rol ve Yetki Sistemi](#5-rol-ve-yetki-sistemi)
6. [Webhook Entegrasyonu](#6-webhook-entegrasyonu)
7. [Hata Kodları ve Çözümleri](#7-hata-kodları-ve-çözümleri)
8. [Güvenlik Notları](#8-güvenlik-notları)
9. [SDK Kullanımı](#9-sdk-kullanımı)
10. [Sık Sorulan Sorular](#10-sık-sorulan-sorular)

---

## 1. Genel Bakış

### Zalt.io Nedir?

Zalt.io, Tediyat için özel olarak yapılandırılmış enterprise-grade kimlik doğrulama platformudur. Auth0, Clerk gibi servislere alternatif olarak geliştirilmiştir.

### Tediyat İçin Özellikler

| Özellik | Durum | Açıklama |
|---------|-------|----------|
| Multi-Tenant | ✅ | Birden fazla şirket/müşteri desteği |
| Rol Tabanlı Yetkilendirme | ✅ | 5 hazır rol + özel rol oluşturma |
| Davetiye Sistemi | ✅ | Email ile kullanıcı davet etme |
| 2FA (TOTP) | ✅ | Google Authenticator desteği |
| Webhook | ✅ | 11 event tipi, HMAC-SHA256 imzalı |
| JWT Token | ✅ | RS256, tenant context içerir |
| Session Yönetimi | ✅ | Aktif oturumları görme/sonlandırma |

### Token Yapılandırması

```
Access Token:  1 saat (Tediyat için özel)
Refresh Token: 30 gün (Tediyat için özel)
Grace Period:  30 saniye (network retry için)
```

---

## 2. Kimlik Doğrulama Akışları

### 2.1 Kayıt (Register)

```http
POST /register
Content-Type: application/json

{
  "realm_id": "tediyat",
  "email": "kullanici@sirket.com",
  "password": "GuvenliSifre123!",
  "first_name": "Ahmet",
  "last_name": "Yılmaz",
  "company_name": "ABC Muhasebe Ltd.",  // İlk şirket otomatik oluşturulur
  "tax_number": "1234567890"            // Opsiyonel
}
```

**Başarılı Yanıt (201):**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "usr_abc123",
    "email": "kullanici@sirket.com",
    "email_verified": false
  },
  "tenant": {
    "id": "tnt_xyz789",
    "name": "ABC Muhasebe Ltd.",
    "slug": "abc-muhasebe-ltd"
  },
  "membership": {
    "role": "owner",
    "permissions": ["*"]
  }
}
```

### 2.2 Giriş (Login)

```http
POST /login
Content-Type: application/json

{
  "realm_id": "tediyat",
  "email": "kullanici@sirket.com",
  "password": "GuvenliSifre123!"
}
```

**Başarılı Yanıt (200):**
```json
{
  "message": "Login successful",
  "tokens": {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
    "expires_in": 3600,
    "token_type": "Bearer"
  },
  "user": {
    "id": "usr_abc123",
    "email": "kullanici@sirket.com",
    "first_name": "Ahmet",
    "last_name": "Yılmaz"
  },
  "tenants": [
    {
      "id": "tnt_xyz789",
      "name": "ABC Muhasebe Ltd.",
      "role": "owner",
      "is_default": true
    },
    {
      "id": "tnt_def456",
      "name": "XYZ Danışmanlık",
      "role": "accountant",
      "is_default": false
    }
  ]
}
```

### 2.3 MFA Gerekli Durumda

Eğer kullanıcının 2FA aktifse:

```json
{
  "mfa_required": true,
  "mfa_session_id": "mfa_sess_abc123",
  "mfa_methods": ["totp"],
  "expires_in": 300
}
```

MFA doğrulama:
```http
POST /mfa/verify
Content-Type: application/json

{
  "mfa_session_id": "mfa_sess_abc123",
  "code": "123456"
}
```

### 2.4 Token Yenileme (Refresh)

```http
POST /refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

### 2.5 Çıkış (Logout)

```http
POST /logout
Authorization: Bearer <access_token>

{
  "all_devices": false  // true: tüm cihazlardan çıkış
}
```

---

## 3. Multi-Tenant (Şirket) Yapısı

### 3.1 Şirket Oluşturma

```http
POST /tediyat/tenants
Authorization: Bearer <access_token>

{
  "name": "Yeni Şirket A.Ş.",
  "tax_number": "9876543210",
  "settings": {
    "currency": "TRY",
    "fiscal_year_start": "01-01"
  }
}
```

### 3.2 Şirket Listesi

```http
GET /tediyat/tenants
Authorization: Bearer <access_token>
```

**Yanıt:**
```json
{
  "tenants": [
    {
      "id": "tnt_xyz789",
      "name": "ABC Muhasebe Ltd.",
      "role": "owner",
      "member_count": 5,
      "created_at": "2026-01-15T10:00:00Z"
    }
  ]
}
```

### 3.3 Şirket Değiştirme (Context Switch)

```http
POST /tediyat/switch
Authorization: Bearer <access_token>

{
  "tenant_id": "tnt_def456"
}
```

**Yanıt:**
```json
{
  "message": "Switched to tenant successfully",
  "tokens": {
    "access_token": "eyJhbGciOiJSUzI1NiIs...",  // Yeni tenant context
    "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
    "expires_in": 3600
  },
  "tenant": {
    "id": "tnt_def456",
    "name": "XYZ Danışmanlık",
    "role": "accountant"
  }
}
```

### 3.4 JWT Token İçeriği

Şirket değiştirme sonrası token payload:

```json
{
  "sub": "usr_abc123",
  "email": "kullanici@sirket.com",
  "realm_id": "tediyat",
  "org_id": "tnt_def456",           // Aktif şirket
  "org_role": "accountant",          // Şirketteki rol
  "permissions": [                   // Yetkiler
    "invoices:read",
    "invoices:create",
    "accounts:read"
  ],
  "iat": 1706428800,
  "exp": 1706432400
}
```

---

## 4. API Endpoint'leri

### 4.1 Kimlik Doğrulama

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/register` | Yeni kullanıcı + şirket kaydı |
| POST | `/login` | Giriş yap |
| POST | `/logout` | Çıkış yap |
| POST | `/refresh` | Token yenile |
| GET | `/me` | Kullanıcı bilgisi |
| POST | `/password-reset/request` | Şifre sıfırlama isteği |
| POST | `/password-reset/confirm` | Şifre sıfırlama onayı |
| POST | `/verify-email/send` | Email doğrulama kodu gönder |
| POST | `/verify-email/confirm` | Email doğrula |

### 4.2 MFA (2FA)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/mfa/totp/setup` | TOTP kurulumu başlat |
| POST | `/mfa/totp/verify` | TOTP kurulumu doğrula |
| DELETE | `/mfa/totp` | TOTP kapat |
| POST | `/mfa/verify` | Login MFA doğrulama |

### 4.3 Tediyat Multi-Tenant

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/tediyat/tenants` | Şirket listesi |
| POST | `/tediyat/tenants` | Yeni şirket oluştur |
| POST | `/tediyat/switch` | Şirket değiştir |
| GET | `/tediyat/members` | Üye listesi |
| PATCH | `/tediyat/members/:id` | Üye güncelle |
| DELETE | `/tediyat/members/:id` | Üye çıkar |
| POST | `/tediyat/invitations` | Davet gönder |
| POST | `/tediyat/invitations/:token/accept` | Daveti kabul et |
| GET | `/tediyat/roles` | Rol listesi |
| POST | `/tediyat/roles` | Özel rol oluştur |
| GET | `/tediyat/sessions` | Aktif oturumlar |
| DELETE | `/tediyat/sessions/:id` | Oturum sonlandır |
| GET | `/tediyat/permissions` | Yetki listesi |

### 4.4 JWKS (Public Key)

```http
GET /.well-known/jwks.json
```

Token doğrulama için public key'leri döner.

---

## 5. Rol ve Yetki Sistemi

### 5.1 Hazır Roller

| Rol | Açıklama | Yetkiler |
|-----|----------|----------|
| `owner` | Şirket sahibi | Tüm yetkiler (`*`) |
| `admin` | Yönetici | Üye yönetimi hariç tüm yetkiler |
| `accountant` | Muhasebeci | Fatura, hesap, kasa, banka |
| `viewer` | Görüntüleyici | Sadece okuma |
| `external_accountant` | Dış muhasebeci | Raporlar + sınırlı erişim |

### 5.2 Yetki Listesi

```javascript
const PERMISSIONS = {
  // Faturalar
  'invoices:read': 'Faturaları görüntüle',
  'invoices:create': 'Fatura oluştur',
  'invoices:update': 'Fatura düzenle',
  'invoices:delete': 'Fatura sil',
  
  // Hesaplar
  'accounts:read': 'Hesapları görüntüle',
  'accounts:create': 'Hesap oluştur',
  'accounts:update': 'Hesap düzenle',
  'accounts:delete': 'Hesap sil',
  
  // Kasa
  'cash:read': 'Kasa hareketlerini görüntüle',
  'cash:create': 'Kasa hareketi ekle',
  'cash:update': 'Kasa hareketi düzenle',
  'cash:delete': 'Kasa hareketi sil',
  
  // Banka
  'bank:read': 'Banka hareketlerini görüntüle',
  'bank:create': 'Banka hareketi ekle',
  'bank:update': 'Banka hareketi düzenle',
  'bank:delete': 'Banka hareketi sil',
  
  // Raporlar
  'reports:read': 'Raporları görüntüle',
  'reports:export': 'Rapor dışa aktar',
  
  // Ayarlar
  'settings:read': 'Ayarları görüntüle',
  'settings:update': 'Ayarları düzenle',
  
  // Üyeler
  'members:read': 'Üyeleri görüntüle',
  'members:invite': 'Üye davet et',
  'members:update': 'Üye düzenle',
  'members:remove': 'Üye çıkar'
};
```

### 5.3 Özel Rol Oluşturma

```http
POST /tediyat/roles
Authorization: Bearer <access_token>

{
  "name": "Stajyer",
  "description": "Sadece görüntüleme yetkisi",
  "permissions": [
    "invoices:read",
    "accounts:read",
    "reports:read"
  ]
}
```

### 5.4 Frontend'de Yetki Kontrolü

```typescript
// JWT'den yetkiler
const permissions = decodedToken.permissions;

// Yetki kontrolü
function hasPermission(permission: string): boolean {
  if (permissions.includes('*')) return true;  // Owner
  return permissions.includes(permission);
}

// Kullanım
if (hasPermission('invoices:create')) {
  // Fatura oluşturma butonu göster
}
```

---

## 6. Webhook Entegrasyonu

### 6.1 Webhook Kurulumu

Tediyat backend'inde webhook endpoint'i tanımlayın:

```
POST https://api.tediyat.com/webhooks/zalt
```

### 6.2 Event Tipleri

| Event | Açıklama |
|-------|----------|
| `user.registered` | Yeni kullanıcı kaydı |
| `user.login` | Kullanıcı girişi |
| `user.logout` | Kullanıcı çıkışı |
| `user.password_changed` | Şifre değişikliği |
| `tenant.created` | Yeni şirket oluşturuldu |
| `tenant.updated` | Şirket güncellendi |
| `member.invited` | Üye davet edildi |
| `member.joined` | Üye katıldı |
| `member.removed` | Üye çıkarıldı |
| `member.role_changed` | Üye rolü değişti |
| `mfa.enabled` | 2FA aktifleştirildi |

### 6.3 Webhook Payload

```json
{
  "event": "member.joined",
  "timestamp": "2026-01-28T10:30:00Z",
  "data": {
    "user_id": "usr_abc123",
    "tenant_id": "tnt_xyz789",
    "role": "accountant",
    "invited_by": "usr_def456"
  }
}
```

### 6.4 İmza Doğrulama (HMAC-SHA256)

```typescript
import crypto from 'crypto';

function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): boolean {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// Express middleware
app.post('/webhooks/zalt', (req, res) => {
  const signature = req.headers['x-zalt-signature'];
  const payload = JSON.stringify(req.body);
  
  if (!verifyWebhookSignature(payload, signature, WEBHOOK_SECRET)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  // Event'i işle
  handleWebhookEvent(req.body);
  res.status(200).json({ received: true });
});
```

---

## 7. Hata Kodları ve Çözümleri

### 7.1 Kimlik Doğrulama Hataları

| Kod | HTTP | Açıklama | Çözüm |
|-----|------|----------|-------|
| `INVALID_CREDENTIALS` | 401 | Email veya şifre yanlış | Bilgileri kontrol edin |
| `EMAIL_NOT_VERIFIED` | 403 | Email doğrulanmamış | Email doğrulama kodu gönderin |
| `ACCOUNT_LOCKED` | 423 | Hesap kilitli | 15 dakika bekleyin veya şifre sıfırlayın |
| `MFA_REQUIRED` | 403 | 2FA gerekli | MFA kodu ile doğrulayın |
| `MFA_INVALID_CODE` | 401 | Geçersiz MFA kodu | Kodu kontrol edin |
| `TOKEN_EXPIRED` | 401 | Token süresi dolmuş | Refresh token ile yenileyin |
| `TOKEN_INVALID` | 401 | Geçersiz token | Tekrar giriş yapın |

### 7.2 Rate Limit Hataları

| Kod | HTTP | Açıklama | Çözüm |
|-----|------|----------|-------|
| `RATE_LIMITED` | 429 | Çok fazla istek | `retry_after` süresini bekleyin |
| `RATE_LIMIT_EXCEEDED` | 429 | Limit aşıldı | Belirtilen süre sonra tekrar deneyin |

**Rate Limit Değerleri:**
- Login: 5 deneme / 15 dakika / IP
- Register: 3 deneme / 1 saat / IP
- Password Reset: 3 deneme / 1 saat / email
- API Genel: 100 istek / 1 dakika / kullanıcı

### 7.3 Yetkilendirme Hataları

| Kod | HTTP | Açıklama | Çözüm |
|-----|------|----------|-------|
| `FORBIDDEN` | 403 | Yetkisiz işlem | Yetkileri kontrol edin |
| `NOT_MEMBER` | 403 | Şirket üyesi değil | Şirkete davet edilmeniz gerekli |
| `INSUFFICIENT_PERMISSIONS` | 403 | Yetki yetersiz | Admin'den yetki isteyin |

### 7.4 Validasyon Hataları

| Kod | HTTP | Açıklama | Çözüm |
|-----|------|----------|-------|
| `VALIDATION_ERROR` | 400 | Geçersiz veri | `details` alanını kontrol edin |
| `EMAIL_ALREADY_EXISTS` | 409 | Email zaten kayıtlı | Farklı email kullanın veya giriş yapın |
| `WEAK_PASSWORD` | 400 | Zayıf şifre | En az 8 karakter, büyük/küçük harf, rakam |
| `INVALID_REALM` | 400 | Geçersiz realm | `realm_id: "tediyat"` kullanın |

### 7.5 Tenant Hataları

| Kod | HTTP | Açıklama | Çözüm |
|-----|------|----------|-------|
| `TENANT_NOT_FOUND` | 404 | Şirket bulunamadı | Tenant ID'yi kontrol edin |
| `ALREADY_MEMBER` | 409 | Zaten üye | Kullanıcı bu şirkette zaten üye |
| `CANNOT_REMOVE_OWNER` | 400 | Owner çıkarılamaz | Önce ownership transfer edin |
| `INVITATION_EXPIRED` | 410 | Davet süresi dolmuş | Yeni davet gönderin |
| `INVITATION_ALREADY_USED` | 410 | Davet kullanılmış | Yeni davet gönderin |

### 7.6 Hata Yanıt Formatı

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request data",
    "details": {
      "email": "Invalid email format",
      "password": "Password must be at least 8 characters"
    },
    "timestamp": "2026-01-28T10:30:00Z",
    "request_id": "req_abc123"
  }
}
```

---

## 8. Güvenlik Notları

### 8.1 Şifre Gereksinimleri

- Minimum 8 karakter
- En az 1 büyük harf
- En az 1 küçük harf
- En az 1 rakam
- Sızıntı veritabanlarında kontrol edilir (HaveIBeenPwned)

### 8.2 Token Güvenliği

- **ASLA** access token'ı localStorage'da saklamayın
- httpOnly cookie veya memory'de tutun
- Refresh token'ı güvenli şekilde saklayın
- Token'ları URL'de geçirmeyin

### 8.3 HTTPS Zorunluluğu

Tüm API çağrıları HTTPS üzerinden yapılmalıdır.

### 8.4 CORS Ayarları

Tediyat için izin verilen origin'ler:
```
https://tediyat.com
https://app.tediyat.com
https://api.tediyat.com
http://localhost:3000 (development)
```

### 8.5 2FA Önerisi

Özellikle `owner` ve `admin` rolündeki kullanıcılar için 2FA aktifleştirmesi önerilir.

---

## 9. SDK Kullanımı

### 9.1 Kurulum

```bash
npm install @zalt/auth-sdk
```

### 9.2 Başlatma

```typescript
import { createZaltClient } from '@zalt/auth-sdk';

const auth = createZaltClient({
  baseUrl: 'https://api.zalt.io',
  realmId: 'tediyat',
  storage: 'memory'  // veya 'localStorage', 'sessionStorage'
});
```

### 9.3 Temel Kullanım

```typescript
// Kayıt
const registerResult = await auth.register({
  email: 'user@example.com',
  password: 'SecurePass123!',
  profile: {
    first_name: 'Ahmet',
    last_name: 'Yılmaz'
  }
});

// Giriş
const loginResult = await auth.login({
  email: 'user@example.com',
  password: 'SecurePass123!'
});

// MFA gerekli mi?
if (loginResult.mfaRequired) {
  const mfaResult = await auth.mfa.verifyLogin(
    loginResult.mfaSessionId,
    '123456'
  );
}

// Kullanıcı bilgisi
const user = await auth.getCurrentUser();

// Çıkış
await auth.logout();
```

### 9.4 Token Yönetimi

```typescript
// Otomatik token yenileme (SDK otomatik yapar)
// Manuel yenileme gerekirse:
await auth.refreshToken();

// Token'ı al
const token = auth.getAccessToken();

// Authenticated mi?
const isAuth = auth.isAuthenticated();
```

---

## 10. Sık Sorulan Sorular

### S: Rate limit'e takıldım, ne yapmalıyım?

**C:** `retry_after` değerini bekleyin. Login için 15 dakika, register için 1 saat. Production'da bu değerler IP bazlıdır.

### S: Token süresi doldu, kullanıcı tekrar giriş yapmalı mı?

**C:** Hayır. Refresh token ile otomatik yenileme yapılır. SDK bunu otomatik yapar. Manuel yapıyorsanız `/refresh` endpoint'ini kullanın.

### S: Kullanıcı birden fazla şirkette olabilir mi?

**C:** Evet. Login sonrası `tenants` array'i tüm şirketleri döner. `/tediyat/switch` ile şirket değiştirebilirsiniz.

### S: Şirket sahibi (owner) değiştirilebilir mi?

**C:** Evet, ancak mevcut owner bu işlemi yapmalıdır. Ownership transfer endpoint'i kullanılır.

### S: Davet linki ne kadar süre geçerli?

**C:** 7 gün. Süresi dolan davetler için yeni davet gönderilmelidir.

### S: 2FA zorunlu mu?

**C:** Hayır, opsiyoneldir. Ancak güvenlik için önerilir.

### S: Webhook secret'ı nasıl alırım?

**C:** Zalt.io admin panelinden veya API üzerinden webhook oluştururken secret döner.

### S: API'ye erişemiyorum, ne yapmalıyım?

**C:** 
1. `realm_id: "tediyat"` kullandığınızdan emin olun
2. HTTPS kullandığınızdan emin olun
3. Token'ın geçerli olduğunu kontrol edin
4. Rate limit'e takılmadığınızı kontrol edin

---

## Destek

Teknik sorular için: **dev@zalt.io**

API Status: https://status.zalt.io

---

*Bu dokümantasyon Zalt.io v1.0.0 için hazırlanmıştır.*
