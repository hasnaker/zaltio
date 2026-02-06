# Zalt.io - HSD Finans Platform CTO İhtiyaç Raporu Yanıtı

**Tarih:** 28 Ocak 2026  
**Hazırlayan:** Zalt.io Teknik Ekip  
**Konu:** CTO İhtiyaç Raporu Yanıtları

---

## ✅ DURUM ÖZETİ

| Öğe | Durum | Not |
|-----|-------|-----|
| Realm | ✅ HAZIR | `tediyat` realm'i production'da aktif |
| API | ✅ HAZIR | `https://api.zalt.io` |
| JWKS | ✅ HAZIR | `https://api.zalt.io/.well-known/jwks.json` |
| Webhook | ✅ HAZIR | 11 event tipi destekleniyor |
| Custom Roles | ✅ HAZIR | API mevcut |

---

## 🔴 KRİTİK İHTİYAÇLAR - YANITLAR

### 1. Zalt Realm ✅ TAMAMLANDI

**Realm Bilgileri:**
```yaml
Realm ID: tediyat
Realm Adı: Tediyat Finans Platform
Bölge: EU (Frankfurt) - eu-central-1
Durum: ✅ Production'da aktif
```

**Test:**
```bash
curl -X POST https://api.zalt.io/register \
  -H "Content-Type: application/json" \
  -d '{"realm_id":"tediyat","email":"test@example.com","password":"Test123!"}'
```

---

### 2. OAuth Credentials

**Backend için gerekli DEĞİL!**

Zalt.io, Clerk/Auth0 gibi client credentials gerektirmez. Doğrudan API çağrısı yapılır:

```typescript
// ❌ YANLIŞ - Client credentials gerekmiyor
const auth = new ZaltClient({
  clientId: 'xxx',
  clientSecret: 'xxx'
});

// ✅ DOĞRU - Sadece realm_id yeterli
const auth = createZaltClient({
  baseUrl: 'https://api.zalt.io',
  realmId: 'tediyat'
});
```

**Environment Variables:**
```env
# Backend
ZALT_BASE_URL=https://api.zalt.io
ZALT_REALM_ID=tediyat
ZALT_JWKS_URL=https://api.zalt.io/.well-known/jwks.json

# Frontend
NEXT_PUBLIC_ZALT_BASE_URL=https://api.zalt.io
NEXT_PUBLIC_ZALT_REALM_ID=tediyat
```

---

### 3. JWKS Endpoint ✅ HAZIR

**URL:**
```
https://api.zalt.io/.well-known/jwks.json
```

**Örnek Yanıt:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "w1xUfuE27AzVJWuUqYOibFTHerA69Nlpxs80tmPoiGhrXp37zKAvY0...",
      "e": "AQAB",
      "alg": "RS256",
      "kid": "zalt-key-2026-01",
      "use": "sig"
    }
  ]
}
```

**Backend JWT Verification:**
```typescript
import jwksClient from 'jwks-rsa';
import jwt from 'jsonwebtoken';

const client = jwksClient({
  jwksUri: 'https://api.zalt.io/.well-known/jwks.json',
  cache: true,
  rateLimit: true
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// Token doğrulama
jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
  if (err) throw new Error('Invalid token');
  return decoded;
});
```

---

### 4. Webhook Secret

**Webhook oluşturma endpoint'i:**
```http
POST /tediyat/webhooks
Authorization: Bearer <admin_access_token>

{
  "url": "https://api.finans-platform.com/webhooks/zalt",
  "events": ["user.registered", "tenant.created", "member.joined"],
  "description": "Finans Platform Sync"
}
```

**Yanıt:**
```json
{
  "webhook_id": "whk_abc123",
  "secret": "whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "url": "https://api.finans-platform.com/webhooks/zalt",
  "events": ["user.registered", "tenant.created", "member.joined"],
  "created_at": "2026-01-28T10:00:00Z"
}
```

**⚠️ ÖNEMLİ:** Secret sadece bir kez gösterilir, güvenli şekilde saklayın!

---

## 🟡 YÜKSEK ÖNCELİKLİ İHTİYAÇLAR - YANITLAR

### 5. API Base URL ✅ ONAYLANDI

```
https://api.zalt.io
```

**Endpoint Yapısı:**
```
POST /register          - Kayıt
POST /login             - Giriş
POST /logout            - Çıkış
POST /refresh           - Token yenileme
GET  /me                - Kullanıcı bilgisi
POST /tediyat/tenants   - Şirket oluştur
POST /tediyat/switch    - Şirket değiştir
GET  /tediyat/members   - Üye listesi
...
```

**NOT:** `/v1/tediyat` değil, doğrudan `/tediyat` prefix'i kullanılır.

---

### 6. JWT Token Payload Yapısı ✅ ONAYLANDI

**Zalt JWT Payload:**
```typescript
interface ZaltJwtPayload {
  // Standart claims
  sub: string;           // User ID (usr_xxx)
  email: string;         // user@example.com
  iat: number;           // Issued at
  exp: number;           // Expiration
  jti: string;           // Token ID
  
  // Zalt claims
  realm_id: string;      // "tediyat"
  type: string;          // "access" | "refresh"
  
  // Tediyat multi-tenant claims (switch sonrası)
  org_id?: string;       // Aktif tenant ID (tnt_xxx)
  org_role?: string;     // Tenant'taki rol
  permissions?: string[];// Flatten yetkiler
  
  // User info
  first_name?: string;
  last_name?: string;
  email_verified?: boolean;
  mfa_enabled?: boolean;
}
```

**Örnek Token (decoded):**
```json
{
  "sub": "usr_abc123",
  "email": "ahmet@sirket.com",
  "realm_id": "tediyat",
  "type": "access",
  "org_id": "tnt_xyz789",
  "org_role": "owner",
  "permissions": ["*"],
  "first_name": "Ahmet",
  "last_name": "Yılmaz",
  "email_verified": true,
  "mfa_enabled": false,
  "iat": 1706428800,
  "exp": 1706432400,
  "jti": "tok_def456"
}
```

**Uyumluluk Notu:**
- `tenant_id` yerine `org_id` kullanılıyor
- `tenant_ids` array'i login response'da döner, JWT'de değil
- `roles` yerine `org_role` (tekil) kullanılıyor
- `session_id` JWT'de yok, ayrı session endpoint'inden alınır

---

### 7. Token Süreleri ✅ ONAYLANDI

| Token Tipi | Süre | Not |
|------------|------|-----|
| Access Token | **1 saat** (3600s) | Tediyat için özel |
| Refresh Token | **30 gün** | Tediyat için özel |
| MFA Session | 5 dakika | Standart |
| Password Reset | 1 saat | Standart |
| Email Verification | 24 saat | 6 haneli kod |
| Invitation | 7 gün | Davet linki |

**NOT:** Clinisyn için farklı (15 dk / 7 gün), Tediyat için özel konfigürasyon yapıldı.

---

### 8. Rate Limiting ✅ ONAYLANDI

| Endpoint | Limit | Window | Header |
|----------|-------|--------|--------|
| `/login` | 5 | 15 dakika / IP | `X-RateLimit-*` |
| `/register` | 3 | 1 saat / IP | `X-RateLimit-*` |
| `/password-reset/request` | 3 | 1 saat / email | `X-RateLimit-*` |
| `/mfa/verify` | 5 | 1 dakika / user | `X-RateLimit-*` |
| Genel API | 100 | 1 dakika / user | `X-RateLimit-*` |

**Response Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1706428860
Retry-After: 60  (sadece 429 durumunda)
```

**429 Response:**
```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Too many requests. Please try again later.",
    "details": {
      "retry_after": 900
    }
  }
}
```

---

## 🟢 ORTA ÖNCELİKLİ İHTİYAÇLAR - YANITLAR

### 9. Webhook Event Listesi ✅ DESTEKLENIYOR

**Desteklenen Event'ler:**

| Event | Payload |
|-------|---------|
| `user.registered` | `{ user_id, email, realm_id, tenant_id }` |
| `user.login` | `{ user_id, email, ip, user_agent, tenant_id }` |
| `user.logout` | `{ user_id, session_id }` |
| `user.password_changed` | `{ user_id, email }` |
| `tenant.created` | `{ tenant_id, name, owner_id }` |
| `tenant.updated` | `{ tenant_id, changes }` |
| `member.invited` | `{ invitation_id, email, tenant_id, role }` |
| `member.joined` | `{ user_id, tenant_id, role, invited_by }` |
| `member.removed` | `{ user_id, tenant_id, removed_by }` |
| `member.role_changed` | `{ user_id, tenant_id, old_role, new_role }` |
| `mfa.enabled` | `{ user_id, method }` |

**Webhook Payload Formatı:**
```json
{
  "event": "member.joined",
  "timestamp": "2026-01-28T10:30:00Z",
  "webhook_id": "whk_abc123",
  "data": {
    "user_id": "usr_abc123",
    "tenant_id": "tnt_xyz789",
    "role": "accountant",
    "invited_by": "usr_def456"
  }
}
```

**Headers:**
```
Content-Type: application/json
X-Zalt-Signature: sha256=xxxxxxxx
X-Zalt-Webhook-ID: whk_abc123
X-Zalt-Timestamp: 1706428800
```

---

### 10. User Migration Desteği

**Desteklenen Yöntem: Lazy Migration**

Zalt, bcrypt hash'lerini doğrudan import etmez. Önerilen yöntem:

**Seçenek A: Şifre Sıfırlama (Önerilen)**
```typescript
// 1. Kullanıcıları email ile import et (şifresiz)
await importUsers(users.map(u => ({
  email: u.email,
  first_name: u.first_name,
  last_name: u.last_name,
  email_verified: true,
  metadata: { migrated_from: 'legacy', legacy_id: u.id }
})));

// 2. Toplu şifre sıfırlama emaili gönder
await sendBulkPasswordReset(userEmails);
```

**Seçenek B: Dual-Auth (Geçiş Dönemi)**
```typescript
// Login sırasında önce Zalt'ı dene
try {
  return await zaltLogin(email, password);
} catch (e) {
  if (e.code === 'INVALID_CREDENTIALS') {
    // Legacy sistemde kontrol et
    const legacyUser = await legacyAuth(email, password);
    if (legacyUser) {
      // Zalt'ta oluştur ve login yap
      await zaltRegister({ email, password, ...legacyUser });
      return await zaltLogin(email, password);
    }
  }
  throw e;
}
```

---

### 11. Custom Role Desteği ✅ MEVCUT

**Endpoint:**
```http
POST /tediyat/roles
Authorization: Bearer <access_token>

{
  "name": "Satış Müdürü",
  "description": "Satış ekibi yöneticisi",
  "permissions": [
    "invoices:read",
    "invoices:create",
    "accounts:read",
    "reports:read"
  ]
}
```

**Yanıt:**
```json
{
  "role": {
    "id": "role_abc123",
    "name": "Satış Müdürü",
    "slug": "satis-muduru",
    "description": "Satış ekibi yöneticisi",
    "permissions": ["invoices:read", "invoices:create", "accounts:read", "reports:read"],
    "is_system": false,
    "tenant_id": "tnt_xyz789",
    "created_at": "2026-01-28T10:00:00Z"
  }
}
```

**Hazır Roller:**
| Rol | Slug | Yetkiler |
|-----|------|----------|
| Şirket Sahibi | `owner` | `*` (tümü) |
| Yönetici | `admin` | Üye yönetimi hariç tümü |
| Muhasebeci | `accountant` | Fatura, hesap, kasa, banka |
| Görüntüleyici | `viewer` | Sadece okuma |
| Dış Muhasebeci | `external_accountant` | Raporlar + sınırlı |

---

### 12. Permission Listesi ✅ ONAYLANDI

**Zalt'ta Tanımlı Permission'lar:**

```typescript
const TEDIYAT_PERMISSIONS = {
  // Faturalar
  'invoices:read': 'Faturaları görüntüle',
  'invoices:create': 'Fatura oluştur',
  'invoices:update': 'Fatura düzenle',
  'invoices:delete': 'Fatura sil',
  
  // Cari Hesaplar
  'accounts:read': 'Hesapları görüntüle',
  'accounts:create': 'Hesap oluştur',
  'accounts:update': 'Hesap düzenle',
  'accounts:delete': 'Hesap sil',
  
  // Kasa
  'cash:read': 'Kasa görüntüle',
  'cash:create': 'Kasa hareketi ekle',
  'cash:update': 'Kasa hareketi düzenle',
  'cash:delete': 'Kasa hareketi sil',
  
  // Banka
  'bank:read': 'Banka görüntüle',
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

**JWT'de Nasıl Geçer:**
```json
{
  "permissions": ["invoices:read", "invoices:create", "accounts:read"]
}
```

**Wildcard Desteği:**
- `*` = Tüm yetkiler (owner)
- `invoices:*` = Tüm fatura yetkileri (şu an desteklenmiyor, explicit liste gerekli)

---

## 📋 GÜNCEL CHECKLIST

### Zalt Tarafından Sağlananlar

| # | Öğe | Durum | Not |
|---|-----|-------|-----|
| 1 | Realm oluşturma | ✅ HAZIR | `tediyat` |
| 2 | Backend credentials | ✅ GEREKMİYOR | Doğrudan API |
| 3 | Frontend client ID | ✅ GEREKMİYOR | Doğrudan API |
| 4 | JWKS endpoint | ✅ HAZIR | `/.well-known/jwks.json` |
| 5 | Webhook secret | ✅ API ile oluşturulur | POST /tediyat/webhooks |
| 6 | API base URL | ✅ ONAYLANDI | `https://api.zalt.io` |
| 7 | JWT payload yapısı | ✅ ONAYLANDI | Yukarıda detaylı |
| 8 | Token süreleri | ✅ ONAYLANDI | 1 saat / 30 gün |
| 9 | Rate limit bilgisi | ✅ ONAYLANDI | Header'larda döner |
| 10 | Webhook events | ✅ ONAYLANDI | 11 event |
| 11 | User migration | ✅ LAZY MIGRATION | Şifre sıfırlama önerilir |
| 12 | Custom role API | ✅ HAZIR | POST /tediyat/roles |

---

## 🔧 HIZLI BAŞLANGIÇ

### 1. Environment Variables

```env
# Backend (.env)
ZALT_BASE_URL=https://api.zalt.io
ZALT_REALM_ID=tediyat
ZALT_JWKS_URL=https://api.zalt.io/.well-known/jwks.json

# Frontend (.env.local)
NEXT_PUBLIC_ZALT_BASE_URL=https://api.zalt.io
NEXT_PUBLIC_ZALT_REALM_ID=tediyat
```

### 2. Test Kullanıcısı Oluşturma

```bash
curl -X POST https://api.zalt.io/register \
  -H "Content-Type: application/json" \
  -d '{
    "realm_id": "tediyat",
    "email": "test@finans-platform.com",
    "password": "TestSifre123!",
    "first_name": "Test",
    "last_name": "Kullanıcı",
    "company_name": "Test Şirketi"
  }'
```

### 3. Login Test

```bash
curl -X POST https://api.zalt.io/login \
  -H "Content-Type: application/json" \
  -d '{
    "realm_id": "tediyat",
    "email": "test@finans-platform.com",
    "password": "TestSifre123!"
  }'
```

---

## 📞 DESTEK

**Teknik Sorular:** dev@zalt.io

**API Status:** https://api.zalt.io/health

**Dokümantasyon:**
- `docs/tediyat/TEDIYAT-ZALT-DOCUMENTATION.md` - Tam API referansı
- `docs/tediyat/TEDIYAT-TROUBLESHOOTING.md` - Hata çözümleri
- `docs/tediyat/TEDIYAT-QUICKSTART.md` - Hızlı başlangıç

---

*Bu yanıt raporu 28 Ocak 2026 tarihinde hazırlanmıştır.*
