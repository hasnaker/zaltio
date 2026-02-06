# Zalt - Tediyat İçin Gerekli Özellikler

**Proje:** Tediyat (Ön Muhasebe Platformu)  
**Tarih:** 27 Ocak 2026  
**Hazırlayan:** Tediyat Geliştirme Ekibi

---

## Özet

Tediyat, multi-tenant bir ön muhasebe ve finans yönetim platformudur. Zalt'tan Clerk benzeri bir authentication ve authorization servisi bekliyoruz. Bu doküman, Tediyat'ın E2E çalışabilmesi için Zalt'tan ihtiyaç duyduğu tüm özellikleri listeler.

---

## 1. AUTHENTICATION ÖZELLİKLERİ

### 1.1 Kullanıcı Kaydı (Register)
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Email + şifre ile kayıt
- Kayıt sırasında şirket (tenant) oluşturma
- Email doğrulama (verification email)
- Şifre kuralları: min 8 karakter, büyük/küçük harf, rakam, özel karakter

**Beklenen Request:**
```json
POST /api/v1/auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "Ahmet",
  "lastName": "Yılmaz",
  "phone": "+905551234567",
  "companyName": "ABC Şirketi",
  "metadata": {
    "taxNumber": "1234567890"
  }
}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": {
    "user": { "id", "email", "firstName", "lastName" },
    "tenant": { "id", "name", "slug" },
    "tokens": { "accessToken", "refreshToken", "expiresIn" }
  }
}
```

---

### 1.2 Giriş (Login)
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Email + şifre ile giriş
- Başarılı girişte access token + refresh token dönmeli
- Kullanıcının üye olduğu tenant listesi dönmeli
- Son giriş zamanı ve IP kaydedilmeli

**Beklenen Request:**
```json
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "usr_xxx",
      "email": "user@example.com",
      "firstName": "Ahmet",
      "lastName": "Yılmaz"
    },
    "tenants": [
      { "id": "ten_xxx", "name": "ABC Şirketi", "slug": "abc-sirketi", "role": "owner" },
      { "id": "ten_yyy", "name": "XYZ Ltd", "slug": "xyz-ltd", "role": "member" }
    ],
    "tokens": {
      "accessToken": "eyJhbG...",
      "refreshToken": "eyJhbG...",
      "expiresIn": 3600
    }
  }
}
```

---

### 1.3 Token Yenileme (Refresh)
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Refresh token ile yeni access token alma
- Refresh token rotation (her kullanımda yeni refresh token)
- Eski refresh token'ı invalidate etme

**Beklenen Request:**
```json
POST /api/v1/auth/refresh
{
  "refreshToken": "eyJhbG..."
}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbG...",
    "refreshToken": "eyJhbG...",
    "expiresIn": 3600
  }
}
```

---

### 1.4 Çıkış (Logout)
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Mevcut session'ı sonlandırma
- Refresh token'ı invalidate etme
- Opsiyonel: Tüm cihazlardan çıkış

**Beklenen Request:**
```json
POST /api/v1/auth/logout
Authorization: Bearer {accessToken}
{
  "allDevices": false  // true ise tüm session'ları sonlandır
}
```

---

### 1.5 Mevcut Kullanıcı Bilgisi (Me)
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Token'dan kullanıcı bilgilerini döndürme
- Aktif tenant bilgisi
- Kullanıcının yetkileri (permissions)

**Beklenen Request:**
```json
GET /api/v1/auth/me
Authorization: Bearer {accessToken}
X-Tenant-ID: ten_xxx
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "usr_xxx",
      "email": "user@example.com",
      "firstName": "Ahmet",
      "lastName": "Yılmaz",
      "phone": "+905551234567",
      "emailVerified": true,
      "createdAt": "2026-01-15T10:00:00Z"
    },
    "currentTenant": {
      "id": "ten_xxx",
      "name": "ABC Şirketi",
      "slug": "abc-sirketi",
      "role": "owner"
    },
    "permissions": [
      "invoices:read",
      "invoices:write",
      "accounts:read",
      "accounts:write",
      "reports:read"
    ]
  }
}
```

---

### 1.6 Şifre Sıfırlama (Forgot Password)
**Öncelik:** P1 - Yüksek

**Gereksinimler:**
- Email ile şifre sıfırlama linki gönderme
- Sıfırlama token'ı 1 saat geçerli
- Tek kullanımlık token

**Beklenen Request - İstek:**
```json
POST /api/v1/auth/forgot-password
{
  "email": "user@example.com"
}
```

**Beklenen Request - Sıfırlama:**
```json
POST /api/v1/auth/reset-password
{
  "token": "reset_token_xxx",
  "newPassword": "NewSecurePass123!"
}
```

---

### 1.7 Email Doğrulama
**Öncelik:** P1 - Yüksek

**Gereksinimler:**
- Kayıt sonrası doğrulama emaili
- Doğrulama linki 24 saat geçerli
- Yeniden gönderme özelliği

**Beklenen Request - Doğrulama:**
```json
POST /api/v1/auth/verify-email
{
  "token": "verify_token_xxx"
}
```

**Beklenen Request - Yeniden Gönder:**
```json
POST /api/v1/auth/resend-verification
Authorization: Bearer {accessToken}
```

---

### 1.8 İki Faktörlü Doğrulama (2FA)
**Öncelik:** P2 - Orta

**Gereksinimler:**
- TOTP (Google Authenticator, Authy) desteği
- Backup kodları (10 adet, tek kullanımlık)
- 2FA aktif/pasif yapma

**Beklenen Request - Aktifleştirme:**
```json
POST /api/v1/auth/2fa/enable
Authorization: Bearer {accessToken}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qrCode": "data:image/png;base64,...",
    "backupCodes": ["ABC123", "DEF456", ...]
  }
}
```

**Beklenen Request - Doğrulama:**
```json
POST /api/v1/auth/2fa/verify
{
  "code": "123456"
}
```

---

## 2. MULTI-TENANT ÖZELLİKLERİ

### 2.1 Tenant Oluşturma
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Yeni şirket/organizasyon oluşturma
- Oluşturan kullanıcı otomatik "owner" rolü alır
- Benzersiz slug oluşturma

**Beklenen Request:**
```json
POST /api/v1/tenants
Authorization: Bearer {accessToken}
{
  "name": "Yeni Şirket A.Ş.",
  "metadata": {
    "taxNumber": "9876543210",
    "address": "İstanbul, Türkiye"
  }
}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": {
    "id": "ten_zzz",
    "name": "Yeni Şirket A.Ş.",
    "slug": "yeni-sirket-as",
    "createdAt": "2026-01-27T10:00:00Z"
  }
}
```

---

### 2.2 Tenant Listesi
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Kullanıcının üye olduğu tüm tenant'ları listeleme
- Her tenant için kullanıcının rolünü gösterme

**Beklenen Request:**
```json
GET /api/v1/tenants
Authorization: Bearer {accessToken}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "ten_xxx",
      "name": "ABC Şirketi",
      "slug": "abc-sirketi",
      "role": "owner",
      "memberCount": 5,
      "createdAt": "2026-01-15T10:00:00Z"
    },
    {
      "id": "ten_yyy",
      "name": "XYZ Ltd",
      "slug": "xyz-ltd",
      "role": "member",
      "memberCount": 12,
      "createdAt": "2026-01-20T10:00:00Z"
    }
  ]
}
```

---

### 2.3 Tenant Değiştirme (Switch)
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Aktif tenant'ı değiştirme
- Yeni tenant için yetkilendirilmiş token döndürme
- Kullanıcının o tenant'a erişim yetkisi kontrolü

**Beklenen Request:**
```json
POST /api/v1/tenants/{tenantId}/switch
Authorization: Bearer {accessToken}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbG...",
    "tenant": {
      "id": "ten_yyy",
      "name": "XYZ Ltd",
      "slug": "xyz-ltd"
    },
    "role": "member",
    "permissions": ["invoices:read", "accounts:read"]
  }
}
```

---

### 2.4 Kullanıcı Davet Etme
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Email ile tenant'a kullanıcı davet etme
- Davet edilen rol belirleme
- Davet linki 7 gün geçerli
- Mevcut kullanıcı veya yeni kullanıcı desteği

**Beklenen Request:**
```json
POST /api/v1/tenants/{tenantId}/invitations
Authorization: Bearer {accessToken}
{
  "email": "newuser@example.com",
  "role": "accountant",
  "permissions": ["invoices:read", "reports:read"]
}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": {
    "id": "inv_xxx",
    "email": "newuser@example.com",
    "role": "accountant",
    "status": "pending",
    "expiresAt": "2026-02-03T10:00:00Z"
  }
}
```

---

### 2.5 Daveti Kabul Etme
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Davet token'ı ile tenant'a katılma
- Yeni kullanıcı ise kayıt + katılım
- Mevcut kullanıcı ise sadece katılım

**Beklenen Request - Mevcut Kullanıcı:**
```json
POST /api/v1/invitations/{token}/accept
Authorization: Bearer {accessToken}
```

**Beklenen Request - Yeni Kullanıcı:**
```json
POST /api/v1/invitations/{token}/accept
{
  "firstName": "Mehmet",
  "lastName": "Demir",
  "password": "SecurePass123!"
}
```

---

### 2.6 Tenant Üyeleri Listesi
**Öncelik:** P1 - Yüksek

**Gereksinimler:**
- Tenant'taki tüm kullanıcıları listeleme
- Her kullanıcının rolü ve yetkileri
- Sadece owner/admin görebilir

**Beklenen Request:**
```json
GET /api/v1/tenants/{tenantId}/members
Authorization: Bearer {accessToken}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "usr_xxx",
      "email": "owner@example.com",
      "firstName": "Ahmet",
      "lastName": "Yılmaz",
      "role": "owner",
      "permissions": ["*"],
      "joinedAt": "2026-01-15T10:00:00Z"
    },
    {
      "id": "usr_yyy",
      "email": "accountant@example.com",
      "firstName": "Ayşe",
      "lastName": "Kaya",
      "role": "accountant",
      "permissions": ["invoices:read", "reports:read"],
      "joinedAt": "2026-01-20T10:00:00Z"
    }
  ]
}
```

---

### 2.7 Üye Çıkarma
**Öncelik:** P1 - Yüksek

**Gereksinimler:**
- Tenant'tan kullanıcı çıkarma
- Owner çıkarılamaz (önce devretmeli)
- Sadece owner/admin yapabilir

**Beklenen Request:**
```json
DELETE /api/v1/tenants/{tenantId}/members/{userId}
Authorization: Bearer {accessToken}
```

---

## 3. ROL VE YETKİ YÖNETİMİ

### 3.1 Önceden Tanımlı Roller
**Öncelik:** P0 - Kritik

Tediyat için gerekli standart roller:

| Rol | Açıklama | Yetkiler |
|-----|----------|----------|
| `owner` | Şirket sahibi | Tüm yetkiler (*) |
| `admin` | Yönetici | Kullanıcı yönetimi hariç tüm yetkiler |
| `accountant` | Muhasebeci | Fatura, cari, rapor okuma/yazma |
| `viewer` | Görüntüleyici | Sadece okuma yetkileri |
| `external_accountant` | Mali Müşavir | Sınırlı okuma + dışa aktarma |

---

### 3.2 Özel Rol Oluşturma
**Öncelik:** P2 - Orta

**Gereksinimler:**
- Tenant bazında özel rol tanımlama
- Yetki listesinden seçim

**Beklenen Request:**
```json
POST /api/v1/tenants/{tenantId}/roles
Authorization: Bearer {accessToken}
{
  "name": "Satış Temsilcisi",
  "slug": "sales-rep",
  "permissions": [
    "invoices:read",
    "invoices:create",
    "accounts:read",
    "quotes:*"
  ]
}
```

---

### 3.3 Yetki Listesi (Permissions)
**Öncelik:** P0 - Kritik

Tediyat'ın ihtiyaç duyduğu yetkiler:

```
# Fatura Yönetimi
invoices:read          - Faturaları görüntüleme
invoices:create        - Fatura oluşturma
invoices:update        - Fatura güncelleme
invoices:delete        - Fatura silme
invoices:*             - Tüm fatura yetkileri

# Cari Hesaplar
accounts:read          - Cari hesapları görüntüleme
accounts:create        - Cari hesap oluşturma
accounts:update        - Cari hesap güncelleme
accounts:delete        - Cari hesap silme
accounts:*             - Tüm cari yetkileri

# Kasa/Banka
cash:read              - Kasa işlemlerini görüntüleme
cash:write             - Kasa işlemi yapma
bank:read              - Banka işlemlerini görüntüleme
bank:write             - Banka işlemi yapma

# Raporlar
reports:read           - Raporları görüntüleme
reports:export         - Rapor dışa aktarma

# Stok
inventory:read         - Stok görüntüleme
inventory:write        - Stok işlemi yapma

# e-Dönüşüm
e-invoice:read         - e-Fatura görüntüleme
e-invoice:send         - e-Fatura gönderme

# Ayarlar
settings:read          - Ayarları görüntüleme
settings:write         - Ayarları değiştirme

# Kullanıcı Yönetimi
users:read             - Kullanıcıları görüntüleme
users:invite           - Kullanıcı davet etme
users:manage           - Kullanıcı yönetimi (rol değiştirme, çıkarma)

# Teklif
quotes:read            - Teklifleri görüntüleme
quotes:create          - Teklif oluşturma
quotes:update          - Teklif güncelleme
quotes:delete          - Teklif silme
quotes:*               - Tüm teklif yetkileri

# Online Ödeme
payments:read          - Ödemeleri görüntüleme
payments:create        - Ödeme linki oluşturma
payments:refund        - İade işlemi yapma
```

---

### 3.4 Üye Yetkilerini Güncelleme
**Öncelik:** P1 - Yüksek

**Gereksinimler:**
- Kullanıcının rolünü değiştirme
- Özel yetki ekleme/çıkarma

**Beklenen Request:**
```json
PATCH /api/v1/tenants/{tenantId}/members/{userId}
Authorization: Bearer {accessToken}
{
  "role": "accountant",
  "additionalPermissions": ["reports:export"]
}
```

---

## 4. SESSION YÖNETİMİ

### 4.1 Aktif Session Listesi
**Öncelik:** P1 - Yüksek

**Gereksinimler:**
- Kullanıcının tüm aktif oturumlarını listeleme
- Cihaz bilgisi, IP, son aktivite zamanı

**Beklenen Request:**
```json
GET /api/v1/auth/sessions
Authorization: Bearer {accessToken}
```

**Beklenen Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "ses_xxx",
      "device": "Chrome on MacOS",
      "ip": "192.168.1.1",
      "location": "İstanbul, TR",
      "lastActivity": "2026-01-27T10:30:00Z",
      "current": true
    },
    {
      "id": "ses_yyy",
      "device": "Safari on iPhone",
      "ip": "192.168.1.2",
      "location": "Ankara, TR",
      "lastActivity": "2026-01-26T15:00:00Z",
      "current": false
    }
  ]
}
```

---

### 4.2 Session Sonlandırma
**Öncelik:** P1 - Yüksek

**Gereksinimler:**
- Belirli bir session'ı sonlandırma
- Tüm session'ları sonlandırma (mevcut hariç)

**Beklenen Request:**
```json
DELETE /api/v1/auth/sessions/{sessionId}
Authorization: Bearer {accessToken}
```

**Tüm Session'ları Sonlandırma:**
```json
DELETE /api/v1/auth/sessions?all=true
Authorization: Bearer {accessToken}
```

---

## 5. WEBHOOK'LAR

### 5.1 Desteklenmesi Gereken Event'ler
**Öncelik:** P1 - Yüksek

Zalt'ın Tediyat'a göndermesi gereken webhook event'leri:

| Event | Açıklama |
|-------|----------|
| `user.created` | Yeni kullanıcı kaydı |
| `user.updated` | Kullanıcı bilgisi güncellendi |
| `user.deleted` | Kullanıcı silindi |
| `tenant.created` | Yeni tenant oluşturuldu |
| `tenant.updated` | Tenant bilgisi güncellendi |
| `member.invited` | Tenant'a kullanıcı davet edildi |
| `member.joined` | Kullanıcı tenant'a katıldı |
| `member.removed` | Kullanıcı tenant'tan çıkarıldı |
| `member.role_changed` | Kullanıcının rolü değişti |
| `session.created` | Yeni oturum açıldı |
| `session.revoked` | Oturum sonlandırıldı |

---

### 5.2 Webhook Payload Formatı
**Öncelik:** P1 - Yüksek

**Beklenen Format:**
```json
{
  "id": "evt_xxx",
  "type": "member.joined",
  "timestamp": "2026-01-27T10:00:00Z",
  "data": {
    "userId": "usr_xxx",
    "tenantId": "ten_xxx",
    "role": "accountant"
  }
}
```

**Güvenlik:**
- HMAC-SHA256 imza (X-Zalt-Signature header)
- Timestamp doğrulama (5 dakika tolerans)

---

## 6. JWT TOKEN YAPISI

### 6.1 Access Token İçeriği
**Öncelik:** P0 - Kritik

```json
{
  "sub": "usr_xxx",
  "email": "user@example.com",
  "tenantId": "ten_xxx",
  "role": "owner",
  "permissions": ["invoices:*", "accounts:*", "reports:read"],
  "iat": 1706349600,
  "exp": 1706353200,
  "iss": "https://auth.zalt.dev",
  "aud": "tediyat"
}
```

---

### 6.2 JWKS Endpoint
**Öncelik:** P0 - Kritik

**Gereksinimler:**
- Public key'leri döndüren endpoint
- Key rotation desteği
- Cache-friendly headers

**Beklenen Endpoint:**
```
GET /.well-known/jwks.json
```

**Beklenen Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key_xxx",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

---

## 7. GÜVENLİK GEREKSİNİMLERİ

### 7.1 Şifre Politikası
- Minimum 8 karakter
- En az 1 büyük harf
- En az 1 küçük harf
- En az 1 rakam
- En az 1 özel karakter (!@#$%^&*)
- Son 5 şifre tekrar edilemez

### 7.2 Token Süreleri
- Access Token: 1 saat (3600 saniye)
- Refresh Token: 30 gün
- Password Reset Token: 1 saat
- Email Verification Token: 24 saat
- Invitation Token: 7 gün

### 7.3 Rate Limiting
| Endpoint | Limit |
|----------|-------|
| `/auth/login` | 5 istek/dakika/IP |
| `/auth/register` | 3 istek/dakika/IP |
| `/auth/forgot-password` | 3 istek/saat/email |
| Diğer endpoint'ler | 100 istek/dakika/user |

### 7.4 Brute Force Koruması
- 5 başarısız giriş → 15 dakika hesap kilidi
- 10 başarısız giriş → 1 saat hesap kilidi
- Kilit durumunda email bildirimi

---

## 8. SDK / ENTEGRASYON

### 8.1 NestJS Backend Entegrasyonu

**Beklenen Kullanım:**
```typescript
// JWT Doğrulama
@UseGuards(ZaltAuthGuard)
@Get('protected')
async protectedRoute(@CurrentUser() user: ZaltUser) {
  return user;
}

// Yetki Kontrolü
@RequirePermission('invoices:create')
@Post('invoices')
async createInvoice() { }

// Tenant Kontrolü
@Get('data')
async getData(@CurrentTenant() tenant: ZaltTenant) {
  return this.service.getByTenant(tenant.id);
}
```

### 8.2 Next.js Frontend Entegrasyonu

**Beklenen Kullanım:**
```typescript
// Auth Hook
const { user, login, logout, isLoading } = useZaltAuth();

// Tenant Hook
const { currentTenant, tenants, switchTenant } = useZaltTenant();

// Permission Hook
const { hasPermission, permissions } = useZaltPermissions();

// Protected Route
<ZaltProtectedRoute permission="invoices:read">
  <InvoicePage />
</ZaltProtectedRoute>
```

---

## 9. ÖZET CHECKLIST

### P0 - Kritik (Launch Blocker)
- [ ] Kullanıcı kaydı (email + şifre)
- [ ] Giriş/Çıkış
- [ ] Token yenileme
- [ ] Mevcut kullanıcı bilgisi (me)
- [ ] Tenant oluşturma
- [ ] Tenant listesi
- [ ] Tenant değiştirme
- [ ] Kullanıcı davet etme
- [ ] Daveti kabul etme
- [ ] Önceden tanımlı roller
- [ ] Yetki listesi
- [ ] JWT token yapısı
- [ ] JWKS endpoint

### P1 - Yüksek (İlk Ay)
- [ ] Şifre sıfırlama
- [ ] Email doğrulama
- [ ] Tenant üyeleri listesi
- [ ] Üye çıkarma
- [ ] Üye yetkilerini güncelleme
- [ ] Session listesi
- [ ] Session sonlandırma
- [ ] Webhook'lar

### P2 - Orta (İlk Çeyrek)
- [ ] 2FA (TOTP)
- [ ] Özel rol oluşturma
- [ ] Audit log

---

## 10. İLETİŞİM

Sorularınız için:
- **Teknik:** dev@tediyat.com
- **Ürün:** product@tediyat.com

---

*Bu doküman Tediyat geliştirme ekibi tarafından hazırlanmıştır. Zalt ekibi ile birlikte güncellenecektir.*
