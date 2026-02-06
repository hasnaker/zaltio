# Realm Management Guide

Bu kılavuz, HSD Auth Platform'da realm (tenant) yönetiminin tüm yönlerini kapsar.

## İçindekiler

1. [Realm Nedir?](#realm-nedir)
2. [Realm Oluşturma](#realm-oluşturma)
3. [Realm Yapılandırması](#realm-yapılandırması)
4. [Kullanıcı Yönetimi](#kullanıcı-yönetimi)
5. [Güvenlik Ayarları](#güvenlik-ayarları)
6. [SSO Entegrasyonu](#sso-entegrasyonu)
7. [API Anahtarları](#api-anahtarları)
8. [Webhook Yapılandırması](#webhook-yapılandırması)
9. [En İyi Uygulamalar](#en-iyi-uygulamalar)

---

## Realm Nedir?

Realm, HSD Auth Platform'da izole bir kimlik doğrulama alanıdır. Her realm:

- Kendi kullanıcı veritabanına sahiptir
- Bağımsız güvenlik politikaları uygular
- Özel kimlik doğrulama ayarları içerir
- Diğer realm'lerden tamamen izoledir

### Kullanım Senaryoları

| Senaryo | Açıklama |
|---------|----------|
| Proje Bazlı | Her HSD projesi için ayrı realm |
| Ortam Bazlı | Development, staging, production için ayrı realm'ler |
| Müşteri Bazlı | B2B uygulamalarda her müşteri için ayrı realm |

---

## Realm Oluşturma

### Dashboard Üzerinden

1. Dashboard'a admin olarak giriş yapın
2. Sol menüden "Realms" seçin
3. "Create New Realm" butonuna tıklayın
4. Gerekli bilgileri doldurun:
   - **Name**: Realm adı (benzersiz)
   - **Display Name**: Görünen ad
   - **Description**: Açıklama

### API Üzerinden

```bash
curl -X POST https://api.auth.hsdcore.com/admin/realms \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-project",
    "displayName": "My Project",
    "description": "Production realm for My Project",
    "settings": {
      "sessionTimeout": 3600,
      "maxConcurrentSessions": 5
    }
  }'
```

### Yanıt

```json
{
  "id": "realm_abc123",
  "name": "my-project",
  "displayName": "My Project",
  "status": "active",
  "createdAt": "2026-01-11T10:00:00Z",
  "apiKey": "rk_live_xxxxxxxxxxxxx"
}
```

---

## Realm Yapılandırması

### Genel Ayarlar

| Ayar | Varsayılan | Açıklama |
|------|------------|----------|
| `sessionTimeout` | 3600 | Oturum zaman aşımı (saniye) |
| `maxConcurrentSessions` | 5 | Maksimum eşzamanlı oturum |
| `passwordMinLength` | 8 | Minimum şifre uzunluğu |
| `requireEmailVerification` | true | E-posta doğrulama zorunluluğu |
| `allowRegistration` | true | Kullanıcı kaydına izin ver |

### Yapılandırma Güncelleme

```bash
curl -X PATCH https://api.auth.hsdcore.com/admin/realms/realm_abc123 \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "settings": {
      "sessionTimeout": 7200,
      "maxConcurrentSessions": 3,
      "passwordPolicy": {
        "minLength": 12,
        "requireUppercase": true,
        "requireNumbers": true,
        "requireSpecialChars": true
      }
    }
  }'
```

---

## Kullanıcı Yönetimi

### Kullanıcı Listeleme

```bash
# Tüm kullanıcıları listele
curl https://api.auth.hsdcore.com/admin/realms/realm_abc123/users \
  -H "Authorization: Bearer <admin-token>"

# Filtreleme ile
curl "https://api.auth.hsdcore.com/admin/realms/realm_abc123/users?status=active&limit=50" \
  -H "Authorization: Bearer <admin-token>"
```

### Kullanıcı Oluşturma (Admin)

```bash
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/users \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "temporaryPassword123",
    "profile": {
      "firstName": "John",
      "lastName": "Doe"
    },
    "roles": ["user"],
    "emailVerified": true
  }'
```

### Kullanıcı Durumu Yönetimi

```bash
# Kullanıcıyı devre dışı bırak
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/users/user_123/disable \
  -H "Authorization: Bearer <admin-token>"

# Kullanıcıyı etkinleştir
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/users/user_123/enable \
  -H "Authorization: Bearer <admin-token>"

# Şifre sıfırlama e-postası gönder
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/users/user_123/reset-password \
  -H "Authorization: Bearer <admin-token>"
```

### Toplu İşlemler

```bash
# Toplu kullanıcı içe aktarma
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/users/import \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {"email": "user1@example.com", "firstName": "User", "lastName": "One"},
      {"email": "user2@example.com", "firstName": "User", "lastName": "Two"}
    ],
    "sendWelcomeEmail": true
  }'
```

---

## Güvenlik Ayarları

### Şifre Politikası

```json
{
  "passwordPolicy": {
    "minLength": 12,
    "maxLength": 128,
    "requireUppercase": true,
    "requireLowercase": true,
    "requireNumbers": true,
    "requireSpecialChars": true,
    "preventReuse": 5,
    "expiryDays": 90
  }
}
```

### MFA Yapılandırması

```json
{
  "mfa": {
    "enabled": true,
    "required": false,
    "methods": ["totp", "sms"],
    "gracePeriodDays": 7
  }
}
```

### IP Kısıtlamaları

```json
{
  "ipRestrictions": {
    "enabled": true,
    "allowlist": ["192.168.1.0/24", "10.0.0.0/8"],
    "blocklist": ["1.2.3.4"]
  }
}
```

### Rate Limiting

```json
{
  "rateLimiting": {
    "login": {
      "maxAttempts": 5,
      "windowMinutes": 15,
      "lockoutMinutes": 30
    },
    "api": {
      "requestsPerMinute": 100
    }
  }
}
```

---

## SSO Entegrasyonu

### Google OAuth

1. [Google Cloud Console](https://console.cloud.google.com)'da OAuth 2.0 credentials oluşturun
2. Redirect URI ekleyin: `https://api.auth.hsdcore.com/auth/callback/google`
3. Realm ayarlarında yapılandırın:

```json
{
  "sso": {
    "google": {
      "enabled": true,
      "clientId": "your-client-id.apps.googleusercontent.com",
      "clientSecret": "your-client-secret"
    }
  }
}
```

### SAML 2.0

```json
{
  "sso": {
    "saml": {
      "enabled": true,
      "entityId": "https://auth.hsdcore.com/saml/realm_abc123",
      "ssoUrl": "https://idp.example.com/sso",
      "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
      "signatureAlgorithm": "RSA-SHA256"
    }
  }
}
```

### OIDC

```json
{
  "sso": {
    "oidc": {
      "enabled": true,
      "issuer": "https://idp.example.com",
      "clientId": "your-client-id",
      "clientSecret": "your-client-secret",
      "scopes": ["openid", "profile", "email"]
    }
  }
}
```

---

## API Anahtarları

### Anahtar Türleri

| Tür | Prefix | Kullanım |
|-----|--------|----------|
| Live | `rk_live_` | Production ortamı |
| Test | `rk_test_` | Development/test ortamı |

### Anahtar Oluşturma

```bash
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/api-keys \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Backend API Key",
    "type": "live",
    "permissions": ["users:read", "users:write", "sessions:read"]
  }'
```

### Anahtar İptali

```bash
curl -X DELETE https://api.auth.hsdcore.com/admin/realms/realm_abc123/api-keys/key_123 \
  -H "Authorization: Bearer <admin-token>"
```

---

## Webhook Yapılandırması

### Desteklenen Olaylar

| Olay | Açıklama |
|------|----------|
| `user.created` | Yeni kullanıcı kaydı |
| `user.updated` | Kullanıcı profili güncellendi |
| `user.deleted` | Kullanıcı silindi |
| `session.created` | Yeni oturum başlatıldı |
| `session.ended` | Oturum sonlandırıldı |
| `auth.failed` | Başarısız kimlik doğrulama |
| `mfa.enabled` | MFA etkinleştirildi |

### Webhook Oluşturma

```bash
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/webhooks \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/webhooks/auth",
    "events": ["user.created", "session.created", "auth.failed"],
    "secret": "your-webhook-secret"
  }'
```

### Webhook Payload Örneği

```json
{
  "id": "evt_123456",
  "type": "user.created",
  "timestamp": "2026-01-11T10:30:00Z",
  "realmId": "realm_abc123",
  "data": {
    "userId": "user_789",
    "email": "newuser@example.com"
  }
}
```

### İmza Doğrulama

```javascript
const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secret) {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(`sha256=${expectedSignature}`)
  );
}
```

---

## En İyi Uygulamalar

### Realm Organizasyonu

1. **Ortam Ayrımı**: Production ve development için ayrı realm'ler kullanın
2. **İsimlendirme**: Tutarlı isimlendirme kuralları belirleyin (örn: `project-env`)
3. **Dokümantasyon**: Her realm için açıklama ve etiketler ekleyin

### Güvenlik

1. **MFA Zorunluluğu**: Admin hesapları için MFA'yı zorunlu tutun
2. **API Anahtarı Rotasyonu**: API anahtarlarını düzenli olarak yenileyin
3. **IP Kısıtlamaları**: Mümkünse IP allowlist kullanın
4. **Audit Logları**: Güvenlik olaylarını düzenli olarak inceleyin

### Performans

1. **Rate Limiting**: Uygun rate limit değerleri belirleyin
2. **Session Yönetimi**: Gereksiz uzun oturum süreleri kullanmayın
3. **Webhook Timeout**: Webhook endpoint'lerinizin hızlı yanıt vermesini sağlayın

### Bakım

1. **Düzenli Yedekleme**: Realm yapılandırmalarını yedekleyin
2. **Kullanıcı Temizliği**: İnaktif kullanıcıları periyodik olarak temizleyin
3. **Log İnceleme**: Hata ve güvenlik loglarını düzenli kontrol edin

---

## Sorun Giderme

### Yaygın Sorunlar

**Realm oluşturulamıyor**
- Admin yetkilerinizi kontrol edin
- Realm adının benzersiz olduğundan emin olun

**SSO çalışmıyor**
- Redirect URI'ların doğru yapılandırıldığını kontrol edin
- Sertifikaların geçerli olduğunu doğrulayın

**Webhook'lar tetiklenmiyor**
- Endpoint URL'inin erişilebilir olduğunu kontrol edin
- Webhook secret'ının doğru olduğunu doğrulayın

Daha fazla yardım için [Troubleshooting Guide](troubleshooting-guide.md) sayfasına bakın.
