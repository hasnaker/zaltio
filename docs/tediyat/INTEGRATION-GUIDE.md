# Tediyat Integration Guide

## 🚀 Hızlı Başlangıç

### 1. Kayıt (Register)

```typescript
// POST https://api.zalt.io/v1/tediyat/auth/register
const response = await fetch('https://api.zalt.io/v1/tediyat/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'muhasebeci@sirket.com',
    password: 'GüvenliŞifre123!',
    first_name: 'Ahmet',
    last_name: 'Yılmaz',
    company_name: 'Yılmaz Muhasebe Ltd. Şti.'
  })
});

const { data } = await response.json();
// data.user - Kullanıcı bilgileri
// data.tenant - Oluşturulan şirket
// data.tokens - access_token, refresh_token
```

### 2. Giriş (Login)

```typescript
// POST https://api.zalt.io/v1/tediyat/auth/login
const response = await fetch('https://api.zalt.io/v1/tediyat/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'muhasebeci@sirket.com',
    password: 'GüvenliŞifre123!'
  })
});

const { data } = await response.json();
// data.user - Kullanıcı bilgileri
// data.tenants - Kullanıcının üye olduğu tüm şirketler
// data.tokens - access_token, refresh_token
```

### 3. Şirket Değiştirme (Switch Tenant)

```typescript
// POST https://api.zalt.io/v1/tediyat/auth/switch/{tenantId}
const response = await fetch(`https://api.zalt.io/v1/tediyat/auth/switch/${tenantId}`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  }
});

const { data } = await response.json();
// data.tenant_id - Aktif şirket
// data.role - Kullanıcının rolü
// data.permissions - İzinler
// data.tokens - Yeni tokenlar (şirket context'li)
```

---

## 🔑 Token Yönetimi

### Token Yapısı (JWT Claims)

```json
{
  "sub": "user_xxx",
  "email": "user@example.com",
  "realm_id": "tediyat",
  "org_id": "tenant_xxx",
  "roles": ["owner"],
  "permissions": ["users:*", "invoices:*"],
  "iat": 1706400000,
  "exp": 1706403600
}
```

### Token Yenileme

```typescript
// POST https://api.zalt.io/v1/auth/refresh
const response = await fetch('https://api.zalt.io/v1/auth/refresh', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ refresh_token: refreshToken })
});
```

**Not:** 30 saniyelik grace period var - network retry'lar için aynı token tekrar kullanılabilir.


---

## 👥 Üye Yönetimi

### Davet Gönderme

```typescript
// POST https://api.zalt.io/v1/tediyat/tenants/{tenantId}/invitations
const response = await fetch(`https://api.zalt.io/v1/tediyat/tenants/${tenantId}/invitations`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'yeni.muhasebeci@example.com',
    role_id: 'accountant',
    invitee_name: 'Mehmet Demir' // Opsiyonel
  })
});
```

### Daveti Kabul Etme

```typescript
// Mevcut kullanıcı için
// POST https://api.zalt.io/v1/tediyat/invitations/{token}/accept
const response = await fetch(`https://api.zalt.io/v1/tediyat/invitations/${inviteToken}/accept`, {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  }
});

// Yeni kullanıcı için (şifre gerekli)
const response = await fetch(`https://api.zalt.io/v1/tediyat/invitations/${inviteToken}/accept`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    password: 'YeniŞifre123!',
    first_name: 'Mehmet',
    last_name: 'Demir'
  })
});
```

### Üye Listesi

```typescript
// GET https://api.zalt.io/v1/tediyat/tenants/{tenantId}/members
const response = await fetch(`https://api.zalt.io/v1/tediyat/tenants/${tenantId}/members`, {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});
```

### Rol Değiştirme

```typescript
// PATCH https://api.zalt.io/v1/tediyat/tenants/{tenantId}/members/{userId}
const response = await fetch(`https://api.zalt.io/v1/tediyat/tenants/${tenantId}/members/${userId}`, {
  method: 'PATCH',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ role_id: 'admin' })
});
```

---

## 🔐 Oturum Yönetimi

### Aktif Oturumları Listele

```typescript
// GET https://api.zalt.io/v1/tediyat/auth/sessions
const response = await fetch('https://api.zalt.io/v1/tediyat/auth/sessions', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});

// Response:
// {
//   "sessions": [
//     { "id": "...", "is_current": true, "ip_address": "192.168.*.*", "device_info": {...} }
//   ]
// }
```

### Oturum Sonlandırma

```typescript
// Tek oturum
// DELETE https://api.zalt.io/v1/tediyat/auth/sessions/{sessionId}

// Tüm oturumlar (mevcut hariç)
// DELETE https://api.zalt.io/v1/tediyat/auth/sessions?all=true
```

---

## 🎭 Rol ve İzinler

### Sistem Rolleri

| Rol | Açıklama | İzinler |
|-----|----------|---------|
| `owner` | Şirket sahibi | Tam yetki (`*:*`) |
| `admin` | Yönetici | Kullanıcı yönetimi hariç tüm yetkiler |
| `accountant` | Muhasebeci | Fatura, rapor, müşteri işlemleri |
| `viewer` | Görüntüleyici | Sadece okuma |
| `external_accountant` | Dış muhasebeci | Sınırlı okuma |

### İzin Kontrolü (Frontend)

```typescript
function hasPermission(userPermissions: string[], required: string): boolean {
  // Wildcard kontrolü
  if (userPermissions.includes('*:*')) return true;
  
  const [resource, action] = required.split(':');
  
  // Resource wildcard
  if (userPermissions.includes(`${resource}:*`)) return true;
  
  // Exact match
  return userPermissions.includes(required);
}

// Kullanım
if (hasPermission(user.permissions, 'invoices:create')) {
  // Fatura oluşturma butonu göster
}
```

---

## 🔔 Webhook Entegrasyonu

### Webhook Ayarlama

Tediyat admin panelinden webhook URL'i ve secret key tanımlayın.

### İmza Doğrulama

```typescript
import crypto from 'crypto';

function verifyWebhook(body: string, signature: string, timestamp: string, secret: string): boolean {
  const ts = parseInt(timestamp, 10);
  const now = Math.floor(Date.now() / 1000);
  
  // 5 dakikadan eski istekleri reddet (replay protection)
  if (Math.abs(now - ts) > 300) return false;
  
  const signedPayload = `${ts}.${body}`;
  const expectedSig = `v1=${crypto.createHmac('sha256', secret).update(signedPayload).digest('hex')}`;
  
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig));
}
```

### Event Tipleri

- `user.created`, `user.updated`, `user.deleted`
- `tenant.created`, `tenant.updated`, `tenant.deleted`
- `member.added`, `member.removed`, `member.role_changed`
- `session.created`, `session.terminated`

---

## ⚠️ Hata Kodları

| Kod | Açıklama |
|-----|----------|
| `INVALID_CREDENTIALS` | Geçersiz email veya şifre |
| `ACCOUNT_LOCKED` | Hesap kilitli (çok fazla başarısız deneme) |
| `ACCOUNT_SUSPENDED` | Hesap askıya alınmış |
| `NOT_A_MEMBER` | Kullanıcı bu şirkete üye değil |
| `FORBIDDEN` | Yetki yok |
| `RATE_LIMITED` | Çok fazla istek |
| `INVITATION_EXPIRED` | Davet süresi dolmuş |
| `CANNOT_REMOVE_OWNER` | Şirket sahibi çıkarılamaz |
