# Tediyat - Zalt.io Hızlı Başlangıç

**5 dakikada entegrasyon!**

---

## 1. SDK Kurulumu

```bash
npm install @zalt/auth-sdk
```

## 2. Client Oluşturma

```typescript
import { createZaltClient } from '@zalt/auth-sdk';

const auth = createZaltClient({
  baseUrl: 'https://api.zalt.io',
  realmId: 'tediyat'
});
```

## 3. Kayıt

```typescript
const result = await auth.register({
  email: 'user@example.com',
  password: 'SecurePass123!',
  profile: {
    first_name: 'Ahmet',
    last_name: 'Yılmaz'
  },
  metadata: {
    company_name: 'ABC Ltd.'
  }
});

console.log('Kullanıcı:', result.user);
console.log('Şirket:', result.tenant);
```

## 4. Giriş

```typescript
const loginResult = await auth.login({
  email: 'user@example.com',
  password: 'SecurePass123!'
});

// MFA gerekli mi?
if (loginResult.mfaRequired) {
  // MFA ekranına yönlendir
  const mfaResult = await auth.mfa.verifyLogin(
    loginResult.mfaSessionId,
    '123456'  // Kullanıcının girdiği kod
  );
}

// Şirket listesi
console.log('Şirketler:', loginResult.tenants);
```

## 5. Şirket Değiştirme

```typescript
// Kullanıcı birden fazla şirkette üye olabilir
const switchResult = await auth.switchTenant('tnt_xyz789');

// Yeni token'lar otomatik kaydedilir
console.log('Aktif şirket:', switchResult.tenant);
```

## 6. API İstekleri

```typescript
// Token otomatik eklenir
const user = await auth.getCurrentUser();

// Manuel istek
const response = await fetch('https://api.tediyat.com/invoices', {
  headers: {
    'Authorization': `Bearer ${auth.getAccessToken()}`
  }
});
```

## 7. Çıkış

```typescript
await auth.logout();
// veya tüm cihazlardan:
await auth.logout({ allDevices: true });
```

---

## Hızlı Referans

### Endpoint'ler

| İşlem | Endpoint |
|-------|----------|
| Kayıt | `POST /register` |
| Giriş | `POST /login` |
| Çıkış | `POST /logout` |
| Token Yenile | `POST /refresh` |
| Kullanıcı Bilgisi | `GET /me` |
| Şirket Değiştir | `POST /tediyat/switch` |
| Üye Listesi | `GET /tediyat/members` |
| Davet Gönder | `POST /tediyat/invitations` |

### Hazır Roller

| Rol | Açıklama |
|-----|----------|
| `owner` | Tam yetki |
| `admin` | Yönetici |
| `accountant` | Muhasebeci |
| `viewer` | Görüntüleyici |
| `external_accountant` | Dış muhasebeci |

### Hata Kodları

| Kod | Anlamı |
|-----|--------|
| `INVALID_CREDENTIALS` | Yanlış email/şifre |
| `RATE_LIMITED` | Çok fazla deneme |
| `TOKEN_EXPIRED` | Token süresi dolmuş |
| `MFA_REQUIRED` | 2FA gerekli |
| `NOT_MEMBER` | Şirkete üye değil |

---

## Örnek React Kullanımı

```tsx
import { createZaltClient } from '@zalt/auth-sdk';
import { useState, useEffect } from 'react';

const auth = createZaltClient({
  baseUrl: 'https://api.zalt.io',
  realmId: 'tediyat'
});

function App() {
  const [user, setUser] = useState(null);
  const [tenants, setTenants] = useState([]);

  useEffect(() => {
    if (auth.isAuthenticated()) {
      auth.getCurrentUser().then(setUser);
    }
  }, []);

  const handleLogin = async (email, password) => {
    const result = await auth.login({ email, password });
    
    if (result.mfaRequired) {
      // MFA ekranına yönlendir
      return { mfaRequired: true, sessionId: result.mfaSessionId };
    }
    
    setUser(result.user);
    setTenants(result.tenants);
  };

  const handleLogout = async () => {
    await auth.logout();
    setUser(null);
  };

  return (
    <div>
      {user ? (
        <>
          <p>Hoşgeldin, {user.first_name}!</p>
          <button onClick={handleLogout}>Çıkış</button>
        </>
      ) : (
        <LoginForm onSubmit={handleLogin} />
      )}
    </div>
  );
}
```

---

## Detaylı Dokümantasyon

- [Tam API Referansı](./TEDIYAT-ZALT-DOCUMENTATION.md)
- [Hata Çözümleri](./TEDIYAT-TROUBLESHOOTING.md)
- [Entegrasyon Rehberi](./INTEGRATION-GUIDE.md)

---

## Destek

Email: **dev@zalt.io**
