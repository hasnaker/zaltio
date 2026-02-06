# Migration Guide

Bu kılavuz, mevcut kimlik doğrulama sistemlerinden HSD Auth Platform'a geçiş sürecini açıklar.

## İçindekiler

1. [Geçiş Planlaması](#geçiş-planlaması)
2. [Firebase Auth'dan Geçiş](#firebase-authdan-geçiş)
3. [Auth0'dan Geçiş](#auth0dan-geçiş)
4. [AWS Cognito'dan Geçiş](#aws-cognitodan-geçiş)
5. [Özel JWT Sistemlerinden Geçiş](#özel-jwt-sistemlerinden-geçiş)
6. [Veri Aktarımı](#veri-aktarımı)
7. [Geçiş Sonrası Kontroller](#geçiş-sonrası-kontroller)

---

## Geçiş Planlaması

### Geçiş Öncesi Kontrol Listesi

- [ ] Mevcut kullanıcı sayısını belirleyin
- [ ] Kullanıcı veri şemasını analiz edin
- [ ] Mevcut kimlik doğrulama akışlarını belgeleyin
- [ ] SSO/OAuth entegrasyonlarını listeleyin
- [ ] Geçiş zaman çizelgesi oluşturun
- [ ] Geri dönüş planı hazırlayın
- [ ] Test ortamında pilot geçiş yapın

### Önerilen Geçiş Stratejisi

```
┌─────────────────────────────────────────────────────────────┐
│                    GEÇIŞ AŞAMALARI                          │
├─────────────────────────────────────────────────────────────┤
│  1. Hazırlık (1-2 hafta)                                    │
│     - HSD Auth realm oluşturma                              │
│     - SDK entegrasyonu                                      │
│     - Test kullanıcıları ile doğrulama                      │
├─────────────────────────────────────────────────────────────┤
│  2. Paralel Çalışma (2-4 hafta)                             │
│     - Her iki sistem aktif                                  │
│     - Yeni kayıtlar HSD Auth'a                              │
│     - Mevcut kullanıcılar eski sistemde                     │
├─────────────────────────────────────────────────────────────┤
│  3. Kullanıcı Aktarımı (1-2 hafta)                          │
│     - Toplu kullanıcı aktarımı                              │
│     - Şifre sıfırlama kampanyası                            │
│     - SSO geçişi                                            │
├─────────────────────────────────────────────────────────────┤
│  4. Tam Geçiş (1 hafta)                                     │
│     - Eski sistem devre dışı                                │
│     - Yönlendirmeler aktif                                  │
│     - İzleme ve destek                                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Firebase Auth'dan Geçiş

### Kullanıcı Dışa Aktarımı

Firebase Admin SDK kullanarak kullanıcıları dışa aktarın:

```javascript
const admin = require('firebase-admin');
const fs = require('fs');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

async function exportUsers() {
  const users = [];
  let nextPageToken;

  do {
    const result = await admin.auth().listUsers(1000, nextPageToken);
    users.push(...result.users.map(user => ({
      email: user.email,
      emailVerified: user.emailVerified,
      displayName: user.displayName,
      photoURL: user.photoURL,
      disabled: user.disabled,
      metadata: {
        createdAt: user.metadata.creationTime,
        lastSignIn: user.metadata.lastSignInTime
      },
      providerData: user.providerData
    })));
    nextPageToken = result.pageToken;
  } while (nextPageToken);

  fs.writeFileSync('firebase-users.json', JSON.stringify(users, null, 2));
  console.log(`Exported ${users.length} users`);
}

exportUsers();
```

### HSD Auth'a İçe Aktarım

```javascript
const { createHSDAuthClient } = require('@hsd/auth-sdk');
const users = require('./firebase-users.json');

const adminClient = createHSDAuthClient({
  baseUrl: 'https://api.auth.hsdcore.com',
  realmId: 'your-realm-id',
  apiKey: 'your-admin-api-key'
});

async function importUsers() {
  for (const user of users) {
    try {
      await adminClient.admin.createUser({
        email: user.email,
        emailVerified: user.emailVerified,
        profile: {
          firstName: user.displayName?.split(' ')[0] || '',
          lastName: user.displayName?.split(' ').slice(1).join(' ') || '',
          avatarUrl: user.photoURL
        },
        status: user.disabled ? 'disabled' : 'active',
        requirePasswordReset: true // Kullanıcılar yeni şifre belirleyecek
      });
      console.log(`Imported: ${user.email}`);
    } catch (error) {
      console.error(`Failed to import ${user.email}:`, error.message);
    }
  }
}

importUsers();
```

### Firebase SDK'dan HSD SDK'ya Geçiş

**Önce (Firebase):**
```javascript
import { getAuth, signInWithEmailAndPassword } from 'firebase/auth';

const auth = getAuth();
const result = await signInWithEmailAndPassword(auth, email, password);
const token = await result.user.getIdToken();
```

**Sonra (HSD Auth):**
```javascript
import { createHSDAuthClient } from '@hsd/auth-sdk';

const auth = createHSDAuthClient({
  baseUrl: 'https://api.auth.hsdcore.com',
  realmId: 'your-realm-id'
});

const result = await auth.login({ email, password });
const token = result.accessToken;
```

---

## Auth0'dan Geçiş

### Management API ile Dışa Aktarım

```javascript
const { ManagementClient } = require('auth0');

const management = new ManagementClient({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret'
});

async function exportAuth0Users() {
  const users = [];
  let page = 0;
  const perPage = 100;

  while (true) {
    const batch = await management.getUsers({
      page,
      per_page: perPage,
      include_totals: true
    });

    users.push(...batch.users.map(user => ({
      email: user.email,
      emailVerified: user.email_verified,
      name: user.name,
      picture: user.picture,
      blocked: user.blocked,
      metadata: user.user_metadata,
      appMetadata: user.app_metadata,
      createdAt: user.created_at
    })));

    if (users.length >= batch.total) break;
    page++;
  }

  return users;
}
```

### Auth0 SDK'dan HSD SDK'ya Geçiş

**Önce (Auth0):**
```javascript
import { Auth0Client } from '@auth0/auth0-spa-js';

const auth0 = new Auth0Client({
  domain: 'your-tenant.auth0.com',
  clientId: 'your-client-id'
});

await auth0.loginWithRedirect();
const user = await auth0.getUser();
```

**Sonra (HSD Auth):**
```javascript
import { createHSDAuthClient } from '@hsd/auth-sdk';

const auth = createHSDAuthClient({
  baseUrl: 'https://api.auth.hsdcore.com',
  realmId: 'your-realm-id'
});

const result = await auth.login({ email, password });
const user = await auth.getCurrentUser();
```

---

## AWS Cognito'dan Geçiş

### Cognito Kullanıcılarını Dışa Aktarma

```javascript
const AWS = require('aws-sdk');

const cognito = new AWS.CognitoIdentityServiceProvider({
  region: 'eu-central-1'
});

async function exportCognitoUsers(userPoolId) {
  const users = [];
  let paginationToken;

  do {
    const params = {
      UserPoolId: userPoolId,
      Limit: 60,
      PaginationToken: paginationToken
    };

    const result = await cognito.listUsers(params).promise();
    
    users.push(...result.Users.map(user => {
      const attrs = {};
      user.Attributes.forEach(attr => {
        attrs[attr.Name] = attr.Value;
      });

      return {
        email: attrs.email,
        emailVerified: attrs.email_verified === 'true',
        phone: attrs.phone_number,
        name: attrs.name,
        status: user.UserStatus,
        enabled: user.Enabled,
        createdAt: user.UserCreateDate
      };
    }));

    paginationToken = result.PaginationToken;
  } while (paginationToken);

  return users;
}
```

### Cognito SDK'dan HSD SDK'ya Geçiş

**Önce (Cognito):**
```javascript
import { CognitoUserPool, AuthenticationDetails, CognitoUser } from 'amazon-cognito-identity-js';

const userPool = new CognitoUserPool({
  UserPoolId: 'your-user-pool-id',
  ClientId: 'your-client-id'
});

const authDetails = new AuthenticationDetails({
  Username: email,
  Password: password
});

const cognitoUser = new CognitoUser({
  Username: email,
  Pool: userPool
});

cognitoUser.authenticateUser(authDetails, {
  onSuccess: (result) => {
    const token = result.getIdToken().getJwtToken();
  },
  onFailure: (err) => console.error(err)
});
```

**Sonra (HSD Auth):**
```javascript
import { createHSDAuthClient } from '@hsd/auth-sdk';

const auth = createHSDAuthClient({
  baseUrl: 'https://api.auth.hsdcore.com',
  realmId: 'your-realm-id'
});

try {
  const result = await auth.login({ email, password });
  const token = result.accessToken;
} catch (error) {
  console.error(error);
}
```

---

## Özel JWT Sistemlerinden Geçiş

### Mevcut Kullanıcı Tablosunu Aktarma

```javascript
// Örnek: PostgreSQL'den aktarım
const { Pool } = require('pg');
const { createHSDAuthClient } = require('@hsd/auth-sdk');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const adminClient = createHSDAuthClient({
  baseUrl: 'https://api.auth.hsdcore.com',
  realmId: 'your-realm-id',
  apiKey: 'your-admin-api-key'
});

async function migrateUsers() {
  const { rows } = await pool.query(`
    SELECT id, email, first_name, last_name, created_at, is_active
    FROM users
    WHERE deleted_at IS NULL
  `);

  for (const row of rows) {
    await adminClient.admin.createUser({
      email: row.email,
      profile: {
        firstName: row.first_name,
        lastName: row.last_name
      },
      status: row.is_active ? 'active' : 'disabled',
      requirePasswordReset: true,
      metadata: {
        legacyId: row.id,
        migratedAt: new Date().toISOString()
      }
    });
  }
}
```

### JWT Token Formatı Değişikliği

**Eski format:**
```json
{
  "sub": "user123",
  "email": "user@example.com",
  "exp": 1704067200
}
```

**HSD Auth formatı:**
```json
{
  "sub": "user_abc123",
  "email": "user@example.com",
  "realm_id": "realm_xyz",
  "roles": ["user"],
  "iat": 1704063600,
  "exp": 1704067200,
  "iss": "https://auth.hsdcore.com"
}
```

### Backend Token Doğrulama Güncelleme

**Önce:**
```javascript
const jwt = require('jsonwebtoken');

function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}
```

**Sonra:**
```javascript
const { createHSDAuthClient } = require('@hsd/auth-sdk');

const auth = createHSDAuthClient({
  baseUrl: 'https://api.auth.hsdcore.com',
  realmId: 'your-realm-id'
});

async function verifyToken(token) {
  // SDK otomatik olarak token'ı doğrular
  // veya manuel doğrulama için:
  const response = await fetch('https://api.auth.hsdcore.com/auth/verify', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return response.json();
}
```

---

## Veri Aktarımı

### Toplu İçe Aktarım API'si

```bash
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/users/import \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {
        "email": "user1@example.com",
        "emailVerified": true,
        "profile": {
          "firstName": "John",
          "lastName": "Doe"
        },
        "metadata": {
          "legacyId": "old-system-id-1"
        }
      }
    ],
    "options": {
      "sendWelcomeEmail": false,
      "requirePasswordReset": true,
      "skipDuplicates": true
    }
  }'
```

### CSV İçe Aktarım

```csv
email,firstName,lastName,emailVerified,status
user1@example.com,John,Doe,true,active
user2@example.com,Jane,Smith,true,active
```

```bash
# CSV dosyasını içe aktar
curl -X POST https://api.auth.hsdcore.com/admin/realms/realm_abc123/users/import/csv \
  -H "Authorization: Bearer <admin-token>" \
  -F "file=@users.csv" \
  -F "options={\"requirePasswordReset\":true}"
```

---

## Geçiş Sonrası Kontroller

### Doğrulama Kontrol Listesi

- [ ] Tüm kullanıcılar başarıyla aktarıldı
- [ ] Kullanıcılar giriş yapabiliyor
- [ ] Şifre sıfırlama çalışıyor
- [ ] SSO entegrasyonları aktif
- [ ] Token yenileme çalışıyor
- [ ] Webhook'lar tetikleniyor
- [ ] Audit logları kaydediliyor

### İzleme Metrikleri

Geçiş sonrası şu metrikleri izleyin:

| Metrik | Beklenen | Alarm Eşiği |
|--------|----------|-------------|
| Login başarı oranı | >99% | <95% |
| API yanıt süresi | <200ms | >500ms |
| Token yenileme başarısı | >99.9% | <99% |
| Hata oranı | <1% | >5% |

### Geri Dönüş Planı

Sorun durumunda:

1. DNS'i eski sisteme yönlendirin
2. Kullanıcıları bilgilendirin
3. Sorunları analiz edin
4. Düzeltmeleri uygulayın
5. Yeniden geçiş planlayın

```bash
# Acil geri dönüş için DNS güncelleme
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456 \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "api.auth.hsdcore.com",
        "Type": "CNAME",
        "TTL": 60,
        "ResourceRecords": [{"Value": "old-auth-system.hsdcore.com"}]
      }
    }]
  }'
```

---

## Destek

Geçiş sürecinde yardım için:

- 📧 Email: support@hsdcore.com
- 📚 Dokümantasyon: https://docs.auth.hsdcore.com
- 💬 Slack: #zalt-support
