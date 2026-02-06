# How Zalt.io Works

**Mimari ve akış diyagramları**

---

## Genel Mimari

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Application                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Frontend   │  │   Backend    │  │   Mobile     │           │
│  │  (React/Next)│  │  (Node/Go)   │  │  (iOS/And)   │           │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘           │
└─────────┼─────────────────┼─────────────────┼───────────────────┘
          │                 │                 │
          │    HTTPS        │    HTTPS        │    HTTPS
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      api.zalt.io                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   API Gateway + WAF                       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  Login   │ │ Register │ │   MFA    │ │   SSO    │  Lambda   │
│  │  Lambda  │ │  Lambda  │ │  Lambda  │ │  Lambda  │  Functions│
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘           │
│       │            │            │            │                   │
│  ┌────┴────────────┴────────────┴────────────┴────┐             │
│  │                  DynamoDB                       │             │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐         │             │
│  │  │  Users  │ │ Sessions │ │  Realms │         │             │
│  │  └─────────┘ └──────────┘ └─────────┘         │             │
│  └────────────────────────────────────────────────┘             │
│                              │                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                        │
│  │   KMS    │ │   SES    │ │ Secrets  │  AWS Services          │
│  │ (Signing)│ │ (Email)  │ │ Manager  │                        │
│  └──────────┘ └──────────┘ └──────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Authentication Flow

### 1. Login (MFA Yok)

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │     │   API    │     │  Lambda  │     │ DynamoDB │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ POST /login    │                │                │
     │ {email, pass}  │                │                │
     │───────────────>│                │                │
     │                │  Invoke        │                │
     │                │───────────────>│                │
     │                │                │  Query User    │
     │                │                │───────────────>│
     │                │                │<───────────────│
     │                │                │                │
     │                │                │  Verify Pass   │
     │                │                │  (Argon2id)    │
     │                │                │                │
     │                │                │  Sign JWT      │
     │                │                │  (KMS RS256)   │
     │                │                │                │
     │                │                │  Create Session│
     │                │                │───────────────>│
     │                │<───────────────│                │
     │ {tokens, user} │                │                │
     │<───────────────│                │                │
```

### 2. Login (MFA Aktif)

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │     │   API    │     │  Lambda  │     │ DynamoDB │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ POST /login    │                │                │
     │───────────────>│───────────────>│───────────────>│
     │                │                │<───────────────│
     │                │                │                │
     │                │                │  User has MFA  │
     │                │                │  Create MFA    │
     │                │                │  Session       │
     │                │                │───────────────>│
     │                │<───────────────│                │
     │ {mfa_required, │                │                │
     │  mfa_session}  │                │                │
     │<───────────────│                │                │
     │                │                │                │
     │ POST /mfa/     │                │                │
     │ login/verify   │                │                │
     │ {session, code}│                │                │
     │───────────────>│───────────────>│                │
     │                │                │  Verify TOTP   │
     │                │                │  Sign JWT      │
     │                │<───────────────│                │
     │ {tokens, user} │                │                │
     │<───────────────│                │                │
```

---

## Token Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                        Token Timeline                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Login                                                           │
│    │                                                             │
│    ▼                                                             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Access Token (15 min)                                       ││
│  │ ├─────────────────────────────────────────────────────────┐ ││
│  │ │ Valid for API calls                                     │ ││
│  │ └─────────────────────────────────────────────────────────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Refresh Token (7 days)                                      ││
│  │ ├─────────────────────────────────────────────────────────┐ ││
│  │ │ Use to get new access token                             │ ││
│  │ │ Rotated on each use (old token invalid)                 │ ││
│  │ │ 30-second grace period for network retries              │ ││
│  │ └─────────────────────────────────────────────────────────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Token Refresh

```typescript
// Access token expired
if (response.status === 401) {
  // Use refresh token to get new tokens
  const newTokens = await refreshToken();
  // Retry original request
}
```

---

## JWT Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                         JWT Token                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Header                                                          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ {                                                           ││
│  │   "alg": "RS256",                                           ││
│  │   "typ": "JWT",                                             ││
│  │   "kid": "zalt-kms-2026-01-16"  ← Key rotation support      ││
│  │ }                                                           ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  Payload                                                         │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ {                                                           ││
│  │   "sub": "user_abc123",         ← User ID                   ││
│  │   "realm_id": "clinisyn",       ← Tenant                    ││
│  │   "email": "user@example.com",                              ││
│  │   "iss": "https://api.zalt.io", ← Issuer                    ││
│  │   "aud": "https://api.zalt.io", ← Audience                  ││
│  │   "iat": 1737619200,            ← Issued at                 ││
│  │   "exp": 1737620100,            ← Expires (15 min)          ││
│  │   "jti": "unique-token-id",     ← Replay protection         ││
│  │   "type": "access"                                          ││
│  │ }                                                           ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  Signature                                                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ RS256(header + payload, KMS_PRIVATE_KEY)                    ││
│  │ ← Signed by AWS KMS (key never leaves HSM)                  ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Multi-Tenant (Realm) Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Zalt.io Platform                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  Realm: clinisyn│  │  Realm: hsd-crm │  │  Realm: hsd-erp │  │
│  │                 │  │                 │  │                 │  │
│  │  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │  │
│  │  │   Users   │  │  │  │   Users   │  │  │  │   Users   │  │  │
│  │  └───────────┘  │  │  └───────────┘  │  │  └───────────┘  │  │
│  │                 │  │                 │  │                 │  │
│  │  MFA: Required  │  │  MFA: Optional  │  │  MFA: Optional  │  │
│  │  WebAuthn: Yes  │  │  WebAuthn: No   │  │  WebAuthn: No   │  │
│  │                 │  │                 │  │                 │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Shared Infrastructure                     ││
│  │  DynamoDB │ KMS │ API Gateway │ Lambda │ SES                ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

Her realm:
- İzole kullanıcı havuzu
- Kendi MFA politikası
- Kendi OAuth credentials (login ekranında "Clinisyn" görünür)
- Aynı altyapıyı paylaşır

---

## Security Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                        Request Flow                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. WAF (Web Application Firewall)                               │
│     ├── SQL Injection protection                                 │
│     ├── XSS protection                                           │
│     └── Rate limiting (IP-based)                                 │
│                                                                  │
│  2. API Gateway                                                  │
│     ├── Request validation                                       │
│     ├── Throttling                                               │
│     └── CORS                                                     │
│                                                                  │
│  3. Lambda Handler                                               │
│     ├── Input validation (Zod)                                   │
│     ├── Rate limiting (user-based)                               │
│     ├── Account lockout                                          │
│     └── Audit logging                                            │
│                                                                  │
│  4. Password Verification                                        │
│     └── Argon2id (32MB memory, timing-safe)                      │
│                                                                  │
│  5. Token Signing                                                │
│     └── KMS RS256 (HSM-backed, key never exposed)                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Storage

### Naming Convention

**Internal:** `hsd-*` prefix (CloudFormation stack, DynamoDB tables)
**Public:** `zalt.io` domain only

### DynamoDB Tables

| Table | Partition Key | Sort Key | Purpose |
|-------|--------------|----------|---------|
| `zalt-users` | `userId` | - | User data |
| `zalt-sessions` | `SESSION#<id>` | - | Active sessions |
| `zalt-realms` | `REALM#<id>` | - | Realm config |

### User Record

```json
{
  "PK": "REALM#clinisyn",
  "SK": "USER#user_abc123",
  "email": "user@example.com",
  "password_hash": "argon2id$...",
  "mfa_enabled": true,
  "mfa_secret": "encrypted...",
  "webauthn_credentials": [...],
  "status": "active",
  "created_at": "2026-01-15T10:00:00Z"
}
```

---

## Key Rotation

```
┌─────────────────────────────────────────────────────────────────┐
│                      Key Rotation Timeline                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Day 0                    Day 30                   Day 45        │
│    │                        │                        │           │
│    ▼                        ▼                        ▼           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Key A (Active)                                              │ │
│  │ ├──────────────────────────────────────────────────────────┤ │
│  │ │ Signing new tokens                                       │ │
│  │ └──────────────────────────────────────────────────────────┘ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│                        ┌────────────────────────────────────────┐│
│                        │ Key B (Active)                         ││
│                        │ ├──────────────────────────────────────┤││
│                        │ │ Signing new tokens                   │││
│                        │ └──────────────────────────────────────┘││
│                        └────────────────────────────────────────┘│
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Key A (Grace Period)                                        │ │
│  │ ├──────────────────────────────────────────────────────────┤ │
│  │ │ Still valid for verification (15 days)                   │ │
│  │ └──────────────────────────────────────────────────────────┘ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  JWKS always contains both keys during transition                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Sonraki Adımlar

- [Quickstart](./quickstart.md) - 5 dakikada entegrasyon
- [API Reference](./api-reference.md) - Tüm endpoint'ler
- [Security](./security.md) - Güvenlik detayları
