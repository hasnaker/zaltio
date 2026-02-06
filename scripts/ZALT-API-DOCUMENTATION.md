# Zalt API Documentation for Tediyat Integration

> **Version:** 1.0.0  
> **Base URL:** `https://api.zalt.io` (Production) | `http://localhost:4000` (Development)  
> **Last Updated:** 27 Ocak 2026

## Genel Bakış

Zalt, Clerk benzeri bir kimlik doğrulama ve yetkilendirme servisidir. Bu dokümantasyon, Tediyat platformunun Zalt ile entegrasyonu için gerekli tüm bilgileri içerir.

---

## 1. Başlangıç Kurulumu

### 1.1 Zalt Dashboard'dan Application Oluşturma

1. https://dashboard.zalt.io adresine git
2. "Create Application" butonuna tıkla
3. Application bilgilerini gir:
   - **Name:** Tediyat
   - **Type:** Web Application
   - **Allowed Origins:** `http://localhost:3000`, `https://tediyat.com`
   - **Redirect URLs:** `http://localhost:3000/auth/callback`, `https://tediyat.com/auth/callback`

### 1.2 Credentials

Dashboard'dan aldığın credentials:

```env
# .env dosyasına ekle
ZALT_API_URL=https://api.zalt.io
ZALT_CLIENT_ID=zalt_client_xxxxxxxxxxxxxxxx
ZALT_CLIENT_SECRET=zalt_secret_xxxxxxxxxxxxxxxx
ZALT_JWKS_URL=https://api.zalt.io/.well-known/jwks.json
ZALT_ISSUER=https://api.zalt.io
```

---

## 2. Authentication Endpoints

### 2.1 User Registration

**Endpoint:** `POST /api/v1/auth/register`

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "Ahmet",
  "lastName": "Yılmaz",
  "phone": "+905551234567",
  "metadata": {
    "companyName": "ABC Şirketi",
    "taxNumber": "1234567890"
  }
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "usr_xxxxxxxxxxxxxxxx",
      "email": "user@example.com",
      "firstName": "Ahmet",
      "lastName": "Yılmaz",
      "phone": "+905551234567",
      "emailVerified": false,
      "createdAt": "2026-01-27T10:00:00Z"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "zalt_refresh_xxxxxxxxxxxxxxxx",
      "expiresIn": 3600,
      "tokenType": "Bearer"
    }
  }
}
```

**Error Responses:**
- `400` - Validation error (email format, password strength)
- `409` - Email already exists

---

### 2.2 User Login

**Endpoint:** `POST /api/v1/auth/login`

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "usr_xxxxxxxxxxxxxxxx",
      "email": "user@example.com",
      "firstName": "Ahmet",
      "lastName": "Yılmaz",
      "emailVerified": true,
      "lastLoginAt": "2026-01-27T10:00:00Z"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "zalt_refresh_xxxxxxxxxxxxxxxx",
      "expiresIn": 3600,
      "tokenType": "Bearer"
    },
    "tenants": [
      {
        "id": "ten_xxxxxxxxxxxxxxxx",
        "name": "ABC Şirketi",
        "slug": "abc-sirketi",
        "role": "owner"
      }
    ]
  }
}
```

**Error Responses:**
- `401` - Invalid credentials
- `403` - Account locked/disabled

---

### 2.3 Token Refresh

**Endpoint:** `POST /api/v1/auth/refresh`

**Request:**
```json
{
  "refreshToken": "zalt_refresh_xxxxxxxxxxxxxxxx"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "zalt_refresh_yyyyyyyyyyyyyyyy",
    "expiresIn": 3600,
    "tokenType": "Bearer"
  }
}
```

---

### 2.4 Logout

**Endpoint:** `POST /api/v1/auth/logout`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request (optional - logout from all devices):**
```json
{
  "allDevices": true
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### 2.5 Get Current User

**Endpoint:** `GET /api/v1/auth/me`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "usr_xxxxxxxxxxxxxxxx",
    "email": "user@example.com",
    "firstName": "Ahmet",
    "lastName": "Yılmaz",
    "phone": "+905551234567",
    "profilePictureUrl": "https://cdn.zalt.io/avatars/xxx.jpg",
    "emailVerified": true,
    "phoneVerified": false,
    "metadata": {},
    "createdAt": "2026-01-27T10:00:00Z",
    "updatedAt": "2026-01-27T10:00:00Z"
  }
}
```

---

## 3. Multi-Tenant Endpoints

### 3.1 Create Tenant (Organization)

**Endpoint:** `POST /api/v1/tenants`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "name": "ABC Şirketi",
  "slug": "abc-sirketi",
  "metadata": {
    "taxNumber": "1234567890",
    "taxOffice": "Kadıköy",
    "address": {
      "street": "Atatürk Cad. No:123",
      "district": "Kadıköy",
      "city": "İstanbul",
      "postalCode": "34710",
      "country": "Türkiye"
    }
  }
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "ten_xxxxxxxxxxxxxxxx",
    "name": "ABC Şirketi",
    "slug": "abc-sirketi",
    "metadata": {...},
    "createdAt": "2026-01-27T10:00:00Z",
    "membership": {
      "userId": "usr_xxxxxxxxxxxxxxxx",
      "role": "owner",
      "permissions": ["*"]
    }
  }
}
```

---

### 3.2 List User's Tenants

**Endpoint:** `GET /api/v1/tenants`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "id": "ten_xxxxxxxxxxxxxxxx",
      "name": "ABC Şirketi",
      "slug": "abc-sirketi",
      "role": "owner",
      "permissions": ["*"],
      "isDefault": true
    },
    {
      "id": "ten_yyyyyyyyyyyyyyyy",
      "name": "XYZ Ltd.",
      "slug": "xyz-ltd",
      "role": "member",
      "permissions": ["invoice:read", "invoice:create"]
    }
  ]
}
```

---

### 3.3 Switch Active Tenant

**Endpoint:** `POST /api/v1/tenants/{tenantId}/switch`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tenant": {
      "id": "ten_xxxxxxxxxxxxxxxx",
      "name": "ABC Şirketi",
      "slug": "abc-sirketi"
    }
  }
}
```

> **Not:** Yeni access token, seçilen tenant'ın bilgilerini içerir.

---

### 3.4 Invite User to Tenant

**Endpoint:** `POST /api/v1/tenants/{tenantId}/invitations`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "email": "newuser@example.com",
  "role": "member",
  "permissions": ["invoice:read", "invoice:create", "company:read"]
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "inv_xxxxxxxxxxxxxxxx",
    "email": "newuser@example.com",
    "role": "member",
    "status": "pending",
    "expiresAt": "2026-02-03T10:00:00Z",
    "invitedBy": {
      "id": "usr_xxxxxxxxxxxxxxxx",
      "name": "Ahmet Yılmaz"
    }
  }
}
```

---

### 3.5 Accept Invitation

**Endpoint:** `POST /api/v1/invitations/{invitationId}/accept`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "tenant": {
      "id": "ten_xxxxxxxxxxxxxxxx",
      "name": "ABC Şirketi"
    },
    "membership": {
      "role": "member",
      "permissions": ["invoice:read", "invoice:create", "company:read"]
    }
  }
}
```

---

### 3.6 List Tenant Members

**Endpoint:** `GET /api/v1/tenants/{tenantId}/members`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "id": "mem_xxxxxxxxxxxxxxxx",
      "user": {
        "id": "usr_xxxxxxxxxxxxxxxx",
        "email": "owner@example.com",
        "firstName": "Ahmet",
        "lastName": "Yılmaz"
      },
      "role": "owner",
      "permissions": ["*"],
      "joinedAt": "2026-01-27T10:00:00Z"
    },
    {
      "id": "mem_yyyyyyyyyyyyyyyy",
      "user": {
        "id": "usr_yyyyyyyyyyyyyyyy",
        "email": "member@example.com",
        "firstName": "Mehmet",
        "lastName": "Demir"
      },
      "role": "member",
      "permissions": ["invoice:read", "invoice:create"],
      "joinedAt": "2026-01-28T10:00:00Z"
    }
  ]
}
```

---

## 4. Role & Permission Management

### 4.1 Predefined Roles

Zalt, Tediyat için aşağıdaki önceden tanımlı rolleri destekler:

| Role | Description | Default Permissions |
|------|-------------|---------------------|
| `owner` | Tenant sahibi | `*` (tüm yetkiler) |
| `admin` | Yönetici | Kullanıcı yönetimi hariç tüm yetkiler |
| `accountant` | Muhasebeci | Finansal işlemler |
| `member` | Standart kullanıcı | Temel okuma/yazma |
| `viewer` | Salt okunur | Sadece okuma |

---

### 4.2 Permission List

Tediyat'ın kullandığı permission'lar:

```typescript
// Company Management
"company:read"
"company:create"
"company:update"
"company:delete"

// Invoice Management
"invoice:read"
"invoice:create"
"invoice:update"
"invoice:delete"
"invoice:send"

// Current Accounts
"current_account:read"
"current_account:create"
"current_account:update"
"current_account:delete"

// Cash Management
"cash:read"
"cash:create"
"cash:update"
"cash:delete"

// Bank Integration
"bank:read"
"bank:connect"
"bank:transfer"

// Reports
"report:read"
"report:export"

// Settings
"settings:read"
"settings:update"

// User Management (Admin only)
"user:read"
"user:invite"
"user:update"
"user:delete"

// Audit Logs
"audit:read"
"audit:export"
```

---

### 4.3 Create Custom Role

**Endpoint:** `POST /api/v1/tenants/{tenantId}/roles`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "name": "sales_manager",
  "displayName": "Satış Müdürü",
  "description": "Satış ve fatura işlemleri",
  "permissions": [
    "invoice:read",
    "invoice:create",
    "invoice:update",
    "current_account:read",
    "report:read"
  ]
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "role_xxxxxxxxxxxxxxxx",
    "name": "sales_manager",
    "displayName": "Satış Müdürü",
    "description": "Satış ve fatura işlemleri",
    "permissions": [...],
    "isCustom": true,
    "createdAt": "2026-01-27T10:00:00Z"
  }
}
```

---

### 4.4 Update Member Permissions

**Endpoint:** `PATCH /api/v1/tenants/{tenantId}/members/{memberId}`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "role": "member",
  "permissions": ["invoice:read", "invoice:create", "report:read"]
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "mem_xxxxxxxxxxxxxxxx",
    "role": "member",
    "permissions": ["invoice:read", "invoice:create", "report:read"],
    "updatedAt": "2026-01-27T10:00:00Z"
  }
}
```

---

## 5. JWT Token Structure

### 5.1 Access Token Payload

```json
{
  "sub": "usr_xxxxxxxxxxxxxxxx",
  "email": "user@example.com",
  "firstName": "Ahmet",
  "lastName": "Yılmaz",
  "emailVerified": true,
  "tenant": {
    "id": "ten_xxxxxxxxxxxxxxxx",
    "name": "ABC Şirketi",
    "slug": "abc-sirketi"
  },
  "role": "owner",
  "permissions": ["*"],
  "iat": 1706349600,
  "exp": 1706353200,
  "iss": "https://api.zalt.io",
  "aud": "zalt_client_xxxxxxxxxxxxxxxx"
}
```

### 5.2 Token Verification

Tediyat backend'i JWT'yi şu şekilde doğrular:

1. **JWKS Endpoint:** `GET https://api.zalt.io/.well-known/jwks.json`
2. **Algorithm:** RS256
3. **Issuer:** `https://api.zalt.io`
4. **Audience:** `zalt_client_xxxxxxxxxxxxxxxx` (senin client ID'n)

**JWKS Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "zalt_key_xxxxxxxx",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

---

## 6. Webhooks

### 6.1 Webhook Events

Zalt, aşağıdaki olaylar için webhook gönderir:

| Event | Description |
|-------|-------------|
| `user.created` | Yeni kullanıcı kaydı |
| `user.updated` | Kullanıcı bilgisi güncellendi |
| `user.deleted` | Kullanıcı silindi |
| `tenant.created` | Yeni tenant oluşturuldu |
| `tenant.updated` | Tenant güncellendi |
| `member.added` | Tenant'a yeni üye eklendi |
| `member.removed` | Üye tenant'tan çıkarıldı |
| `member.role_changed` | Üye rolü değişti |
| `session.created` | Yeni oturum açıldı |
| `session.revoked` | Oturum sonlandırıldı |

### 6.2 Webhook Payload

```json
{
  "id": "evt_xxxxxxxxxxxxxxxx",
  "type": "user.created",
  "timestamp": "2026-01-27T10:00:00Z",
  "data": {
    "user": {
      "id": "usr_xxxxxxxxxxxxxxxx",
      "email": "user@example.com",
      "firstName": "Ahmet",
      "lastName": "Yılmaz"
    }
  },
  "metadata": {
    "clientId": "zalt_client_xxxxxxxxxxxxxxxx",
    "ipAddress": "192.168.1.1"
  }
}
```

### 6.3 Webhook Signature Verification

```typescript
// Header: X-Zalt-Signature
const signature = req.headers['x-zalt-signature'];
const payload = JSON.stringify(req.body);
const expectedSignature = crypto
  .createHmac('sha256', ZALT_WEBHOOK_SECRET)
  .update(payload)
  .digest('hex');

if (signature !== expectedSignature) {
  throw new Error('Invalid webhook signature');
}
```

---

## 7. Session Management

### 7.1 List Active Sessions

**Endpoint:** `GET /api/v1/auth/sessions`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "id": "ses_xxxxxxxxxxxxxxxx",
      "deviceInfo": {
        "browser": "Chrome",
        "os": "macOS",
        "device": "Desktop"
      },
      "ipAddress": "192.168.1.1",
      "location": "İstanbul, Türkiye",
      "lastActiveAt": "2026-01-27T10:00:00Z",
      "createdAt": "2026-01-25T10:00:00Z",
      "isCurrent": true
    }
  ]
}
```

### 7.2 Revoke Session

**Endpoint:** `DELETE /api/v1/auth/sessions/{sessionId}`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Session revoked successfully"
}
```

---

## 8. Password Management

### 8.1 Request Password Reset

**Endpoint:** `POST /api/v1/auth/forgot-password`

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset email sent"
}
```

### 8.2 Reset Password

**Endpoint:** `POST /api/v1/auth/reset-password`

**Request:**
```json
{
  "token": "reset_token_xxxxxxxx",
  "password": "NewSecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

### 8.3 Change Password (Authenticated)

**Endpoint:** `POST /api/v1/auth/change-password`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "currentPassword": "OldPass123!",
  "newPassword": "NewSecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

---

## 9. Email Verification

### 9.1 Send Verification Email

**Endpoint:** `POST /api/v1/auth/send-verification`

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Verification email sent"
}
```

### 9.2 Verify Email

**Endpoint:** `POST /api/v1/auth/verify-email`

**Request:**
```json
{
  "token": "verify_token_xxxxxxxx"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Email verified successfully"
}
```

---

## 10. Error Handling

### 10.1 Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Email format is invalid",
    "details": {
      "field": "email",
      "value": "invalid-email"
    },
    "requestId": "req_xxxxxxxxxxxxxxxx"
  }
}
```

### 10.2 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `INVALID_CREDENTIALS` | 401 | Wrong email/password |
| `TOKEN_EXPIRED` | 401 | Access token expired |
| `TOKEN_INVALID` | 401 | Invalid token format |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## 11. Rate Limiting

| Endpoint Category | Limit |
|-------------------|-------|
| Authentication | 10 requests/minute |
| Token Refresh | 30 requests/minute |
| API Calls | 1000 requests/minute |
| Webhooks | Unlimited |

**Rate Limit Headers:**
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1706353200
```

---

## 12. SDK & Integration Examples

### 12.1 NestJS Backend Integration

```typescript
// zalt.module.ts
import { Module, Global } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';
import { ZaltService } from './zalt.service';
import { ZaltGuard } from './zalt.guard';

@Global()
@Module({
  imports: [
    HttpModule,
    JwtModule.register({}),
  ],
  providers: [ZaltService, ZaltGuard],
  exports: [ZaltService, ZaltGuard],
})
export class ZaltModule {}
```

```typescript
// zalt.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { ZaltService } from './zalt.service';

@Injectable()
export class ZaltGuard implements CanActivate {
  constructor(private zaltService: ZaltService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractToken(request);
    
    if (!token) return false;
    
    const payload = await this.zaltService.verifyToken(token);
    request.user = payload;
    request.tenantId = payload.tenant?.id;
    
    return true;
  }

  private extractToken(request: any): string | null {
    const auth = request.headers.authorization;
    if (auth?.startsWith('Bearer ')) {
      return auth.substring(7);
    }
    return null;
  }
}
```

```typescript
// zalt.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';

@Injectable()
export class ZaltService {
  private jwksClient: jwksClient.JwksClient;

  constructor(
    private httpService: HttpService,
    private configService: ConfigService,
  ) {
    this.jwksClient = jwksClient({
      jwksUri: this.configService.get('ZALT_JWKS_URL'),
      cache: true,
      cacheMaxAge: 86400000, // 24 hours
    });
  }

  async verifyToken(token: string): Promise<any> {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) throw new UnauthorizedException('Invalid token');

    const key = await this.jwksClient.getSigningKey(decoded.header.kid);
    const publicKey = key.getPublicKey();

    return jwt.verify(token, publicKey, {
      issuer: this.configService.get('ZALT_ISSUER'),
      audience: this.configService.get('ZALT_CLIENT_ID'),
    });
  }

  async getUserTenants(accessToken: string): Promise<any[]> {
    const response = await this.httpService.axiosRef.get(
      `${this.configService.get('ZALT_API_URL')}/api/v1/tenants`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    return response.data.data;
  }
}
```

### 12.2 Next.js Frontend Integration

```typescript
// lib/zalt.ts
const ZALT_API_URL = process.env.NEXT_PUBLIC_ZALT_API_URL;

export const zaltApi = {
  async login(email: string, password: string) {
    const res = await fetch(`${ZALT_API_URL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    return res.json();
  },

  async register(data: RegisterData) {
    const res = await fetch(`${ZALT_API_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return res.json();
  },

  async refreshToken(refreshToken: string) {
    const res = await fetch(`${ZALT_API_URL}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
    return res.json();
  },

  async getMe(accessToken: string) {
    const res = await fetch(`${ZALT_API_URL}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return res.json();
  },
};
```

```typescript
// contexts/AuthContext.tsx
'use client';
import { createContext, useContext, useState, useEffect } from 'react';
import { zaltApi } from '@/lib/zalt';

interface AuthContextType {
  user: User | null;
  tenant: Tenant | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  switchTenant: (tenantId: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      zaltApi.getMe(token).then(res => {
        if (res.success) {
          setUser(res.data);
        }
        setIsLoading(false);
      });
    } else {
      setIsLoading(false);
    }
  }, []);

  const login = async (email: string, password: string) => {
    const res = await zaltApi.login(email, password);
    if (res.success) {
      localStorage.setItem('accessToken', res.data.tokens.accessToken);
      localStorage.setItem('refreshToken', res.data.tokens.refreshToken);
      setUser(res.data.user);
      if (res.data.tenants?.length > 0) {
        setTenant(res.data.tenants[0]);
      }
    }
    return res;
  };

  const logout = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    setUser(null);
    setTenant(null);
  };

  return (
    <AuthContext.Provider value={{ user, tenant, isLoading, login, logout, switchTenant }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext)!;
```

---

## 13. Environment Configuration

### 13.1 Backend (.env)

```env
# Zalt Configuration
ZALT_API_URL=https://api.zalt.io
ZALT_CLIENT_ID=zalt_client_xxxxxxxxxxxxxxxx
ZALT_CLIENT_SECRET=zalt_secret_xxxxxxxxxxxxxxxx
ZALT_JWKS_URL=https://api.zalt.io/.well-known/jwks.json
ZALT_ISSUER=https://api.zalt.io
ZALT_WEBHOOK_SECRET=zalt_webhook_xxxxxxxxxxxxxxxx

# For development
ZALT_API_URL=http://localhost:4000
```

### 13.2 Frontend (.env.local)

```env
NEXT_PUBLIC_ZALT_API_URL=https://api.zalt.io
NEXT_PUBLIC_ZALT_CLIENT_ID=zalt_client_xxxxxxxxxxxxxxxx

# For development
NEXT_PUBLIC_ZALT_API_URL=http://localhost:4000
```

---

## 14. Testing

### 14.1 Test Credentials

Development ortamında kullanılabilecek test hesapları:

| Email | Password | Role |
|-------|----------|------|
| `owner@test.zalt.io` | `Test1234!` | Owner |
| `admin@test.zalt.io` | `Test1234!` | Admin |
| `member@test.zalt.io` | `Test1234!` | Member |

### 14.2 Test Tenant

```json
{
  "id": "ten_test_xxxxxxxx",
  "name": "Test Şirketi",
  "slug": "test-sirketi"
}
```

---

## 15. Migration Checklist

Tediyat'ı Zalt'a entegre ederken yapılacaklar:

### Backend (finans-platform)

- [ ] `ZaltModule` oluştur
- [ ] `ZaltService` - Token verification, API calls
- [ ] `ZaltGuard` - JWT validation guard
- [ ] `@CurrentUser()` decorator
- [ ] `@RequirePermission()` decorator
- [ ] Webhook endpoint (`/api/v1/webhooks/zalt`)
- [ ] Environment variables ekle
- [ ] Mevcut auth endpoint'lerini kaldır veya proxy yap

### Frontend (finans-platform-web)

- [ ] `AuthContext` güncelle
- [ ] Login/Register sayfalarını Zalt API'ye bağla
- [ ] Token storage (localStorage/cookies)
- [ ] Token refresh interceptor
- [ ] Tenant selector component
- [ ] Permission-based UI rendering

### Database

- [ ] `users` tablosuna `zalt_user_id` kolonu ekle
- [ ] `user_tenants` tablosunu Zalt membership ile senkronize et
- [ ] Webhook ile user/tenant sync

---

## 16. Support

- **Documentation:** https://docs.zalt.io
- **API Status:** https://status.zalt.io
- **Support Email:** support@zalt.io
- **Discord:** https://discord.gg/zalt

---

*Bu dokümantasyon Tediyat - Zalt entegrasyonu için hazırlanmıştır.*
