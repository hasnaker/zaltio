# Design Document: Tediyat Multi-Tenant Integration

## Overview

Bu design dokümanı, Zalt.io'nun Tediyat ön muhasebe platformu için multi-tenant authentication ve authorization servisini tanımlar. Mevcut Zalt.io altyapısı üzerine inşa edilecek ve Tediyat'ın özel ihtiyaçlarını karşılayacak şekilde genişletilecektir.

### Key Design Decisions

1. **Mevcut Altyapı Kullanımı**: Zalt.io'nun core auth (login, register, refresh, logout, MFA) altyapısı kullanılacak
2. **Organization = Tenant**: Zalt.io'daki Organization modeli, Tediyat'ın Tenant konseptine map edilecek
3. **Membership = Tenant Üyeliği**: Kullanıcı-tenant ilişkisi membership modeli ile yönetilecek
4. **Role-Based Access**: Predefined + custom roller desteklenecek
5. **JWT with Tenant Context**: Access token'a tenant_id, role, permissions eklenecek

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TEDIYAT FRONTEND                            │
│                    (Next.js / React Application)                    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         ZALT.IO API GATEWAY                         │
│                    (api.zalt.io/v1/tediyat/...)                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌───────────┐   ┌───────────┐   ┌───────────┐
            │   AUTH    │   │  TENANT   │   │   RBAC    │
            │ HANDLERS  │   │ HANDLERS  │   │ HANDLERS  │
            └───────────┘   └───────────┘   └───────────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         SHARED SERVICES                             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │  JWT    │ │ Password│ │  Email  │ │  Rate   │ │  Audit  │       │
│  │ Service │ │ Service │ │ Service │ │ Limiter │ │ Logger  │       │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘       │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         AWS DYNAMODB                                │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │  Users  │ │ Tenants │ │Members  │ │  Roles  │ │Sessions │       │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘       │
└─────────────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Tediyat Auth Handler

Mevcut auth handler'ları extend ederek Tediyat-specific logic ekler.

```typescript
// src/handlers/tediyat/register.handler.ts
interface TediyatRegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phone?: string;
  companyName: string;
  metadata?: {
    taxNumber?: string;
    address?: string;
  };
}

interface TediyatRegisterResponse {
  success: true;
  data: {
    user: {
      id: string;
      email: string;
      firstName: string;
      lastName: string;
    };
    tenant: {
      id: string;
      name: string;
      slug: string;
    };
    tokens: {
      accessToken: string;
      refreshToken: string;
      expiresIn: number;
    };
  };
}
```

### 2. Tediyat Login Handler

Login response'a tenant listesi ekler.

```typescript
// src/handlers/tediyat/login.handler.ts
interface TediyatLoginResponse {
  success: true;
  data: {
    user: {
      id: string;
      email: string;
      firstName: string;
      lastName: string;
    };
    tenants: Array<{
      id: string;
      name: string;
      slug: string;
      role: string;
    }>;
    tokens: {
      accessToken: string;
      refreshToken: string;
      expiresIn: number;
    };
  };
}
```

### 3. Tenant Service

Tenant CRUD ve yönetim işlemleri.

```typescript
// src/services/tediyat/tenant.service.ts
interface TenantService {
  createTenant(input: CreateTenantInput): Promise<Tenant>;
  getTenant(tenantId: string): Promise<Tenant | null>;
  listUserTenants(userId: string): Promise<TenantWithRole[]>;
  updateTenant(tenantId: string, updates: Partial<Tenant>): Promise<Tenant>;
  deleteTenant(tenantId: string): Promise<void>;
  generateSlug(name: string): string;
  validateSlugUniqueness(slug: string): Promise<boolean>;
}
```

### 4. Membership Service

Kullanıcı-tenant ilişkisi yönetimi.

```typescript
// src/services/tediyat/membership.service.ts
interface MembershipService {
  createMembership(input: CreateMembershipInput): Promise<Membership>;
  getMembership(userId: string, tenantId: string): Promise<Membership | null>;
  listTenantMembers(tenantId: string, options?: PaginationOptions): Promise<PaginatedMembers>;
  updateMembership(userId: string, tenantId: string, updates: MembershipUpdates): Promise<Membership>;
  deleteMembership(userId: string, tenantId: string): Promise<void>;
  transferOwnership(tenantId: string, fromUserId: string, toUserId: string): Promise<void>;
}
```

### 5. Invitation Service

Davet mekanizması.

```typescript
// src/services/tediyat/invitation.service.ts
interface InvitationService {
  createInvitation(input: CreateInvitationInput): Promise<Invitation>;
  getInvitation(token: string): Promise<Invitation | null>;
  acceptInvitation(token: string, acceptInput: AcceptInvitationInput): Promise<Membership>;
  cancelInvitation(invitationId: string): Promise<void>;
  listPendingInvitations(tenantId: string): Promise<Invitation[]>;
  resendInvitation(invitationId: string): Promise<void>;
}
```

### 6. Role & Permission Service

Rol ve yetki yönetimi.

```typescript
// src/services/tediyat/role.service.ts
interface RoleService {
  getSystemRoles(): Role[];
  createCustomRole(tenantId: string, input: CreateRoleInput): Promise<Role>;
  updateRole(roleId: string, updates: Partial<Role>): Promise<Role>;
  deleteRole(roleId: string): Promise<void>;
  listTenantRoles(tenantId: string): Promise<Role[]>;
  getEffectivePermissions(roleId: string, additionalPermissions?: string[]): string[];
}

// Predefined Roles
const TEDIYAT_SYSTEM_ROLES = {
  owner: {
    id: 'role_owner',
    name: 'Şirket Sahibi',
    permissions: ['*'],
    isSystem: true
  },
  admin: {
    id: 'role_admin',
    name: 'Yönetici',
    permissions: [
      'invoices:*', 'accounts:*', 'cash:*', 'bank:*',
      'reports:*', 'inventory:*', 'e-invoice:*',
      'settings:*', 'quotes:*', 'payments:*'
    ],
    isSystem: true
  },
  accountant: {
    id: 'role_accountant',
    name: 'Muhasebeci',
    permissions: [
      'invoices:read', 'invoices:create', 'invoices:update',
      'accounts:read', 'accounts:create', 'accounts:update',
      'cash:read', 'cash:write', 'bank:read', 'bank:write',
      'reports:read', 'reports:export'
    ],
    isSystem: true
  },
  viewer: {
    id: 'role_viewer',
    name: 'Görüntüleyici',
    permissions: [
      'invoices:read', 'accounts:read', 'cash:read',
      'bank:read', 'reports:read', 'inventory:read'
    ],
    isSystem: true
  },
  external_accountant: {
    id: 'role_external_accountant',
    name: 'Mali Müşavir',
    permissions: [
      'invoices:read', 'accounts:read', 'reports:read',
      'reports:export', 'e-invoice:read'
    ],
    isSystem: true
  }
};
```

### 7. Tenant Switch Handler

Tenant değiştirme ve yeni token üretme.

```typescript
// src/handlers/tediyat/switch.handler.ts
interface TenantSwitchResponse {
  success: true;
  data: {
    accessToken: string;
    tenant: {
      id: string;
      name: string;
      slug: string;
    };
    role: string;
    permissions: string[];
  };
}
```

## Data Models

### Tenant Model

```typescript
// src/models/tediyat/tenant.model.ts
interface Tenant {
  id: string;              // ten_xxx format
  realm_id: string;        // tediyat realm
  name: string;            // "ABC Şirketi"
  slug: string;            // "abc-sirketi"
  logo_url?: string;
  metadata?: {
    taxNumber?: string;
    address?: string;
    phone?: string;
    email?: string;
  };
  settings?: {
    mfa_required?: boolean;
    session_timeout?: number;
    allowed_domains?: string[];
  };
  status: 'active' | 'suspended' | 'deleted';
  created_at: string;
  updated_at: string;
  created_by: string;      // owner user_id
}

// DynamoDB Schema
// PK: TENANT#{tenant_id}
// SK: METADATA
// GSI1: REALM#{realm_id}#TENANT
// GSI2: SLUG#{slug}
```

### Membership Model

```typescript
// src/models/tediyat/membership.model.ts
interface Membership {
  user_id: string;
  tenant_id: string;
  realm_id: string;
  role_id: string;                    // role_owner, role_admin, etc.
  direct_permissions?: string[];      // Additional permissions beyond role
  status: 'active' | 'invited' | 'suspended';
  is_default: boolean;                // Default tenant for user
  invited_by?: string;
  invited_at?: string;
  joined_at: string;
  updated_at: string;
}

// DynamoDB Schema
// PK: USER#{user_id}#TENANT#{tenant_id}
// SK: MEMBERSHIP
// GSI1: TENANT#{tenant_id}#MEMBERS
// GSI2: USER#{user_id}#MEMBERSHIPS
```

### Invitation Model

```typescript
// src/models/tediyat/invitation.model.ts
interface Invitation {
  id: string;              // inv_xxx format
  tenant_id: string;
  email: string;
  role_id: string;
  direct_permissions?: string[];
  token: string;           // Hashed
  status: 'pending' | 'accepted' | 'expired' | 'cancelled';
  invited_by: string;
  expires_at: string;      // 7 days from creation
  created_at: string;
  accepted_at?: string;
}

// DynamoDB Schema
// PK: INVITATION#{invitation_id}
// SK: METADATA
// GSI1: TENANT#{tenant_id}#INVITATIONS
// GSI2: TOKEN#{token_hash}
// TTL: expires_at (auto-delete expired)
```

### Role Model

```typescript
// src/models/tediyat/role.model.ts
interface Role {
  id: string;              // role_xxx format
  tenant_id?: string;      // null for system roles
  name: string;
  description?: string;
  permissions: string[];
  inherits_from?: string;  // Parent role ID
  is_system: boolean;
  created_at: string;
  updated_at: string;
}

// DynamoDB Schema
// PK: ROLE#{role_id}
// SK: METADATA
// GSI1: TENANT#{tenant_id}#ROLES (for custom roles)
```

### JWT Claims for Tediyat

```typescript
interface TediyatAccessTokenClaims {
  sub: string;             // user_id
  email: string;
  tenantId: string;        // Current tenant
  role: string;            // role_id
  permissions: string[];   // Effective permissions (max 50, else use /permissions endpoint)
  iat: number;
  exp: number;
  iss: 'zalt.io';
  aud: 'tediyat';
  jti: string;
  type: 'access';
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Registration Creates Complete Setup

*For any* valid registration request with email, password, and company name, the system should create a user account, a tenant with unique slug, and a membership with owner role, returning all three in the response.

**Validates: Requirements 1.1, 1.2, 1.5, 9.1, 9.2, 9.3**

### Property 2: Password Policy Enforcement

*For any* password submitted during registration or password change, the system should reject passwords that don't meet all criteria (8+ chars, uppercase, lowercase, number, special char) and accept passwords that meet all criteria.

**Validates: Requirements 1.3, 25.1-25.5**

### Property 3: Slug Generation Consistency

*For any* company name, the slugify function should produce a valid URL-safe slug, and the same input should always produce the same output (deterministic).

**Validates: Requirements 1.6, 9.2**

### Property 4: Login Returns Complete Tenant List

*For any* successful login, the response should include all tenants the user belongs to, with each tenant containing id, name, slug, and the user's role in that tenant.

**Validates: Requirements 2.1, 2.2, 2.3**

### Property 5: No Email Enumeration

*For any* login attempt with invalid credentials (wrong email or wrong password), the system should return the same generic error message and take approximately the same time to respond.

**Validates: Requirements 2.4, 6.5**

### Property 6: Token Refresh Rotation

*For any* valid refresh token, using it should return new access and refresh tokens, and the old refresh token should be invalidated (rejected on subsequent use after grace period).

**Validates: Requirements 3.1, 3.2**

### Property 7: Grace Period Idempotency

*For any* refresh token that has been rotated, using the old token within 30 seconds should return the same new tokens (idempotent response), not generate new ones.

**Validates: Requirements 3.3**

### Property 8: Logout Session Invalidation

*For any* logout request, the refresh token should be invalidated immediately. With allDevices=true, all user sessions should be terminated.

**Validates: Requirements 4.1, 4.2**

### Property 9: Me Endpoint Security

*For any* /me response, the password hash should never be included. The response should include user profile, current tenant (if X-Tenant-ID provided), and permissions.

**Validates: Requirements 5.1, 5.2, 5.3, 5.4**

### Property 10: Password Reset Token Security

*For any* password reset token, it should be 32 bytes random, valid for 1 hour, and single-use. After password reset, all user sessions should be invalidated.

**Validates: Requirements 6.2, 6.3, 6.4**

### Property 11: Email Verification Code Format

*For any* email verification request, the system should generate a 6-digit numeric code. Successful verification should set email_verified=true.

**Validates: Requirements 7.1, 7.4**

### Property 12: TOTP Compliance

*For any* 2FA setup, the system should generate a valid TOTP secret and otpauth:// URL compatible with standard authenticator apps. The system should accept codes within ±1 period window.

**Validates: Requirements 8.1, 8.2, 8.6**

### Property 13: Backup Codes Generation

*For any* 2FA enablement, the system should generate exactly 10 backup codes, each single-use.

**Validates: Requirements 8.3**

### Property 14: Tenant Creation with Ownership

*For any* tenant creation, the system should generate unique tenant ID (ten_xxx format), unique slug, and automatically assign the creator as owner.

**Validates: Requirements 9.1, 9.2, 9.3, 9.5**

### Property 15: Tenant List Completeness

*For any* tenant list request, the response should include all tenants the user belongs to, with complete information (id, name, slug, role, member count, created_at).

**Validates: Requirements 10.1, 10.2, 10.3**

### Property 16: Tenant Switch Authorization

*For any* tenant switch request, the system should verify user has active membership in target tenant. Success returns new token with tenant context; failure returns 403.

**Validates: Requirements 11.1, 11.2, 11.3, 11.4**

### Property 17: Invitation Flow Integrity

*For any* invitation, the system should track status (pending/accepted/expired), support both existing and new users, and create membership with specified role upon acceptance.

**Validates: Requirements 12.3, 12.4, 12.5, 12.6, 12.7, 13.3**

### Property 18: Member List Authorization

*For any* member list request, only users with owner or admin role should receive the list. The list should include all members with their roles, permissions, and joined_at.

**Validates: Requirements 14.1, 14.2, 14.3**

### Property 19: Owner Protection on Removal

*For any* member removal request, the system should prevent removing the only owner. Successful removal should invalidate all removed user's sessions for that tenant.

**Validates: Requirements 15.1, 15.2, 15.4**

### Property 20: Role Permission Mapping

*For any* predefined role, the system should return the correct set of permissions. Owner should have all permissions (*), viewer should have only read permissions.

**Validates: Requirements 16.2, 16.3, 16.4, 16.5, 16.6**

### Property 21: Custom Role Uniqueness

*For any* custom role creation within a tenant, the role name should be unique within that tenant. System roles should not be modifiable or deletable.

**Validates: Requirements 17.1, 17.4**

### Property 22: Permission Format Validation

*For any* permission string, it should follow the "resource:action" format. Wildcard "resource:*" should grant all actions on that resource.

**Validates: Requirements 18.2, 18.3**

### Property 23: Session List Completeness

*For any* session list request, the response should include all active sessions with device info, IP, location, last activity, and mark the current session.

**Validates: Requirements 20.1, 20.2, 20.3, 20.4**

### Property 24: Session Termination Effectiveness

*For any* session termination, the terminated session should be immediately invalid. Bulk termination should preserve only the current session.

**Validates: Requirements 21.1, 21.2**

### Property 25: Webhook Signature Verification

*For any* webhook payload, the system should sign it with HMAC-SHA256 and include timestamp. The signature should be verifiable by the recipient.

**Validates: Requirements 22.2, 22.3, 22.4**

### Property 26: JWT Claims Completeness

*For any* access token issued after tenant switch, it should include sub, email, tenantId, role, permissions, iat, exp, iss, aud, jti, and kid in header.

**Validates: Requirements 23.1, 23.2, 23.3, 23.4, 23.5**

### Property 27: JWKS Key Rotation Support

*For any* JWKS response, it should include all active public keys with kid, kty, use, alg, n, e. Multiple keys should be supported for rotation.

**Validates: Requirements 24.2, 24.3, 24.4**

## Error Handling

### Error Response Format

```typescript
interface TediyatErrorResponse {
  success: false;
  error: {
    code: string;           // INVALID_CREDENTIALS, TENANT_NOT_FOUND, etc.
    message: string;        // User-friendly message (Turkish supported)
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_CREDENTIALS | 401 | Email veya şifre hatalı |
| UNAUTHORIZED | 401 | Token geçersiz veya eksik |
| FORBIDDEN | 403 | Bu işlem için yetkiniz yok |
| TENANT_NOT_FOUND | 404 | Şirket bulunamadı |
| USER_NOT_FOUND | 404 | Kullanıcı bulunamadı |
| INVITATION_NOT_FOUND | 404 | Davet bulunamadı |
| INVITATION_EXPIRED | 400 | Davet süresi dolmuş |
| USER_EXISTS | 409 | Bu email ile kayıtlı kullanıcı var |
| SLUG_EXISTS | 409 | Bu slug kullanımda |
| ROLE_EXISTS | 409 | Bu isimde rol mevcut |
| CANNOT_REMOVE_OWNER | 400 | Tek sahip kaldırılamaz |
| RATE_LIMITED | 429 | Çok fazla istek |
| ACCOUNT_LOCKED | 423 | Hesap geçici olarak kilitli |
| MFA_REQUIRED | 403 | 2FA doğrulaması gerekli |
| INVALID_MFA_CODE | 400 | 2FA kodu hatalı |
| PASSWORD_TOO_WEAK | 400 | Şifre yeterince güçlü değil |
| PASSWORD_COMPROMISED | 400 | Şifre veri sızıntısında bulundu |

## Testing Strategy

### Unit Tests

Unit testler her servis ve handler için yazılacak:

- `src/services/tediyat/tenant.service.test.ts`
- `src/services/tediyat/membership.service.test.ts`
- `src/services/tediyat/invitation.service.test.ts`
- `src/services/tediyat/role.service.test.ts`
- `src/handlers/tediyat/register.handler.test.ts`
- `src/handlers/tediyat/login.handler.test.ts`
- `src/handlers/tediyat/switch.handler.test.ts`

### Property-Based Tests

Property-based testler Hypothesis (Python) veya fast-check (TypeScript) ile yazılacak:

- Minimum 100 iteration per property
- Her property design document'taki property'ye referans verecek
- Tag format: **Feature: tediyat-integration, Property {number}: {property_text}**

### E2E Tests

E2E testler tam akışları test edecek:

- `src/tests/e2e/tediyat/register.e2e.test.ts`
- `src/tests/e2e/tediyat/login.e2e.test.ts`
- `src/tests/e2e/tediyat/tenant-management.e2e.test.ts`
- `src/tests/e2e/tediyat/invitation.e2e.test.ts`
- `src/tests/e2e/tediyat/role-permission.e2e.test.ts`
- `src/tests/e2e/tediyat/session-management.e2e.test.ts`

### Test Scenarios

**Senaryo 1: Yeni Kullanıcı Tam Akış**
```
1. Kullanıcı kayıt olur (şirket ile birlikte)
2. Email doğrulama kodu alır
3. Kodu girer, email doğrulanır
4. Login yapar
5. Tenant listesini görür (1 tenant, owner rolü)
6. /me endpoint'ini çağırır
7. Logout yapar
```

**Senaryo 2: Çoklu Tenant Akışı**
```
1. Kullanıcı login yapar
2. Yeni tenant oluşturur
3. Tenant listesini görür (2 tenant)
4. İkinci tenant'a switch yapar
5. Yeni token alır (tenant context ile)
6. /me endpoint'i yeni tenant bilgisini döner
```

**Senaryo 3: Davet Akışı**
```
1. Owner kullanıcı login yapar
2. Yeni kullanıcıyı davet eder (accountant rolü)
3. Davet emaili gider
4. Yeni kullanıcı daveti kabul eder (kayıt olarak)
5. Yeni kullanıcı login yapar
6. Tenant listesinde davet edilen tenant görünür
7. Accountant yetkileri ile işlem yapabilir
```

**Senaryo 4: Rol ve Yetki Akışı**
```
1. Owner login yapar
2. Custom rol oluşturur (invoices:read, reports:read)
3. Mevcut üyenin rolünü değiştirir
4. Üye login yapar
5. Yeni yetkilerle işlem yapabilir
6. Yetkisi olmayan işlem 403 döner
```
