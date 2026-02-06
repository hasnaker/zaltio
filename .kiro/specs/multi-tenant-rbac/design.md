# Design Document: Multi-Tenant RBAC

## Overview

Zalt.io'ya multi-tenant organization yapısı ve granüler RBAC sistemi eklenmesi. Bu tasarım mevcut authentication altyapısını bozmadan, additive (eklemeli) bir yaklaşımla yeni özellikler ekliyor.

**Kritik Prensip:** Backward compatibility - Clinisyn'in mevcut entegrasyonu çalışmaya devam edecek.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         REALM                                │
│  (clinisyn-prod, finans-platform, mail-hsdcore)             │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Org A     │  │   Org B     │  │   Org C     │         │
│  │  (Klinik)   │  │  (Şube)     │  │  (Dept)     │         │
│  │             │  │             │  │             │         │
│  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │         │
│  │ │ Members │ │  │ │ Members │ │  │ │ Members │ │         │
│  │ │ Roles   │ │  │ │ Roles   │ │  │ │ Roles   │ │         │
│  │ │ Perms   │ │  │ │ Perms   │ │  │ │ Perms   │ │         │
│  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Realm-Level Users (No Org)              │   │
│  │         (Backward compatibility için)                 │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. DynamoDB Tables (Yeni)

#### zalt-organizations
```typescript
interface OrganizationRecord {
  PK: string;              // ORG#<org_id>
  SK: string;              // METADATA
  org_id: string;          // org_xxx (UUID)
  realm_id: string;        // Parent realm
  name: string;
  slug: string;            // URL-friendly unique identifier
  logo_url?: string;
  custom_data?: Record<string, unknown>;
  settings: {
    user_limit?: number;
    mfa_required?: boolean;
    allowed_domains?: string[];
  };
  status: 'active' | 'suspended' | 'deleted';
  created_at: number;
  updated_at: number;
  deleted_at?: number;
  
  // GSI: realm_id-index (realm_id, created_at)
}
```

#### zalt-memberships
```typescript
interface MembershipRecord {
  PK: string;              // MEMBERSHIP#<user_id>
  SK: string;              // ORG#<org_id>
  user_id: string;
  org_id: string;
  realm_id: string;
  role_ids: string[];      // Assigned roles
  direct_permissions: string[]; // Direct permission overrides
  is_default: boolean;     // Default org for this user
  status: 'active' | 'invited' | 'suspended';
  invited_by?: string;
  invited_at?: number;
  joined_at?: number;
  created_at: number;
  updated_at: number;
  
  // GSI: org_id-index (org_id, user_id)
  // GSI: realm_id-user-index (realm_id, user_id)
}
```

#### zalt-roles
```typescript
interface RoleRecord {
  PK: string;              // ROLE#<role_id>
  SK: string;              // ORG#<org_id> veya SYSTEM
  role_id: string;
  org_id?: string;         // null for system roles
  realm_id: string;
  name: string;
  description?: string;
  permissions: string[];   // ["users:read", "invoices:*"]
  is_system: boolean;      // true for immutable roles
  parent_role_id?: string; // For inheritance
  created_at: number;
  updated_at: number;
  
  // GSI: org_id-index (org_id, name)
}
```

### 2. Permission Format

```typescript
// Format: resource:action[:scope]
type Permission = string;

// Examples:
// "users:read"           - Read all users
// "users:read:own"       - Read only own user
// "invoices:*"           - All invoice actions
// "*:read"               - Read all resources
// "patients:create:org"  - Create patients in own org

interface PermissionParts {
  resource: string;        // users, invoices, patients, *
  action: string;          // create, read, update, delete, *, manage
  scope?: 'own' | 'org' | 'realm';  // Default: org
}

// Scope hierarchy: own < org < realm
// "realm" scope includes "org" which includes "own"
```

### 3. System Roles (Immutable)

```typescript
const SYSTEM_ROLES = {
  super_admin: {
    name: 'Super Admin',
    permissions: ['*:*:realm'],  // Full access
    is_system: true
  },
  org_admin: {
    name: 'Organization Admin',
    permissions: [
      'users:*:org',
      'roles:*:org',
      'settings:*:org',
      'audit:read:org'
    ],
    is_system: true
  },
  member: {
    name: 'Member',
    permissions: [
      'users:read:org',
      'profile:*:own'
    ],
    is_system: true
  },
  viewer: {
    name: 'Viewer',
    permissions: ['*:read:org'],
    is_system: true
  }
};
```

### 4. API Endpoints (Yeni)

```typescript
// Organization Management
POST   /admin/organizations              // Create org
GET    /admin/organizations              // List orgs (paginated)
GET    /admin/organizations/:id          // Get org
PATCH  /admin/organizations/:id          // Update org
DELETE /admin/organizations/:id          // Soft delete org

// Membership Management
GET    /admin/organizations/:id/members  // List members
POST   /admin/organizations/:id/members  // Add member (invite)
GET    /admin/organizations/:id/members/:userId
PATCH  /admin/organizations/:id/members/:userId  // Update role
DELETE /admin/organizations/:id/members/:userId  // Remove member

// Role Management
GET    /admin/roles                      // List all roles
GET    /admin/roles/system               // List system roles only
POST   /admin/roles                      // Create custom role
GET    /admin/roles/:id
PATCH  /admin/roles/:id                  // Update custom role
DELETE /admin/roles/:id                  // Delete custom role

// Permission Check
POST   /admin/permissions/check          // Check permission

// Organization Switching (User-facing)
GET    /auth/organizations               // List user's orgs
POST   /auth/switch-organization         // Switch active org

// User Import
POST   /admin/users/import               // Bulk import
POST   /admin/users/import/validate      // Dry-run validation
```

### 5. JWT Claims Extension

```typescript
// MEVCUT JWT (değişmiyor)
interface CurrentJWTPayload {
  sub: string;           // User ID
  email: string;
  realm_id: string;
  session_id: string;
  mfa_verified?: boolean;
  iat: number;
  exp: number;
}

// YENİ JWT (mevcut + ek claim'ler)
interface ExtendedJWTPayload extends CurrentJWTPayload {
  // Yeni claim'ler (opsiyonel - org varsa eklenir)
  org_id?: string;           // Current organization
  org_ids?: string[];        // All organizations user belongs to
  roles?: string[];          // Roles in current org
  permissions?: string[];    // Flattened permissions (max 50)
  permissions_url?: string;  // URL for full list if >50
}
```

### 6. Webhook Events

```typescript
interface WebhookEvent {
  id: string;
  type: WebhookEventType;
  realm_id: string;
  org_id?: string;
  timestamp: string;
  data: Record<string, unknown>;
}

type WebhookEventType =
  | 'organization.created'
  | 'organization.updated'
  | 'organization.deleted'
  | 'membership.created'
  | 'membership.updated'
  | 'membership.deleted'
  | 'role.created'
  | 'role.updated'
  | 'role.deleted'
  | 'role.assigned'
  | 'role.removed';
```

## Data Models

### Organization Model

```typescript
interface Organization {
  id: string;
  realm_id: string;
  name: string;
  slug: string;
  logo_url?: string;
  custom_data?: Record<string, unknown>;
  settings: OrganizationSettings;
  status: 'active' | 'suspended' | 'deleted';
  member_count: number;
  created_at: string;
  updated_at: string;
}

interface OrganizationSettings {
  user_limit?: number;
  mfa_required?: boolean;
  allowed_domains?: string[];
  default_role?: string;
}
```

### Membership Model

```typescript
interface Membership {
  user_id: string;
  org_id: string;
  realm_id: string;
  roles: Role[];
  direct_permissions: string[];
  is_default: boolean;
  status: 'active' | 'invited' | 'suspended';
  user?: User;  // Populated on list
  created_at: string;
  updated_at: string;
}
```

### Role Model

```typescript
interface Role {
  id: string;
  org_id?: string;
  realm_id: string;
  name: string;
  description?: string;
  permissions: string[];
  is_system: boolean;
  parent_role_id?: string;
  created_at: string;
  updated_at: string;
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Organization Realm Isolation
*For any* organization created in a realm, listing organizations from a different realm SHALL return an empty set for that organization.
**Validates: Requirements 1.2, 1.3**

### Property 2: Organization ID Uniqueness
*For any* two organizations, their organization_ids SHALL be different.
**Validates: Requirements 1.1**

### Property 3: Membership Consistency
*For any* user added to an organization, querying that user's memberships SHALL include the organization.
**Validates: Requirements 2.1, 2.3**

### Property 4: Permission Revocation on Removal
*For any* user removed from an organization, checking permissions for that organization SHALL return false for all permissions.
**Validates: Requirements 2.2**

### Property 5: System Role Immutability
*For any* attempt to modify or delete a system role, THE System SHALL reject the operation.
**Validates: Requirements 3.4**

### Property 6: Role Name Uniqueness
*For any* organization, creating two roles with the same name SHALL fail for the second creation.
**Validates: Requirements 3.2**

### Property 7: Permission Format Parsing
*For any* valid permission string in format "resource:action[:scope]", parsing SHALL extract correct resource, action, and scope components.
**Validates: Requirements 4.1**

### Property 8: Wildcard Permission Matching
*For any* permission check against a wildcard permission (e.g., "users:*"), THE System SHALL return true for all actions on that resource.
**Validates: Requirements 4.2**

### Property 9: Scope Hierarchy
*For any* permission with "realm" scope, checking against "org" or "own" scope SHALL return true.
**Validates: Requirements 4.3**

### Property 10: JWT Claims Preservation
*For any* authentication, the JWT SHALL contain all existing claims (sub, email, realm_id, session_id) plus new organization claims.
**Validates: Requirements 5.1, 5.2, 5.3, 5.4, 10.2**

### Property 11: Organization Switch Validation
*For any* organization switch request, THE System SHALL reject if user is not a member of target organization.
**Validates: Requirements 6.1**

### Property 12: Organization Switch Token Update
*For any* successful organization switch, the new JWT SHALL contain the target organization_id.
**Validates: Requirements 6.2**

### Property 13: Webhook Dispatch
*For any* organization/membership/role mutation, THE System SHALL dispatch corresponding webhook event.
**Validates: Requirements 7.1, 7.2, 7.3**

### Property 14: Webhook Signature Validity
*For any* dispatched webhook, the HMAC-SHA256 signature SHALL be verifiable with the webhook secret.
**Validates: Requirements 7.6**

### Property 15: Bcrypt Import and Upgrade
*For any* user imported with bcrypt hash, successful login SHALL upgrade the hash to Argon2id.
**Validates: Requirements 8.1, 8.2**

### Property 16: Import Email Uniqueness
*For any* import batch, duplicate emails within the same realm SHALL be rejected.
**Validates: Requirements 8.5**

### Property 17: Backward Compatibility - No Org Mode
*For any* realm without organizations, authentication SHALL work exactly as before (realm-level permissions).
**Validates: Requirements 10.1, 10.4**

### Property 18: Backward Compatibility - Existing Endpoints
*For any* existing /auth/* endpoint, the request/response format SHALL remain unchanged.
**Validates: Requirements 10.3**

## Error Handling

### Error Codes

```typescript
const RBAC_ERRORS = {
  // Organization errors
  ORG_NOT_FOUND: { code: 'ORG_NOT_FOUND', status: 404 },
  ORG_ALREADY_EXISTS: { code: 'ORG_ALREADY_EXISTS', status: 409 },
  ORG_LIMIT_REACHED: { code: 'ORG_LIMIT_REACHED', status: 403 },
  
  // Membership errors
  MEMBERSHIP_NOT_FOUND: { code: 'MEMBERSHIP_NOT_FOUND', status: 404 },
  ALREADY_MEMBER: { code: 'ALREADY_MEMBER', status: 409 },
  USER_LIMIT_REACHED: { code: 'USER_LIMIT_REACHED', status: 403 },
  CANNOT_REMOVE_LAST_ADMIN: { code: 'CANNOT_REMOVE_LAST_ADMIN', status: 400 },
  
  // Role errors
  ROLE_NOT_FOUND: { code: 'ROLE_NOT_FOUND', status: 404 },
  ROLE_NAME_EXISTS: { code: 'ROLE_NAME_EXISTS', status: 409 },
  SYSTEM_ROLE_IMMUTABLE: { code: 'SYSTEM_ROLE_IMMUTABLE', status: 403 },
  ROLE_IN_USE: { code: 'ROLE_IN_USE', status: 400 },
  
  // Permission errors
  PERMISSION_DENIED: { code: 'PERMISSION_DENIED', status: 403 },
  INVALID_PERMISSION_FORMAT: { code: 'INVALID_PERMISSION_FORMAT', status: 400 },
  
  // Import errors
  IMPORT_VALIDATION_FAILED: { code: 'IMPORT_VALIDATION_FAILED', status: 400 },
  DUPLICATE_EMAIL: { code: 'DUPLICATE_EMAIL', status: 409 },
};
```

## Testing Strategy

### Unit Tests
- Permission parsing and matching
- Role inheritance calculation
- JWT claims generation
- Webhook signature generation/verification

### Property-Based Tests (Hypothesis/fast-check)
- Organization isolation (Property 1)
- Permission wildcard matching (Property 8)
- Scope hierarchy (Property 9)
- Backward compatibility (Properties 17, 18)

### Integration Tests
- Full organization CRUD flow
- Membership lifecycle
- Organization switching with token refresh
- User import with bcrypt upgrade

### Test Configuration
- Minimum 100 iterations per property test
- Tag format: **Feature: multi-tenant-rbac, Property {number}: {property_text}**
