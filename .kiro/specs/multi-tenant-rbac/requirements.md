# Requirements Document

## Introduction

Zalt.io'yu gerçek bir Clerk alternatifi yapmak için multi-tenant organization yapısı ve granüler RBAC (Role-Based Access Control) sistemi eklenmesi. Bu özellik Clinisyn, HSD Finans ve gelecek tüm müşteriler için kritik.

## Glossary

- **Realm**: Zalt'ta en üst seviye izolasyon birimi (müşteri bazlı)
- **Organization**: Realm içinde alt-tenant/şirket birimi (klinik, şube, departman)
- **Member**: Organization'a üye kullanıcı
- **Role**: Yetki grubu (admin, manager, user, viewer)
- **Permission**: Tekil yetki (invoices:read, patients:create)
- **Resource**: Yetkilendirme yapılan kaynak tipi (users, invoices, patients)
- **Action**: Kaynak üzerinde yapılabilecek işlem (create, read, update, delete)
- **Scope**: Yetki kapsamı (own, organization, realm)

## Requirements

### Requirement 1: Organization Management

**User Story:** As a realm admin, I want to create and manage organizations within my realm, so that I can support multi-tenant customers with sub-units.

#### Acceptance Criteria

1. WHEN a realm admin creates an organization, THE System SHALL generate a unique organization_id and store organization metadata
2. WHEN an organization is created, THE System SHALL associate it with the parent realm_id
3. WHEN listing organizations, THE System SHALL return only organizations within the authenticated user's realm
4. WHEN updating an organization, THE System SHALL validate the user has organization admin permissions
5. WHEN deleting an organization, THE System SHALL soft-delete and preserve audit history
6. THE System SHALL support organization metadata including name, slug, logo_url, and custom_data

### Requirement 2: Organization Membership

**User Story:** As an organization admin, I want to add and remove users from my organization, so that I can manage who has access.

#### Acceptance Criteria

1. WHEN a user is added to an organization, THE System SHALL create a membership record with user_id, organization_id, and role
2. WHEN a user is removed from an organization, THE System SHALL revoke all organization-specific permissions
3. THE System SHALL support users belonging to multiple organizations simultaneously
4. WHEN listing organization members, THE System SHALL return user details with their organization-specific roles
5. WHEN a user's membership is updated, THE System SHALL invalidate existing sessions to force re-authentication
6. THE System SHALL enforce organization-level user limits based on subscription plan

### Requirement 3: Role Management

**User Story:** As an organization admin, I want to create custom roles with specific permissions, so that I can implement fine-grained access control.

#### Acceptance Criteria

1. THE System SHALL provide immutable system roles: super_admin, org_admin, member, viewer
2. WHEN an organization admin creates a custom role, THE System SHALL validate role name uniqueness within the organization
3. WHEN a custom role is created, THE System SHALL store the role with associated permissions
4. WHEN a system role is modified or deleted, THE System SHALL reject the operation with an error
5. WHEN deleting a custom role, THE System SHALL prevent deletion if users are assigned to it
6. THE System SHALL support role inheritance where child roles inherit parent role permissions

### Requirement 4: Permission System

**User Story:** As a developer, I want to define granular permissions using resource:action:scope format, so that I can implement precise access control.

#### Acceptance Criteria

1. THE System SHALL support permission format: resource:action[:scope]
2. THE System SHALL support wildcard permissions: resource:* (all actions) and *:read (all resources)
3. WHEN checking permissions, THE System SHALL evaluate scope hierarchy: own < organization < realm
4. THE System SHALL support standard actions: create, read, update, delete, export, manage
5. WHEN a permission check fails, THE System SHALL return 403 Forbidden with permission details
6. THE System SHALL cache permission evaluations for performance (TTL: 5 minutes)

### Requirement 5: JWT Claims Extension

**User Story:** As a backend developer, I want JWT tokens to include organization and permission claims, so that I can authorize requests without additional API calls.

#### Acceptance Criteria

1. WHEN a user authenticates, THE System SHALL include current organization_id in the JWT
2. WHEN a user authenticates, THE System SHALL include all organization_ids the user belongs to
3. WHEN a user authenticates, THE System SHALL include flattened permissions array for current organization
4. WHEN a user authenticates, THE System SHALL include current organization roles
5. THE System SHALL limit JWT payload size by including only essential claims
6. IF permission list exceeds 50 items, THEN THE System SHALL include a permissions_url claim for full list

### Requirement 6: Organization Switching

**User Story:** As a user belonging to multiple organizations, I want to switch between organizations, so that I can work in different contexts.

#### Acceptance Criteria

1. WHEN a user requests organization switch, THE System SHALL validate membership in target organization
2. WHEN organization switch succeeds, THE System SHALL issue new tokens with updated organization context
3. WHEN organization switch succeeds, THE System SHALL preserve the user's session but update claims
4. THE System SHALL provide GET /auth/organizations endpoint to list user's organizations
5. THE System SHALL provide POST /auth/switch-organization endpoint for context switching
6. WHEN switching organizations, THE System SHALL log the event for audit purposes

### Requirement 7: Webhook Events

**User Story:** As an integrating application, I want to receive webhook notifications for organization and membership changes, so that I can sync my local database.

#### Acceptance Criteria

1. WHEN an organization is created/updated/deleted, THE System SHALL dispatch organization.created/updated/deleted webhook
2. WHEN a membership is added/removed/updated, THE System SHALL dispatch membership.created/deleted/updated webhook
3. WHEN a role is assigned/removed, THE System SHALL dispatch role.assigned/removed webhook
4. THE System SHALL include full entity data in webhook payload
5. THE System SHALL retry failed webhook deliveries with exponential backoff (max 5 attempts)
6. THE System SHALL sign webhook payloads with HMAC-SHA256 for verification

### Requirement 8: User Import API

**User Story:** As a platform migrating to Zalt, I want to bulk import users with existing password hashes, so that users don't need to reset passwords.

#### Acceptance Criteria

1. WHEN importing users with bcrypt hashes, THE System SHALL store the hash and verify on first login
2. WHEN a bcrypt user logs in successfully, THE System SHALL upgrade the hash to Argon2id
3. THE System SHALL support import of user metadata, organization memberships, and roles
4. WHEN import fails for a user, THE System SHALL continue processing and report errors at the end
5. THE System SHALL validate email uniqueness within realm during import
6. THE System SHALL support dry-run mode to validate import data without persisting

### Requirement 9: Admin API Endpoints

**User Story:** As a realm admin, I want comprehensive API endpoints to manage organizations, roles, and permissions programmatically.

#### Acceptance Criteria

1. THE System SHALL provide CRUD endpoints for organizations: GET/POST/PATCH/DELETE /admin/organizations
2. THE System SHALL provide membership endpoints: GET/POST/DELETE /admin/organizations/:id/members
3. THE System SHALL provide role endpoints: GET/POST/PATCH/DELETE /admin/roles
4. THE System SHALL provide permission assignment: POST/DELETE /admin/roles/:id/permissions
5. THE System SHALL require realm admin or org admin authentication for all admin endpoints
6. THE System SHALL support pagination, filtering, and sorting on list endpoints

### Requirement 10: Backward Compatibility

**User Story:** As an existing Zalt customer (Clinisyn), I want the new features to not break my current integration.

#### Acceptance Criteria

1. WHEN organization features are not used, THE System SHALL default to realm-level permissions (current behavior)
2. THE System SHALL maintain existing JWT structure with new claims as additions, not replacements
3. THE System SHALL continue supporting existing /auth/* endpoints without changes
4. WHEN a realm has no organizations, THE System SHALL treat the realm as a single implicit organization
5. THE System SHALL provide migration guide documentation for existing customers
6. THE System SHALL support gradual adoption - organizations can be enabled per-realm
