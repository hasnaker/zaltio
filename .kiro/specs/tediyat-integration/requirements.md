# Requirements Document: Tediyat Multi-Tenant Integration

## Introduction

Tediyat, multi-tenant bir ön muhasebe ve finans yönetim platformudur. Bu spec, Zalt.io'nun Tediyat için Clerk benzeri bir authentication ve authorization servisi sağlamasını tanımlar. Tediyat'ın E2E çalışabilmesi için gerekli tüm özellikleri kapsar.

**Müşteri:** Tediyat (Ön Muhasebe Platformu)
**Öncelik:** P0 özellikleri launch-blocker
**Hedef:** Tediyat kullanıcılarının şirketler arası geçiş yapabildiği, rol bazlı yetkilendirmeli auth sistemi

## Glossary

- **Tediyat_System**: Tediyat ön muhasebe platformu
- **Tenant**: Tediyat'ta bir şirket/organizasyon (multi-tenant yapı)
- **User**: Tediyat kullanıcısı (muhasebeci, şirket sahibi, vb.)
- **Membership**: Kullanıcının bir tenant'a üyeliği ve rolü
- **Role**: Kullanıcının tenant içindeki yetkilerini belirleyen rol (owner, admin, accountant, viewer)
- **Permission**: Granüler yetki (invoices:read, accounts:write, vb.)
- **Invitation**: Tenant'a kullanıcı davet etme mekanizması
- **Access_Token**: JWT formatında kısa ömürlü yetkilendirme token'ı (1 saat)
- **Refresh_Token**: Uzun ömürlü token yenileme token'ı (30 gün)

---

## SECTION 1: AUTHENTICATION

### Requirement 1: User Registration with Tenant Creation

**User Story:** As a new Tediyat user, I want to register and create my company, so that I can start using the accounting platform.

#### Acceptance Criteria

1. WHEN a user registers with email, password, and company name, THE Tediyat_System SHALL create both user account and initial tenant
2. WHEN registration completes, THE Tediyat_System SHALL assign the registering user as "owner" role of the created tenant
3. WHEN a password is submitted, THE Tediyat_System SHALL enforce minimum 8 characters with uppercase, lowercase, number, and special character
4. WHEN registration completes, THE Tediyat_System SHALL send verification email within 30 seconds
5. WHEN registration completes, THE Tediyat_System SHALL return user info, tenant info, and token pair
6. THE Tediyat_System SHALL generate unique tenant slug from company name (e.g., "ABC Şirketi" → "abc-sirketi")
7. THE Tediyat_System SHALL support Turkish characters in company names and user profiles
8. THE Tediyat_System SHALL rate limit registration to 3 attempts per IP per hour

### Requirement 2: User Login with Tenant List

**User Story:** As a Tediyat user, I want to login and see all my companies, so that I can choose which one to work with.

#### Acceptance Criteria

1. WHEN a user logs in with valid credentials, THE Tediyat_System SHALL return user info and list of all tenants user belongs to
2. WHEN returning tenant list, THE Tediyat_System SHALL include tenant id, name, slug, and user's role in each tenant
3. WHEN login succeeds, THE Tediyat_System SHALL return access token (1 hour) and refresh token (30 days)
4. WHEN login fails, THE Tediyat_System SHALL return generic "Invalid credentials" message (no email enumeration)
5. WHEN 5 login failures occur in 15 minutes, THE Tediyat_System SHALL lock account for 15 minutes
6. WHEN 10 login failures occur, THE Tediyat_System SHALL require email verification to unlock
7. THE Tediyat_System SHALL record last login timestamp and IP address
8. THE Tediyat_System SHALL implement progressive delays: 1s, 2s, 4s, 8s, 16s after failures

### Requirement 3: Token Refresh with Rotation

**User Story:** As a Tediyat user, I want my session to stay active, so that I don't have to login frequently.

#### Acceptance Criteria

1. WHEN a valid refresh token is submitted, THE Tediyat_System SHALL return new access token and new refresh token
2. WHEN refresh token is used, THE Tediyat_System SHALL invalidate the old refresh token (rotation)
3. WHEN old refresh token is used within 30 seconds of rotation, THE Tediyat_System SHALL return same new tokens (grace period)
4. WHEN old refresh token is used after grace period, THE Tediyat_System SHALL reject and require re-login
5. WHEN refresh token is expired (30 days), THE Tediyat_System SHALL reject and require re-login

### Requirement 4: Logout

**User Story:** As a Tediyat user, I want to logout securely, so that my session cannot be hijacked.

#### Acceptance Criteria

1. WHEN logout is requested, THE Tediyat_System SHALL invalidate the refresh token immediately
2. WHEN logout with allDevices=true is requested, THE Tediyat_System SHALL terminate all user sessions
3. THE Tediyat_System SHALL log logout events with device information

### Requirement 5: Current User Info

**User Story:** As a Tediyat user, I want to get my profile and current tenant info, so that the app can display my context.

#### Acceptance Criteria

1. WHEN /me endpoint is called with valid token, THE Tediyat_System SHALL return user profile, current tenant, and permissions
2. WHEN X-Tenant-ID header is provided, THE Tediyat_System SHALL return permissions for that specific tenant
3. THE Tediyat_System SHALL never return password hash in any response
4. THE Tediyat_System SHALL return email_verified status

### Requirement 6: Password Reset

**User Story:** As a Tediyat user who forgot password, I want to reset it securely, so that I can regain access.

#### Acceptance Criteria

1. WHEN password reset is requested, THE Tediyat_System SHALL send reset link via email
2. THE reset token SHALL be 32 bytes cryptographically random and valid for 1 hour
3. THE reset token SHALL be single-use (invalidated after use)
4. WHEN password is reset, THE Tediyat_System SHALL invalidate ALL user sessions
5. THE Tediyat_System SHALL NOT reveal if email exists (prevent enumeration)
6. THE Tediyat_System SHALL rate limit to 3 reset requests per hour per email

### Requirement 7: Email Verification

**User Story:** As a Tediyat user, I want to verify my email, so that my account is fully activated.

#### Acceptance Criteria

1. WHEN verification is requested, THE Tediyat_System SHALL send 6-digit code via email
2. THE verification code SHALL expire in 24 hours
3. THE Tediyat_System SHALL allow maximum 3 verification attempts per code
4. WHEN code is verified, THE Tediyat_System SHALL set email_verified=true
5. THE Tediyat_System SHALL support resend verification functionality

### Requirement 8: Two-Factor Authentication (2FA)

**User Story:** As a security-conscious Tediyat user, I want to enable 2FA, so that my account is protected.

#### Acceptance Criteria

1. WHEN 2FA setup is requested, THE Tediyat_System SHALL generate TOTP secret and QR code
2. THE Tediyat_System SHALL be compatible with Google Authenticator and Authy
3. WHEN 2FA is enabled, THE Tediyat_System SHALL generate 10 backup codes (single-use)
4. WHEN 2FA is enabled, THE Tediyat_System SHALL require code verification before activation
5. WHEN disabling 2FA, THE Tediyat_System SHALL require password confirmation
6. THE Tediyat_System SHALL allow 1 period window (30 seconds) for clock drift

---

## SECTION 2: MULTI-TENANT (ORGANIZATION) MANAGEMENT

### Requirement 9: Tenant Creation

**User Story:** As a Tediyat user, I want to create additional companies, so that I can manage multiple businesses.

#### Acceptance Criteria

1. WHEN a tenant is created, THE Tediyat_System SHALL generate unique tenant ID (ten_xxx format)
2. WHEN a tenant is created, THE Tediyat_System SHALL generate unique slug from name
3. WHEN a tenant is created, THE creating user SHALL automatically become "owner" role
4. THE Tediyat_System SHALL support custom metadata (taxNumber, address, etc.)
5. THE Tediyat_System SHALL validate slug uniqueness

### Requirement 10: Tenant List

**User Story:** As a Tediyat user, I want to see all my companies, so that I can switch between them.

#### Acceptance Criteria

1. WHEN tenant list is requested, THE Tediyat_System SHALL return all tenants user belongs to
2. FOR each tenant, THE Tediyat_System SHALL include id, name, slug, user's role, and member count
3. THE Tediyat_System SHALL include created_at timestamp for each tenant

### Requirement 11: Tenant Switch

**User Story:** As a Tediyat user, I want to switch between my companies, so that I can work on different businesses.

#### Acceptance Criteria

1. WHEN tenant switch is requested, THE Tediyat_System SHALL verify user has membership in target tenant
2. WHEN tenant switch succeeds, THE Tediyat_System SHALL return new access token with tenant context
3. THE new access token SHALL include tenant_id, role, and permissions for that tenant
4. WHEN user has no membership in target tenant, THE Tediyat_System SHALL return 403 Forbidden

### Requirement 12: User Invitation

**User Story:** As a Tediyat tenant owner, I want to invite users to my company, so that they can collaborate.

#### Acceptance Criteria

1. WHEN invitation is sent, THE Tediyat_System SHALL send invitation email with unique link
2. THE invitation link SHALL be valid for 7 days
3. WHEN inviting, THE inviter SHALL specify role and optional custom permissions
4. THE Tediyat_System SHALL support inviting existing users or new users
5. WHEN existing user accepts, THE Tediyat_System SHALL add membership to tenant
6. WHEN new user accepts, THE Tediyat_System SHALL create user account and add membership
7. THE Tediyat_System SHALL track invitation status (pending, accepted, expired)

### Requirement 13: Invitation Acceptance

**User Story:** As an invited user, I want to accept the invitation, so that I can join the company.

#### Acceptance Criteria

1. WHEN existing user accepts invitation, THE Tediyat_System SHALL require authentication
2. WHEN new user accepts invitation, THE Tediyat_System SHALL require registration (firstName, lastName, password)
3. WHEN invitation is accepted, THE Tediyat_System SHALL create membership with specified role
4. WHEN invitation is expired, THE Tediyat_System SHALL return appropriate error

### Requirement 14: Tenant Members List

**User Story:** As a Tediyat tenant admin, I want to see all members, so that I can manage access.

#### Acceptance Criteria

1. WHEN member list is requested, THE Tediyat_System SHALL return all members with their roles and permissions
2. THE Tediyat_System SHALL include joined_at timestamp for each member
3. THE Tediyat_System SHALL only allow owner/admin to view member list
4. THE Tediyat_System SHALL support pagination for large member lists

### Requirement 15: Member Removal

**User Story:** As a Tediyat tenant owner, I want to remove members, so that I can revoke access.

#### Acceptance Criteria

1. WHEN member removal is requested, THE Tediyat_System SHALL delete membership
2. THE Tediyat_System SHALL NOT allow removing the only owner (must transfer ownership first)
3. THE Tediyat_System SHALL only allow owner/admin to remove members
4. WHEN member is removed, THE Tediyat_System SHALL invalidate all their sessions for that tenant

---

## SECTION 3: ROLE & PERMISSION MANAGEMENT

### Requirement 16: Predefined Roles

**User Story:** As a Tediyat platform, I want standard roles, so that permission management is consistent.

#### Acceptance Criteria

1. THE Tediyat_System SHALL provide predefined roles: owner, admin, accountant, viewer, external_accountant
2. THE "owner" role SHALL have all permissions (*)
3. THE "admin" role SHALL have all permissions except user management
4. THE "accountant" role SHALL have invoice, account, and report read/write permissions
5. THE "viewer" role SHALL have read-only permissions
6. THE "external_accountant" role SHALL have limited read and export permissions

### Requirement 17: Custom Role Creation

**User Story:** As a Tediyat tenant owner, I want to create custom roles, so that I can define specific access levels.

#### Acceptance Criteria

1. WHEN custom role is created, THE Tediyat_System SHALL validate role name uniqueness within tenant
2. THE Tediyat_System SHALL allow selecting permissions from predefined permission list
3. THE Tediyat_System SHALL support role inheritance (inherits_from)
4. THE Tediyat_System SHALL NOT allow modifying or deleting system roles

### Requirement 18: Permission List

**User Story:** As a Tediyat platform, I want granular permissions, so that access can be precisely controlled.

#### Acceptance Criteria

1. THE Tediyat_System SHALL support these permission categories:
   - invoices: read, create, update, delete, *
   - accounts: read, create, update, delete, *
   - cash: read, write
   - bank: read, write
   - reports: read, export
   - inventory: read, write
   - e-invoice: read, send
   - settings: read, write
   - users: read, invite, manage
   - quotes: read, create, update, delete, *
   - payments: read, create, refund
2. THE permission format SHALL be "resource:action" (e.g., "invoices:read")
3. THE wildcard permission SHALL be "resource:*" for all actions on a resource

### Requirement 19: Member Permission Update

**User Story:** As a Tediyat tenant owner, I want to update member permissions, so that I can adjust access levels.

#### Acceptance Criteria

1. WHEN member role is updated, THE Tediyat_System SHALL update their permissions immediately
2. THE Tediyat_System SHALL support adding additional permissions beyond role
3. THE Tediyat_System SHALL only allow owner/admin to update permissions
4. WHEN permissions change, THE Tediyat_System SHALL NOT invalidate existing tokens (permissions checked at runtime)

---

## SECTION 4: SESSION MANAGEMENT

### Requirement 20: Active Session List

**User Story:** As a Tediyat user, I want to see my active sessions, so that I can monitor access.

#### Acceptance Criteria

1. WHEN session list is requested, THE Tediyat_System SHALL return all active sessions
2. FOR each session, THE Tediyat_System SHALL include device info, IP, location, and last activity
3. THE Tediyat_System SHALL mark the current session distinctly
4. THE Tediyat_System SHALL include session creation timestamp

### Requirement 21: Session Termination

**User Story:** As a Tediyat user, I want to terminate sessions, so that I can revoke access from lost devices.

#### Acceptance Criteria

1. WHEN session termination is requested, THE Tediyat_System SHALL invalidate that session immediately
2. THE Tediyat_System SHALL support terminating all sessions except current
3. WHEN session is terminated, THE Tediyat_System SHALL log the event

---

## SECTION 5: WEBHOOKS

### Requirement 22: Webhook Events

**User Story:** As a Tediyat platform, I want to receive auth events, so that I can sync user data.

#### Acceptance Criteria

1. THE Tediyat_System SHALL support these webhook events:
   - user.created, user.updated, user.deleted
   - tenant.created, tenant.updated
   - member.invited, member.joined, member.removed, member.role_changed
   - session.created, session.revoked
2. THE webhook payload SHALL include event id, type, timestamp, and data
3. THE Tediyat_System SHALL sign webhooks with HMAC-SHA256 (X-Zalt-Signature header)
4. THE Tediyat_System SHALL include timestamp for replay protection (5 minute tolerance)

---

## SECTION 6: JWT TOKEN STRUCTURE

### Requirement 23: Access Token Claims

**User Story:** As a Tediyat backend, I want JWT with tenant context, so that I can authorize requests.

#### Acceptance Criteria

1. THE access token SHALL include: sub (user_id), email, tenantId, role, permissions
2. THE access token SHALL include: iat, exp, iss (zalt.io), aud (tediyat)
3. THE access token SHALL expire in 1 hour (3600 seconds)
4. THE Tediyat_System SHALL use RS256 algorithm for JWT signing
5. THE JWT header SHALL include "kid" for key rotation support

### Requirement 24: JWKS Endpoint

**User Story:** As a Tediyat backend, I want to verify JWTs, so that I can validate requests.

#### Acceptance Criteria

1. THE Tediyat_System SHALL expose /.well-known/jwks.json endpoint
2. THE JWKS response SHALL include public keys with kid, kty, use, alg, n, e
3. THE Tediyat_System SHALL support key rotation with multiple active keys
4. THE Tediyat_System SHALL set appropriate cache headers for JWKS

---

## SECTION 7: SECURITY REQUIREMENTS

### Requirement 25: Password Policy

**User Story:** As a Tediyat platform, I want strong passwords, so that accounts are secure.

#### Acceptance Criteria

1. THE Tediyat_System SHALL enforce minimum 8 characters
2. THE Tediyat_System SHALL require at least 1 uppercase letter
3. THE Tediyat_System SHALL require at least 1 lowercase letter
4. THE Tediyat_System SHALL require at least 1 number
5. THE Tediyat_System SHALL require at least 1 special character (!@#$%^&*)
6. THE Tediyat_System SHALL prevent reuse of last 5 passwords
7. THE Tediyat_System SHALL check passwords against HaveIBeenPwned database

### Requirement 26: Rate Limiting

**User Story:** As a Tediyat platform, I want rate limiting, so that brute force attacks are prevented.

#### Acceptance Criteria

1. THE Tediyat_System SHALL rate limit /login to 5 requests per minute per IP
2. THE Tediyat_System SHALL rate limit /register to 3 requests per hour per IP
3. THE Tediyat_System SHALL rate limit /forgot-password to 3 requests per hour per email
4. THE Tediyat_System SHALL rate limit other endpoints to 100 requests per minute per user
5. WHEN rate limit is exceeded, THE Tediyat_System SHALL return 429 with Retry-After header

### Requirement 27: Brute Force Protection

**User Story:** As a Tediyat platform, I want account lockout, so that password guessing is prevented.

#### Acceptance Criteria

1. AFTER 5 failed login attempts, THE Tediyat_System SHALL lock account for 15 minutes
2. AFTER 10 failed login attempts, THE Tediyat_System SHALL require email verification
3. WHEN account is locked, THE Tediyat_System SHALL send email notification
4. THE Tediyat_System SHALL log all lockout events

---

## API Endpoints Summary

### Authentication
- POST /api/v1/auth/register - Register with company creation
- POST /api/v1/auth/login - Login with tenant list
- POST /api/v1/auth/refresh - Token refresh
- POST /api/v1/auth/logout - Logout
- GET /api/v1/auth/me - Current user info
- POST /api/v1/auth/forgot-password - Request password reset
- POST /api/v1/auth/reset-password - Reset password
- POST /api/v1/auth/verify-email - Verify email
- POST /api/v1/auth/resend-verification - Resend verification

### 2FA
- POST /api/v1/auth/2fa/enable - Enable 2FA
- POST /api/v1/auth/2fa/verify - Verify 2FA code
- POST /api/v1/auth/2fa/disable - Disable 2FA

### Tenants
- POST /api/v1/tenants - Create tenant
- GET /api/v1/tenants - List user's tenants
- POST /api/v1/tenants/{tenantId}/switch - Switch tenant
- POST /api/v1/tenants/{tenantId}/invitations - Invite user
- POST /api/v1/invitations/{token}/accept - Accept invitation
- GET /api/v1/tenants/{tenantId}/members - List members
- DELETE /api/v1/tenants/{tenantId}/members/{userId} - Remove member
- PATCH /api/v1/tenants/{tenantId}/members/{userId} - Update member

### Roles
- POST /api/v1/tenants/{tenantId}/roles - Create custom role
- GET /api/v1/tenants/{tenantId}/roles - List roles

### Sessions
- GET /api/v1/auth/sessions - List sessions
- DELETE /api/v1/auth/sessions/{sessionId} - Terminate session
- DELETE /api/v1/auth/sessions?all=true - Terminate all sessions

### JWKS
- GET /.well-known/jwks.json - Public keys
