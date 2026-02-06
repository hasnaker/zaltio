# Requirements Document

## Introduction

Zalt Game-Changer Features - Clerk'in 2025-2026 yılında çıkardığı ve Zalt'ı rakiplerinden ayıracak enterprise-grade özellikler. Machine Authentication, Reverification, Session Tasks, Billing Integration, ve AI-powered security özellikleri.

## Glossary

- **Machine_Token**: M2M (Machine-to-Machine) authentication için kullanılan token
- **API_Key**: End-user'ların oluşturduğu, uygulamaya API erişimi sağlayan long-lived token
- **Reverification**: Hassas işlemler için step-up authentication
- **Session_Task**: Login sonrası zorunlu görevler (MFA setup, org seçimi, password reset)
- **Waitlist**: Uygulama lansmanı öncesi kullanıcı kayıt sistemi
- **Impersonation**: Admin'in kullanıcı olarak giriş yapması
- **Billing_Plan**: Subscription tier (Free, Pro, Enterprise)
- **Entitlement**: Plan'a bağlı özellik erişimi
- **Risk_Score**: AI tarafından hesaplanan login risk puanı (0-100)
- **Compromised_Password**: Breach database'de bulunan şifre

## Requirements

### Requirement 1: Machine-to-Machine (M2M) Authentication

**User Story:** As a backend developer, I want to authenticate service-to-service communication, so that my microservices can securely communicate without user context.

#### Acceptance Criteria

1. WHEN admin creates a Machine THEN THE Zalt_Platform SHALL generate unique machine_id and store configuration
2. WHEN admin configures machine permissions THEN THE Zalt_Platform SHALL store allowed scopes and target machines
3. WHEN machine requests M2M token THEN THE Zalt_Platform SHALL validate machine credentials and issue JWT
4. THE M2M token SHALL include: machine_id, scopes, target_machines, iat, exp, iss
5. WHEN M2M token expires THEN THE Zalt_Platform SHALL require new token request (no refresh)
6. THE Zalt_Platform SHALL support M2M token as JWT for local verification (no network call)
7. WHEN machine calls protected endpoint THEN THE Zalt_Platform SHALL validate M2M token and check scopes
8. THE Dashboard SHALL provide machine management: create, list, edit, delete, rotate credentials
9. THE Zalt_Platform SHALL audit all M2M token issuance and usage
10. THE SDK SHALL provide M2M client for backend services

### Requirement 2: User-Generated API Keys

**User Story:** As an end-user, I want to create API keys for my integrations, so that I can automate tasks without sharing my password.

#### Acceptance Criteria

1. WHEN end-user creates API key THEN THE Zalt_Platform SHALL generate secure key with prefix (zalt_key_)
2. WHEN API key created THEN THE Zalt_Platform SHALL display full key once with copy functionality
3. THE API key SHALL support scopes limiting which endpoints can be accessed
4. WHEN end-user lists API keys THEN THE Zalt_Platform SHALL return masked keys with metadata
5. WHEN end-user revokes API key THEN THE Zalt_Platform SHALL invalidate immediately
6. THE Zalt_Platform SHALL support API key expiration (optional, default: never)
7. WHEN request uses API key THEN THE Zalt_Platform SHALL validate and return user context
8. THE API key SHALL inherit user's tenant context and permissions
9. THE Dashboard SHALL provide API key management UI component
10. THE SDK SHALL provide <APIKeyManager /> component for end-user key management

### Requirement 3: Reverification (Step-Up Authentication)

**User Story:** As a security-conscious developer, I want to require re-authentication for sensitive actions, so that compromised sessions cannot perform critical operations.

#### Acceptance Criteria

1. WHEN endpoint requires reverification THEN THE Zalt_Platform SHALL check session reverification status
2. IF reverification required AND not verified THEN THE Zalt_Platform SHALL return 403 with reverification_required
3. WHEN user completes reverification THEN THE Zalt_Platform SHALL update session with verification timestamp
4. THE reverification SHALL support levels: password, mfa, webauthn
5. THE reverification SHALL have configurable validity period (default: 10 minutes)
6. THE SDK SHALL provide useReverification() hook for automatic modal handling
7. WHEN reverification succeeds THEN THE SDK SHALL automatically retry original request
8. THE Zalt_Platform SHALL support reverification for: password change, email change, delete account, sensitive data access
9. THE Dashboard SHALL allow configuring which endpoints require reverification
10. THE audit log SHALL record all reverification attempts and results

### Requirement 4: Session Tasks (Post-Login Requirements)

**User Story:** As an admin, I want to enforce certain actions after login, so that users complete required setup before accessing the application.

#### Acceptance Criteria

1. THE Zalt_Platform SHALL support session tasks: choose_organization, setup_mfa, reset_password, accept_terms
2. WHEN user has pending session task THEN THE Zalt_Platform SHALL block API access until completed
3. WHEN password marked as compromised THEN THE Zalt_Platform SHALL create reset_password session task
4. WHEN MFA required by policy AND not enabled THEN THE Zalt_Platform SHALL create setup_mfa session task
5. WHEN user belongs to multiple orgs AND none selected THEN THE Zalt_Platform SHALL create choose_organization task
6. THE SDK components SHALL automatically handle session tasks in sign-in flow
7. THE Dashboard SHALL allow admin to force password reset for specific user
8. THE Dashboard SHALL allow admin to force password reset for all users (security incident)
9. WHEN session task completed THEN THE Zalt_Platform SHALL remove task and allow normal access
10. THE Zalt_Platform SHALL support custom session tasks via webhook

### Requirement 5: Waitlist Mode

**User Story:** As a startup founder, I want to collect interested users before launch, so that I can build anticipation and control early access.

#### Acceptance Criteria

1. WHEN waitlist mode enabled THEN THE Zalt_Platform SHALL show waitlist signup instead of registration
2. WHEN user joins waitlist THEN THE Zalt_Platform SHALL store email and optional metadata
3. THE Zalt_Platform SHALL send confirmation email when user joins waitlist
4. WHEN admin approves waitlist user THEN THE Zalt_Platform SHALL send invitation email
5. THE Dashboard SHALL provide waitlist management: list, approve, reject, bulk actions
6. THE Zalt_Platform SHALL support automatic approval rules (domain whitelist, referral code)
7. THE SDK SHALL provide <Waitlist /> component for waitlist signup
8. THE Zalt_Platform SHALL track waitlist position and notify users of status changes
9. WHEN waitlist mode disabled THEN THE Zalt_Platform SHALL allow normal registration
10. THE Zalt_Platform SHALL support waitlist analytics: signups per day, conversion rate

### Requirement 6: User Impersonation

**User Story:** As a support agent, I want to log in as a user, so that I can debug issues and provide better support.

#### Acceptance Criteria

1. WHEN admin requests impersonation THEN THE Zalt_Platform SHALL validate admin permissions
2. WHEN impersonation starts THEN THE Zalt_Platform SHALL create special session with impersonator context
3. THE impersonation session SHALL include: original_admin_id, impersonated_user_id, reason
4. WHEN impersonating THEN THE Zalt_Platform SHALL show visual indicator in UI
5. THE impersonation session SHALL have maximum duration (default: 1 hour)
6. WHEN impersonation ends THEN THE Zalt_Platform SHALL return admin to their session
7. THE audit log SHALL record all impersonation sessions with full context
8. THE Zalt_Platform SHALL support impersonation restrictions: cannot change password, cannot delete account
9. THE Dashboard SHALL provide impersonation button on user detail page
10. THE SDK SHALL provide useImpersonation() hook to detect and display impersonation status

### Requirement 7: Integrated Billing (Clerk Billing Style)

**User Story:** As a SaaS founder, I want built-in billing management, so that I don't need to integrate a separate billing system.

#### Acceptance Criteria

1. THE Zalt_Platform SHALL integrate with Stripe for payment processing
2. WHEN admin creates billing plan THEN THE Zalt_Platform SHALL store plan with features and limits
3. THE Zalt_Platform SHALL support plan types: per-user, per-organization, flat-rate, usage-based
4. WHEN organization subscribes THEN THE Zalt_Platform SHALL create Stripe subscription
5. THE Zalt_Platform SHALL sync subscription status with Stripe webhooks
6. WHEN checking feature access THEN THE Zalt_Platform SHALL evaluate plan entitlements
7. THE SDK SHALL provide <PricingTable /> component for plan selection
8. THE SDK SHALL provide <BillingPortal /> component for subscription management
9. THE SDK SHALL provide useBilling() hook for entitlement checks
10. THE Dashboard SHALL provide billing analytics: MRR, churn, upgrades, downgrades

### Requirement 8: Compromised Password Detection

**User Story:** As a security admin, I want to detect and force reset of compromised passwords, so that breached credentials cannot be used.

#### Acceptance Criteria

1. WHEN user sets password THEN THE Zalt_Platform SHALL check against HaveIBeenPwned API
2. IF password found in breach database THEN THE Zalt_Platform SHALL reject with specific error
3. THE Dashboard SHALL allow admin to mark specific user's password as compromised
4. THE Dashboard SHALL allow admin to mark all passwords as compromised (security incident)
5. WHEN password marked compromised THEN THE Zalt_Platform SHALL create reset_password session task
6. WHEN password marked compromised THEN THE Zalt_Platform SHALL optionally revoke all sessions
7. THE Zalt_Platform SHALL periodically check existing passwords against new breaches (background job)
8. WHEN breach detected for existing user THEN THE Zalt_Platform SHALL notify user via email
9. THE audit log SHALL record all compromised password detections and resets
10. THE Dashboard SHALL show compromised password statistics

### Requirement 9: Organization-Level SSO

**User Story:** As an enterprise customer, I want to configure SSO for my organization, so that my employees can use their corporate identity.

#### Acceptance Criteria

1. WHEN org admin configures SSO THEN THE Zalt_Platform SHALL store IdP metadata per organization
2. THE Zalt_Platform SHALL support SAML 2.0 per organization
3. THE Zalt_Platform SHALL support OIDC per organization (Google Workspace, Microsoft Entra, Okta)
4. WHEN user from SSO domain signs in THEN THE Zalt_Platform SHALL redirect to org's IdP
5. THE Zalt_Platform SHALL support domain verification for SSO enforcement
6. WHEN SSO enforced THEN THE Zalt_Platform SHALL block password login for org members
7. THE Dashboard SHALL provide SSO configuration wizard per organization
8. THE Zalt_Platform SHALL support Just-In-Time (JIT) user provisioning from SSO
9. THE Zalt_Platform SHALL support SCIM for user/group sync from IdP
10. THE audit log SHALL record all SSO authentication events

### Requirement 10: AI-Powered Risk Assessment

**User Story:** As a security team, I want AI to assess login risk in real-time, so that suspicious logins are blocked or require additional verification.

#### Acceptance Criteria

1. WHEN user attempts login THEN THE Zalt_Platform SHALL calculate risk score (0-100)
2. THE risk score SHALL consider: IP reputation, device fingerprint, geo-velocity, behavior patterns
3. IF risk score > 70 THEN THE Zalt_Platform SHALL require MFA regardless of user setting
4. IF risk score > 90 THEN THE Zalt_Platform SHALL block login and notify admin
5. THE Zalt_Platform SHALL use AWS Bedrock for anomaly detection
6. THE Zalt_Platform SHALL learn user behavior patterns over time
7. THE Dashboard SHALL display risk score history per user
8. THE Zalt_Platform SHALL support custom risk rules (IP whitelist, trusted devices)
9. WHEN high-risk login detected THEN THE Zalt_Platform SHALL trigger webhook
10. THE audit log SHALL record risk scores for all login attempts

### Requirement 11: Invitation System

**User Story:** As a tenant owner, I want to invite team members by email, so that they can join my organization with appropriate roles.

#### Acceptance Criteria

1. WHEN owner/admin invites user THEN THE Zalt_Platform SHALL create invitation with 7-day expiry
2. THE invitation email SHALL include: tenant name, inviter name, role, accept link
3. WHEN existing user accepts THEN THE Zalt_Platform SHALL add to tenant with specified role
4. WHEN new user accepts THEN THE Zalt_Platform SHALL create account and add to tenant
5. WHEN invitation expires THEN THE Zalt_Platform SHALL reject acceptance attempts
6. WHEN admin revokes invitation THEN THE Zalt_Platform SHALL invalidate immediately
7. THE Dashboard SHALL show pending and expired invitations
8. THE Zalt_Platform SHALL trigger member.invited webhook on creation
9. THE Zalt_Platform SHALL trigger member.joined webhook on acceptance
10. THE SDK SHALL provide <InvitationList /> component for invitation management

### Requirement 12: Webhook System

**User Story:** As a developer, I want to receive real-time notifications of auth events, so that I can sync data and trigger workflows.

#### Acceptance Criteria

1. WHEN admin configures webhook THEN THE Zalt_Platform SHALL validate URL and generate signing secret
2. THE Zalt_Platform SHALL support events: user.*, session.*, tenant.*, member.*, mfa.*, billing.*
3. WHEN event occurs THEN THE Zalt_Platform SHALL POST with HMAC-SHA256 signature
4. THE webhook payload SHALL include: id, type, timestamp, data, idempotency_key
5. WHEN delivery fails THEN THE Zalt_Platform SHALL retry with exponential backoff (1s, 5s, 30s, 5m)
6. THE Dashboard SHALL provide webhook testing functionality
7. THE Dashboard SHALL show last 100 delivery logs with status and latency
8. THE Zalt_Platform SHALL support event filtering per webhook
9. THE Zalt_Platform SHALL support webhook secret rotation
10. THE SDK SHALL provide webhook signature verification utility

### Requirement 13: Session Handler

**User Story:** As a user, I want to see and manage all my active sessions, so that I can detect and revoke unauthorized access.

#### Acceptance Criteria

1. WHEN user requests sessions THEN THE Zalt_Platform SHALL return all active sessions
2. THE session info SHALL include: device, browser, IP, location, last_activity, is_current
3. WHEN user revokes session THEN THE Zalt_Platform SHALL invalidate immediately
4. WHEN user revokes all sessions THEN THE Zalt_Platform SHALL keep current session only
5. THE Zalt_Platform SHALL detect impossible travel and alert user
6. THE Zalt_Platform SHALL enforce session limits per realm policy
7. THE SDK SHALL provide <SessionList /> component for session management
8. THE Zalt_Platform SHALL trigger session.revoked webhook
9. THE Dashboard SHALL show session analytics: concurrent sessions, devices, locations
10. THE Zalt_Platform SHALL support session binding to device fingerprint

## Notes

- Bu özellikler Clerk'in 2025-2026 yılında çıkardığı en yeni özelliklerdir
- Machine Authentication (M2M + API Keys) enterprise müşteriler için kritik
- Reverification ve Session Tasks güvenlik için game-changer
- Integrated Billing SaaS müşterileri için büyük kolaylık
- AI-powered risk assessment Zalt'ı rakiplerinden ayıracak
