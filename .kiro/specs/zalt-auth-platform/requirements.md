# ZALT.IO Authentication Platform - Requirements

## Introduction

Zalt.io is a professional-grade Authentication-as-a-Service platform designed to compete with and surpass Clerk. Built for healthcare compliance (HIPAA, GDPR) with security measures against sophisticated darkweb attackers, credential stuffing, phishing (Evilginx2), and nation-state level threats.

**First Customer:** Clinisyn (4000 Psychologists, 11 Countries, Healthcare/HIPAA)
**Deadline:** 29 January 2026
**Security Level:** Enterprise/Healthcare Grade

## Glossary

- **Zalt.io**: The authentication platform (Clerk alternative)
- **Realm**: Isolated tenant environment (e.g., clinisyn-psychologists)
- **Access Token**: Short-lived JWT (15 minutes) for API authorization
- **Refresh Token**: Long-lived token (7 days) for session continuity
- **Grace Period**: 30-second window for network retry tolerance
- **Device Trust**: Fuzzy fingerprint matching (70% threshold)
- **WebAuthn**: Phishing-resistant passwordless authentication
- **TOTP**: Time-based One-Time Password (Authenticator apps)
- **Credential Stuffing**: Automated attack using leaked password databases
- **Evilginx2**: Advanced phishing proxy that bypasses traditional MFA

---

## SECTION 1: CORE AUTHENTICATION

### Requirement 1.1: Secure User Registration

**User Story:** As a user, I want to register securely so that my account is protected from the moment of creation.

#### Acceptance Criteria
1. WHEN a user registers, THE system SHALL validate email format and check against disposable email providers
2. WHEN a password is submitted, THE system SHALL check against HaveIBeenPwned API (k-anonymity model)
3. WHEN a password is weak or breached, THE system SHALL reject with specific guidance
4. THE system SHALL hash passwords using Argon2id (32MB memory, timeCost 5, parallelism 2)
5. WHEN registration completes, THE system SHALL send verification email within 30 seconds
6. THE system SHALL rate limit registration to 3 attempts per IP per hour
7. THE system SHALL log all registration attempts with IP, user-agent, and timestamp

### Requirement 1.2: Secure User Login

**User Story:** As a user, I want to login securely so that attackers cannot access my account.

#### Acceptance Criteria
1. WHEN credentials are submitted, THE system SHALL validate against stored Argon2id hash
2. WHEN login succeeds, THE system SHALL issue JWT RS256 access token (15 min) and refresh token (7 days)
3. WHEN login fails, THE system SHALL return generic "Invalid credentials" (no email enumeration)
4. THE system SHALL implement progressive delays: 1s, 2s, 4s, 8s, 16s after failures
5. WHEN 5 failures occur in 15 minutes, THE system SHALL lock account temporarily (15 min)
6. WHEN 10 failures occur, THE system SHALL require email verification to unlock
7. THE system SHALL detect and block credential stuffing patterns (same password, different emails)
8. THE system SHALL log all login attempts with success/failure, IP, device fingerprint

### Requirement 1.3: Token Management

**User Story:** As a developer, I want reliable token management so that users don't experience random logouts.

#### Acceptance Criteria
1. THE system SHALL issue JWT with RS256 algorithm (FIPS-compliant for HIPAA)
2. THE JWT SHALL contain: sub (user_id), realm_id, email, iat, exp, jti, type
3. WHEN refresh token is used, THE system SHALL rotate it (issue new, invalidate old)
4. THE system SHALL implement 30-second grace period for network retry tolerance
5. WHEN old token is used within grace period, THE system SHALL return same new tokens (idempotent)
6. WHEN old token is used after grace period, THE system SHALL reject and require re-login
7. THE system SHALL support JWT key rotation (30 days, 15-day grace period)
8. THE JWT header SHALL include "kid" (key ID) for multi-key support

### Requirement 1.4: Secure Logout

**User Story:** As a user, I want to logout securely so that my session cannot be hijacked.

#### Acceptance Criteria
1. WHEN logout is requested, THE system SHALL invalidate refresh token immediately
2. THE system SHALL add access token JTI to blacklist until expiry
3. THE system SHALL support "logout all devices" functionality
4. THE system SHALL clear all session data from server-side storage
5. THE system SHALL log logout events with device information

---

## SECTION 2: MULTI-FACTOR AUTHENTICATION (MFA)

### Requirement 2.1: TOTP MFA (Authenticator Apps)

**User Story:** As a security-conscious user, I want TOTP MFA so that my account is protected even if password is compromised.

#### Acceptance Criteria
1. THE system SHALL generate TOTP secrets using cryptographically secure random
2. THE system SHALL display QR code compatible with Google Authenticator, Authy, 1Password
3. WHEN TOTP is enabled, THE system SHALL require code verification before activation
4. THE system SHALL allow 1 period window (30 seconds before/after) for clock drift
5. THE system SHALL rate limit TOTP attempts: 5 per minute, lockout after 10 failures
6. THE system SHALL NOT use SMS MFA (SS7 vulnerability, SIM swap attacks)

### Requirement 2.2: Backup Codes

**User Story:** As a user, I want backup codes so that I can recover access if I lose my authenticator.

#### Acceptance Criteria
1. THE system SHALL generate 8 backup codes (8 characters each, alphanumeric)
2. THE system SHALL hash backup codes before storage (cannot be retrieved)
3. WHEN backup code is used, THE system SHALL invalidate it (single use)
4. THE system SHALL allow regeneration of backup codes (invalidates all previous)
5. THE system SHALL warn user when only 2 backup codes remain

### Requirement 2.3: WebAuthn/Passkeys (Phishing-Resistant)

**User Story:** As a healthcare professional, I want passkey authentication so that I'm protected against phishing attacks.

#### Acceptance Criteria
1. THE system SHALL implement WebAuthn using @simplewebauthn/server
2. THE system SHALL support platform authenticators (Face ID, Touch ID, Windows Hello)
3. THE system SHALL support roaming authenticators (YubiKey, security keys)
4. WHEN credential is registered, THE system SHALL store: credentialId, publicKey, counter, transports
5. THE system SHALL validate counter on each authentication (replay prevention)
6. FOR healthcare realms, THE system SHALL require WebAuthn as primary MFA
7. THE system SHALL allow multiple passkeys per user (max 10)
8. THE system SHALL support passkey naming and management

### Requirement 2.4: MFA Enforcement Policies

**User Story:** As a realm administrator, I want to enforce MFA policies so that all users meet security requirements.

#### Acceptance Criteria
1. THE system SHALL support realm-level MFA policies: disabled, optional, required
2. FOR healthcare realms, MFA SHALL be mandatory (no bypass)
3. WHEN MFA is required, THE system SHALL force setup on first login
4. THE system SHALL support "remember device" for 30 days (reduces MFA prompts)
5. THE system SHALL require MFA re-verification for sensitive actions (password change, MFA disable)

---

## SECTION 3: DEVICE TRUST & FINGERPRINTING

### Requirement 3.1: Device Fingerprinting

**User Story:** As a security system, I want to identify devices so that I can detect suspicious login attempts.

#### Acceptance Criteria
1. THE system SHALL collect device fingerprint components:
   - User-Agent (browser, version, OS)
   - Screen resolution
   - Timezone
   - Language
   - Platform
2. THE system SHALL hash fingerprint components for storage
3. THE system SHALL implement fuzzy matching with 70% threshold
4. THE system SHALL weight components: User-Agent 30%, Screen 20%, Timezone 20%, Language 15%, Platform 15%

### Requirement 3.2: Device Trust Scoring

**User Story:** As a security system, I want to score device trust so that I can apply appropriate security measures.

#### Acceptance Criteria
1. THE system SHALL calculate trust score (0-100) based on:
   - Fingerprint similarity (50%)
   - IP geolocation proximity (20%)
   - User-Agent consistency (15%)
   - Login time pattern (15%)
2. WHEN trust score >= 80, THE system SHALL allow login without additional MFA
3. WHEN trust score 50-79, THE system SHALL require MFA
4. WHEN trust score < 50, THE system SHALL require MFA + email verification
5. THE system SHALL send email alert for new device logins

### Requirement 3.3: Known Device Management

**User Story:** As a user, I want to manage my trusted devices so that I can revoke access from lost devices.

#### Acceptance Criteria
1. THE system SHALL store known devices with: id, name, fingerprint, lastSeen, ipHistory
2. THE system SHALL allow users to view all their devices
3. THE system SHALL allow users to revoke individual devices
4. THE system SHALL allow users to revoke all devices except current
5. WHEN device is revoked, THE system SHALL invalidate all sessions from that device

---

## SECTION 4: SOCIAL LOGIN (OAuth)

### Requirement 4.1: Google OAuth

**User Story:** As a user, I want to login with Google so that I don't need another password.

#### Acceptance Criteria
1. THE system SHALL implement OAuth 2.0 with PKCE flow
2. THE system SHALL store OAuth credentials per realm (customer's credentials)
3. WHEN user authorizes, Google SHALL show customer's app name (e.g., "Clinisyn")
4. THE system SHALL verify Google's ID token using Google's public keys
5. THE system SHALL link Google account to existing user if email matches
6. THE system SHALL create new user if email doesn't exist
7. THE system SHALL request minimal scopes: openid, email, profile

### Requirement 4.2: Apple Sign-In

**User Story:** As an iOS user, I want to login with Apple so that I can use Face ID seamlessly.

#### Acceptance Criteria
1. THE system SHALL implement Apple Sign-In with PKCE
2. THE system SHALL handle Apple's POST callback (unlike Google's GET)
3. THE system SHALL verify Apple's JWT using Apple's public keys
4. THE system SHALL handle Apple's email hiding feature (relay email)
5. THE system SHALL store Apple credentials per realm (customer's credentials)

### Requirement 4.3: Account Linking

**User Story:** As a user, I want my social accounts linked so that I can login with any method.

#### Acceptance Criteria
1. WHEN social login email matches existing user, THE system SHALL prompt to link accounts
2. THE system SHALL require password verification before linking
3. THE system SHALL allow multiple social providers per user
4. THE system SHALL allow unlinking social providers (if password exists)
5. THE system SHALL prevent account takeover via social login email change

---

## SECTION 5: EMAIL VERIFICATION & PASSWORD RESET

### Requirement 5.1: Email Verification

**User Story:** As a platform, I want to verify emails so that fake accounts are prevented.

#### Acceptance Criteria
1. THE system SHALL send 6-digit verification code via email
2. THE code SHALL expire in 15 minutes
3. THE system SHALL allow maximum 3 verification attempts per code
4. THE system SHALL rate limit: 5 emails per hour per user
5. THE system SHALL use secure random for code generation
6. THE system SHALL hash verification codes before storage

### Requirement 5.2: Password Reset

**User Story:** As a user, I want to reset my password securely so that I can recover my account.

#### Acceptance Criteria
1. THE system SHALL send password reset link via email
2. THE reset token SHALL be 32 bytes, cryptographically random
3. THE token SHALL expire in 1 hour
4. THE token SHALL be single-use (invalidated after use)
5. WHEN password is reset, THE system SHALL invalidate ALL sessions
6. THE system SHALL NOT reveal if email exists (prevent enumeration)
7. THE system SHALL rate limit: 3 reset requests per hour per email

---

## SECTION 6: MULTI-TENANT (REALM) ARCHITECTURE

### Requirement 6.1: Realm Isolation

**User Story:** As a platform, I want complete tenant isolation so that customer data is never mixed.

#### Acceptance Criteria
1. THE system SHALL isolate all user data by realm_id
2. THE system SHALL use composite keys: PK = realm_id, SK = user_id
3. THE system SHALL prevent cross-realm queries at database level
4. THE system SHALL validate realm_id on every API request
5. THE system SHALL support realm-specific configuration (MFA policy, session timeout, etc.)

### Requirement 6.2: Realm Configuration

**User Story:** As a realm administrator, I want to configure my realm so that it meets my security requirements.

#### Acceptance Criteria
1. THE system SHALL support realm settings:
   - MFA policy (disabled, optional, required)
   - Session timeout (default 7 days)
   - Password policy (min length, complexity)
   - Allowed origins (CORS)
   - OAuth provider credentials
2. THE system SHALL validate configuration changes
3. THE system SHALL audit log all configuration changes

---

## SECTION 7: RATE LIMITING & BRUTE FORCE PROTECTION

### Requirement 7.1: API Rate Limiting

**User Story:** As a platform, I want rate limiting so that abuse is prevented.

#### Acceptance Criteria
1. THE system SHALL implement rate limits per endpoint:
   - Login: 5 attempts / 15 min / IP
   - Register: 3 attempts / hour / IP
   - Password Reset: 3 attempts / hour / email
   - MFA Verify: 5 attempts / min / user
   - API General: 100 requests / min / user
2. WHEN rate limit exceeded, THE system SHALL return 429 with Retry-After header
3. THE system SHALL use sliding window algorithm

### Requirement 7.2: Credential Stuffing Detection

**User Story:** As a platform, I want to detect credential stuffing so that mass attacks are blocked.

#### Acceptance Criteria
1. THE system SHALL detect patterns: same password, different emails
2. THE system SHALL detect patterns: same IP, many failed logins
3. THE system SHALL detect patterns: distributed attack (many IPs, same target)
4. WHEN attack detected, THE system SHALL trigger CAPTCHA or block
5. THE system SHALL alert security team on detected attacks

### Requirement 7.3: Account Lockout

**User Story:** As a platform, I want account lockout so that brute force is prevented.

#### Acceptance Criteria
1. AFTER 5 failed attempts in 15 min, THE system SHALL lock account for 15 min
2. AFTER 10 failed attempts, THE system SHALL require email verification
3. AFTER 20 failed attempts, THE system SHALL require admin intervention
4. THE system SHALL notify user via email on lockout
5. THE system SHALL log all lockout events

---

## SECTION 8: SECURITY LOGGING & MONITORING

### Requirement 8.1: Audit Logging

**User Story:** As a security officer, I want comprehensive audit logs so that I can investigate incidents.

#### Acceptance Criteria
1. THE system SHALL log all authentication events:
   - Login success/failure
   - Registration
   - Password change/reset
   - MFA enable/disable
   - Session creation/termination
   - Device trust changes
2. THE log SHALL include: timestamp, user_id, realm_id, IP, user_agent, action, result
3. THE system SHALL retain logs for minimum 90 days
4. THE system SHALL support log export for compliance

### Requirement 8.2: Security Alerts

**User Story:** As a security officer, I want real-time alerts so that I can respond to threats quickly.

#### Acceptance Criteria
1. THE system SHALL alert on:
   - Failed login spike (>10/min for single user)
   - New device login
   - Password change
   - MFA disable
   - Account lockout
   - Suspicious IP (known bad actors)
2. THE system SHALL support alert channels: email, webhook
3. THE system SHALL allow alert configuration per realm

---

## SECTION 9: SDK & DEVELOPER EXPERIENCE

### Requirement 9.1: TypeScript SDK

**User Story:** As a developer, I want a TypeScript SDK so that I can integrate quickly.

#### Acceptance Criteria
1. THE SDK SHALL provide: login, register, logout, refreshToken, getCurrentUser
2. THE SDK SHALL handle automatic token refresh (5 min before expiry)
3. THE SDK SHALL provide proper TypeScript types
4. THE SDK SHALL support multiple storage backends (localStorage, sessionStorage, custom)
5. THE SDK SHALL handle errors with typed error classes
6. THE SDK SHALL be published to npm as @zalt/auth-sdk

### Requirement 9.2: React SDK

**User Story:** As a React developer, I want React hooks so that I can integrate with minimal code.

#### Acceptance Criteria
1. THE SDK SHALL provide: useAuth, useUser, AuthProvider
2. THE SDK SHALL handle loading states
3. THE SDK SHALL support SSR (Next.js)
4. THE SDK SHALL be published to npm as @zalt/auth-react

---

## SECTION 10: COMPLIANCE & DATA PROTECTION

### Requirement 10.1: HIPAA Compliance

**User Story:** As a healthcare platform, I want HIPAA compliance so that we can serve healthcare customers.

#### Acceptance Criteria
1. THE system SHALL use FIPS-compliant cryptography (RS256, AES-256-GCM)
2. THE system SHALL encrypt all PII at rest
3. THE system SHALL encrypt all data in transit (TLS 1.3)
4. THE system SHALL maintain audit logs for 6 years (HIPAA requirement)
5. THE system SHALL support BAA (Business Associate Agreement)

### Requirement 10.2: GDPR Compliance

**User Story:** As a platform serving EU users, I want GDPR compliance so that we meet legal requirements.

#### Acceptance Criteria
1. THE system SHALL support data export (user's right to portability)
2. THE system SHALL support data deletion (right to be forgotten)
3. THE system SHALL support regional data residency (EU data stays in EU)
4. THE system SHALL obtain explicit consent for data processing
5. THE system SHALL maintain data processing records

---

## SECTION 11: INFRASTRUCTURE & RELIABILITY

### Requirement 11.1: High Availability

**User Story:** As a platform, I want high availability so that authentication never fails.

#### Acceptance Criteria
1. THE system SHALL target 99.9% uptime (8.76 hours downtime/year max)
2. THE system SHALL use multi-AZ deployment
3. THE system SHALL implement health checks with automatic failover
4. THE system SHALL support graceful degradation (read-only mode if write fails)

### Requirement 11.2: Performance

**User Story:** As a platform, I want fast authentication so that users don't wait.

#### Acceptance Criteria
1. THE system SHALL respond to login requests in <500ms (p95)
2. THE system SHALL respond to token refresh in <200ms (p95)
3. THE system SHALL support 1000 concurrent authentications
4. THE system SHALL use connection pooling and caching appropriately

### Requirement 11.3: Disaster Recovery

**User Story:** As a platform, I want disaster recovery so that data is never lost.

#### Acceptance Criteria
1. THE system SHALL backup data with point-in-time recovery
2. THE system SHALL support cross-region backup replication
3. THE system SHALL have documented recovery procedures
4. THE system SHALL test recovery procedures quarterly
5. THE system SHALL achieve RPO < 1 hour, RTO < 4 hours
