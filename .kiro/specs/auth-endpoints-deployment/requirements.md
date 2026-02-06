# Auth Endpoints Deployment - Requirements

## Giriş

Bu spec, mevcut kodda yazılmış ancak AWS'ye deploy EDİLMEMİŞ authentication endpoint'lerinin deployment'ını tanımlar.

**Durum:** Handler'lar YAZILMIŞ, testler GEÇİYOR, ancak API Gateway'de route YOK!

**Deadline:** 29 Ocak 2026 (Clinisyn Launch)

---

## Mevcut Durum Analizi

### ✅ Deploy Edilmiş Endpoint'ler (Çalışıyor)
```
POST /login          → zalt-login Lambda
POST /register       → zalt-register Lambda  
POST /refresh        → zalt-refresh Lambda
POST /logout         → zalt-logout Lambda
GET  /health/*       → zalt-health Lambda
/v1/admin/*          → zalt-admin Lambda
/oauth/*             → zalt-sso Lambda
```

### ❌ Deploy EDİLMEMİŞ Endpoint'ler (Handler var, route yok!)
```
MFA Endpoints:
├── POST /v1/auth/mfa/setup           → mfa.handler.ts (mfaSetupHandler)
├── POST /v1/auth/mfa/verify          → mfa.handler.ts (mfaVerifyHandler)
├── POST /v1/auth/mfa/disable         → mfa.handler.ts (mfaDisableHandler)
└── POST /v1/auth/mfa/login/verify    → mfa.handler.ts (mfaLoginVerifyHandler)

Password Reset Endpoints:
├── POST /v1/auth/password-reset/request  → password-reset.handler.ts (requestPasswordResetHandler)
└── POST /v1/auth/password-reset/confirm  → password-reset.handler.ts (confirmPasswordResetHandler)

Email Verification Endpoints:
├── POST /v1/auth/verify-email/send       → verify-email.handler.ts (sendVerificationCodeHandler)
└── POST /v1/auth/verify-email/confirm    → verify-email.handler.ts (confirmVerificationHandler)

WebAuthn Endpoints:
├── POST /v1/auth/webauthn/register/options   → webauthn.handler.ts
├── POST /v1/auth/webauthn/register/verify    → webauthn.handler.ts
├── POST /v1/auth/webauthn/authenticate/options → webauthn.handler.ts
├── POST /v1/auth/webauthn/authenticate/verify  → webauthn.handler.ts
├── GET  /v1/auth/webauthn/credentials        → webauthn.handler.ts
└── DELETE /v1/auth/webauthn/credentials/{id} → webauthn.handler.ts
```

---

## SECTION 1: MFA ENDPOINTS DEPLOYMENT

### Requirement 1.1: MFA Setup Endpoint

**User Story:** Psikolog olarak, TOTP MFA kurulumu yapabilmeliyim ki hesabım güvende olsun.

#### Acceptance Criteria
1. WHEN authenticated user calls POST /v1/auth/mfa/setup, THE system SHALL return TOTP secret and QR code URL
2. THE response SHALL include otpauth:// URL for authenticator apps
3. THE system SHALL validate access token before processing
4. THE system SHALL reject if MFA already enabled
5. THE endpoint SHALL be rate limited (5/min/user)

### Requirement 1.2: MFA Verify Endpoint

**User Story:** Psikolog olarak, TOTP kodumu doğrulayıp MFA'yı aktifleştirebilmeliyim.

#### Acceptance Criteria
1. WHEN user submits valid TOTP code, THE system SHALL enable MFA
2. THE system SHALL generate and return 8 backup codes
3. THE backup codes SHALL be hashed before storage
4. THE system SHALL warn user to save backup codes
5. THE endpoint SHALL be rate limited (5/min/user)

### Requirement 1.3: MFA Disable Endpoint

**User Story:** Psikolog olarak, şifremi doğrulayarak MFA'yı kapatabilirim.

#### Acceptance Criteria
1. WHEN user provides correct password, THE system SHALL disable MFA
2. THE system SHALL require password verification
3. THE system SHALL clear TOTP secret and backup codes
4. THE system SHALL log security event

### Requirement 1.4: MFA Login Verify Endpoint

**User Story:** Psikolog olarak, login sırasında MFA challenge'ı geçebilmeliyim.

#### Acceptance Criteria
1. WHEN user submits valid TOTP code with mfa_session_id, THE system SHALL return tokens
2. THE system SHALL accept backup codes as alternative
3. THE mfa_session_id SHALL expire in 5 minutes
4. THE system SHALL rate limit (5/min/user)
5. THE system SHALL log MFA verification result

---

## SECTION 2: PASSWORD RESET ENDPOINTS DEPLOYMENT

### Requirement 2.1: Password Reset Request Endpoint

**User Story:** Kullanıcı olarak, şifremi unuttum diyerek reset email alabilmeliyim.

#### Acceptance Criteria
1. WHEN user requests password reset, THE system SHALL send email with reset token
2. THE system SHALL NOT reveal if email exists (no enumeration)
3. THE reset token SHALL be 32 bytes, 1 hour expiry
4. THE system SHALL rate limit (3/hour/email)
5. THE system SHALL log request

### Requirement 2.2: Password Reset Confirm Endpoint

**User Story:** Kullanıcı olarak, reset token ile yeni şifre belirleyebilmeliyim.

#### Acceptance Criteria
1. WHEN user submits valid token and new password, THE system SHALL update password
2. THE system SHALL invalidate ALL user sessions
3. THE system SHALL check new password against HaveIBeenPwned
4. THE token SHALL be single-use
5. THE system SHALL log password change

---

## SECTION 3: EMAIL VERIFICATION ENDPOINTS DEPLOYMENT

### Requirement 3.1: Send Verification Code Endpoint

**User Story:** Kullanıcı olarak, email doğrulama kodu alabilmeliyim.

#### Acceptance Criteria
1. WHEN authenticated user requests verification, THE system SHALL send 6-digit code
2. THE code SHALL expire in 15 minutes
3. THE system SHALL rate limit (5/hour/user)
4. THE system SHALL reject if already verified

### Requirement 3.2: Confirm Verification Endpoint

**User Story:** Kullanıcı olarak, kodu girerek emailimi doğrulayabilmeliyim.

#### Acceptance Criteria
1. WHEN user submits correct code, THE system SHALL mark email as verified
2. THE system SHALL allow max 3 attempts per code
3. THE system SHALL reject expired codes
4. THE system SHALL log verification

---

## SECTION 4: WEBAUTHN ENDPOINTS DEPLOYMENT

### Requirement 4.1: WebAuthn Registration Options

**User Story:** Psikolog olarak, passkey kayıt seçeneklerini alabilmeliyim.

#### Acceptance Criteria
1. WHEN authenticated user requests options, THE system SHALL return WebAuthn registration options
2. THE challenge SHALL be cryptographically random
3. THE options SHALL include supported authenticator types

### Requirement 4.2: WebAuthn Registration Verify

**User Story:** Psikolog olarak, passkey'imi kaydedebilmeliyim.

#### Acceptance Criteria
1. WHEN user submits credential, THE system SHALL verify and store
2. THE system SHALL validate origin (phishing protection!)
3. THE system SHALL allow max 10 credentials per user
4. THE system SHALL allow credential naming

### Requirement 4.3: WebAuthn Authentication Options

**User Story:** Psikolog olarak, passkey ile giriş seçeneklerini alabilmeliyim.

#### Acceptance Criteria
1. WHEN user requests auth options, THE system SHALL return challenge
2. THE system SHALL include user's registered credentials

### Requirement 4.4: WebAuthn Authentication Verify

**User Story:** Psikolog olarak, passkey ile giriş yapabilmeliyim.

#### Acceptance Criteria
1. WHEN user submits assertion, THE system SHALL verify and return tokens
2. THE system SHALL validate counter (replay protection)
3. THE system SHALL update last_used timestamp

### Requirement 4.5: WebAuthn Credentials Management

**User Story:** Psikolog olarak, passkey'lerimi yönetebilmeliyim.

#### Acceptance Criteria
1. THE system SHALL list user's credentials
2. THE system SHALL allow deletion with password verification
3. THE system SHALL prevent deleting last credential if MFA required

---

## SECTION 5: WAF CONFIGURATION

### Requirement 5.1: WAF Path Allowlist Update

**User Story:** Sistem olarak, yeni endpoint'lerin WAF'tan geçmesini sağlamalıyım.

#### Acceptance Criteria
1. THE WAF SHALL allow /v1/auth/mfa/* paths
2. THE WAF SHALL allow /v1/auth/password-reset/* paths
3. THE WAF SHALL allow /v1/auth/verify-email/* paths
4. THE WAF SHALL allow /v1/auth/webauthn/* paths
5. THE WAF SHALL apply rate limiting to new paths

---

## SECTION 6: SDK LOCAL DEPLOYMENT

### Requirement 6.1: SDK Package Build

**User Story:** Geliştirici olarak, @zalt/auth-sdk paketini local olarak kullanabilmeliyim.

#### Acceptance Criteria
1. THE SDK SHALL be buildable with npm run build
2. THE SDK SHALL export all auth methods
3. THE SDK SHALL include TypeScript types
4. THE SDK SHALL be linkable locally (npm link)

---

## Glossary

- **MFA:** Multi-Factor Authentication
- **TOTP:** Time-based One-Time Password
- **WebAuthn:** Web Authentication API (passkeys)
- **WAF:** Web Application Firewall
- **Grace Period:** Token rotation tolerance window

