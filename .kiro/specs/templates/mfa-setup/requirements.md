# MFA Setup Requirements Template

## Overview
Requirements for implementing Multi-Factor Authentication with Zalt.

## Functional Requirements

### 1. TOTP Setup
- [ ] 1.1 Generate TOTP secret
- [ ] 1.2 Display QR code for authenticator apps
- [ ] 1.3 Show manual entry code
- [ ] 1.4 Verify initial code
- [ ] 1.5 Generate backup codes

### 2. WebAuthn/Passkeys
- [ ] 2.1 Check browser support
- [ ] 2.2 Register new passkey
- [ ] 2.3 Name/label passkey
- [ ] 2.4 List registered passkeys
- [ ] 2.5 Remove passkey

### 3. SMS MFA (Optional - Not Recommended)
- [ ] 3.1 Phone number input
- [ ] 3.2 Risk acceptance dialog
- [ ] 3.3 SMS code verification
- [ ] 3.4 Rate limiting (3 codes/hour)

### 4. MFA Verification
- [ ] 4.1 Code input form
- [ ] 4.2 Backup code option
- [ ] 4.3 Remember device option
- [ ] 4.4 Error handling

### 5. MFA Management
- [ ] 5.1 View enabled methods
- [ ] 5.2 Add new method
- [ ] 5.3 Remove method (with verification)
- [ ] 5.4 Regenerate backup codes

## Security Requirements

- [ ] S1. TOTP codes valid for 30 seconds
- [ ] S2. Backup codes single-use
- [ ] S3. WebAuthn mandatory for healthcare
- [ ] S4. SMS MFA requires explicit risk acceptance
- [ ] S5. Rate limit MFA attempts (5/min)

## User Stories

### US1: Enable TOTP
As a user, I want to enable TOTP so that my account is protected with 2FA.

### US2: Use Passkey
As a user, I want to use my fingerprint/face to log in securely.

### US3: Backup Access
As a user who lost my authenticator, I want to use backup codes to regain access.
