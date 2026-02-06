# Zalt.io Authentication Platform - Architecture Document

> **Last Updated:** 27 Ocak 2026  
> **Status:** Production (Clinisyn entegrasyonu aktif)  
> **Deadline:** 29 Ocak 2026

## 🎯 Platform Overview

Zalt.io, enterprise-grade Auth-as-a-Service platformudur. Clerk alternatifi olarak tasarlanmış, HIPAA/GDPR uyumlu, darkweb-resistant güvenlik seviyesinde çalışır.

### İlk Müşteri
- **Clinisyn** - Healthcare platform (4000 Psikolog, 11 Ülke)
- Realm ID: `clinisyn`
- Domain: clinisyn.com (SES verified)

---

## 🏗️ AWS Infrastructure (Verified)

### API Gateway
```
Endpoint: https://gqgckg77af.execute-api.eu-central-1.amazonaws.com/prod
Name: zalt-api
Region: eu-central-1
```

### Lambda Functions (20+ deployed)
| Function | Purpose | Last Modified |
|----------|---------|---------------|
| zalt-register | User registration + email verification | 26 Jan 2026 |
| zalt-login | Authentication + MFA flow | 26 Jan 2026 |
| zalt-mfa | TOTP setup/verify (000000 test bypass) | 26 Jan 2026 |
| zalt-refresh | Token refresh with grace period | 26 Jan 2026 |
| zalt-logout | Session termination | 26 Jan 2026 |
| zalt-verify-email | Email verification | 26 Jan 2026 |
| zalt-password-reset | Password reset flow | 26 Jan 2026 |
| zalt-webauthn | Passkey/WebAuthn support | 26 Jan 2026 |
| zalt-social-login | Google/Apple OAuth | 26 Jan 2026 |
| zalt-sso | SAML/OIDC SSO | 26 Jan 2026 |
| zalt-admin | Admin operations | 26 Jan 2026 |
| zalt-admin-realm | Realm management | 26 Jan 2026 |
| zalt-organization | Organization CRUD | 26 Jan 2026 |
| zalt-membership | Membership management | 26 Jan 2026 |
| zalt-role | Role management | 26 Jan 2026 |
| zalt-health | Health check | 26 Jan 2026 |

### DynamoDB Tables
| Table | Purpose | GSIs |
|-------|---------|------|
| zalt-users | User data | email-index, realm-index |
| zalt-sessions | Active sessions | user-index |
| zalt-realms | Realm configurations | - |
| zalt-audit | Security audit logs | - |
| zalt-devices | Device fingerprints | - |
| zalt-mfa | MFA secrets | - |
| zalt-organizations | Organizations | - |
| zalt-memberships | User-Org memberships | - |

### AWS SES
- **Status:** Production enabled
- **Verified Domains:** clinisyn.com, zalt.io, hsdcore.com
- **Verified Emails:** hasan.aker@clinisyn.com

---

## 📁 Project Structure

```
zalt-auth/
├── src/                      # Backend Lambda code
│   ├── handlers/             # Lambda handlers (20+)
│   ├── services/             # Business logic
│   ├── repositories/         # DynamoDB operations
│   ├── models/               # TypeScript types
│   ├── utils/                # Helpers (JWT, password, validation)
│   ├── middleware/           # CORS, security, validation
│   └── config/               # AWS configs
│
├── dashboard/                # Next.js admin panel (WIP)
│   ├── src/app/              # Pages
│   ├── src/components/       # React components
│   └── src/lib/              # Utilities
│
├── packages/                 # SDK packages (WIP)
│   ├── core/                 # @zalt/core
│   ├── react/                # @zalt/react
│   ├── next/                 # @zalt/next
│   └── mcp-server/           # MCP server
│
├── docs/                     # Documentation
├── template.yaml             # SAM template
└── samconfig.toml            # SAM config
```

---

## 🔐 Security Configuration

### JWT
- **Algorithm:** RS256 (FIPS-compliant for HIPAA)
- **Access Token:** 15 minutes
- **Refresh Token:** 7 days (rotated on use)
- **Grace Period:** 30 seconds

### Password
- **Hashing:** Argon2id (32MB memory, timeCost 5, parallelism 2)
- **Min Length:** 8 characters
- **Requirements:** uppercase, lowercase, number
- **Breach Check:** HaveIBeenPwned API

### MFA
- **TOTP:** 6-digit, 30-second window
- **WebAuthn:** Passkeys (phishing-proof)
- **SMS:** Disabled (SS7 vulnerability)
- **Test Mode:** 000000 bypass for clinisyn realm

### Rate Limiting
| Endpoint | Limit | Window |
|----------|-------|--------|
| Login | 5 attempts | 15 min / IP |
| Register | 3 attempts | 1 hour / IP |
| Password Reset | 3 attempts | 1 hour / email |
| MFA Verify | 5 attempts | 1 min / user |

---

## 🏢 Multi-Tenant Architecture

### Realm Structure
Her müşteri izole realm(lar) alır:
```
clinisyn (realmId)
├── Users (REALM#clinisyn#USER#xxx)
├── Sessions
├── OAuth Credentials (müşterinin kendi Google/Apple)
├── Branding (email from: noreply@clinisyn.com)
└── Settings (MFA policy, session timeout, etc.)
```

### Clinisyn Realm Config (DynamoDB'den)
```json
{
  "realmId": "clinisyn",
  "name": "Clinisyn Healthcare Platform",
  "settings": {
    "branding": {
      "display_name": "Clinisyn",
      "email_from_address": "noreply@clinisyn.com",
      "email_from_name": "Clinisyn",
      "support_email": "support@clinisyn.com",
      "app_url": "https://app.clinisyn.com"
    },
    "password_policy": {
      "min_length": 8,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true
    },
    "mfa_required": false,
    "session_timeout": 3600
  }
}
```

---

## 🚀 API Endpoints

### Authentication
```
POST /register          - User registration
POST /login             - Login (returns MFA session if enabled)
POST /logout            - Logout
POST /refresh           - Token refresh
POST /verify-email      - Email verification
POST /password-reset    - Password reset request
POST /password-reset/confirm - Password reset confirm
```

### MFA
```
POST /mfa/setup         - Initialize TOTP
POST /mfa/verify        - Verify and enable MFA
POST /mfa/disable       - Disable MFA
POST /mfa/login/verify  - Verify MFA during login
```

### WebAuthn
```
POST /webauthn/register/options  - Get registration options
POST /webauthn/register/verify   - Verify registration
POST /webauthn/login/options     - Get login options
POST /webauthn/login/verify      - Verify login
```

### Social Login
```
GET  /social/google     - Google OAuth redirect
GET  /social/google/callback - Google callback
GET  /social/apple      - Apple Sign-In redirect
GET  /social/apple/callback - Apple callback
```

### Admin
```
GET  /admin/users       - List users
GET  /admin/users/:id   - Get user
PUT  /admin/users/:id   - Update user
DELETE /admin/users/:id - Delete user
```

---

## ⚠️ Known Issues & TODOs

### Working ✅
- [x] User registration with email verification
- [x] Login with MFA support
- [x] TOTP MFA (000000 test bypass)
- [x] Token refresh with grace period
- [x] SES email sending (clinisyn.com verified)
- [x] Rate limiting
- [x] Audit logging
- [x] Realm branding

### Not Working / WIP ❌
- [ ] Dashboard (npm install issues, needs fix)
- [ ] SDK packages (not published to npm)
- [ ] WebAuthn (handler exists, not tested)
- [ ] Social login (Google/Apple - needs testing)
- [ ] Organization/Role management (handlers exist, not tested)

### Missing Features (vs Clerk)
- [ ] User management UI
- [ ] Session management UI
- [ ] Webhook management
- [ ] Custom email templates UI
- [ ] Analytics dashboard
- [ ] Billing/Stripe integration

---

## 🔧 Deployment

### SAM Build & Deploy
```bash
# Build all functions
sam build

# Deploy to AWS
sam deploy --guided

# Or use existing config
sam deploy --config-file samconfig.toml
```

### Manual Lambda Update
```bash
# Build specific function
sam build RegisterFunction

# Zip and upload
cd .aws-sam/build/RegisterFunction
zip -r ../../../lambda-zips/register.zip .
aws lambda update-function-code --function-name zalt-register --zip-file fileb://lambda-zips/register.zip
```

---

## 📞 Support

- **Deadline:** 29 Ocak 2026
- **First Customer:** Clinisyn
- **Test Account:** enessgozee38@gmail.com (MFA bypass: 000000)
