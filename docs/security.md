# Zalt.io Security Guide

Enterprise-grade security for healthcare and regulated industries.

## Compliance

| Standard | Status |
|----------|--------|
| HIPAA | ✅ Compliant |
| GDPR | ✅ Compliant |
| SOC 2 Type II | 🔄 In Progress |
| ISO 27001 | 🔄 Planned |

## Security Architecture

### Authentication

- **JWT Algorithm:** RS256 (RSA + SHA-256)
  - FIPS 140-2 compliant for HIPAA
  - Asymmetric keys managed by AWS KMS
  - Key rotation every 30 days
  - **KMS Key Spec:** RSA_4096
  - **Signing Algorithm:** RSASSA_PKCS1_V1_5_SHA_256
  - **Key ID:** `zalt-kms-2026-01-16`

- **Password Security:**
  - Argon2id hashing (memory: 32MB, iterations: 5)
  - Minimum 12 characters required
  - Breach detection via HaveIBeenPwned API (k-Anonymity)
  - Password history (last 12 passwords blocked)

## Compromised Password Detection (HaveIBeenPwned)

### Overview

Zalt.io integrates with the HaveIBeenPwned (HIBP) API to detect passwords that have been exposed in known data breaches. This protects users from using compromised credentials that attackers may already possess.

**Task 17.1 Implementation - Requirements 8.1, 8.2**

### How It Works

The HIBP integration uses the **k-Anonymity** model to check passwords without exposing them:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Password Check Flow                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Hash password with SHA-1                                     │
│     "password" → "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Send only first 5 characters to HIBP API                     │
│     Prefix: "5BAA6" (k-Anonymity - never send full hash!)       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. HIBP returns all hash suffixes matching the prefix           │
│     Response: ~500-800 hash suffixes with breach counts          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Check locally if our suffix is in the response               │
│     Suffix: "1E4C9B93F3F0682250B6CF8331B7EE68FD8"               │
│     Found? → Password is compromised!                            │
└─────────────────────────────────────────────────────────────────┘
```

### Privacy Guarantees

**CRITICAL:** The full password or full hash is NEVER sent to HIBP:

| What is sent | What is NOT sent |
|--------------|------------------|
| First 5 chars of SHA-1 hash | Full password |
| (e.g., "5BAA6") | Full SHA-1 hash |
| | Any user information |

This k-Anonymity model ensures that even if the HIBP API were compromised, attackers could not determine which password was being checked.

### When Passwords Are Checked

| Event | Check Performed | Action on Compromise |
|-------|-----------------|---------------------|
| Registration | ✅ Yes | Reject with `PASSWORD_COMPROMISED` error |
| Password Change | ✅ Yes | Reject with `PASSWORD_COMPROMISED` error |
| Password Reset | ✅ Yes | Reject with `PASSWORD_COMPROMISED` error |
| Login | ❌ No | (Checked via background job) |

### Error Response

When a compromised password is detected:

```json
{
  "error": {
    "code": "PASSWORD_COMPROMISED",
    "message": "This password has been found in data breaches. Please choose a different password.",
    "timestamp": "2026-01-25T10:00:00Z"
  },
  "details": {
    "breach_count": 3861493,
    "recommendation": "Use a unique password with at least 12 characters"
  }
}
```

### HIBPService API

The `HIBPService` class provides programmatic access to breach checking:

```typescript
import { HIBPService, createHIBPService, checkPassword } from '@zalt/auth';

// Using convenience function
const result = await checkPassword('password123');
if (result.isCompromised) {
  console.log(`Password found ${result.count} times in breaches`);
}

// Using service instance with custom config
const hibp = createHIBPService({
  cacheTtlMs: 300000,    // 5 minutes cache
  maxCacheSize: 10000,   // Max cache entries
  timeoutMs: 5000,       // API timeout
  failOpen: true         // Don't block on API errors
});

const result = await hibp.checkPassword('mypassword');
// Result: { isCompromised: boolean, count: number, fromCache: boolean }
```

### Caching

Results are cached to improve performance and reduce API calls:

| Setting | Default | Description |
|---------|---------|-------------|
| `cacheTtlMs` | 5 minutes | How long to cache results |
| `maxCacheSize` | 10,000 | Maximum cache entries |

Cache statistics are available:

```typescript
const stats = hibp.getCacheStats();
// { size: 150, hits: 1200, misses: 300, hitRate: 0.8, apiCalls: 300, apiErrors: 2 }
```

### Fail-Open Design

The HIBP service is designed to **fail open** - if the API is unavailable, authentication continues:

```typescript
// Default behavior: fail open
const hibp = createHIBPService({ failOpen: true });

// On API error:
// - Returns { isCompromised: false, error: "..." }
// - Logs warning for monitoring
// - Does NOT block registration/password change
```

**Why Fail Open?**
- Availability is critical for authentication
- HIBP API outages shouldn't block all registrations
- All failures are logged for monitoring
- Background job can re-check later

### Configuration

```typescript
interface HIBPServiceConfig {
  apiBaseUrl?: string;      // Default: https://api.pwnedpasswords.com
  cacheTtlMs?: number;      // Default: 300000 (5 minutes)
  maxCacheSize?: number;    // Default: 10000
  timeoutMs?: number;       // Default: 5000
  userAgent?: string;       // Default: Zalt.io-Auth-Service/1.0
  addPadding?: boolean;     // Default: true (prevents response size analysis)
  failOpen?: boolean;       // Default: true
}
```

### Best Practices

1. **Always Check on Registration:** Never allow compromised passwords for new accounts
2. **Check on Password Change:** Ensure users don't switch to compromised passwords
3. **Monitor Cache Stats:** High miss rates may indicate cache issues
4. **Review API Errors:** Frequent errors may indicate network issues
5. **Educate Users:** Explain why their password was rejected

### Security Considerations

- SHA-1 is used only for HIBP compatibility (not for password storage)
- Passwords are hashed with Argon2id for storage
- k-Anonymity ensures privacy even if HIBP is compromised
- Add-Padding header prevents response size analysis attacks
- All checks are audit logged (without password details)

## Background Breach Detection

### Overview

Zalt.io includes a background job that periodically checks existing user passwords against new breaches in the HaveIBeenPwned database. This proactive approach ensures that users are notified even if their password becomes compromised after registration.

**Task 17.4 Implementation - Requirements 8.7, 8.8**

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                  Background Breach Check Job                     │
│                  (CloudWatch Events - Daily)                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Iterate through all realms                                   │
│     Process users in batches (default: 100)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. For each user with stored SHA-1 hash:                        │
│     - Check if enough time since last check (default: 7 days)    │
│     - Skip if already marked as compromised                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Check password hash against HIBP API                         │
│     - Uses k-Anonymity (only first 5 chars sent)                 │
│     - Rate limited to avoid API blocking                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. If compromised:                                              │
│     - Update user's breach status in database                    │
│     - Create reset_password session task                         │
│     - Send notification email to user                            │
│     - Log security event for audit                               │
└─────────────────────────────────────────────────────────────────┘
```

### Configuration

The breach check job can be configured via CloudWatch Events:

| Setting | Default | Description |
|---------|---------|-------------|
| `batchSize` | 100 | Users processed per batch |
| `apiDelayMs` | 100 | Delay between HIBP API calls (rate limiting) |
| `maxUsersPerInvocation` | 1000 | Max users per Lambda invocation |
| `sendNotifications` | true | Send email notifications |
| `createSessionTasks` | true | Create password reset tasks |
| `minDaysSinceLastCheck` | 7 | Days before re-checking a user |

### User Notification

When a breach is detected, users receive an email notification that includes:

- Clear explanation of what happened
- Number of breaches the password was found in
- Step-by-step instructions to secure their account
- Direct link to reset their password
- Recommendations for password security

### Session Task Integration

When a breach is detected for a user with active sessions:

1. A `reset_password` session task is created
2. The task blocks API access until password is reset
3. User is prompted to reset password on next login
4. All sessions remain active (not revoked by default)

### Security Events

The following events are logged for audit:

| Event | Description |
|-------|-------------|
| `breach_check_job_started` | Job execution started |
| `breach_check_job_completed` | Job execution completed with metrics |
| `breach_check_job_failed` | Job execution failed |
| `password_breach_detected` | Compromised password found for user |

### Metrics

The job reports the following metrics:

```json
{
  "usersChecked": 1000,
  "breachesFound": 5,
  "emailsSent": 5,
  "tasksCreated": 3,
  "errors": [],
  "processingTimeMs": 45000,
  "completed": true,
  "realmsProcessed": 3
}
```

### Privacy Considerations

- **SHA-1 Hash Storage:** A SHA-1 hash of the password is stored separately for HIBP checking only
- **k-Anonymity:** Only the first 5 characters of the hash are sent to HIBP
- **No Password Logging:** Passwords and full hashes are never logged
- **Secure Notifications:** Emails do not contain password information

### Fail-Safe Design

The breach check job is designed to be resilient:

- **Fail-Open:** API errors don't block the entire job
- **Batch Processing:** Processes users in batches to avoid timeouts
- **Progress Tracking:** Can resume from last position if interrupted
- **Error Isolation:** Individual user errors don't affect other users

- **Token Lifecycle:**
  - Access Token: 15 minutes (realm-configurable)
  - Refresh Token: 7 days (rotated on use)
  - Grace Period: 30 seconds for network retries

### Multi-Factor Authentication

**Supported Methods:**
- ✅ TOTP (Google Authenticator, Authy, etc.)
- ✅ WebAuthn/Passkeys (phishing-resistant)
- ❌ SMS (disabled - SS7 vulnerability)
- ❌ Email OTP (disabled - phishing risk)

**Why WebAuthn?**
WebAuthn is the only MFA method that prevents phishing attacks. Even sophisticated attacks like Evilginx2 cannot bypass WebAuthn because the credential is bound to the origin.

### Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| Login | 5 attempts | 15 minutes |
| Register | 3 attempts | 1 hour |
| Password Reset | 3 attempts | 1 hour |
| MFA Verify | 5 attempts | 1 minute |
| API General | 100 requests | 1 minute |

Progressive delays are applied after failed attempts.

### Account Protection

- **Lockout Policy:** 5 failed attempts = 15 min lockout
- **Breach Detection:** Passwords checked against known breaches
- **Session Management:** Max 5 concurrent sessions per user
- **Device Fingerprinting:** 70% similarity threshold for trusted devices

## Infrastructure Security

### AWS Services

```
┌─────────────────────────────────────────────────┐
│                   CloudFront                     │
│                   (WAF + DDoS)                   │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│               API Gateway                        │
│         (Rate Limiting + Auth)                   │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│              Lambda Functions                    │
│            (Node.js 20.x + TypeScript)          │
└─────────────────────┬───────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
┌───────▼───────┐ ┌───▼───┐ ┌──────▼──────┐
│   DynamoDB    │ │  KMS  │ │     SES     │
│  (Encrypted)  │ │(Keys) │ │  (Email)    │
└───────────────┘ └───────┘ └─────────────┘
```

### Data Protection

- **Encryption at Rest:** AES-256-GCM (AWS managed keys)
- **Encryption in Transit:** TLS 1.3
- **Key Management:** AWS KMS with automatic rotation
- **Data Residency:** Regional isolation (EU/US/Asia)

### WAF Rules

- SQL Injection protection
- XSS prevention
- Rate-based blocking
- Geo-blocking (configurable)
- Bot detection

## Threat Model

### Protected Against

| Threat | Protection |
|--------|------------|
| Credential Stuffing | Rate limiting, breach detection, progressive delays |
| Phishing | WebAuthn, origin-bound credentials |
| Session Hijacking | Short-lived tokens, device binding |
| Brute Force | Account lockout, rate limiting |
| Man-in-the-Middle | TLS 1.3, certificate pinning |
| Token Theft | Short expiry, rotation on use |

### Security Headers

All responses include:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

## Best Practices for Integration

### Token Storage

```typescript
// ✅ Good - HttpOnly cookies (server-side)
// ✅ Good - Secure memory storage (mobile)
// ⚠️ Acceptable - localStorage (with XSS protection)
// ❌ Bad - URL parameters
// ❌ Bad - Plain cookies
```

### Secure Implementation

```typescript
// Always validate tokens server-side
const user = await auth.getCurrentUser();
if (!user) {
  redirect('/login');
}

// Check email verification for sensitive operations
if (!user.email_verified) {
  redirect('/verify-email');
}

// Require MFA for admin actions
if (!user.mfa_enabled && isAdminAction) {
  redirect('/setup-mfa');
}
```

### Session Monitoring

```typescript
// Implement session activity checks
setInterval(async () => {
  const isValid = await auth.isAuthenticated();
  if (!isValid) {
    // Session expired or revoked
    await auth.logout();
    redirect('/login');
  }
}, 60000); // Check every minute
```

## Machine-to-Machine (M2M) Authentication

### Overview

M2M authentication enables secure service-to-service communication using OAuth 2.0 client credentials flow. Each machine gets a unique `client_id` and `client_secret` pair.

### M2M Scopes

Scopes control what resources a machine can access:

| Scope | Description |
|-------|-------------|
| `read:users` | Read user data |
| `write:users` | Create/update users |
| `delete:users` | Delete users |
| `read:sessions` | Read session data |
| `write:sessions` | Create sessions |
| `revoke:sessions` | Revoke sessions |
| `read:tenants` | Read tenant data |
| `write:tenants` | Create/update tenants |
| `read:roles` | Read role data |
| `write:roles` | Create/update roles |
| `read:audit` | Read audit logs |
| `read:webhooks` | Read webhook config |
| `write:webhooks` | Create/update webhooks |
| `read:analytics` | Read analytics data |
| `admin:all` | Full access (all scopes) |

### Token Security

- **Algorithm:** HS256 (testing) / RS256 (production)
- **Expiry:** 1 hour (no refresh tokens)
- **Issuer:** `https://api.zalt.io`
- **Token Type:** `m2m`

### Scope Enforcement

The M2M middleware validates tokens and enforces scopes:

```typescript
// Endpoint scope requirements
'GET /users'     → 'read:users'
'POST /users'    → 'write:users'
'DELETE /users'  → 'delete:users'
'GET /sessions'  → 'read:sessions'
'DELETE /sessions' → 'revoke:sessions'
```

### Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 401 | `MISSING_TOKEN` | No Authorization header |
| 401 | `INVALID_TOKEN` | Malformed or invalid token |
| 401 | `TOKEN_EXPIRED` | Token has expired |
| 403 | `INSUFFICIENT_SCOPE` | Token lacks required scope |

### Best Practices

1. **Principle of Least Privilege:** Request only needed scopes
2. **Credential Rotation:** Rotate secrets every 90 days
3. **IP Allowlisting:** Restrict machine access by IP
4. **Audit Logging:** All M2M requests are logged
5. **Short-Lived Tokens:** 1-hour expiry limits exposure

## User API Key Authentication

### Overview

User-generated API keys allow end users to create their own keys for programmatic access. These keys inherit the user's permissions and tenant context.

### Key Format

```
zalt_key_{32 alphanumeric characters}
Example: zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef
```

### User API Key Scopes

| Scope | Description |
|-------|-------------|
| `profile:read` | Read own profile |
| `profile:write` | Update own profile |
| `sessions:read` | Read own sessions |
| `sessions:revoke` | Revoke own sessions |
| `tenants:read` | Read tenant data |
| `tenants:write` | Update tenant data |
| `members:read` | Read tenant members |
| `members:invite` | Invite members |
| `members:remove` | Remove members |
| `roles:read` | Read roles |
| `roles:write` | Manage roles |
| `api:read` | Read API data |
| `api:write` | Write API data |
| `full:access` | Full access (all user permissions) |

### Security Features

1. **SHA-256 Hashing:** Keys are hashed before storage
2. **Single Display:** Full key shown only once on creation
3. **Immediate Revocation:** Revoked keys are invalidated instantly
4. **Expiration Support:** Optional expiry dates
5. **IP Restrictions:** Optional IP allowlisting (CIDR)
6. **Scope Limiting:** Keys can have subset of user permissions

### Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 401 | `MISSING_API_KEY` | No API key provided |
| 401 | `INVALID_KEY_FORMAT` | Malformed key |
| 401 | `API_KEY_INVALID` | Key not found or revoked |
| 401 | `API_KEY_EXPIRED` | Key has expired |
| 403 | `INSUFFICIENT_SCOPE` | Key lacks required scope |
| 403 | `IP_NOT_ALLOWED` | Request from blocked IP |

### Best Practices

1. **Minimal Scopes:** Create keys with only needed scopes
2. **Short Expiry:** Set expiration for temporary access
3. **IP Restrictions:** Limit access to known IPs
4. **Regular Rotation:** Revoke and recreate keys periodically
5. **Audit Review:** Monitor key usage in audit logs

## Reverification (Step-Up Authentication)

### Overview

Reverification provides step-up authentication for sensitive operations. Even with a valid session, users must re-authenticate before performing critical actions like changing passwords, disabling MFA, or deleting accounts.

This protects against:
- Session hijacking attacks
- Compromised sessions performing critical operations
- Unauthorized access to sensitive features

### Reverification Levels

| Level | Method | Security | Use Case |
|-------|--------|----------|----------|
| `password` | Re-enter password | Basic | Password change, email change |
| `mfa` | TOTP/Backup code | Medium | MFA disable, account deletion |
| `webauthn` | WebAuthn/Passkey | Highest | Organization deletion, critical admin ops |

**Higher levels satisfy lower level requirements.** For example, WebAuthn reverification satisfies both MFA and password requirements.

### Default Protected Endpoints

| Endpoint | Method | Required Level | Validity |
|----------|--------|----------------|----------|
| `/me/password` | PUT | password | 5 min |
| `/me/email` | PUT | password | 5 min |
| `/me/delete` | DELETE | mfa | 5 min |
| `/mfa/disable` | POST | mfa | 5 min |
| `/mfa/recovery-codes` | POST | mfa | 5 min |
| `/api-keys` | POST | password | 10 min |
| `/api-keys/*` | DELETE | password | 10 min |
| `/sessions` | DELETE | password | 5 min |
| `/billing/cancel` | POST | mfa | 5 min |
| `/organizations/*/delete` | DELETE | webauthn | 5 min |

### Reverification Flow

```
1. User attempts sensitive operation
2. Middleware checks reverification status
3. If not verified → Return 403 REVERIFICATION_REQUIRED
4. User completes reverification (password/MFA/WebAuthn)
5. Session marked as verified for configured duration
6. User retries original operation → Success
```

### Error Response

When reverification is required, the API returns:

```json
{
  "error": {
    "code": "REVERIFICATION_REQUIRED",
    "message": "This operation requires password reverification",
    "timestamp": "2026-01-25T10:00:00Z"
  },
  "reverification": {
    "required": true,
    "level": "password",
    "validityMinutes": 10,
    "endpoints": {
      "password": "/reverify/password",
      "mfa": "/reverify/mfa",
      "webauthn": "/reverify/webauthn"
    }
  }
}
```

**Response Headers:**
- `X-Reverification-Required: true`
- `X-Reverification-Level: password`

### SDK Integration

The SDK automatically handles reverification:

```typescript
// Using useReverification hook
const { reverify, isReverifying } = useReverification();

// Automatic modal handling
try {
  await api.changePassword(newPassword);
} catch (error) {
  if (error.code === 'REVERIFICATION_REQUIRED') {
    // SDK shows reverification modal automatically
    // After success, retries the original request
  }
}
```

### Middleware Usage

```typescript
import { 
  withReverification, 
  requirePasswordReverification,
  requireMFAReverification,
  requireWebAuthnReverification 
} from '@zalt/middleware';

// Using wrapper
export const handler = withReverification(
  async (event) => {
    // Handler logic - only runs if reverified
  },
  { requiredLevel: 'password' }
);

// Using convenience wrappers
export const changePassword = requirePasswordReverification(handler);
export const disableMFA = requireMFAReverification(handler);
export const deleteOrg = requireWebAuthnReverification(handler);

// Inline check
const result = await reverificationMiddleware(event, { 
  requiredLevel: 'mfa' 
});
if (!result.valid) {
  return result.response;
}
```

### Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 401 | `SESSION_REQUIRED` | No valid session found |
| 403 | `REVERIFICATION_REQUIRED` | Step-up auth needed |

### Best Practices

1. **Use Appropriate Levels:** Match reverification level to operation sensitivity
2. **Short Validity:** Keep validity periods short (5-10 minutes)
3. **WebAuthn for Critical Ops:** Use WebAuthn for irreversible operations
4. **Audit All Attempts:** Log both successful and failed reverification
5. **Clear Error Messages:** Tell users exactly what's required

### Security Considerations

- Reverification status is bound to the session
- Expired reverification requires re-authentication
- All reverification attempts are audit logged
- Rate limiting applies to reverification endpoints
- WebAuthn is phishing-proof (recommended for healthcare)

## Session Task Blocking

### Overview

Session Tasks are mandatory actions that users must complete after login before they can access the application. The Session Task Blocking middleware enforces this by returning 403 errors for any API request when blocking tasks are pending.

This protects against:
- Users bypassing required security setup (MFA enrollment)
- Compromised passwords remaining in use
- Outdated terms of service acceptance
- Unauthorized access before organization selection

### Task Types

| Task Type | Blocking | Priority | Description |
|-----------|----------|----------|-------------|
| `reset_password` | ✅ Yes | 1 (Highest) | Password must be reset (compromised/expired) |
| `setup_mfa` | ✅ Yes | 2 | MFA setup required by policy |
| `accept_terms` | ✅ Yes | 3 | Terms of service must be accepted |
| `choose_organization` | ✅ Yes | 4 | Organization must be selected |
| `custom` | ⚙️ Configurable | 5 | Custom tasks via webhook |

### Blocking Behavior

When a session has pending blocking tasks:

1. **All API requests are blocked** (except whitelisted endpoints)
2. **403 SESSION_TASK_PENDING** is returned
3. **Task details are included** in the response
4. **X-Session-Task-Pending header** is set to `true`

### Whitelisted Endpoints

These endpoints bypass session task blocking to allow task completion:

| Category | Endpoints |
|----------|-----------|
| **Task Management** | `GET /session/tasks`, `POST /session/tasks/*/complete`, `POST /session/tasks/*/skip` |
| **Logout** | `POST /logout`, `POST /auth/logout`, `DELETE /sessions/current` |
| **Password Reset** | `PUT /me/password`, `POST /password/reset`, `POST /password/change` |
| **MFA Setup** | `POST /mfa/setup`, `POST /mfa/totp/setup`, `POST /mfa/webauthn/setup`, `POST /mfa/verify` |
| **Organization** | `POST /organizations/select`, `POST /organizations/switch`, `PUT /me/organization` |
| **Terms** | `POST /terms/accept`, `POST /me/terms` |
| **Health/Info** | `GET /health`, `GET /health/*`, `GET /.well-known/*`, `GET /me`, `GET /auth/me` |
| **Reverification** | `POST /reverify/*` |

### Error Response

When blocked by pending tasks:

```json
{
  "error": {
    "code": "SESSION_TASK_PENDING",
    "message": "You have pending tasks that must be completed before accessing this resource",
    "timestamp": "2026-01-25T10:00:00Z",
    "request_id": "req_abc123"
  },
  "session_tasks": {
    "pending": true,
    "count": 1,
    "tasks": [
      {
        "id": "task_xyz789",
        "type": "reset_password",
        "priority": 1,
        "metadata": {
          "reason": "compromised",
          "message": "Your password must be reset"
        }
      }
    ],
    "endpoints": {
      "list": "/session/tasks",
      "complete": "/session/tasks/{id}/complete",
      "skip": "/session/tasks/{id}/skip"
    }
  }
}
```

**Response Headers:**
- `X-Session-Task-Pending: true`
- `X-Session-Task-Count: 1`

### SDK Integration

The SDK automatically handles session tasks:

```typescript
// SDK detects SESSION_TASK_PENDING and shows task UI
try {
  await api.getData();
} catch (error) {
  if (error.code === 'SESSION_TASK_PENDING') {
    // SDK shows task completion UI automatically
    // After completion, retries the original request
  }
}

// Check for pending tasks
const { tasks, hasBlockingTasks } = await auth.getSessionTasks();
if (hasBlockingTasks) {
  // Redirect to task completion flow
}
```

### Middleware Usage

```typescript
import { 
  withSessionTaskBlocking,
  sessionTaskBlockingMiddleware,
  isSessionTaskPending,
  extractSessionTaskDetails
} from '@zalt/middleware';

// Using wrapper
export const handler = withSessionTaskBlocking(
  async (event) => {
    // Handler logic - only runs if no blocking tasks
  }
);

// Inline check
const result = await sessionTaskBlockingMiddleware(event);
if (!result.valid) {
  return result.response;
}

// Check response for SDK
if (isSessionTaskPending(response)) {
  const details = extractSessionTaskDetails(response);
  // Handle task completion flow
}
```

### Admin Operations

Administrators can force tasks on users:

```typescript
// Force password reset for a user
POST /admin/users/{id}/force-password-reset
{
  "reason": "compromised",
  "revoke_sessions": true,
  "message": "Your password was found in a data breach"
}

// Mass password reset (security incident)
POST /admin/realm/force-password-reset
{
  "reason": "compromised",
  "revoke_all_sessions": true,
  "message": "Security incident: All passwords must be reset"
}
```

### Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 403 | `SESSION_TASK_PENDING` | Blocking tasks must be completed |

### Best Practices

1. **Complete Tasks Promptly:** Guide users through task completion immediately after login
2. **Clear Instructions:** Provide clear metadata explaining why each task is required
3. **Graceful Degradation:** SDK should handle blocking gracefully with user-friendly UI
4. **Audit Everything:** All task creation, completion, and blocking events are logged
5. **Security First:** Never skip blocking tasks for security-critical operations

### Security Considerations

- Blocking tasks cannot be bypassed (except via whitelisted endpoints)
- Task completion is validated (e.g., password strength, MFA verification)
- All blocking events are audit logged with session and IP information
- Force password reset can optionally revoke all sessions
- Mass password reset is rate-limited (1 per 5 minutes per admin)

## Impossible Travel Detection

### Overview

Zalt.io detects impossible travel by calculating the geographic velocity between consecutive logins. When a user logs in from two locations that would require faster-than-possible travel (e.g., New York to Tokyo in 1 hour), the system flags this as suspicious and can optionally revoke the session.

**Task 21.3 Implementation - Requirement 13.5**

This protects against:
- Session hijacking from different geographic locations
- Credential theft and unauthorized access
- Account takeover attempts
- Compromised session tokens

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                  Impossible Travel Detection                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. Get last login location from IP geolocation                  │
│     Previous: New York (40.7128°N, 74.0060°W)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Get current login location from IP geolocation               │
│     Current: Tokyo (35.6762°N, 139.6503°E)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Calculate distance using Haversine formula                   │
│     Distance: ~10,850 km                                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Calculate time elapsed since last login                      │
│     Time: 1 hour                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Calculate velocity                                           │
│     Speed = 10,850 km / 1 hour = 10,850 km/h                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. Compare against thresholds                                   │
│     Speed > 1000 km/h → IMPOSSIBLE TRAVEL DETECTED              │
│     Speed > 500 km/h  → SUSPICIOUS TRAVEL                       │
└─────────────────────────────────────────────────────────────────┘
```

### Velocity Thresholds

| Speed (km/h) | Risk Level | Action |
|--------------|------------|--------|
| < 250 | Low | Normal - no action |
| 250-500 | Medium | Suspicious - enhanced logging |
| 500-1000 | High | Suspicious - require MFA |
| > 1000 | Critical | **Impossible travel** - alert admin, optionally revoke |

**Note:** Commercial aircraft typically cruise at ~900 km/h, so speeds above 1000 km/h are physically impossible.

### Realm-Specific Configuration

Different realms can have different velocity configurations:

```typescript
// Default configuration
const DEFAULT_VELOCITY_CONFIG = {
  maxSpeedKmh: 1000,           // Impossible travel threshold
  suspiciousSpeedKmh: 500,     // Suspicious travel threshold
  minTimeBetweenChecks: 60,    // Minimum seconds between checks
  sameCityToleranceKm: 50,     // Same city tolerance
  blockOnImpossibleTravel: false,  // Alert only, don't block
  requireMfaOnSuspicious: true,
  sendAlertOnDetection: true
};

// Healthcare realm (stricter - HIPAA compliance)
const HEALTHCARE_VELOCITY_CONFIG = {
  maxSpeedKmh: 800,            // More conservative threshold
  suspiciousSpeedKmh: 300,     // Lower suspicious threshold
  minTimeBetweenChecks: 60,
  sameCityToleranceKm: 30,
  blockOnImpossibleTravel: true,   // Auto-revoke sessions
  requireMfaOnSuspicious: true,
  sendAlertOnDetection: true
};
```

### Session Response with Impossible Travel

When impossible travel is detected, the session info includes travel details:

```json
{
  "sessions": [
    {
      "id": "session_xxx",
      "device": "Desktop",
      "browser": "Chrome 120",
      "ip_address": "74.125.*.*",
      "location": {
        "city": "Tokyo",
        "country": "Japan",
        "country_code": "JP"
      },
      "last_activity": "2026-01-25T10:00:00Z",
      "is_current": true,
      "impossible_travel": {
        "detected": true,
        "risk_level": "critical",
        "previous_location": {
          "city": "New York",
          "country": "United States"
        },
        "current_location": {
          "city": "Tokyo",
          "country": "Japan"
        },
        "distance_km": 10850,
        "time_elapsed_hours": 1.0,
        "speed_kmh": 10850,
        "reason": "Impossible travel detected: 10850km in 1.00h (10850km/h)"
      }
    }
  ],
  "impossible_travel_detected": true
}
```

### Admin Alerts

When impossible travel is detected, an admin alert is generated:

```json
{
  "event_type": "impossible_travel_alert",
  "timestamp": "2026-01-25T10:00:00Z",
  "realm_id": "realm_xxx",
  "user_id": "user_xxx",
  "details": {
    "session_id": "session_xxx",
    "previous_location": "New York, United States",
    "current_location": "Tokyo, Japan",
    "distance_km": 10850,
    "time_elapsed_hours": 1.0,
    "speed_kmh": 10850,
    "risk_level": "critical",
    "action_taken": "alert_only"
  }
}
```

### Automatic Session Revocation

For healthcare realms (or realms with `blockOnImpossibleTravel: true`), sessions are automatically revoked:

```json
{
  "error": {
    "code": "SESSION_REVOKED_IMPOSSIBLE_TRAVEL",
    "message": "Session revoked due to impossible travel detection",
    "timestamp": "2026-01-25T10:00:00Z"
  },
  "details": {
    "reason": "Impossible travel detected: 10850km in 1.00h (10850km/h)",
    "previous_location": {
      "city": "New York",
      "country": "United States"
    },
    "current_location": {
      "city": "Tokyo",
      "country": "Japan"
    }
  }
}
```

### Audit Events

The following events are logged for impossible travel:

| Event | Description |
|-------|-------------|
| `impossible_travel_alert` | Impossible travel detected, admin alerted |
| `session_auto_revoked_impossible_travel` | Session automatically revoked due to impossible travel |
| `suspicious_travel_detected` | Suspicious (but not impossible) travel detected |

### VPN/Proxy Detection

The system also detects VPN, Proxy, and Tor connections which can affect location accuracy:

```json
{
  "impossible_travel": {
    "detected": false,
    "risk_level": "medium",
    "reason": "VPN/Proxy/Tor detected",
    "current_location": {
      "city": "Unknown",
      "country": "Unknown",
      "is_vpn": true
    }
  }
}
```

### Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 403 | `SESSION_REVOKED_IMPOSSIBLE_TRAVEL` | Session revoked due to impossible travel |

### Best Practices

1. **Enable for Healthcare:** Always enable `blockOnImpossibleTravel` for HIPAA-compliant realms
2. **Monitor Alerts:** Set up webhook notifications for `impossible_travel_alert` events
3. **Review False Positives:** VPN users may trigger false positives - consider IP whitelisting
4. **Educate Users:** Inform users about session security and impossible travel detection
5. **Audit Regularly:** Review impossible travel events to identify attack patterns

### Security Considerations

- Location data is derived from IP geolocation (not GPS)
- VPN/Proxy users may have inaccurate location data
- Same-city tolerance prevents false positives for local movement
- All detection events are audit logged
- No PII is exposed in error messages

## AI-Powered Risk Assessment

### Overview

Zalt.io uses AI-powered risk assessment to evaluate login attempts and user behavior in real-time. Each assessment produces a risk score (0-100) and a recommendation for how to proceed with the authentication request.

This protects against:
- Credential stuffing attacks
- Account takeover attempts
- Impossible travel scenarios
- Bot and automation attacks
- Suspicious behavior patterns

### Risk Score Thresholds

| Score Range | Risk Level | Action |
|-------------|------------|--------|
| 0-30 | Low | Allow login |
| 31-60 | Medium | Allow with monitoring |
| 61-70 | High | Allow with enhanced logging |
| 71-90 | Very High | **Require MFA** regardless of user settings |
| 91-100 | Critical | **Block login** and notify admin |

### Risk Factors

The risk score is calculated from multiple factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| `ip_reputation` | 20% | IP address reputation from threat intelligence |
| `geo_velocity` | 25% | Impossible travel detection (>1000 km/h) |
| `device_trust` | 15% | Device fingerprint trust score |
| `behavior_anomaly` | 15% | Unusual behavior patterns |
| `credential_stuffing` | 20% | Credential stuffing attack detection |
| `brute_force` | 20% | Brute force attack detection |
| `tor_exit_node` | 10% | Tor network exit node detection |
| `vpn_proxy` | 5% | VPN/Proxy detection |
| `bot_detection` | 15% | Bot/automation detection |
| `time_anomaly` | 5% | Unusual login time for user |

### Risk Assessment Response

When a login is assessed, the API returns risk information:

```json
{
  "risk": {
    "score": 75,
    "recommendation": "mfa_required",
    "factors": [
      {
        "type": "geo_velocity",
        "score": 90,
        "description": "Geographic velocity analysis"
      },
      {
        "type": "device_trust",
        "score": 60,
        "description": "Device trust verification"
      }
    ],
    "assessedAt": "2026-01-25T10:00:00Z",
    "requiresMfa": true,
    "blocked": false
  }
}
```

### Impossible Travel Detection

Zalt detects impossible travel by calculating the velocity between consecutive logins:

```
Velocity = Distance (km) / Time (hours)

If Velocity > 1000 km/h → Impossible travel detected
```

Example: Login from Istanbul, then New York 1 hour later (~8000 km) = 8000 km/h → **Blocked**

### AWS Bedrock Integration

Zalt uses AWS Bedrock for advanced ML-powered security analysis. The integration provides three key capabilities:

#### 1. Anomaly Detection Model

The anomaly detection model identifies deviations from normal user behavior:

```typescript
// Anomaly types detected
type AnomalyType = 
  | 'time_anomaly'        // Unusual login time
  | 'location_anomaly'    // Unusual location/network
  | 'device_anomaly'      // Unusual device
  | 'frequency_anomaly'   // Unusual login frequency
  | 'credential_anomaly'  // Credential-related issues
  | 'attack_pattern';     // Attack pattern detected

// Example anomaly detection result
{
  anomalyDetected: true,
  anomalyScore: 75,
  anomalyTypes: ['time_anomaly', 'location_anomaly'],
  confidence: 85
}
```

#### 2. Behavior Pattern Analysis

The behavior analysis learns user patterns over time:

- **Typical Login Hours:** When the user normally logs in (0-23 UTC)
- **Typical Locations:** Countries and cities where user logs in
- **Typical Devices:** Device fingerprints the user commonly uses
- **Login Frequency:** How often the user logs in

```typescript
// Behavior analysis result
{
  isTypicalBehavior: false,
  behaviorDeviation: 2.5,  // Standard deviations from normal
  reasoning: "Login at unusual hour (3 AM) from new country"
}
```

#### 3. Risk Factor Correlation

The ML model correlates multiple risk signals to identify attack patterns:

```typescript
// Correlated risk factors
{
  correlatedFactors: [
    { factor: 'new_device', contribution: 30, correlation: 'Combined with VPN indicates potential account takeover' },
    { factor: 'vpn_detected', contribution: 25, correlation: 'VPN from datacenter IP' },
    { factor: 'failed_attempts', contribution: 20, correlation: 'Multiple failures before success' }
  ],
  primaryThreat: 'credential_stuffing',
  riskScore: 78
}
```

#### Privacy Protection (HIPAA/GDPR Compliant)

**CRITICAL:** No PII is ever sent to AWS Bedrock. All data is anonymized before ML processing:

```typescript
// Anonymized context sent to Bedrock (NO PII)
interface AnonymizedRiskContext {
  // Device signals (anonymized)
  deviceTrustScore: number;      // 0-100
  isNewDevice: boolean;
  
  // Geographic signals (no actual location)
  geoRiskScore: number;          // 0-100
  isVpn: boolean;
  isTor: boolean;
  
  // Behavioral signals
  loginHour: number;             // 0-23 UTC
  failedAttempts: number;
  
  // Account signals
  accountAgeDays: number;
  mfaEnabled: boolean;
  
  // NO: email, userId, ip, name, address, phone
}
```

#### Configuration

```typescript
// Bedrock configuration
const BEDROCK_CONFIG = {
  modelId: 'anthropic.claude-3-haiku-20240307-v1:0',
  region: 'us-east-1',
  maxTokens: 1000,
  temperature: 0.1,           // Low for consistent results
  timeoutMs: 5000,            // 5 second timeout
  rateLimitPerMinute: 100,    // Rate limit protection
  fallbackOnError: true       // Use rule-based on error
};
```

#### Fallback Behavior

When Bedrock is unavailable, Zalt automatically falls back to rule-based risk assessment:

1. **Bedrock Timeout:** Falls back after 5 seconds
2. **Rate Limit Exceeded:** Falls back when > 100 calls/minute
3. **API Error:** Falls back on any Bedrock API error
4. **Disabled:** Falls back when `BEDROCK_ENABLED=false`

#### Audit Logging

All Bedrock calls are audit logged (without PII):

```json
{
  "event_type": "bedrock_risk_analysis",
  "timestamp": "2026-01-25T10:00:00Z",
  "details": {
    "input_device_trust": 80,
    "input_geo_risk": 15,
    "input_is_tor": false,
    "output_risk_score": 25,
    "output_confidence": 85,
    "output_anomaly_detected": false,
    "model_id": "anthropic.claude-3-haiku-20240307-v1:0",
    "processing_time_ms": 150
  }
}
```

### Custom Risk Rules

Administrators can configure custom risk rules per realm to fine-tune AI risk assessment behavior. Custom rules support:

- **IP Whitelist**: Bypass or reduce risk for trusted IP addresses/ranges
- **Trusted Devices**: Reduce risk scores for pre-approved devices
- **Custom Thresholds**: Override default MFA and block thresholds

#### Configuration

Custom risk rules are configured in realm settings:

```typescript
// Realm settings with custom risk rules
{
  custom_risk_rules: {
    enabled: true,
    
    // IP Whitelist - Supports IPv4, IPv6, and CIDR notation
    ip_whitelist: [
      '10.0.0.0/8',           // Corporate network
      '192.168.1.0/24',       // Office subnet
      '203.0.113.1',          // VPN exit node
      '2001:db8::/32'         // IPv6 range
    ],
    
    // Trusted Devices - Pre-approved device fingerprints
    trusted_devices: [
      {
        fingerprint_hash: 'sha256-64-char-hash...',
        name: 'CEO MacBook Pro',
        added_at: '2025-01-15T10:00:00Z',
        added_by: 'admin_security_team',
        expires_at: '2026-01-15T10:00:00Z',
        active: true
      }
    ],
    
    // Custom Thresholds
    thresholds: {
      mfa_threshold: 50,      // Default: 70
      block_threshold: 80,    // Default: 90
      alert_threshold: 60     // Default: 75
    },
    
    // Score Reductions
    ip_whitelist_score_reduction: 100,    // 100 = complete bypass
    trusted_device_score_reduction: 30,   // Reduce score by 30 points
    
    // Audit Logging
    audit_enabled: true
  }
}
```

#### Healthcare Realm Configuration

For HIPAA-compliant healthcare realms, use stricter thresholds:

```typescript
{
  custom_risk_rules: {
    enabled: true,
    thresholds: {
      mfa_threshold: 50,      // Require MFA earlier
      block_threshold: 80,    // Block suspicious logins sooner
      alert_threshold: 60     // Alert security team earlier
    },
    trusted_device_score_reduction: 20,  // Less reduction for healthcare
    audit_enabled: true
  }
}
```

#### Rule Application Order

1. **IP Whitelist** (highest priority) - If IP matches, score is reduced/bypassed
2. **Trusted Device** - If device matches, additional score reduction applied
3. **Custom Thresholds** - Applied to final adjusted score

#### Audit Logging

When `audit_enabled: true`, all rule applications are logged:

```json
{
  "event_type": "custom_risk_rule_applied",
  "realm_id": "realm_xxx",
  "timestamp": "2025-01-25T10:30:00Z",
  "details": {
    "rule_type": "ip_whitelist",
    "ip": "192.168.1.50",
    "matched_entry": "192.168.1.0/24",
    "original_score": 75,
    "adjusted_score": 0,
    "bypassed": true
  }
}
```

> 📖 **Full Documentation**: See [Custom Risk Rules Configuration](/docs/configuration/risk-rules.md) for complete details.

### High-Risk Webhook

When a high-risk login is detected, Zalt triggers a webhook:

```json
{
  "type": "risk.high_score",
  "timestamp": "2026-01-25T10:00:00Z",
  "data": {
    "userId": "user_xxx",
    "email": "user@example.com",
    "riskScore": 85,
    "recommendation": "mfa_required",
    "factors": [
      { "type": "geo_velocity", "score": 95 },
      { "type": "ip_reputation", "score": 75 }
    ],
    "ip": "masked",
    "location": {
      "country": "XX",
      "city": "Unknown"
    }
  }
}
```

### Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 403 | `RISK_SCORE_TOO_HIGH` | Login blocked due to high risk |
| 403 | `MFA_REQUIRED_BY_RISK` | MFA required due to elevated risk |

### Privacy Considerations

- IP addresses are masked in logs and responses
- Geo-location data is anonymized
- Risk assessments are not stored long-term
- User behavior profiles are encrypted at rest

### Best Practices

1. **Monitor High-Risk Events:** Set up webhook alerts for risk scores > 70
2. **Review Blocked Logins:** Investigate blocked logins for false positives
3. **Whitelist Known IPs:** Add corporate IPs to whitelist to reduce friction
4. **Trust Known Devices:** Register trusted devices for frequent users
5. **Adjust Thresholds:** Fine-tune thresholds based on your security requirements

### Security Considerations

- Risk scores are deterministic for the same inputs (within ±5 tolerance)
- All risk assessments are audit logged
- No information leakage in error messages
- Rate limiting applies to all login attempts
- Risk assessment adds minimal latency (<100ms)

### AIRiskService API

The `AIRiskService` class provides programmatic access to risk assessment:

```typescript
import { AIRiskService, createAIRiskService } from '@zalt/auth';

// Create service instance for a realm
const riskService = createAIRiskService('my-realm');

// Assess login risk
const result = await riskService.assessLoginRisk({
  email: 'user@example.com',
  realmId: 'my-realm',
  ip: '192.168.1.1',
  userAgent: 'Mozilla/5.0...',
  deviceFingerprint: { /* fingerprint data */ },
  geoLocation: { latitude: 41.0, longitude: 28.9, city: 'Istanbul' },
  mfaEnabled: true,
  accountAge: 365
});

// Result includes:
// - riskScore: 0-100
// - riskLevel: 'low' | 'medium' | 'high' | 'critical'
// - requiresMfa: boolean
// - shouldBlock: boolean
// - riskFactors: array of detected risk factors
```

#### Service Methods

| Method | Description |
|--------|-------------|
| `assessLoginRisk(context)` | Calculate risk score (0-100) for a login attempt |
| `updateUserBehaviorProfile(userId, event)` | Learn user patterns over time |
| `detectImpossibleTravel(userId, location)` | Check for geo-velocity violations (>1000 km/h) |
| `checkIPReputation(ip)` | Get IP reputation score (0-100, higher is better) |
| `getDeviceTrustScore(fingerprint, userId)` | Get device trust score (0-100, higher is more trusted) |

#### IP Reputation Scoring

The `checkIPReputation` method evaluates IPs against multiple threat indicators:

```typescript
const score = await riskService.checkIPReputation('185.220.101.1');
// Returns: 0-100 (0 = malicious, 100 = clean)

// Detailed information
const details = await riskService.getIPReputationDetails('185.220.101.1');
// Returns: { score, isTor, isVpn, isProxy, isDatacenter, threatLevel }
```

**Threat Detection:**
- Tor exit nodes: -60 points
- VPN connections: -30 points
- Proxy servers: -25 points
- Datacenter IPs: -20 points
- Known malicious ASNs: -40 points

#### Device Trust Scoring

The `getDeviceTrustScore` method evaluates device trustworthiness:

```typescript
const score = await riskService.getDeviceTrustScore(fingerprint, userId);
// Returns: 0-100 (0 = untrusted, 100 = fully trusted)

// Detailed information
const details = await riskService.getDeviceTrustDetails(fingerprint, userId);
// Returns: { score, isKnownDevice, isNewDevice, trustLevel, lastSeen, loginCount }
```

**Trust Factors:**
- Fingerprint similarity: 0-40 points
- Login count from device: 0-30 points
- Device age: 0-20 points
- Trusted flag: 0-10 points

#### Behavior Profile Learning

The service learns user patterns to improve risk assessment accuracy:

```typescript
// Record successful login
await riskService.updateUserBehaviorProfile(userId, {
  type: 'login_success',
  timestamp: Date.now(),
  ip: '192.168.1.1',
  geoLocation: { countryCode: 'TR', city: 'Istanbul' },
  deviceFingerprint: 'fp_hash_123'
});

// Tracked patterns:
// - Typical login hours (0-23)
// - Typical countries
// - Typical devices
// - Login frequency
```

## Risk-Based Authentication

### Overview

Zalt.io integrates AI-powered risk assessment directly into the login flow. Every login attempt is evaluated in real-time, and the system automatically enforces additional security measures based on the calculated risk score.

**Task 15.4 Implementation - Requirements 10.3, 10.4, 10.10**

### Risk Score Thresholds

| Score Range | Action | Description |
|-------------|--------|-------------|
| 0-70 | Allow | Normal login flow proceeds |
| 71-90 | **Require MFA** | MFA required regardless of user settings |
| 91-100 | **Block Login** | Login blocked, admin notified |

### Login Flow Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                     Login Request                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Rate Limit Check                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Validate Request                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Find User                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              AI Risk Assessment (Task 15.4)                      │
│  • Calculate risk score (0-100)                                  │
│  • Evaluate: IP, device, geo, behavior, credentials              │
│  • Log assessment to audit log                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
        Score > 90      Score > 70      Score ≤ 70
              │               │               │
              ▼               ▼               ▼
        ┌─────────┐    ┌─────────────┐  ┌─────────────┐
        │  BLOCK  │    │ REQUIRE MFA │  │  CONTINUE   │
        │  LOGIN  │    │ (Regardless │  │   NORMAL    │
        │         │    │ of settings)│  │    FLOW     │
        └─────────┘    └─────────────┘  └─────────────┘
```

### Risk-Triggered MFA (Requirement 10.3)

When the risk score exceeds 70, MFA is required regardless of user settings:

```json
// Response when risk score > 70
{
  "message": "MFA verification required",
  "mfa_required": true,
  "mfa_session_id": "abc123...",
  "mfa_expires_in": 300,
  "allowed_methods": ["totp", "webauthn"],
  "risk_triggered": true,
  "risk_score": 75,
  "risk_level": "high",
  "user": {
    "id": "user_xxx",
    "email": "user@example.com"
  }
}
```

**Key Points:**
- `risk_triggered: true` indicates MFA was required due to risk assessment
- User must complete MFA even if they haven't enabled it
- All MFA methods are available (TOTP, WebAuthn)
- Risk score and level are included for transparency

### Login Blocking (Requirement 10.4)

When the risk score exceeds 90, the login is blocked immediately:

```json
// Response when risk score > 90
{
  "error": {
    "code": "RISK_SCORE_TOO_HIGH",
    "message": "Login blocked due to security concerns. Please contact support.",
    "timestamp": "2026-01-25T10:00:00Z"
  }
}
```

**Security Considerations:**
- Generic error message prevents information leakage
- No risk details exposed in response
- Full details logged for admin review
- Admin notification triggered via security events

### Audit Logging (Requirement 10.10)

All login attempts include risk assessment in the audit log:

```json
// Risk assessment logged for every login attempt
{
  "event_type": "risk_assessment",
  "timestamp": "2026-01-25T10:00:00Z",
  "realm_id": "realm_xxx",
  "user_id": "user_xxx",
  "ip_address": "masked",
  "details": {
    "risk_score": 75,
    "risk_level": "high",
    "recommendation": "mfa",
    "requires_mfa": true,
    "should_block": false,
    "risk_factors": [
      { "type": "new_device", "severity": "medium", "score": 40 },
      { "type": "vpn_detected", "severity": "medium", "score": 30 }
    ],
    "assessment_id": "risk_abc123"
  }
}

// Successful login includes risk score
{
  "event_type": "login_success",
  "timestamp": "2026-01-25T10:00:05Z",
  "realm_id": "realm_xxx",
  "user_id": "user_xxx",
  "details": {
    "risk_score": 25,
    "risk_level": "low",
    "user_agent": "masked",
    "device_fingerprint": "provided"
  }
}

// Blocked login logged with full details
{
  "event_type": "login_blocked_high_risk",
  "timestamp": "2026-01-25T10:00:00Z",
  "realm_id": "realm_xxx",
  "user_id": "user_xxx",
  "details": {
    "risk_score": 95,
    "risk_level": "critical",
    "blocked_reason": "risk_score_exceeded_threshold",
    "threshold": 90,
    "risk_factors": [
      { "type": "tor_detected", "severity": "critical", "description": "Tor exit node detected" },
      { "type": "impossible_travel", "severity": "critical", "description": "Impossible travel detected" }
    ]
  }
}
```

### Graceful Error Handling

The risk assessment system is designed to fail open with logging:

```typescript
// If risk assessment fails, login continues with logging
try {
  riskAssessment = await riskService.assessLoginRisk(context);
} catch (error) {
  // Log the error
  await logSecurityEvent({
    event_type: 'risk_assessment_error',
    details: { error: error.message, fail_open: true }
  });
  // Continue with login (fail open)
}
```

**Why Fail Open?**
- Availability is critical for authentication
- Bedrock/ML service outages shouldn't block all logins
- All failures are logged for monitoring
- Administrators can review and take action

### Configuration

Risk thresholds can be configured per realm:

```typescript
// Default configuration
const RISK_ASSESSMENT_CONFIG = {
  mfaRequiredThreshold: 70,  // Score > 70: Require MFA
  blockThreshold: 90,        // Score > 90: Block login
  failOpenOnError: true      // Continue on assessment failure
};

// Healthcare realm (stricter)
const HEALTHCARE_RISK_CONFIG = {
  mfaRequiredThreshold: 50,  // Lower threshold for healthcare
  blockThreshold: 80,        // Block earlier
  failOpenOnError: false     // Fail closed for healthcare
};
```

### Best Practices

1. **Monitor Risk Events:** Set up alerts for `login_blocked_high_risk` events
2. **Review Blocked Logins:** Investigate blocked logins for false positives
3. **Whitelist Known IPs:** Add corporate IPs to reduce friction
4. **Trust Known Devices:** Register trusted devices for frequent users
5. **Adjust Thresholds:** Fine-tune thresholds based on your security requirements

### Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 403 | `RISK_SCORE_TOO_HIGH` | Login blocked due to critical risk |
| 200 | (with `mfa_required: true`) | MFA required due to elevated risk |

## Audit Logging

All security events are logged:

- Login attempts (success/failure)
- MFA setup/verification
- Password changes
- Session creation/termination
- Admin actions
- API access patterns

Logs are retained for 90 days (configurable per compliance requirements).

## Incident Response

### Reporting Security Issues

Email: security@zalt.io

We follow responsible disclosure and will:
1. Acknowledge within 24 hours
2. Provide initial assessment within 72 hours
3. Keep you informed of remediation progress

### Bug Bounty

Coming soon - contact security@zalt.io for details.

## Security Checklist for Customers

- [ ] Use HTTPS everywhere
- [ ] Enable MFA for all users (required for healthcare)
- [ ] Implement proper token storage
- [ ] Set up session timeout handling
- [ ] Configure allowed origins in realm settings
- [ ] Review audit logs regularly
- [ ] Keep SDK updated


## User Impersonation Security

### Overview

User Impersonation allows administrators to log in as a user for debugging and support purposes. This is a powerful feature that requires strict security controls to prevent abuse.

**Task 11 Implementation - Requirements 6.1-6.10**

### Security Controls

| Control | Description |
|---------|-------------|
| **Permission Required** | Only users with `admin:impersonate` permission |
| **Reason Required** | Must provide reason (audit logged) |
| **Time-Limited** | Maximum 1 hour (configurable, max 2 hours) |
| **Restricted Actions** | Cannot change password, delete account, disable MFA |
| **Full Audit Trail** | All actions during impersonation are logged |
| **Visual Indicator** | SDK shows impersonation banner to user |

### Impersonation Restrictions

During impersonation, the following actions are **blocked**:

| Action | Reason |
|--------|--------|
| Change Password | Prevents admin from locking out user |
| Delete Account | Prevents irreversible damage |
| Disable MFA | Prevents security downgrade |
| Change Email | Prevents account takeover |
| Revoke All Sessions | Prevents disruption |
| Access Billing | Prevents financial actions |

### Token Structure

Impersonation tokens include special claims for identification:

```json
{
  "sub": "user_target",
  "type": "impersonation",
  "impersonator_id": "user_admin",
  "impersonation_session_id": "imp_abc123",
  "restrictions": ["no_password_change", "no_delete_account", "no_mfa_disable"],
  "exp": 1704070800,
  "iat": 1704067200
}
```

### Audit Events

All impersonation events are logged for compliance:

| Event | Description |
|-------|-------------|
| `impersonation.started` | Admin started impersonation session |
| `impersonation.ended` | Impersonation session ended (manual or timeout) |
| `impersonation.expired` | Session expired automatically |
| `impersonation.action_blocked` | Restricted action was attempted |
| `impersonation.action` | Any action performed during impersonation |

### Audit Log Format

```json
{
  "event_type": "impersonation.started",
  "timestamp": "2026-01-25T10:00:00Z",
  "realm_id": "realm_xxx",
  "details": {
    "session_id": "imp_abc123",
    "admin_id": "user_admin",
    "admin_email": "admin@example.com",
    "target_user_id": "user_target",
    "target_user_email": "user@example.com",
    "reason": "Debugging login issue reported in ticket #1234",
    "duration_minutes": 60,
    "ip_address": "masked"
  }
}
```

### Best Practices

1. **Require Reason**: Always require a detailed reason (e.g., ticket number)
2. **Minimize Duration**: Use shortest duration needed
3. **Review Logs**: Regularly audit impersonation sessions
4. **Limit Permissions**: Only grant `admin:impersonate` to trusted admins
5. **Notify Users**: Consider notifying users when impersonation occurs
6. **Healthcare Compliance**: For HIPAA realms, require additional approval

### Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 403 | `IMPERSONATION_RESTRICTED` | Action blocked during impersonation |
| 403 | `IMPERSONATION_NOT_ALLOWED` | User cannot be impersonated (e.g., another admin) |
| 403 | `IMPERSONATION_PERMISSION_DENIED` | Admin lacks `admin:impersonate` permission |

### SDK Integration

The SDK provides automatic impersonation detection:

```typescript
import { useImpersonation, ImpersonationBanner } from '@zalt/react';

function App() {
  const { isImpersonating, session, endImpersonation } = useImpersonation();
  
  return (
    <>
      {isImpersonating && (
        <ImpersonationBanner
          adminEmail={session.admin_email}
          targetEmail={session.target_user_email}
          expiresAt={session.expires_at}
          onEnd={endImpersonation}
        />
      )}
      <MainApp />
    </>
  );
}
```

### Middleware Usage

```typescript
import { impersonationMiddleware } from '@zalt/middleware';

// Check if action is restricted during impersonation
const result = await impersonationMiddleware(event, {
  restrictedActions: ['password_change', 'account_delete', 'mfa_disable']
});

if (!result.allowed) {
  return {
    statusCode: 403,
    body: JSON.stringify({
      error: {
        code: 'IMPERSONATION_RESTRICTED',
        message: 'This action is not allowed during impersonation'
      }
    })
  };
}
```

