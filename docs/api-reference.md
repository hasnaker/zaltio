# Zalt.io API Reference

Base URL: `https://api.zalt.io`

## Authentication

All authenticated endpoints require a Bearer token:

```
Authorization: Bearer <access_token>
```

## Response Format

All responses follow this structure:

```json
// Success
{
  "message": "Operation successful",
  "data": { ... }
}

// Error
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "request_id": "uuid"
  }
}
```

---

## Core Authentication

### Register User

Creates a new user account.

```
POST /register
```

**Request Body:**
```json
{
  "realm_id": "string (required)",
  "email": "string (required)",
  "password": "string (required, min 12 chars)",
  "profile": {
    "first_name": "string",
    "last_name": "string",
    "metadata": {}
  }
}
```

**Response:** `201 Created`
```json
{
  "message": "User registered successfully. Please check your email to verify your account.",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": false,
    "created_at": "2026-01-16T00:00:00Z"
  }
}
```

**Errors:**
- `400` - Invalid input / Password too weak / Password compromised
- `409` - Email already registered
- `429` - Rate limit exceeded (3/hour/IP)

**PASSWORD_COMPROMISED Error Response:** `400 Bad Request`

When the password is found in the HaveIBeenPwned breach database:

```json
{
  "error": {
    "code": "PASSWORD_COMPROMISED",
    "message": "This password has been found in data breaches. Please choose a different password.",
    "timestamp": "2026-01-25T10:00:00Z",
    "request_id": "uuid"
  },
  "details": {
    "breach_count": 3861493,
    "recommendation": "Use a unique password with at least 12 characters"
  }
}
```

> **Security Note:** Passwords are checked against the HaveIBeenPwned API using k-Anonymity. Only the first 5 characters of the SHA-1 hash are sent to the API, ensuring your password is never transmitted in full.

---

### Login

Authenticates a user and returns tokens.

```
POST /login
```

**Request Body:**
```json
{
  "realm_id": "string (required)",
  "email": "string (required)",
  "password": "string (required)"
}
```

**Response:** `200 OK`
```json
{
  "message": "Login successful",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": true,
    "profile": {},
    "mfa_enabled": false
  },
  "tokens": {
    "access_token": "eyJhbG...",
    "refresh_token": "eyJhbG...",
    "expires_in": 900
  }
}
```

**Response with Session Tasks:** `200 OK`

When the user has pending session tasks (e.g., password reset required, MFA setup required, organization selection needed), the response includes a `session_tasks` array:

```json
{
  "message": "Login successful - action required",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": true,
    "profile": {},
    "mfa_enabled": false
  },
  "tokens": {
    "access_token": "eyJhbG...",
    "refresh_token": "eyJhbG...",
    "expires_in": 900
  },
  "session_tasks": [
    {
      "id": "task_xxx",
      "session_id": "session_xxx",
      "type": "reset_password",
      "status": "pending",
      "metadata": {
        "reason": "compromised",
        "message": "Your password has been found in a data breach. Please reset it immediately."
      },
      "priority": 1,
      "blocking": true,
      "created_at": "2026-01-25T10:00:00Z"
    }
  ],
  "has_blocking_tasks": true
}
```

**Session Task Types:**
- `reset_password` - User must reset their password (compromised or expired)
- `setup_mfa` - User must set up MFA (required by realm policy)
- `choose_organization` - User must select an organization (multiple memberships)
- `accept_terms` - User must accept updated terms of service
- `custom` - Custom task defined via webhook

**Session Task Conditions:**
| Task Type | Condition |
|-----------|-----------|
| `reset_password` | Password marked as compromised or expired |
| `setup_mfa` | Realm MFA policy is "required" AND user has no MFA enabled |
| `choose_organization` | User belongs to multiple organizations AND no default selected |
| `accept_terms` | Realm has updated terms AND user hasn't accepted current version |

> **Note:** When `has_blocking_tasks` is `true`, API access is blocked until all blocking tasks are completed. See [Session Tasks](#session-tasks-post-login-requirements) for task completion endpoints.

**MFA Required Response:** `200 OK`
```json
{
  "mfa_required": true,
  "mfa_session_id": "uuid",
  "mfa_methods": ["totp", "webauthn"],
  "expires_in": 300
}
```

**Errors:**
- `401` - Invalid credentials
- `403` - Account locked
- `429` - Rate limit exceeded (5/15min/IP)

---

### Refresh Token

Exchanges a refresh token for new tokens.

```
POST /refresh
```

**Request Body:**
```json
{
  "refresh_token": "string (required)"
}
```

**Response:** `200 OK`
```json
{
  "tokens": {
    "access_token": "eyJhbG...",
    "refresh_token": "eyJhbG...",
    "expires_in": 900
  }
}
```

---

### Logout

Invalidates the current session.

```
POST /logout
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Logged out successfully"
}
```

---

## MFA (Multi-Factor Authentication)

### Setup MFA

Initiates TOTP MFA setup.

```
POST /v1/auth/mfa/setup
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "secret": "BASE32_SECRET",
  "otpauth_url": "otpauth://totp/Zalt.io:user@example.com?secret=...",
  "message": "Scan the QR code with your authenticator app"
}
```

---

### Verify MFA Setup

Confirms MFA setup with a code from authenticator.

```
POST /v1/auth/mfa/verify
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "code": "123456",
  "secret": "BASE32_SECRET"
}
```

**Response:** `200 OK`
```json
{
  "message": "MFA enabled successfully",
  "backup_codes": ["code1", "code2", "..."]
}
```

---

### Verify MFA Login

Completes login when MFA is required.

```
POST /v1/auth/mfa/login/verify
```

**Request Body:**
```json
{
  "mfa_session_id": "uuid",
  "code": "123456"
}
```

**Response:** `200 OK`
```json
{
  "user": { ... },
  "tokens": {
    "access_token": "...",
    "refresh_token": "...",
    "expires_in": 900
  }
}
```

---

### Disable MFA

```
POST /v1/auth/mfa/disable
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "code": "123456"
}
```

---

## WebAuthn (Passkeys)

### Get Registration Options

```
POST /v1/auth/webauthn/register/options
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "options": {
    "challenge": "base64url",
    "rp": {"name": "Zalt.io", "id": "zalt.io"},
    "user": {"id": "base64", "name": "email", "displayName": "name"},
    "pubKeyCredParams": [{"alg": -7, "type": "public-key"}],
    "timeout": 60000,
    "attestation": "none"
  },
  "expires_in": 300
}
```

---

### Register Credential

```
POST /v1/auth/webauthn/register
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "credential": {
    "id": "base64url",
    "rawId": "base64url",
    "response": {
      "clientDataJSON": "base64url",
      "attestationObject": "base64url"
    },
    "type": "public-key"
  },
  "name": "My MacBook"
}
```

---

### Get Authentication Options

```
POST /v1/auth/webauthn/authenticate/options
```

**Request Body:**
```json
{
  "realm_id": "string",
  "email": "user@example.com"
}
```

---

### Authenticate with WebAuthn

```
POST /v1/auth/webauthn/authenticate
```

**Request Body:**
```json
{
  "realm_id": "string",
  "email": "user@example.com",
  "credential": {
    "id": "base64url",
    "rawId": "base64url",
    "response": {
      "clientDataJSON": "base64url",
      "authenticatorData": "base64url",
      "signature": "base64url"
    },
    "type": "public-key"
  }
}
```

---

### List Credentials

```
GET /v1/auth/webauthn/credentials
Authorization: Bearer <access_token>
```

---

### Delete Credential

```
DELETE /v1/auth/webauthn/credentials/{credential_id}
Authorization: Bearer <access_token>
```

---

## Password Management

### Request Password Reset

```
POST /v1/auth/password-reset/request
```

**Request Body:**
```json
{
  "realm_id": "string",
  "email": "user@example.com"
}
```

**Response:** `200 OK` (always, to prevent email enumeration)
```json
{
  "message": "If the email exists, a reset link has been sent"
}
```

---

### Confirm Password Reset

```
POST /v1/auth/password-reset/confirm
```

**Request Body:**
```json
{
  "token": "reset_token_from_email",
  "new_password": "NewSecurePassword123!"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password has been reset successfully. Please log in with your new password.",
  "sessions_invalidated": true
}
```

**Errors:**
- `400` - Invalid token / Token expired / Weak password / Password compromised
- `429` - Rate limit exceeded

**PASSWORD_COMPROMISED Error Response:** `400 Bad Request`

When the new password is found in the HaveIBeenPwned breach database:

```json
{
  "error": {
    "code": "PASSWORD_COMPROMISED",
    "message": "This password has been found in data breaches. Please choose a different password.",
    "timestamp": "2026-01-25T10:00:00Z",
    "request_id": "uuid"
  },
  "details": {
    "breach_count": 3861493,
    "recommendation": "Use a unique password with at least 12 characters"
  }
}
```

> **Security Note:** All existing sessions are invalidated when password is reset successfully.

---

## Email Verification

### Send Verification Email

```
POST /v1/auth/verify-email/send
Authorization: Bearer <access_token>
```

---

### Verify Email

```
POST /v1/auth/verify-email/confirm
```

**Request Body:**
```json
{
  "token": "verification_token_from_email"
}
```

---

## User Profile

### Get Current User

```
GET /me
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": true,
    "profile": {
      "first_name": "John",
      "last_name": "Doe",
      "metadata": {}
    },
    "mfa_enabled": true,
    "created_at": "2026-01-16T00:00:00Z"
  }
}
```

---

## Health Check

```
GET /health/ready
```

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-01-16T00:00:00Z"
}
```

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/login` | 5 requests / 15 min / IP |
| `/register` | 3 requests / hour / IP |
| `/password-reset/request` | 3 requests / hour / email |
| `/mfa/*/verify` | 5 requests / min / user |
| General API | 100 requests / min / user |

---

## Error Codes

| Code | Description |
|------|-------------|
| `INVALID_CREDENTIALS` | Wrong email or password |
| `ACCOUNT_LOCKED` | Too many failed attempts |
| `MFA_REQUIRED` | MFA verification needed |
| `TOKEN_EXPIRED` | Access token expired |
| `TOKEN_INVALID` | Invalid or malformed token |
| `RATE_LIMITED` | Too many requests |
| `PASSWORD_COMPROMISED` | Password found in breaches |
| `VALIDATION_ERROR` | Invalid request body |

---

## Machine Authentication (M2M)

Machine-to-Machine authentication allows backend services to authenticate without user context for service-to-service communication.

### Create Machine

Creates a new machine for M2M authentication.

```
POST /machines
Authorization: Bearer <admin_access_token>
```

**Request Body:**
```json
{
  "realm_id": "string (required)",
  "name": "string (required)",
  "description": "string (optional)",
  "scopes": ["read:users", "write:sessions"],
  "allowed_targets": ["machine_xxx"],
  "rate_limit": 1000,
  "allowed_ips": ["10.0.0.0/8"]
}
```

**Response:** `201 Created`
```json
{
  "message": "Machine created successfully",
  "machine": {
    "id": "machine_xxx",
    "realm_id": "realm_xxx",
    "name": "Backend Service",
    "client_id": "zalt_m2m_xxx",
    "scopes": ["read:users", "write:sessions"],
    "allowed_targets": [],
    "status": "active",
    "created_at": "2026-01-01T00:00:00Z"
  },
  "client_secret": "xxx (shown only once)"
}
```

**Note:** The `client_secret` is only returned once during creation. Store it securely.

---

### Get M2M Token

Authenticates a machine and returns an M2M token.

```
POST /machines/token
Content-Type: application/x-www-form-urlencoded
```

**Request Body:**
```
grant_type=client_credentials
client_id=zalt_m2m_xxx
client_secret=xxx
scope=read:users write:sessions
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:users write:sessions"
}
```

**Errors:**
- `401` - Invalid client credentials
- `403` - Machine disabled
- `400` - Invalid scope requested

---

### List Machines

Lists all machines in a realm.

```
GET /machines?realm_id=xxx
Authorization: Bearer <admin_access_token>
```

**Response:** `200 OK`
```json
{
  "machines": [
    {
      "id": "machine_xxx",
      "name": "Backend Service",
      "client_id": "zalt_m2m_xxx",
      "scopes": ["read:users"],
      "status": "active",
      "last_used_at": "2026-01-01T00:00:00Z"
    }
  ]
}
```

---

### Delete Machine

Soft deletes a machine (sets status to deleted).

```
DELETE /machines/{machine_id}
Authorization: Bearer <admin_access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Machine deleted successfully"
}
```

---

### Rotate Credentials

Generates new client credentials for a machine.

```
POST /machines/{machine_id}/rotate
Authorization: Bearer <admin_access_token>
```

**Response:** `200 OK`
```json
{
  "client_id": "zalt_m2m_xxx",
  "client_secret": "new_secret (shown only once)"
}
```

**Note:** Old credentials are immediately invalidated.

---

### M2M Scopes

| Scope | Description |
|-------|-------------|
| `read:users` | Read user information |
| `write:users` | Create and update users |
| `delete:users` | Delete users |
| `read:sessions` | Read session information |
| `write:sessions` | Create and manage sessions |
| `revoke:sessions` | Revoke user sessions |
| `read:tenants` | Read tenant information |
| `write:tenants` | Create and update tenants |
| `read:roles` | Read role information |
| `write:roles` | Create and update roles |
| `read:audit` | Read audit logs |
| `read:webhooks` | Read webhook configurations |
| `write:webhooks` | Manage webhooks |
| `read:analytics` | Read analytics data |
| `admin:all` | Full administrative access |

---

### M2M Token Claims

```json
{
  "machine_id": "machine_xxx",
  "realm_id": "realm_xxx",
  "scopes": ["read:users", "write:sessions"],
  "target_machines": [],
  "type": "m2m",
  "iat": 1704067200,
  "exp": 1704070800,
  "iss": "https://api.zalt.io",
  "jti": "unique_token_id"
}
```

---

### DynamoDB Schema: zalt-machines

| Attribute | Type | Description |
|-----------|------|-------------|
| pk | String | `REALM#{realm_id}#MACHINE#{machine_id}` |
| sk | String | `MACHINE` |
| id | String | Machine ID (machine_xxx) |
| realm_id | String | Realm ID |
| name | String | Human-readable name |
| client_id | String | Public identifier (zalt_m2m_xxx) |
| client_secret_hash | String | Argon2id hashed secret |
| scopes | List | Allowed scopes |
| allowed_targets | List | Target machine IDs |
| status | String | active, disabled, deleted |
| created_at | String | ISO timestamp |
| updated_at | String | ISO timestamp |
| last_used_at | String | ISO timestamp |

**GSI: client-id-index**
- Partition Key: `client_id`
- Enables lookup by client ID for authentication

**GSI: realm-index**
- Partition Key: `realm_id`
- Enables listing all machines in a realm

---

## User-Generated API Keys

User API keys allow end users to create their own API keys for programmatic access. These keys inherit the user's permissions and tenant context.

### Create API Key

Creates a new API key for the authenticated user.

```
POST /api-keys
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "name": "string (required)",
  "description": "string (optional)",
  "scopes": ["profile:read", "sessions:read"],
  "expires_at": "2026-12-31T23:59:59Z",
  "ip_restrictions": ["192.168.1.0/24"]
}
```

**Response:** `201 Created`
```json
{
  "message": "API key created successfully",
  "key": {
    "id": "key_xxx",
    "name": "My API Key",
    "key_prefix": "zalt_key_ABC...",
    "scopes": ["profile:read", "sessions:read"],
    "status": "active",
    "created_at": "2026-01-01T00:00:00Z"
  },
  "full_key": "zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
}
```

**Note:** The `full_key` is only returned once during creation. Store it securely.

---

### List API Keys

Lists all API keys for the authenticated user.

```
GET /api-keys
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "keys": [
    {
      "id": "key_xxx",
      "name": "My API Key",
      "key_prefix": "zalt_key_ABC...",
      "scopes": ["profile:read"],
      "status": "active",
      "last_used_at": "2026-01-15T10:00:00Z",
      "usage_count": 42,
      "created_at": "2026-01-01T00:00:00Z"
    }
  ]
}
```

---

### Revoke API Key

Revokes an API key (cannot be undone).

```
DELETE /api-keys/{key_id}
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "message": "API key revoked successfully"
}
```

---

### Using API Keys

API keys can be used instead of Bearer tokens for API authentication:

```
Authorization: Bearer zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef
```

The request will execute with the key owner's permissions, limited by the key's scopes.

---

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

---

### DynamoDB Schema: zalt-user-api-keys

| Attribute | Type | Description |
|-----------|------|-------------|
| pk | String | `USER#{user_id}#KEY#{key_id}` |
| sk | String | `KEY` |
| id | String | Key ID (key_xxx) |
| user_id | String | Owner user ID |
| realm_id | String | Realm ID |
| tenant_id | String | Optional tenant context |
| name | String | User-friendly name |
| key_prefix | String | Display prefix (zalt_key_xxx...) |
| key_hash | String | SHA-256 hash for lookup |
| scopes | List | Allowed scopes |
| status | String | active, revoked, expired |
| expires_at | String | Optional expiration |
| last_used_at | String | Last usage timestamp |
| usage_count | Number | Total usage count |

**GSI: key-hash-index**
- Partition Key: `key_hash`
- Enables lookup by key hash for validation

**GSI: user-index**
- Partition Key: `user_id`
- Enables listing all keys for a user


---

## Reverification (Step-Up Authentication)

Reverification provides step-up authentication for sensitive operations. When an endpoint requires reverification, users must re-authenticate even if they have a valid session.

### Reverification Levels

| Level | Description | Validity |
|-------|-------------|----------|
| `password` | Re-enter password | 10 minutes |
| `mfa` | Verify with TOTP/backup code | 15 minutes |
| `webauthn` | Verify with WebAuthn (highest) | 30 minutes |

**Note:** Higher levels satisfy lower level requirements. For example, `webauthn` verification satisfies `mfa` and `password` requirements.

---

### Verify with Password

Re-authenticates the user with their password.

```
POST /reverify/password
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "password": "string (required)"
}
```

**Response:** `200 OK`
```json
{
  "message": "Reverification successful",
  "reverification": {
    "level": "password",
    "verified_at": "2026-01-16T10:00:00Z",
    "expires_at": "2026-01-16T10:10:00Z"
  }
}
```

**Errors:**
- `400` - Missing password
- `401` - Invalid credentials
- `429` - Rate limit exceeded (5/min/user)

---

### Verify with MFA

Re-authenticates the user with their MFA code (TOTP or backup code).

```
POST /reverify/mfa
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "code": "123456"
}
```

**Response:** `200 OK`
```json
{
  "message": "Reverification successful",
  "reverification": {
    "level": "mfa",
    "verified_at": "2026-01-16T10:00:00Z",
    "expires_at": "2026-01-16T10:15:00Z"
  },
  "used_backup_code": false
}
```

**Errors:**
- `400` - Missing code / Invalid code format / MFA not enabled
- `401` - Invalid MFA code
- `429` - Rate limit exceeded (5/min/user)

---

### Verify with WebAuthn

Re-authenticates the user with their WebAuthn credential (passkey).

```
POST /reverify/webauthn
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "credential": {
    "id": "base64url",
    "rawId": "base64url",
    "response": {
      "clientDataJSON": "base64url",
      "authenticatorData": "base64url",
      "signature": "base64url"
    },
    "type": "public-key"
  },
  "challenge": "base64url"
}
```

**Response:** `200 OK`
```json
{
  "message": "Reverification successful",
  "reverification": {
    "level": "webauthn",
    "verified_at": "2026-01-16T10:00:00Z",
    "expires_at": "2026-01-16T10:30:00Z"
  }
}
```

**Errors:**
- `400` - Missing credential/challenge / Invalid format / WebAuthn not configured
- `401` - Invalid WebAuthn assertion
- `429` - Rate limit exceeded (5/min/user)

---

### Check Reverification Status

Checks the current reverification status for the session.

```
GET /reverify/status
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `level` (optional): Check if current reverification satisfies this level (`password`, `mfa`, `webauthn`)

**Response:** `200 OK`
```json
{
  "has_reverification": true,
  "is_valid": true,
  "reverification": {
    "level": "mfa",
    "verified_at": "2026-01-16T10:00:00Z",
    "expires_at": "2026-01-16T10:15:00Z",
    "method": "totp"
  },
  "required_level": "password",
  "satisfies_required": true
}
```

**Response (no reverification):**
```json
{
  "has_reverification": false,
  "is_valid": false,
  "reverification": null,
  "required_level": null,
  "satisfies_required": null
}
```

**Errors:**
- `400` - Invalid level parameter
- `401` - Authentication required

---

### Reverification Required Response

When an endpoint requires reverification and the session is not verified, the API returns:

```json
{
  "error": {
    "code": "REVERIFICATION_REQUIRED",
    "message": "This action requires reverification",
    "required_level": "mfa"
  }
}
```

**HTTP Status:** `403 Forbidden`

---

### Endpoints Requiring Reverification

| Endpoint | Method | Required Level |
|----------|--------|----------------|
| `/me/password` | PUT | password |
| `/me/email` | PUT | password |
| `/me/delete` | DELETE | mfa |
| `/mfa/disable` | POST | mfa |
| `/mfa/recovery-codes` | POST | mfa |
| `/api-keys` | POST | password |
| `/api-keys/*` | DELETE | password |
| `/sessions` | DELETE | password |
| `/organizations/*/members/*/remove` | POST | mfa |
| `/organizations/*/delete` | DELETE | webauthn |
| `/billing/cancel` | POST | mfa |
| `/billing/payment-method` | PUT | password |

---

### SDK Integration

The SDK provides automatic reverification handling:

```typescript
import { useReverification } from '@zalt/react';

function DeleteAccountButton() {
  const { reverify, isReverifying } = useReverification();
  
  const handleDelete = async () => {
    try {
      await api.deleteAccount();
    } catch (error) {
      if (error.code === 'REVERIFICATION_REQUIRED') {
        // SDK automatically shows reverification modal
        const verified = await reverify(error.required_level);
        if (verified) {
          // Retry the original request
          await api.deleteAccount();
        }
      }
    }
  };
  
  return (
    <button onClick={handleDelete} disabled={isReverifying}>
      Delete Account
    </button>
  );
}
```

---

### Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/reverify/password` | 5 requests / min / user |
| `/reverify/mfa` | 5 requests / min / user |
| `/reverify/webauthn` | 5 requests / min / user |
| `/reverify/status` | 100 requests / min / user |


---

## Session Tasks (Post-Login Requirements)

Session Tasks are mandatory actions that users must complete after login before they can access the application. These tasks enforce security policies and compliance requirements.

### Task Types

| Type | Description | Blocking | Priority |
|------|-------------|----------|----------|
| `reset_password` | User must reset their password (compromised/expired) | Yes | 1 (Highest) |
| `setup_mfa` | User must set up MFA (required by policy) | Yes | 2 |
| `accept_terms` | User must accept terms of service | Yes | 3 |
| `choose_organization` | User must select an organization (multi-org) | Yes | 4 |
| `custom` | Custom task type via webhook | No (default) | 5 (Lowest) |

**Note:** Blocking tasks prevent API access until completed. Priority determines the order in which tasks should be completed (lower number = higher priority).

---

### Get Pending Tasks

Returns all pending session tasks for the current session.

```
GET /session/tasks
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "tasks": [
    {
      "id": "task_xxx",
      "session_id": "session_xxx",
      "type": "reset_password",
      "status": "pending",
      "metadata": {
        "reason": "compromised",
        "message": "Your password was found in a data breach"
      },
      "created_at": "2026-01-16T10:00:00Z",
      "priority": 1,
      "blocking": true
    },
    {
      "id": "task_yyy",
      "session_id": "session_xxx",
      "type": "setup_mfa",
      "status": "pending",
      "metadata": {
        "required_mfa_methods": ["totp", "webauthn"],
        "mfa_policy_id": "policy_xxx"
      },
      "created_at": "2026-01-16T10:00:00Z",
      "priority": 2,
      "blocking": true
    }
  ],
  "has_blocking_tasks": true
}
```

---

### Complete Task

Marks a session task as completed.

```
POST /session/tasks/{task_id}/complete
Authorization: Bearer <access_token>
```

**Request Body (varies by task type):**

For `reset_password`:
```json
{
  "new_password": "NewSecurePassword123!"
}
```

For `setup_mfa`:
```json
{
  "mfa_method": "totp",
  "verification_code": "123456"
}
```

For `choose_organization`:
```json
{
  "organization_id": "org_xxx"
}
```

For `accept_terms`:
```json
{
  "accepted": true,
  "terms_version": "2.0"
}
```

**Response:** `200 OK`
```json
{
  "message": "Task completed successfully",
  "task": {
    "id": "task_xxx",
    "type": "reset_password",
    "status": "completed",
    "completed_at": "2026-01-16T10:05:00Z"
  },
  "remaining_tasks": 1
}
```

**Errors:**
- `400` - Invalid completion data
- `404` - Task not found
- `409` - Task already completed

---

### Skip Task (Non-Blocking Only)

Skips a non-blocking session task.

```
POST /session/tasks/{task_id}/skip
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Task skipped",
  "task": {
    "id": "task_xxx",
    "type": "custom",
    "status": "skipped",
    "completed_at": "2026-01-16T10:05:00Z"
  }
}
```

**Errors:**
- `400` - Cannot skip blocking tasks
- `404` - Task not found

---

### Admin: Force Password Reset

Forces a password reset for a specific user.

```
POST /admin/users/{user_id}/force-password-reset
Authorization: Bearer <admin_access_token>
```

**Request Body:**
```json
{
  "reason": "compromised",
  "revoke_sessions": true,
  "notify_user": true
}
```

**Response:** `200 OK`
```json
{
  "message": "Password reset forced",
  "user_id": "user_xxx",
  "sessions_revoked": 3,
  "task_created": true
}
```

---

### Admin: Mark Password Compromised

Marks a specific user's password as compromised. Creates a `reset_password` session task and optionally revokes all sessions.

**Validates:** Requirements 8.3, 8.5, 8.6

```
POST /v1/admin/users/{user_id}/mark-password-compromised
Authorization: Bearer <admin_access_token>
```

**Request Body:**
```json
{
  "reason": "Security incident - credential leak detected",
  "revoke_sessions": true,
  "notify_user": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | No | Reason for marking password as compromised |
| `revoke_sessions` | boolean | No | Whether to revoke all user sessions (default: false) |
| `notify_user` | boolean | No | Whether to send security alert email (default: true) |

**Response:** `200 OK`
```json
{
  "data": {
    "success": true,
    "message": "Password marked as compromised. User must reset password on next login.",
    "affected_users": 1,
    "sessions_revoked": 5,
    "task_created": true,
    "user_notified": true
  }
}
```

**Errors:**
- `400` - Invalid request or JSON body
- `401` - Unauthorized (admin privileges required)
- `404` - User not found
- `429` - Rate limited

---

### Admin: Mark All Passwords Compromised (Security Incident)

Marks all passwords in a realm as compromised. Used for security incident response (e.g., potential breach). Creates `reset_password` session tasks for all users.

**Validates:** Requirements 8.4, 8.5, 8.6

```
POST /v1/admin/realm/mark-all-passwords-compromised
Authorization: Bearer <admin_access_token>
```

**Request Body:**
```json
{
  "reason": "Security incident - potential breach",
  "revoke_sessions": true,
  "confirm": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | No | Reason for mass password compromise (default: "Security incident: All passwords must be reset") |
| `revoke_sessions` | boolean | No | Whether to revoke all sessions for all users (default: false) |
| `confirm` | boolean | **Yes** | Must be `true` to confirm this critical operation |

**Response:** `200 OK`
```json
{
  "data": {
    "success": true,
    "message": "All passwords marked as compromised. Users must reset passwords on next login.",
    "affected_users": 1500,
    "tasks_created": 1450,
    "sessions_revoked": 4200,
    "errors": [
      {
        "userId": "user_xxx",
        "error": "Database error"
      }
    ]
  }
}
```

**Note:** This is a **CRITICAL** security operation:
- Rate limited to 1 request per 5 minutes
- Requires explicit `confirm: true` in request body
- All affected users will be required to reset their passwords on next login
- Audit logged for compliance

**Errors:**
- `400` - Invalid request, JSON body, or missing confirmation
- `401` - Unauthorized (admin privileges required)
- `429` - Rate limited (once per 5 minutes)

---

### Admin: Mass Password Reset

Forces password reset for all users in a realm (security incident response).

```
POST /admin/realm/force-password-reset
Authorization: Bearer <admin_access_token>
```

**Request Body:**
```json
{
  "realm_id": "realm_xxx",
  "reason": "security_incident",
  "revoke_all_sessions": true,
  "notify_users": true
}
```

**Response:** `200 OK`
```json
{
  "message": "Mass password reset initiated",
  "realm_id": "realm_xxx",
  "users_affected": 1500,
  "sessions_revoked": 4200
}
```

**Note:** This is a critical security operation. All affected users will be required to reset their passwords on next login.

---

### Session Task Blocking Response

When a user has pending blocking tasks, API calls return:

```json
{
  "error": {
    "code": "SESSION_TASK_PENDING",
    "message": "You have pending tasks that must be completed",
    "tasks": [
      {
        "id": "task_xxx",
        "type": "reset_password",
        "priority": 1
      }
    ]
  }
}
```

**HTTP Status:** `403 Forbidden`

**Allowed Endpoints During Blocking:**
- `GET /session/tasks` - View pending tasks
- `POST /session/tasks/{id}/complete` - Complete tasks
- `POST /logout` - Logout

---

### Task Metadata by Type

#### reset_password
```json
{
  "reason": "compromised | expired | admin_forced | policy",
  "compromised_at": "2026-01-15T00:00:00Z",
  "message": "Your password was found in a data breach"
}
```

#### setup_mfa
```json
{
  "required_mfa_methods": ["totp", "webauthn"],
  "mfa_policy_id": "policy_xxx",
  "instructions": "Your organization requires MFA"
}
```

#### choose_organization
```json
{
  "available_organizations": [
    { "id": "org_1", "name": "Acme Corp", "role": "admin" },
    { "id": "org_2", "name": "Beta Inc", "role": "member" }
  ]
}
```

#### accept_terms
```json
{
  "terms_version": "2.0",
  "terms_url": "https://example.com/terms",
  "message": "Please review and accept our updated terms"
}
```

#### custom
```json
{
  "custom_type": "verify_phone",
  "webhook_url": "https://api.example.com/verify",
  "custom_data": { "phone": "+1234567890" },
  "instructions": "Please verify your phone number"
}
```

---

### DynamoDB Schema: Session Tasks

Session tasks are stored in the `zalt-sessions` table with the following schema:

| Attribute | Type | Description |
|-----------|------|-------------|
| pk | String | `SESSION#{session_id}#TASK#{task_id}` |
| sk | String | `TASK` |
| id | String | Task ID (task_xxx) |
| session_id | String | Associated session ID |
| user_id | String | User who must complete the task |
| realm_id | String | Realm context |
| type | String | Task type (reset_password, setup_mfa, etc.) |
| status | String | pending, completed, skipped |
| metadata | Map | Task-specific metadata |
| created_at | String | ISO timestamp |
| completed_at | String | ISO timestamp (when completed) |
| expires_at | String | Optional expiration |
| priority | Number | Task priority (1-5) |
| blocking | Boolean | Whether task blocks API access |

---

### SDK Integration

The SDK provides automatic session task handling:

```typescript
import { useSessionTasks } from '@zalt/react';

function App() {
  const { tasks, hasPendingTasks, completeTask } = useSessionTasks();
  
  if (hasPendingTasks) {
    return <SessionTaskHandler tasks={tasks} onComplete={completeTask} />;
  }
  
  return <MainApp />;
}
```

---

### Webhooks

Session task events trigger webhooks:

| Event | Description |
|-------|-------------|
| `session_task.created` | New task created |
| `session_task.completed` | Task completed |
| `session_task.skipped` | Task skipped |
| `session_task.expired` | Task expired |

**Webhook Payload:**
```json
{
  "id": "evt_xxx",
  "type": "session_task.completed",
  "timestamp": "2026-01-16T10:05:00Z",
  "data": {
    "task_id": "task_xxx",
    "session_id": "session_xxx",
    "user_id": "user_xxx",
    "task_type": "reset_password",
    "status": "completed"
  }
}
```

---

## Session Management

Session Management allows users to view and manage all their active sessions across devices. This enables users to detect unauthorized access and revoke sessions remotely.

**Validates:** Requirements 13.1, 13.2, 13.3, 13.4

### Security Features

- **Rate Limiting**: 100 requests/min/user
- **Audit Logging**: All session operations are logged
- **IP Masking**: IP addresses are partially masked for privacy
- **Webhook Integration**: Session revocation triggers webhooks

---

### List Sessions

Returns all active sessions for the authenticated user.

**Validates:** Requirement 13.1 - WHEN user requests sessions THEN return all active sessions

```
GET /sessions
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Sessions retrieved successfully",
  "sessions": [
    {
      "id": "session_abc123",
      "device": "Desktop",
      "browser": "Chrome 120",
      "ip_address": "192.168.*.*",
      "location": {
        "city": "Istanbul",
        "country": "Turkey",
        "country_code": "TR"
      },
      "last_activity": "2026-01-25T10:30:00Z",
      "created_at": "2026-01-24T08:00:00Z",
      "is_current": true,
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
    },
    {
      "id": "session_def456",
      "device": "Mobile",
      "browser": "Safari 17",
      "ip_address": "10.0.*.*",
      "location": {
        "city": "London",
        "country": "United Kingdom",
        "country_code": "GB"
      },
      "last_activity": "2026-01-25T09:15:00Z",
      "created_at": "2026-01-23T14:30:00Z",
      "is_current": false,
      "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) Version/17.2 Safari/605.1.15"
    }
  ],
  "total": 2
}
```

**Session Info Fields:**

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique session identifier |
| device | string | Device type (Desktop, Mobile, Tablet, Unknown) - Enhanced detection for tablets, Android devices, iOS |
| browser | string | Browser name with major version (e.g., "Chrome 120", "Firefox 119", "Safari 17", "Edge 120", "Opera 106") |
| ip_address | string | Partially masked IP address for privacy (e.g., "192.168.*.*") |
| location | object | Geo-location data from IP lookup (optional, may be undefined if lookup fails) |
| location.city | string | City name (e.g., "Istanbul", "New York") |
| location.country | string | Country name (e.g., "Turkey", "United States") |
| location.country_code | string | ISO 3166-1 alpha-2 country code (e.g., "TR", "US") |
| last_activity | string | ISO timestamp of last activity (updated on session access) |
| created_at | string | ISO timestamp of session creation |
| is_current | boolean | Whether this is the current session making the request |
| user_agent | string | Full user agent string for detailed analysis |

**Device Type Detection:**
- **Desktop**: Windows, macOS, Linux, Chrome OS
- **Mobile**: iPhone, Android phones, Windows Phone, BlackBerry
- **Tablet**: iPad, Android tablets (without "mobile" in UA), Kindle, Surface
- **Unknown**: Bots, custom clients, unrecognized user agents

**Browser Detection:**
Supports detection with version for: Chrome, Firefox, Safari, Edge, Opera, Samsung Browser, UC Browser, Brave, Internet Explorer

**IP Geolocation:**
- Location data is enriched from IP address using geolocation service
- Returns `undefined` if IP lookup fails (graceful degradation)
- Privacy: Only city/country level, no precise coordinates exposed

**Last Activity Tracking:**
- Updated automatically when session is accessed
- Falls back to `created_at` if `last_used_at` is not set

**Errors:**
- `401` - Unauthorized (invalid or expired token)
- `429` - Rate limit exceeded (100/min/user)

---

### Get Session Details

Returns detailed information about a specific session.

**Validates:** Requirement 13.2 - Session info includes device, browser, IP, location, last_activity, is_current

```
GET /sessions/{session_id}
Authorization: Bearer <access_token>
```

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| session_id | string | Session ID to retrieve |

**Response:** `200 OK`
```json
{
  "message": "Session retrieved successfully",
  "session": {
    "id": "session_abc123",
    "device": "Desktop",
    "browser": "Chrome 120",
    "ip_address": "192.168.*.*",
    "location": {
      "city": "Istanbul",
      "country": "Turkey",
      "country_code": "TR"
    },
    "last_activity": "2026-01-25T10:30:00Z",
    "created_at": "2026-01-24T08:00:00Z",
    "is_current": true,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
  }
}
```

**Errors:**
- `401` - Unauthorized
- `403` - Forbidden (session belongs to another user)
- `404` - Session not found
- `429` - Rate limit exceeded

---

### Revoke Session

Revokes a specific session immediately. The session is invalidated and cannot be used for authentication.

**Validates:** Requirement 13.3 - WHEN user revokes session THEN invalidate immediately

```
DELETE /sessions/{session_id}
Authorization: Bearer <access_token>
```

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| session_id | string | Session ID to revoke |

**Response:** `200 OK`
```json
{
  "message": "Session revoked successfully",
  "session_id": "session_abc123",
  "is_current_session": false
}
```

**Note:** If you revoke your current session, you will be logged out.

**Webhook Triggered:** `session.revoked`
```json
{
  "type": "session.revoked",
  "session_id": "session_abc123",
  "user_id": "user_xxx",
  "realm_id": "realm_xxx",
  "reason": "logout",
  "timestamp": "2026-01-25T10:35:00Z"
}
```

**Errors:**
- `401` - Unauthorized
- `403` - Forbidden (session belongs to another user)
- `404` - Session not found
- `429` - Rate limit exceeded
- `500` - Revocation failed

---

### Revoke All Sessions

Revokes all sessions except the current one. Useful when a user suspects unauthorized access.

**Validates:** Requirement 13.4 - WHEN user revokes all sessions THEN keep current session only

```
DELETE /sessions
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "message": "3 session(s) revoked successfully",
  "revoked_count": 3
}
```

**Response (no other sessions):** `200 OK`
```json
{
  "message": "No other sessions to revoke",
  "revoked_count": 0
}
```

**Webhook Triggered:** `session.revoked` (for each revoked session)

**Errors:**
- `401` - Unauthorized
- `429` - Rate limit exceeded
- `500` - Revocation failed

---

### Session Webhooks

Session events trigger webhooks for real-time notifications:

| Event | Description |
|-------|-------------|
| `session.created` | New session created (login) |
| `session.revoked` | Session revoked (logout, force logout) |

**Webhook Payload (session.revoked):**
```json
{
  "id": "evt_xxx",
  "type": "session.revoked",
  "timestamp": "2026-01-25T10:35:00Z",
  "data": {
    "session_id": "session_abc123",
    "user_id": "user_xxx",
    "realm_id": "realm_xxx",
    "reason": "logout"
  }
}
```

---

### SDK Integration

The SDK provides session management components and hooks:

```typescript
import { useSession, SessionList } from '@zalt/react';

function SecuritySettings() {
  const { sessions, currentSession, revokeSession, revokeAllSessions } = useSession();
  
  return (
    <div>
      <h2>Active Sessions</h2>
      <SessionList 
        sessions={sessions}
        currentSessionId={currentSession?.id}
        onRevoke={revokeSession}
        onRevokeAll={revokeAllSessions}
      />
    </div>
  );
}
```

**SessionList Component Props:**

| Prop | Type | Description |
|------|------|-------------|
| sessions | Session[] | Array of session objects |
| currentSessionId | string | ID of the current session |
| onRevoke | (sessionId: string) => void | Callback when revoking a session |
| onRevokeAll | () => void | Callback when revoking all sessions |
| showLocation | boolean | Whether to show location info (default: true) |

---

## Invitations

The Invitation System allows tenant owners and admins to invite team members by email. Invitations include role assignment and optional permissions.

### Security Features

- **Cryptographically Secure Tokens**: 32-byte random tokens (64 hex characters)
- **Token Hashing**: Tokens are hashed with SHA-256 before storage
- **Single Use**: Each invitation token can only be used once
- **Automatic Expiry**: Default 7-day expiration with TTL cleanup
- **No Email Enumeration**: Same response for valid/invalid emails

---

### Create Invitation

Creates a new invitation for a team member.

```
POST /tenants/{tenant_id}/invitations
```

**Authorization:** Bearer token (requires `tenant:admin` or `tenant:owner` role)

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| tenant_id | string | Target tenant ID |

**Request Body:**
```json
{
  "email": "newmember@example.com",
  "role": "member",
  "permissions": ["read:reports", "write:comments"],
  "metadata": {
    "custom_message": "Welcome to our team!"
  },
  "expires_in_days": 7
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Email address to invite |
| role | string | Yes | Role to assign (member, admin, etc.) |
| permissions | string[] | No | Additional direct permissions |
| metadata | object | No | Custom metadata for the invitation |
| expires_in_days | number | No | Days until expiry (default: 7, max: 30) |

**Response:** `201 Created`
```json
{
  "message": "Invitation sent successfully",
  "invitation": {
    "id": "inv_abc123def456789012345678",
    "tenant_id": "tenant_xxx",
    "email": "newmember@example.com",
    "role": "member",
    "permissions": ["read:reports", "write:comments"],
    "invited_by": "user_xxx",
    "status": "pending",
    "expires_at": "2026-02-01T10:00:00Z",
    "created_at": "2026-01-25T10:00:00Z"
  }
}
```

> **Note:** The invitation token is sent via email and is never returned in the API response for security.

**Errors:**
- `400` - Invalid email format
- `401` - Unauthorized
- `403` - Insufficient permissions
- `409` - Pending invitation already exists for this email
- `429` - Rate limit exceeded

---

### List Invitations

Lists all invitations for a tenant.

```
GET /tenants/{tenant_id}/invitations
```

**Authorization:** Bearer token (requires `tenant:admin` or `tenant:owner` role)

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| status | string | Filter by status: pending, accepted, expired, revoked |
| limit | number | Max results (default: 50, max: 100) |
| cursor | string | Pagination cursor |

**Response:** `200 OK`
```json
{
  "invitations": [
    {
      "id": "inv_abc123def456789012345678",
      "tenant_id": "tenant_xxx",
      "email": "user1@example.com",
      "role": "member",
      "invited_by": "user_xxx",
      "status": "pending",
      "expires_at": "2026-02-01T10:00:00Z",
      "created_at": "2026-01-25T10:00:00Z"
    },
    {
      "id": "inv_def456abc789012345678901",
      "tenant_id": "tenant_xxx",
      "email": "user2@example.com",
      "role": "admin",
      "invited_by": "user_xxx",
      "status": "accepted",
      "expires_at": "2026-02-01T10:00:00Z",
      "created_at": "2026-01-24T10:00:00Z",
      "accepted_at": "2026-01-24T15:00:00Z"
    }
  ],
  "next_cursor": "eyJsYXN0X2tl..."
}
```

---

### Get Invitation

Gets a specific invitation by ID.

```
GET /tenants/{tenant_id}/invitations/{invitation_id}
```

**Authorization:** Bearer token (requires `tenant:admin` or `tenant:owner` role)

**Response:** `200 OK`
```json
{
  "invitation": {
    "id": "inv_abc123def456789012345678",
    "tenant_id": "tenant_xxx",
    "email": "newmember@example.com",
    "role": "member",
    "permissions": ["read:reports"],
    "invited_by": "user_xxx",
    "status": "pending",
    "expires_at": "2026-02-01T10:00:00Z",
    "created_at": "2026-01-25T10:00:00Z",
    "metadata": {
      "tenant_name": "Acme Corp",
      "inviter_name": "John Doe",
      "resend_count": 0
    }
  }
}
```

**Errors:**
- `401` - Unauthorized
- `403` - Insufficient permissions
- `404` - Invitation not found

---

### Accept Invitation

Accepts an invitation using the token from the invitation email.

```
POST /invitations/accept
```

**Authorization:** None required (token-based authentication)

**Request Body (Existing User):**
```json
{
  "token": "abc123def456...",
  "user_id": "user_existing123"
}
```

**Request Body (New User Registration):**
```json
{
  "token": "abc123def456...",
  "new_user": {
    "first_name": "Jane",
    "last_name": "Doe",
    "password": "SecurePassword123!"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| token | string | Yes | Invitation token from email |
| user_id | string | No* | Existing user ID |
| new_user | object | No* | New user registration data |

> *Either `user_id` or `new_user` must be provided.

**Response:** `200 OK`
```json
{
  "message": "Invitation accepted successfully",
  "membership": {
    "tenant_id": "tenant_xxx",
    "user_id": "user_xxx",
    "role": "member",
    "permissions": ["read:reports"],
    "joined_at": "2026-01-25T15:00:00Z"
  }
}
```

**Errors:**
- `400` - Invalid token format / Missing required fields
- `400` - `INVITATION_EXPIRED` - Invitation has expired
- `400` - `INVITATION_ALREADY_USED` - Invitation already accepted
- `400` - `INVITATION_REVOKED` - Invitation was revoked
- `404` - `INVITATION_NOT_FOUND` - Invalid invitation token

---

### Validate Invitation Token

Validates an invitation token without accepting it. Useful for showing invitation details before acceptance.

```
GET /invitations/validate?token={token}
```

**Authorization:** None required (token-based validation)

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| token | string | Invitation token from email |

**Response:** `200 OK`
```json
{
  "valid": true,
  "invitation": {
    "id": "inv_abc123def456789012345678",
    "tenant_id": "tenant_xxx",
    "email": "newmember@example.com",
    "role": "member",
    "status": "pending",
    "expires_at": "2026-02-01T10:00:00Z",
    "created_at": "2026-01-25T10:00:00Z",
    "metadata": {
      "tenant_name": "Acme Corp",
      "inviter_name": "John Doe"
    }
  }
}
```

**Errors:**
- `400` - `MISSING_TOKEN` - Token parameter is required
- `400` - `INVITATION_NOT_FOUND` - Invalid invitation token
- `400` - `INVITATION_EXPIRED` - Invitation has expired
- `400` - `INVITATION_ALREADY_USED` - Invitation already accepted
- `400` - `INVITATION_REVOKED` - Invitation was revoked
- `429` - Rate limit exceeded

---

### Revoke Invitation

Revokes a pending invitation so it can no longer be accepted.

```
DELETE /tenants/{tenant_id}/invitations/{invitation_id}
```

**Authorization:** Bearer token (requires `tenant:admin` or `tenant:owner` role)

**Response:** `200 OK`
```json
{
  "message": "Invitation revoked successfully",
  "invitation": {
    "id": "inv_abc123def456789012345678",
    "status": "revoked",
    "revoked_at": "2026-01-25T12:00:00Z",
    "revoked_by": "user_admin123"
  }
}
```

**Errors:**
- `401` - Unauthorized
- `403` - Insufficient permissions
- `404` - Invitation not found
- `409` - Invitation already accepted/revoked/expired

---

### Resend Invitation

Resends an invitation email with a new token and extended expiry.

```
POST /tenants/{tenant_id}/invitations/{invitation_id}/resend
```

**Authorization:** Bearer token (requires `tenant:admin` or `tenant:owner` role)

**Request Body (Optional):**
```json
{
  "expires_in_days": 14
}
```

**Response:** `200 OK`
```json
{
  "message": "Invitation resent successfully",
  "invitation": {
    "id": "inv_abc123def456789012345678",
    "email": "newmember@example.com",
    "status": "pending",
    "expires_at": "2026-02-08T10:00:00Z",
    "metadata": {
      "resend_count": 1,
      "last_resent_at": "2026-01-25T12:00:00Z"
    }
  }
}
```

> **Note:** Resending generates a new token and invalidates the previous one.

**Errors:**
- `401` - Unauthorized
- `403` - Insufficient permissions
- `404` - Invitation not found
- `409` - Invitation already accepted/revoked/expired

---

### DynamoDB Schema: Invitations

Invitations are stored in the `zalt-invitations` table with the following schema:

| Attribute | Type | Description |
|-----------|------|-------------|
| pk | String | `TENANT#{tenant_id}#INVITATION#{invitation_id}` |
| sk | String | `INVITATION` |
| id | String | Invitation ID (inv_xxx) |
| tenant_id | String | Target tenant ID |
| email | String | Invited email (lowercase) |
| role | String | Assigned role |
| permissions | List | Additional direct permissions |
| invited_by | String | Inviter user ID |
| token_hash | String | SHA-256 hash of invitation token |
| status | String | pending, accepted, expired, revoked |
| expires_at | String | ISO timestamp |
| created_at | String | ISO timestamp |
| accepted_at | String | ISO timestamp (when accepted) |
| accepted_by_user_id | String | User ID who accepted |
| revoked_at | String | ISO timestamp (when revoked) |
| revoked_by | String | User ID who revoked |
| metadata | Map | Additional metadata |
| ttl | Number | Unix timestamp for DynamoDB TTL |

**GSI Indexes:**
| Index | Key | Description |
|-------|-----|-------------|
| token-index | token_hash | Lookup invitation by token |
| email-index | email | List invitations by email |
| tenant-index | tenant_id | List invitations by tenant |

---

### Webhooks

Invitation events trigger webhooks:

| Event | Description |
|-------|-------------|
| `member.invited` | New invitation created |
| `member.joined` | Invitation accepted, member added |
| `invitation.revoked` | Invitation revoked |
| `invitation.expired` | Invitation expired |

**Webhook Payload (member.invited):**
```json
{
  "id": "evt_xxx",
  "type": "member.invited",
  "timestamp": "2026-01-25T10:00:00Z",
  "data": {
    "invitation_id": "inv_xxx",
    "tenant_id": "tenant_xxx",
    "email": "newmember@example.com",
    "role": "member",
    "invited_by": "user_xxx",
    "expires_at": "2026-02-01T10:00:00Z"
  }
}
```

**Webhook Payload (member.joined):**
```json
{
  "id": "evt_xxx",
  "type": "member.joined",
  "timestamp": "2026-01-25T15:00:00Z",
  "data": {
    "invitation_id": "inv_xxx",
    "tenant_id": "tenant_xxx",
    "user_id": "user_xxx",
    "email": "newmember@example.com",
    "role": "member",
    "is_new_user": false
  }
}
```

---

### SDK Integration

The SDK provides invitation management components:

```typescript
import { useInvitations, InvitationList } from '@zalt/react';

function TeamManagement() {
  const { 
    invitations, 
    createInvitation, 
    revokeInvitation,
    resendInvitation,
    isLoading 
  } = useInvitations();
  
  const handleInvite = async (email: string, role: string) => {
    await createInvitation({ email, role });
  };
  
  return (
    <div>
      <InviteForm onSubmit={handleInvite} />
      <InvitationList 
        invitations={invitations}
        onRevoke={revokeInvitation}
        onResend={resendInvitation}
      />
    </div>
  );
}
```

**Accept Invitation Page:**
```typescript
import { useAcceptInvitation } from '@zalt/react';

function AcceptInvitationPage() {
  const { token } = useParams();
  const { 
    invitation, 
    acceptAsExistingUser,
    acceptAsNewUser,
    isLoading,
    error 
  } = useAcceptInvitation(token);
  
  if (error) {
    return <InvitationError error={error} />;
  }
  
  return (
    <AcceptInvitationForm
      invitation={invitation}
      onAcceptExisting={acceptAsExistingUser}
      onAcceptNew={acceptAsNewUser}
    />
  );
}
```


---

## Waitlist

The Waitlist system allows you to collect interested users before launch and control early access. When waitlist mode is enabled, registration is blocked and users are directed to join the waitlist instead.

### Security Features

- **Rate Limiting**: 10 requests/hour/IP for joining
- **Email Validation**: Prevents invalid email submissions
- **Duplicate Prevention**: Same email cannot join twice
- **Position Tracking**: Real-time waitlist position updates

---

### Join Waitlist

Adds a user to the waitlist.

```
POST /waitlist
```

**Request Body:**
```json
{
  "realm_id": "string (required)",
  "email": "string (required)",
  "metadata": {
    "referral_code": "string (optional)",
    "source": "string (optional)",
    "custom_fields": {}
  }
}
```

**Response:** `201 Created`
```json
{
  "message": "Successfully joined waitlist",
  "entry": {
    "id": "waitlist_abc123",
    "email": "user@example.com",
    "position": 42,
    "status": "pending",
    "created_at": "2026-01-25T10:00:00Z"
  }
}
```

**Errors:**
- `400` - Invalid email format
- `403` - `WAITLIST_MODE_INACTIVE` - Waitlist mode not enabled
- `409` - Email already on waitlist
- `429` - Rate limit exceeded

---

### Get Waitlist Position

Returns the current position for a waitlist entry.

```
GET /waitlist/position/{entry_id}
```

**Response:** `200 OK`
```json
{
  "entry_id": "waitlist_abc123",
  "position": 42,
  "total_entries": 500,
  "status": "pending",
  "estimated_wait": "2-3 weeks"
}
```

---

### List Waitlist Entries (Admin)

Lists all waitlist entries for a realm.

```
GET /waitlist?realm_id=xxx
Authorization: Bearer <admin_access_token>
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| realm_id | string | Realm ID (required) |
| status | string | Filter by status: pending, approved, rejected |
| limit | number | Max results (default: 50, max: 100) |
| cursor | string | Pagination cursor |

**Response:** `200 OK`
```json
{
  "entries": [
    {
      "id": "waitlist_abc123",
      "email": "user1@example.com",
      "position": 1,
      "status": "pending",
      "metadata": {
        "referral_code": "FRIEND123",
        "source": "twitter"
      },
      "created_at": "2026-01-20T10:00:00Z"
    }
  ],
  "total": 500,
  "next_cursor": "eyJsYXN0..."
}
```

---

### Approve Waitlist Entry (Admin)

Approves a waitlist entry and sends an invitation email.

```
POST /waitlist/{entry_id}/approve
Authorization: Bearer <admin_access_token>
```

**Request Body (Optional):**
```json
{
  "send_invitation": true,
  "custom_message": "Welcome to our platform!"
}
```

**Response:** `200 OK`
```json
{
  "message": "Entry approved successfully",
  "entry": {
    "id": "waitlist_abc123",
    "email": "user@example.com",
    "status": "approved",
    "approved_at": "2026-01-25T10:00:00Z"
  },
  "invitation_sent": true
}
```

---

### Reject Waitlist Entry (Admin)

Rejects a waitlist entry.

```
POST /waitlist/{entry_id}/reject
Authorization: Bearer <admin_access_token>
```

**Request Body (Optional):**
```json
{
  "reason": "Not eligible for early access"
}
```

**Response:** `200 OK`
```json
{
  "message": "Entry rejected",
  "entry": {
    "id": "waitlist_abc123",
    "status": "rejected",
    "rejected_at": "2026-01-25T10:00:00Z"
  }
}
```

---

### Bulk Approve (Admin)

Approves multiple waitlist entries at once.

```
POST /waitlist/bulk-approve
Authorization: Bearer <admin_access_token>
```

**Request Body:**
```json
{
  "entry_ids": ["waitlist_abc123", "waitlist_def456"],
  "send_invitations": true
}
```

**Response:** `200 OK`
```json
{
  "message": "Bulk approval completed",
  "approved_count": 2,
  "invitations_sent": 2,
  "errors": []
}
```

---

### Waitlist Mode Response

When waitlist mode is enabled and a user tries to register:

```json
{
  "error": {
    "code": "WAITLIST_MODE_ACTIVE",
    "message": "Registration is currently closed. Please join our waitlist.",
    "waitlist_url": "/waitlist"
  }
}
```

**HTTP Status:** `403 Forbidden`

---

### DynamoDB Schema: Waitlist

| Attribute | Type | Description |
|-----------|------|-------------|
| pk | String | `REALM#{realm_id}#WAITLIST#{entry_id}` |
| sk | String | `WAITLIST` |
| id | String | Entry ID (waitlist_xxx) |
| realm_id | String | Realm ID |
| email | String | User email (lowercase) |
| status | String | pending, approved, rejected |
| position | Number | Waitlist position |
| metadata | Map | Custom metadata |
| referral_code | String | Optional referral code |
| created_at | String | ISO timestamp |
| approved_at | String | ISO timestamp |
| rejected_at | String | ISO timestamp |

**GSI: email-index**
- Partition Key: `email`
- Enables lookup by email

---

### SDK Integration

```typescript
import { Waitlist } from '@zalt/react';

function WaitlistPage() {
  return (
    <Waitlist
      realmId="your-realm"
      onSuccess={(entry) => console.log('Joined!', entry.position)}
      onError={(error) => console.error(error)}
      showPosition={true}
      customFields={[
        { name: 'company', label: 'Company Name', required: false }
      ]}
    />
  );
}
```

---

## Impersonation

User Impersonation allows administrators to log in as a user for debugging and support purposes. All impersonation sessions are fully audited and have restrictions to prevent abuse.

### Security Features

- **Admin Permission Required**: Only users with `admin:impersonate` permission
- **Full Audit Trail**: All actions during impersonation are logged
- **Time-Limited Sessions**: Maximum 1 hour by default
- **Restricted Actions**: Cannot change password or delete account
- **Visual Indicator**: SDK shows impersonation banner

---

### Start Impersonation (Admin)

Starts an impersonation session for a target user.

```
POST /admin/users/{user_id}/impersonate
Authorization: Bearer <admin_access_token>
```

**Request Body:**
```json
{
  "reason": "string (required)",
  "duration_minutes": 60
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| reason | string | Yes | Reason for impersonation (audit logged) |
| duration_minutes | number | No | Session duration (default: 60, max: 120) |

**Response:** `200 OK`
```json
{
  "message": "Impersonation session started",
  "session": {
    "id": "imp_abc123",
    "admin_id": "user_admin",
    "target_user_id": "user_target",
    "reason": "Debugging login issue",
    "started_at": "2026-01-25T10:00:00Z",
    "expires_at": "2026-01-25T11:00:00Z",
    "restrictions": ["no_password_change", "no_delete_account", "no_mfa_disable"]
  },
  "tokens": {
    "access_token": "eyJhbG...",
    "refresh_token": "eyJhbG...",
    "expires_in": 900
  }
}
```

**Errors:**
- `400` - Missing reason
- `401` - Unauthorized
- `403` - Insufficient permissions (requires `admin:impersonate`)
- `404` - Target user not found
- `409` - Cannot impersonate another admin

---

### End Impersonation

Ends the current impersonation session and returns to admin context.

```
POST /impersonation/end
Authorization: Bearer <impersonation_access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Impersonation session ended",
  "session": {
    "id": "imp_abc123",
    "ended_at": "2026-01-25T10:30:00Z",
    "duration_minutes": 30
  },
  "admin_tokens": {
    "access_token": "eyJhbG...",
    "refresh_token": "eyJhbG...",
    "expires_in": 900
  }
}
```

---

### Check Impersonation Status

Checks if the current session is an impersonation session.

```
GET /impersonation/status
Authorization: Bearer <access_token>
```

**Response (Impersonating):** `200 OK`
```json
{
  "is_impersonating": true,
  "session": {
    "id": "imp_abc123",
    "admin_id": "user_admin",
    "admin_email": "admin@example.com",
    "target_user_id": "user_target",
    "target_user_email": "user@example.com",
    "reason": "Debugging login issue",
    "started_at": "2026-01-25T10:00:00Z",
    "expires_at": "2026-01-25T11:00:00Z",
    "remaining_minutes": 30,
    "restrictions": ["no_password_change", "no_delete_account", "no_mfa_disable"]
  }
}
```

**Response (Not Impersonating):** `200 OK`
```json
{
  "is_impersonating": false,
  "session": null
}
```

---

### Impersonation Restrictions

During impersonation, certain actions are blocked:

| Action | Blocked | Error Code |
|--------|---------|------------|
| Change Password | ✅ Yes | `IMPERSONATION_RESTRICTED` |
| Delete Account | ✅ Yes | `IMPERSONATION_RESTRICTED` |
| Disable MFA | ✅ Yes | `IMPERSONATION_RESTRICTED` |
| Change Email | ✅ Yes | `IMPERSONATION_RESTRICTED` |
| Revoke All Sessions | ✅ Yes | `IMPERSONATION_RESTRICTED` |
| View Data | ❌ No | - |
| Update Profile | ❌ No | - |
| Create Resources | ❌ No | - |

**Error Response:**
```json
{
  "error": {
    "code": "IMPERSONATION_RESTRICTED",
    "message": "This action is not allowed during impersonation",
    "restriction": "no_password_change"
  }
}
```

---

### Impersonation Token Claims

Impersonation tokens include special claims:

```json
{
  "sub": "user_target",
  "type": "impersonation",
  "impersonator_id": "user_admin",
  "impersonation_session_id": "imp_abc123",
  "restrictions": ["no_password_change", "no_delete_account"],
  "exp": 1704070800,
  "iat": 1704067200
}
```

---

### Audit Events

All impersonation events are logged:

| Event | Description |
|-------|-------------|
| `impersonation.started` | Admin started impersonation |
| `impersonation.ended` | Impersonation session ended |
| `impersonation.expired` | Session expired automatically |
| `impersonation.action_blocked` | Restricted action attempted |
| `impersonation.action` | Action performed during impersonation |

**Webhook Payload:**
```json
{
  "type": "impersonation.started",
  "timestamp": "2026-01-25T10:00:00Z",
  "data": {
    "session_id": "imp_abc123",
    "admin_id": "user_admin",
    "admin_email": "admin@example.com",
    "target_user_id": "user_target",
    "target_user_email": "user@example.com",
    "reason": "Debugging login issue",
    "expires_at": "2026-01-25T11:00:00Z"
  }
}
```

---

### SDK Integration

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

---

## Billing

Integrated billing management with Stripe for subscription-based pricing. Supports per-user, per-organization, flat-rate, and usage-based billing models.

### Security Features

- **Stripe Integration**: PCI-compliant payment processing
- **Webhook Verification**: All Stripe webhooks are signature-verified
- **Entitlement Enforcement**: Feature access controlled by plan
- **Usage Tracking**: Real-time usage metrics

---

### List Plans

Returns all available billing plans for a realm.

```
GET /billing/plans?realm_id=xxx
```

**Response:** `200 OK`
```json
{
  "plans": [
    {
      "id": "plan_free",
      "name": "Free",
      "type": "flat_rate",
      "price_monthly": 0,
      "price_yearly": 0,
      "features": ["5 users", "Basic support"],
      "limits": {
        "users": 5,
        "api_calls": 1000
      }
    },
    {
      "id": "plan_pro",
      "name": "Pro",
      "type": "per_user",
      "price_monthly": 10,
      "price_yearly": 100,
      "features": ["Unlimited users", "Priority support", "SSO"],
      "limits": {
        "users": -1,
        "api_calls": 100000
      }
    },
    {
      "id": "plan_enterprise",
      "name": "Enterprise",
      "type": "custom",
      "price_monthly": null,
      "price_yearly": null,
      "features": ["Custom limits", "Dedicated support", "SLA"],
      "limits": {},
      "contact_sales": true
    }
  ]
}
```

---

### Get Current Subscription

Returns the current subscription for a tenant.

```
GET /billing/subscription
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "subscription": {
    "id": "sub_abc123",
    "tenant_id": "tenant_xxx",
    "plan_id": "plan_pro",
    "plan_name": "Pro",
    "status": "active",
    "current_period_start": "2026-01-01T00:00:00Z",
    "current_period_end": "2026-02-01T00:00:00Z",
    "cancel_at_period_end": false,
    "quantity": 10,
    "amount_due": 100
  },
  "entitlements": {
    "sso": true,
    "webhooks": true,
    "api_keys": true,
    "max_users": -1,
    "max_api_calls": 100000
  }
}
```

---

### Subscribe to Plan

Creates a new subscription for a tenant.

```
POST /billing/subscribe
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "plan_id": "plan_pro",
  "payment_method_id": "pm_xxx",
  "billing_cycle": "monthly",
  "quantity": 10
}
```

**Response:** `200 OK`
```json
{
  "message": "Subscription created successfully",
  "subscription": {
    "id": "sub_abc123",
    "plan_id": "plan_pro",
    "status": "active",
    "current_period_end": "2026-02-01T00:00:00Z"
  },
  "client_secret": "pi_xxx_secret_xxx"
}
```

**Errors:**
- `400` - Invalid plan or payment method
- `402` - Payment required (card declined)
- `409` - Already subscribed

---

### Cancel Subscription

Cancels the current subscription at period end.

```
POST /billing/cancel
Authorization: Bearer <access_token>
```

**Note:** Requires reverification (MFA level).

**Request Body:**
```json
{
  "reason": "string (optional)",
  "feedback": "string (optional)"
}
```

**Response:** `200 OK`
```json
{
  "message": "Subscription will be canceled at period end",
  "subscription": {
    "id": "sub_abc123",
    "status": "active",
    "cancel_at_period_end": true,
    "current_period_end": "2026-02-01T00:00:00Z"
  }
}
```

---

### Get Usage

Returns current usage metrics for a tenant.

```
GET /billing/usage
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "usage": {
    "period_start": "2026-01-01T00:00:00Z",
    "period_end": "2026-02-01T00:00:00Z",
    "metrics": {
      "users": {
        "current": 8,
        "limit": -1,
        "percentage": 0
      },
      "api_calls": {
        "current": 45000,
        "limit": 100000,
        "percentage": 45
      },
      "storage_gb": {
        "current": 2.5,
        "limit": 10,
        "percentage": 25
      }
    }
  }
}
```

---

### Check Entitlement

Checks if a feature is available for the current plan.

```
GET /billing/entitlement/{feature}
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "feature": "sso",
  "entitled": true,
  "plan": "Pro"
}
```

**Response (Not Entitled):** `200 OK`
```json
{
  "feature": "sso",
  "entitled": false,
  "plan": "Free",
  "upgrade_required": true,
  "available_in": ["Pro", "Enterprise"]
}
```

---

### Entitlement Enforcement

When a feature is not available, the API returns:

```json
{
  "error": {
    "code": "PLAN_LIMIT_EXCEEDED",
    "message": "This feature requires a Pro plan or higher",
    "feature": "sso",
    "current_plan": "Free",
    "upgrade_url": "/billing/upgrade"
  }
}
```

**HTTP Status:** `403 Forbidden`

---

### Stripe Webhook

Handles Stripe webhook events for subscription management.

```
POST /billing/webhook
```

**Supported Events:**
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_succeeded`
- `invoice.payment_failed`

---

### Billing Webhooks

Billing events trigger webhooks:

| Event | Description |
|-------|-------------|
| `billing.subscription.created` | New subscription created |
| `billing.subscription.updated` | Subscription updated (plan change, quantity) |
| `billing.subscription.canceled` | Subscription canceled |
| `billing.payment.succeeded` | Payment successful |
| `billing.payment.failed` | Payment failed |

---

### SDK Integration

```typescript
import { PricingTable, BillingPortal, useBilling } from '@zalt/react';

// Pricing Table
function PricingPage() {
  return (
    <PricingTable
      realmId="your-realm"
      onSelect={(planId) => console.log('Selected:', planId)}
      highlightPlan="plan_pro"
    />
  );
}

// Billing Portal
function SettingsPage() {
  return (
    <BillingPortal
      showInvoices={true}
      showPaymentMethods={true}
      showUsage={true}
    />
  );
}

// Entitlement Check
function FeatureGate({ feature, children }) {
  const { checkEntitlement, isLoading } = useBilling();
  const entitled = checkEntitlement(feature);
  
  if (!entitled) {
    return <UpgradePrompt feature={feature} />;
  }
  
  return children;
}
```

---

## Webhooks Management

Manage webhook endpoints for receiving real-time event notifications.

### Create Webhook

Creates a new webhook endpoint.

```
POST /webhooks
Authorization: Bearer <admin_access_token>
```

**Request Body:**
```json
{
  "realm_id": "string (required)",
  "url": "string (required, HTTPS)",
  "events": ["user.created", "session.created"],
  "description": "string (optional)"
}
```

**Response:** `201 Created`
```json
{
  "message": "Webhook created successfully",
  "webhook": {
    "id": "webhook_abc123",
    "url": "https://yourapp.com/webhooks/zalt",
    "events": ["user.created", "session.created"],
    "status": "active",
    "created_at": "2026-01-25T10:00:00Z"
  },
  "secret": "whsec_xxx (shown only once)"
}
```

---

### List Webhooks

Lists all webhooks for a realm.

```
GET /webhooks?realm_id=xxx
Authorization: Bearer <admin_access_token>
```

**Response:** `200 OK`
```json
{
  "webhooks": [
    {
      "id": "webhook_abc123",
      "url": "https://yourapp.com/webhooks/zalt",
      "events": ["user.created", "session.created"],
      "status": "active",
      "last_triggered_at": "2026-01-25T09:00:00Z"
    }
  ]
}
```

---

### Delete Webhook

Deletes a webhook endpoint.

```
DELETE /webhooks/{webhook_id}
Authorization: Bearer <admin_access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Webhook deleted successfully"
}
```

---

### Test Webhook

Sends a test event to a webhook endpoint.

```
POST /webhooks/{webhook_id}/test
Authorization: Bearer <admin_access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Test event sent",
  "delivery": {
    "id": "del_abc123",
    "status": "success",
    "response_code": 200,
    "response_time_ms": 150
  }
}
```

---

### Get Delivery Logs

Returns recent delivery logs for a webhook.

```
GET /webhooks/{webhook_id}/deliveries
Authorization: Bearer <admin_access_token>
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| limit | number | Max results (default: 50, max: 100) |
| status | string | Filter by status: success, failed, pending |

**Response:** `200 OK`
```json
{
  "deliveries": [
    {
      "id": "del_abc123",
      "event_type": "user.created",
      "status": "success",
      "response_code": 200,
      "response_time_ms": 150,
      "attempts": 1,
      "created_at": "2026-01-25T10:00:00Z"
    },
    {
      "id": "del_def456",
      "event_type": "session.created",
      "status": "failed",
      "response_code": 500,
      "error": "Internal Server Error",
      "attempts": 5,
      "created_at": "2026-01-25T09:00:00Z"
    }
  ]
}
```

---

### Rotate Webhook Secret

Generates a new signing secret for a webhook.

```
POST /webhooks/{webhook_id}/rotate-secret
Authorization: Bearer <admin_access_token>
```

**Response:** `200 OK`
```json
{
  "message": "Secret rotated successfully",
  "secret": "whsec_new_xxx (shown only once)"
}
```

**Note:** The old secret is immediately invalidated.

