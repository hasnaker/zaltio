# Error Codes Reference

Complete list of error codes returned by the Zalt.io API.

## Error Response Format

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description",
    "details": {},
    "timestamp": "2026-01-16T00:00:00Z",
    "request_id": "uuid"
  }
}
```

## Authentication Errors

### INVALID_CREDENTIALS
**HTTP Status:** 401

Invalid email or password combination.

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password"
  }
}
```

**Handling:**
- Display generic error message (don't reveal which field is wrong)
- Increment failed attempt counter
- Consider showing "Forgot password?" link

---

### ACCOUNT_LOCKED
**HTTP Status:** 403

Account temporarily locked due to too many failed login attempts.

```json
{
  "error": {
    "code": "ACCOUNT_LOCKED",
    "message": "Account locked due to too many failed attempts",
    "details": {
      "locked_until": "2026-01-16T12:30:00Z",
      "remaining_seconds": 900
    }
  }
}
```

**Handling:**
- Show lockout duration to user
- Suggest password reset if they forgot password
- Do not allow further login attempts until unlocked

---

### ACCOUNT_SUSPENDED
**HTTP Status:** 403

Account has been suspended by an administrator.

```json
{
  "error": {
    "code": "ACCOUNT_SUSPENDED",
    "message": "Your account has been suspended"
  }
}
```

**Handling:**
- Direct user to contact support
- Do not reveal suspension reason

---

### ACCOUNT_NOT_VERIFIED
**HTTP Status:** 403

Email address has not been verified.

```json
{
  "error": {
    "code": "ACCOUNT_NOT_VERIFIED",
    "message": "Please verify your email address"
  }
}
```

**Handling:**
- Offer to resend verification email
- Show instructions for checking spam folder

---

### MFA_REQUIRED
**HTTP Status:** 200 (not an error, but a state)

Multi-factor authentication is required to complete login.

```json
{
  "mfa_required": true,
  "mfa_session_id": "uuid",
  "mfa_methods": ["totp", "webauthn"],
  "expires_in": 300
}
```

**Handling:**
- Redirect to MFA verification page
- Store mfa_session_id for verification step

---

### MFA_INVALID_CODE
**HTTP Status:** 401

The MFA code provided is incorrect.

```json
{
  "error": {
    "code": "MFA_INVALID_CODE",
    "message": "Invalid verification code",
    "details": {
      "attempts_remaining": 4
    }
  }
}
```

**Handling:**
- Clear input field
- Show remaining attempts
- Suggest checking time sync on authenticator app

---

### MFA_SESSION_EXPIRED
**HTTP Status:** 401

The MFA session has expired (default: 5 minutes).

```json
{
  "error": {
    "code": "MFA_SESSION_EXPIRED",
    "message": "MFA session expired. Please login again."
  }
}
```

**Handling:**
- Redirect back to login page
- Show message explaining timeout

## Token Errors

### TOKEN_EXPIRED
**HTTP Status:** 401

The access token has expired.

```json
{
  "error": {
    "code": "TOKEN_EXPIRED",
    "message": "Access token has expired"
  }
}
```

**Handling:**
- Attempt token refresh using refresh_token
- If refresh fails, redirect to login

---

### TOKEN_INVALID
**HTTP Status:** 401

The token is malformed or has an invalid signature.

```json
{
  "error": {
    "code": "TOKEN_INVALID",
    "message": "Invalid or malformed token"
  }
}
```

**Handling:**
- Clear stored tokens
- Redirect to login

---

### TOKEN_REVOKED
**HTTP Status:** 401

The token has been revoked (e.g., user logged out elsewhere).

```json
{
  "error": {
    "code": "TOKEN_REVOKED",
    "message": "Token has been revoked"
  }
}
```

**Handling:**
- Clear stored tokens
- Redirect to login
- Optionally show "You were logged out" message

---

### REFRESH_TOKEN_EXPIRED
**HTTP Status:** 401

The refresh token has expired (default: 7 days).

```json
{
  "error": {
    "code": "REFRESH_TOKEN_EXPIRED",
    "message": "Refresh token has expired"
  }
}
```

**Handling:**
- Clear all tokens
- Redirect to login

## Validation Errors

### VALIDATION_ERROR
**HTTP Status:** 400

Request body failed validation.

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": {
      "fields": {
        "email": "Invalid email format",
        "password": "Password must be at least 12 characters"
      }
    }
  }
}
```

**Handling:**
- Display field-specific error messages
- Highlight invalid fields

---

### PASSWORD_TOO_WEAK
**HTTP Status:** 400

Password doesn't meet strength requirements.

```json
{
  "error": {
    "code": "PASSWORD_TOO_WEAK",
    "message": "Password does not meet requirements",
    "details": {
      "requirements": {
        "min_length": 12,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_numbers": true,
        "require_symbols": true
      },
      "missing": ["uppercase", "symbol"]
    }
  }
}
```

**Handling:**
- Show password requirements checklist
- Highlight missing requirements

---

### PASSWORD_COMPROMISED
**HTTP Status:** 400

Password has been found in known data breaches.

```json
{
  "error": {
    "code": "PASSWORD_COMPROMISED",
    "message": "This password has been found in data breaches",
    "details": {
      "breach_count": 17
    }
  }
}
```

**Handling:**
- Explain the security risk
- Require user to choose a different password
- Link to haveibeenpwned.com for more info

---

### PASSWORD_RECENTLY_USED
**HTTP Status:** 400

Password was used recently (password history check).

```json
{
  "error": {
    "code": "PASSWORD_RECENTLY_USED",
    "message": "Cannot reuse recent passwords",
    "details": {
      "history_count": 12
    }
  }
}
```

**Handling:**
- Inform user they cannot reuse recent passwords
- Suggest creating a new unique password

## Rate Limiting Errors

### RATE_LIMITED
**HTTP Status:** 429

Too many requests in the time window.

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Too many requests",
    "details": {
      "retry_after": 60,
      "limit": 5,
      "window": "15 minutes"
    }
  }
}
```

**Headers:**
```
Retry-After: 60
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705406400
```

**Handling:**
- Show countdown timer
- Disable submit button until retry_after
- Consider implementing exponential backoff

## Resource Errors

### USER_NOT_FOUND
**HTTP Status:** 404

User does not exist (only returned for admin operations).

```json
{
  "error": {
    "code": "USER_NOT_FOUND",
    "message": "User not found"
  }
}
```

**Note:** For security, login/password-reset endpoints return generic errors to prevent email enumeration.

---

### REALM_NOT_FOUND
**HTTP Status:** 404

The specified realm does not exist.

```json
{
  "error": {
    "code": "REALM_NOT_FOUND",
    "message": "Realm not found"
  }
}
```

**Handling:**
- Check realm_id configuration
- Contact support if realm should exist

---

### SESSION_NOT_FOUND
**HTTP Status:** 404

Session does not exist or has been terminated.

```json
{
  "error": {
    "code": "SESSION_NOT_FOUND",
    "message": "Session not found"
  }
}
```

---

### CREDENTIAL_NOT_FOUND
**HTTP Status:** 404

WebAuthn credential not found.

```json
{
  "error": {
    "code": "CREDENTIAL_NOT_FOUND",
    "message": "Credential not found"
  }
}
```

## Permission Errors

### FORBIDDEN
**HTTP Status:** 403

User doesn't have permission for this action.

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You don't have permission to perform this action"
  }
}
```

---

### REALM_ACCESS_DENIED
**HTTP Status:** 403

User doesn't have access to this realm.

```json
{
  "error": {
    "code": "REALM_ACCESS_DENIED",
    "message": "Access denied to this realm"
  }
}
```

## Server Errors

### INTERNAL_ERROR
**HTTP Status:** 500

An unexpected error occurred.

```json
{
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "An unexpected error occurred",
    "request_id": "uuid"
  }
}
```

**Handling:**
- Log the request_id for support
- Show generic error message
- Offer retry option

---

### SERVICE_UNAVAILABLE
**HTTP Status:** 503

Service is temporarily unavailable.

```json
{
  "error": {
    "code": "SERVICE_UNAVAILABLE",
    "message": "Service temporarily unavailable",
    "details": {
      "retry_after": 30
    }
  }
}
```

**Handling:**
- Implement retry with exponential backoff
- Show maintenance message if prolonged

## Error Handling Best Practices

```typescript
async function handleApiCall<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error: any) {
    switch (error.code) {
      case 'TOKEN_EXPIRED':
        // Try refresh
        await refreshTokens();
        return fn();
        
      case 'RATE_LIMITED':
        // Wait and retry
        await sleep(error.details.retry_after * 1000);
        return fn();
        
      case 'INTERNAL_ERROR':
        // Log for debugging
        console.error('Server error:', error.request_id);
        throw new Error('Something went wrong. Please try again.');
        
      default:
        throw error;
    }
  }
}
```
