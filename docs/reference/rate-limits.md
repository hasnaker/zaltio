# Rate Limits Reference

Zalt.io implements rate limiting to protect against abuse and ensure fair usage.

## Default Rate Limits

### Authentication Endpoints

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /login` | 5 | 15 minutes | IP + Email |
| `POST /register` | 3 | 1 hour | IP |
| `POST /refresh` | 30 | 1 minute | User ID |
| `POST /logout` | 10 | 1 minute | User ID |

### MFA Endpoints

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /v1/auth/mfa/setup` | 3 | 1 hour | User ID |
| `POST /v1/auth/mfa/verify` | 5 | 1 minute | User ID |
| `POST /v1/auth/mfa/login/verify` | 5 | 1 minute | MFA Session |
| `POST /v1/auth/mfa/disable` | 3 | 1 hour | User ID |

### Password Endpoints

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /v1/auth/password-reset/request` | 3 | 1 hour | Email |
| `POST /v1/auth/password-reset/confirm` | 5 | 15 minutes | Token |

### WebAuthn Endpoints

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /v1/auth/webauthn/register/options` | 10 | 1 minute | User ID |
| `POST /v1/auth/webauthn/register` | 5 | 1 minute | User ID |
| `POST /v1/auth/webauthn/authenticate/options` | 10 | 1 minute | IP |
| `POST /v1/auth/webauthn/authenticate` | 10 | 1 minute | IP |

### General API

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `GET /me` | 60 | 1 minute | User ID |
| Admin endpoints | 100 | 1 minute | User ID |
| All other endpoints | 100 | 1 minute | User ID |

## Rate Limit Headers

All responses include rate limit information:

```http
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 3
X-RateLimit-Reset: 1705407300
```

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |

## Rate Limit Exceeded Response

**HTTP Status:** 429 Too Many Requests

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
```http
Retry-After: 60
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705407300
```

## Rate Limit Keys

Rate limits are tracked by different keys depending on the endpoint:

### IP-Based
Used for unauthenticated endpoints:
- Registration
- Password reset request
- WebAuthn authentication

### User-Based
Used for authenticated endpoints:
- Profile operations
- MFA setup/disable
- Session management

### Composite Keys
Some endpoints use multiple factors:
- Login: IP + Email (prevents both IP-based and account-based attacks)
- MFA verify: User ID + Session ID

## Progressive Delays

For security-sensitive endpoints, Zalt.io implements progressive delays:

### Login Attempts

| Attempt | Delay |
|---------|-------|
| 1-2 | None |
| 3 | 1 second |
| 4 | 2 seconds |
| 5 | 5 seconds |
| 6+ | Account locked |

### MFA Verification

| Attempt | Delay |
|---------|-------|
| 1-3 | None |
| 4 | 2 seconds |
| 5 | 5 seconds |
| 6+ | Session invalidated |

## Handling Rate Limits

### Basic Retry Logic

```typescript
async function apiCallWithRetry<T>(
  fn: () => Promise<T>,
  maxRetries = 3
): Promise<T> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: any) {
      if (error.code === 'RATE_LIMITED' && attempt < maxRetries - 1) {
        const retryAfter = error.details?.retry_after || 60;
        await sleep(retryAfter * 1000);
        continue;
      }
      throw error;
    }
  }
  throw new Error('Max retries exceeded');
}
```

### Exponential Backoff

```typescript
async function apiCallWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries = 5
): Promise<T> {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: any) {
      if (error.code === 'RATE_LIMITED' && attempt < maxRetries - 1) {
        // Exponential backoff: 1s, 2s, 4s, 8s, 16s
        const delay = Math.pow(2, attempt) * 1000;
        const jitter = Math.random() * 1000;
        await sleep(delay + jitter);
        continue;
      }
      throw error;
    }
  }
  throw new Error('Max retries exceeded');
}
```

### Proactive Rate Limit Handling

```typescript
class RateLimitTracker {
  private limits: Map<string, { remaining: number; reset: number }> = new Map();

  updateFromHeaders(endpoint: string, headers: Headers) {
    this.limits.set(endpoint, {
      remaining: parseInt(headers.get('X-RateLimit-Remaining') || '100'),
      reset: parseInt(headers.get('X-RateLimit-Reset') || '0')
    });
  }

  async waitIfNeeded(endpoint: string) {
    const limit = this.limits.get(endpoint);
    if (limit && limit.remaining <= 0) {
      const waitTime = (limit.reset * 1000) - Date.now();
      if (waitTime > 0) {
        await sleep(waitTime);
      }
    }
  }
}
```

## Enterprise Rate Limits

Enterprise tier customers can request custom rate limits:

| Feature | Pro | Enterprise |
|---------|-----|------------|
| Login attempts | 5/15min | Configurable |
| API requests | 100/min | 1000/min+ |
| Burst allowance | None | 2x limit |
| Custom endpoints | No | Yes |

Contact sales@zalt.io for enterprise rate limit configuration.

## Best Practices

1. **Cache responses** - Reduce unnecessary API calls
2. **Implement backoff** - Don't hammer the API on errors
3. **Monitor headers** - Track remaining requests proactively
4. **Queue requests** - Spread requests over time
5. **Use webhooks** - Instead of polling for changes

## Rate Limit Bypass (Testing)

For development and testing, you can request a rate limit bypass token:

```bash
curl -X POST https://api.zalt.io/v1/admin/rate-limit/bypass \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"duration": 3600}'
```

**Note:** Only available in development/staging realms.
