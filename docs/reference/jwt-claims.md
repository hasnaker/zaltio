# JWT Token Reference

Detailed documentation of JWT tokens issued by Zalt.io.

## Token Types

Zalt.io issues two types of tokens:

| Token | Default Lifetime | Purpose |
|-------|------------------|---------|
| Access Token | 15 minutes (realm-configurable) | API authentication |
| Refresh Token | 7 days | Obtain new access tokens |

**Note:** Access token lifetime can be configured per-realm via `session_timeout` setting. Default is 900 seconds (15 minutes), but realms can override this (e.g., 3600 seconds for 1 hour).

## Access Token Structure

### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "zalt-kms-2026-01-16"
}
```

| Field | Description |
|-------|-------------|
| `alg` | Algorithm (always RS256) |
| `typ` | Token type (always JWT) |
| `kid` | Key ID for signature verification |

### Payload (Claims)

```json
{
  "sub": "usr_abc123def456",
  "realm_id": "your-realm-id",
  "email": "user@example.com",
  "email_verified": true,
  "iat": 1705406400,
  "exp": 1705407300,
  "type": "access",
  "jti": "unique-token-id",
  "iss": "https://api.zalt.io",
  "aud": "https://api.zalt.io",
  "roles": ["user"],
  "permissions": ["read:profile", "write:profile"],
  "session_id": "ses_xyz789",
  "device_id": "dev_abc123"
}
```

### Standard Claims

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | User ID (subject) |
| `iat` | number | Issued at (Unix timestamp) |
| `exp` | number | Expiration (Unix timestamp) |
| `jti` | string | Unique token identifier |
| `iss` | string | Issuer (always "https://api.zalt.io") |
| `aud` | string | Audience (always "https://api.zalt.io") |

### Zalt.io Custom Claims

| Claim | Type | Description |
|-------|------|-------------|
| `realm_id` | string | Realm identifier |
| `email` | string | User's email address |
| `email_verified` | boolean | Email verification status |
| `type` | string | Token type ("access" or "refresh") |
| `roles` | string[] | User's roles in the realm |
| `permissions` | string[] | Specific permissions granted |
| `session_id` | string | Associated session ID |
| `device_id` | string | Device that created the session |
| `mfa_verified` | boolean | Whether MFA was completed |
| `auth_time` | number | Time of authentication |

### Optional Claims (Realm-Configurable)

| Claim | Type | Description |
|-------|------|-------------|
| `name` | string | User's full name |
| `given_name` | string | First name |
| `family_name` | string | Last name |
| `picture` | string | Profile picture URL |
| `locale` | string | User's locale |
| `metadata` | object | Custom user metadata |

## Refresh Token Structure

Refresh tokens have a similar structure but with:
- `type`: "refresh"
- Longer expiration (7 days default)
- No `permissions` claim

```json
{
  "sub": "usr_abc123def456",
  "realm_id": "your-realm-id",
  "email": "user@example.com",
  "iat": 1705406400,
  "exp": 1706011200,
  "type": "refresh",
  "jti": "unique-refresh-token-id",
  "iss": "https://api.zalt.io",
  "aud": "https://api.zalt.io",
  "session_id": "ses_xyz789"
}
```

## Token Verification

### Using JWKS

Fetch public keys from the JWKS endpoint:

```
GET https://api.zalt.io/.well-known/jwks.json
```

Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "zalt-kms-2026-01-16",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Verification Steps

1. **Decode header** - Extract `kid` to find the correct key
2. **Fetch public key** - From JWKS endpoint (cache this!)
3. **Verify signature** - Using RS256 algorithm
4. **Validate claims:**
   - `iss` must be "https://api.zalt.io"
   - `aud` must be "https://api.zalt.io"
   - `exp` must be in the future
   - `type` must be "access" for API calls
   - `realm_id` must match expected realm

### Code Examples

**Node.js:**
```typescript
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const client = jwksClient({
  jwksUri: 'https://api.zalt.io/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 86400000
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    callback(err, key?.getPublicKey());
  });
}

function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, {
      algorithms: ['RS256'],
      issuer: 'https://api.zalt.io',
      audience: 'https://api.zalt.io'
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}
```

**Python:**
```python
import jwt
from jwt import PyJWKClient

jwks_client = PyJWKClient("https://api.zalt.io/.well-known/jwks.json")

def verify_token(token: str) -> dict:
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        issuer="https://api.zalt.io",
        audience="https://api.zalt.io"
    )
```

**Go:**
```go
import (
    "github.com/golang-jwt/jwt/v5"
    "github.com/MicahParks/keyfunc/v2"
)

func verifyToken(tokenString string) (*jwt.Token, error) {
    jwks, _ := keyfunc.Get("https://api.zalt.io/.well-known/jwks.json", keyfunc.Options{})
    
    return jwt.Parse(tokenString, jwks.Keyfunc, 
        jwt.WithIssuer("https://api.zalt.io"),
        jwt.WithAudience("https://api.zalt.io"),
        jwt.WithValidMethods([]string{"RS256"}),
    )
}
```

## Token Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                        Login                                 │
│                          │                                   │
│                          ▼                                   │
│              ┌───────────────────────┐                      │
│              │   Access Token (15m)  │                      │
│              │   Refresh Token (7d)  │                      │
│              └───────────────────────┘                      │
│                          │                                   │
│         ┌────────────────┼────────────────┐                 │
│         │                │                │                 │
│         ▼                ▼                ▼                 │
│    API Request      Token Expires     Logout               │
│         │                │                │                 │
│         │                ▼                ▼                 │
│         │         ┌─────────────┐   Tokens Revoked         │
│         │         │   Refresh   │                          │
│         │         └─────────────┘                          │
│         │                │                                  │
│         │                ▼                                  │
│         │         New Access Token                         │
│         │         New Refresh Token                        │
│         │                │                                  │
│         └────────────────┘                                  │
└─────────────────────────────────────────────────────────────┘
```

## Security Considerations

### Token Storage

| Platform | Recommended Storage |
|----------|---------------------|
| Web (SPA) | HttpOnly cookies or memory |
| Web (SSR) | HttpOnly cookies |
| Mobile | Secure Keychain/Keystore |
| Desktop | OS credential manager |

### What NOT to do

❌ Store tokens in localStorage (XSS vulnerable)
❌ Include tokens in URLs
❌ Log tokens
❌ Share tokens between users
❌ Use tokens after logout

### Token Rotation

- Refresh tokens are rotated on each use
- Old refresh token is invalidated
- 30-second grace period for network retries
- Reuse of old refresh token triggers session termination

### Key Rotation

- JWT signing keys are rotated every 30 days
- 15-day grace period for old keys
- JWKS endpoint always has current and previous keys
- `kid` header identifies which key to use

## OpenID Connect Discovery

```
GET https://api.zalt.io/.well-known/openid-configuration
```

```json
{
  "issuer": "https://api.zalt.io",
  "authorization_endpoint": "https://api.zalt.io/oauth/authorize",
  "token_endpoint": "https://api.zalt.io/oauth/token",
  "userinfo_endpoint": "https://api.zalt.io/oauth/userinfo",
  "jwks_uri": "https://api.zalt.io/.well-known/jwks.json",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "claims_supported": [
    "sub", "email", "email_verified", "name", 
    "given_name", "family_name", "picture"
  ]
}
```
