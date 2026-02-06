# HSD Auth Platform - SSO Integration Guide

## Overview

This guide provides comprehensive documentation for integrating HSD applications with the HSD Auth Platform's Single Sign-On (SSO) functionality. The platform implements OAuth 2.0 and OpenID Connect standards for secure authentication across all HSD services.

## Supported Applications

The following HSD applications are supported for SSO integration:

| Application | Display Name | Base URL |
|-------------|--------------|----------|
| `hsd-portal` | HSD Portal | https://portal.hsdcore.com |
| `hsd-chat` | HSD Chat | https://chat.hsdcore.com |
| `hsd-tasks` | HSD Task Management | https://tasks.hsdcore.com |
| `hsd-docs` | HSD Docs | https://docs.hsdcore.com |
| `hsd-crm` | HSD CRM | https://crm.hsdcore.com |

## OAuth 2.0 / OpenID Connect Endpoints

### Discovery Document
```
GET https://auth.hsdcore.com/.well-known/openid-configuration
```

Returns the OpenID Connect Discovery Document with all supported endpoints and capabilities.

### Authorization Endpoint
```
GET https://auth.hsdcore.com/oauth/authorize
```

**Query Parameters:**
- `response_type` (required): `code` for authorization code flow
- `client_id` (required): Your registered client ID
- `redirect_uri` (required): Registered callback URL
- `scope` (required): Space-separated scopes (e.g., `openid profile email`)
- `state` (required): CSRF protection token
- `nonce` (optional): Replay protection for ID tokens
- `code_challenge` (optional): PKCE code challenge
- `code_challenge_method` (optional): `S256` or `plain`

### Token Endpoint
```
POST https://auth.hsdcore.com/oauth/token
Content-Type: application/x-www-form-urlencoded
```

**Parameters:**
- `grant_type`: `authorization_code` or `refresh_token`
- `code`: Authorization code (for authorization_code grant)
- `redirect_uri`: Must match the authorization request
- `client_id`: Your client ID
- `client_secret`: Your client secret
- `code_verifier`: PKCE verifier (if code_challenge was used)

### UserInfo Endpoint
```
GET https://auth.hsdcore.com/oauth/userinfo
Authorization: Bearer <access_token>
```

Returns user profile information based on granted scopes.

## SSO Endpoints

### Validate SSO Token
```
POST https://auth.hsdcore.com/sso/validate
Content-Type: application/json

{
  "token": "<sso_token>",
  "application": "hsd-portal"
}
```

### Create SSO Session
```
POST https://auth.hsdcore.com/sso/session
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "application": "hsd-portal",
  "session_id": "<primary_session_id>"
}
```

### Add Application to SSO Session
```
POST https://auth.hsdcore.com/sso/session/{sessionId}/applications
Content-Type: application/json

{
  "application": "hsd-chat"
}
```

## Legacy Token Support

For backward compatibility during migration, the platform supports legacy token conversion:

### Convert Legacy Token
```
POST https://auth.hsdcore.com/sso/legacy/convert
Content-Type: application/json

{
  "legacy_token": "<old_format_token>",
  "application": "hsd-portal"
}
```

### Validate Legacy Token
```
POST https://auth.hsdcore.com/sso/legacy/validate
Content-Type: application/json

{
  "token": "<legacy_token>"
}
```

## Integration Steps

### 1. Register Your Application

Contact the HSD Auth Platform administrator to register your application and receive:
- `client_id`
- `client_secret`
- Approved `redirect_uris`

### 2. Implement Authorization Code Flow

```typescript
// Step 1: Redirect user to authorization endpoint
const authUrl = new URL('https://auth.hsdcore.com/oauth/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', CLIENT_ID);
authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', generateRandomState());

window.location.href = authUrl.toString();

// Step 2: Handle callback and exchange code for tokens
async function handleCallback(code: string) {
  const response = await fetch('https://auth.hsdcore.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });

  const tokens = await response.json();
  // Store tokens securely
  return tokens;
}
```

### 3. Implement SSO Session Sharing

```typescript
// After successful authentication, create SSO session
async function createSSOSession(accessToken: string, sessionId: string) {
  const response = await fetch('https://auth.hsdcore.com/sso/session', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      application: 'hsd-portal',
      session_id: sessionId,
    }),
  });

  const ssoSession = await response.json();
  // Store sso_token for cross-application authentication
  return ssoSession;
}

// Validate SSO token when user navigates to another HSD application
async function validateSSOToken(ssoToken: string) {
  const response = await fetch('https://auth.hsdcore.com/sso/validate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      token: ssoToken,
      application: 'hsd-chat',
    }),
  });

  return response.json();
}
```

### 4. Handle Token Refresh

```typescript
async function refreshTokens(refreshToken: string) {
  const response = await fetch('https://auth.hsdcore.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  });

  return response.json();
}
```

## Supported Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Required for OpenID Connect. Returns `id_token` |
| `profile` | Access to user profile (name, picture) |
| `email` | Access to user email and verification status |
| `offline_access` | Returns `refresh_token` for long-lived sessions |

## Error Handling

All error responses follow OAuth 2.0 error format:

```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter: client_id"
}
```

### Common Error Codes

| Error | Description |
|-------|-------------|
| `invalid_request` | Missing or invalid parameters |
| `invalid_client` | Unknown or invalid client credentials |
| `invalid_grant` | Invalid authorization code or refresh token |
| `invalid_scope` | Requested scope is invalid or not allowed |
| `unauthorized_client` | Client not authorized for this grant type |
| `access_denied` | User denied authorization |
| `invalid_token` | Token is invalid or expired |

## Security Best Practices

1. **Always use HTTPS** for all API calls
2. **Implement PKCE** for public clients (SPAs, mobile apps)
3. **Validate state parameter** to prevent CSRF attacks
4. **Store tokens securely** - use httpOnly cookies or secure storage
5. **Implement token refresh** before expiration
6. **Validate ID token claims** including `iss`, `aud`, and `exp`

## Support

For integration support, contact the HSD Auth Platform team or refer to the API documentation at https://docs.auth.hsdcore.com.
