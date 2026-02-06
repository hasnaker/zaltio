# HSD Auth Platform - API Reference

Base URL: `https://api.auth.hsdcore.com/v1`

## Authentication

All protected endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

## Endpoints

### Authentication

#### Register User

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "realm_id": "realm-123",
  "profile": {
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

**Response (201 Created)**
```json
{
  "user": {
    "id": "user-abc123",
    "email": "user@example.com",
    "realm_id": "realm-123",
    "email_verified": false,
    "status": "pending_verification",
    "created_at": "2024-01-15T10:30:00Z"
  },
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_in": 3600
  }
}
```

**Error Responses**
- `400 Bad Request` - Invalid input data
- `409 Conflict` - Email already registered

---

#### Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "realm_id": "realm-123"
}
```

**Response (200 OK)**
```json
{
  "user": {
    "id": "user-abc123",
    "email": "user@example.com",
    "realm_id": "realm-123",
    "email_verified": true,
    "status": "active",
    "last_login": "2024-01-15T10:30:00Z"
  },
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_in": 3600
  }
}
```

**Error Responses**
- `401 Unauthorized` - Invalid credentials
- `423 Locked` - Account locked due to too many failed attempts
- `429 Too Many Requests` - Rate limit exceeded

---

#### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200 OK)**
```json
{
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_in": 3600
  }
}
```

**Error Responses**
- `401 Unauthorized` - Invalid or expired refresh token

---

#### Logout

```http
POST /auth/logout
Authorization: Bearer <access_token>
```

**Response (200 OK)**
```json
{
  "message": "Successfully logged out"
}
```

---

#### Get Current User

```http
GET /auth/me
Authorization: Bearer <access_token>
```

**Response (200 OK)**
```json
{
  "user": {
    "id": "user-abc123",
    "email": "user@example.com",
    "realm_id": "realm-123",
    "email_verified": true,
    "status": "active",
    "profile": {
      "first_name": "John",
      "last_name": "Doe",
      "avatar_url": null
    },
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  }
}
```

---

### Realm Management (Admin)

#### List Realms

```http
GET /admin/realms
Authorization: Bearer <admin_token>
```

**Response (200 OK)**
```json
{
  "realms": [
    {
      "id": "realm-123",
      "name": "HSD Portal",
      "domain": "portal.hsdcore.com",
      "settings": {
        "session_timeout": 3600,
        "mfa_required": false,
        "password_policy": {
          "min_length": 8,
          "require_uppercase": true,
          "require_lowercase": true,
          "require_numbers": true,
          "require_special_chars": false
        }
      },
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

---

#### Create Realm

```http
POST /admin/realms
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "My Application",
  "domain": "myapp.hsdcore.com",
  "settings": {
    "session_timeout": 7200,
    "mfa_required": true
  }
}
```

**Response (201 Created)**
```json
{
  "realm": {
    "id": "realm-456",
    "name": "My Application",
    "domain": "myapp.hsdcore.com",
    "settings": {...},
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

---

#### Update Realm

```http
PUT /admin/realms/{realm_id}
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "Updated Name",
  "settings": {
    "mfa_required": true
  }
}
```

---

#### Delete Realm

```http
DELETE /admin/realms/{realm_id}
Authorization: Bearer <admin_token>
```

**Response (200 OK)**
```json
{
  "message": "Realm deleted successfully",
  "deleted_users": 150,
  "deleted_sessions": 45
}
```

---

### User Management (Admin)

#### List Users

```http
GET /admin/users?realm_id=realm-123&status=active&limit=50&offset=0
Authorization: Bearer <admin_token>
```

**Query Parameters**
- `realm_id` (optional) - Filter by realm
- `status` (optional) - Filter by status: `active`, `suspended`, `pending_verification`
- `limit` (optional) - Results per page (default: 50, max: 100)
- `offset` (optional) - Pagination offset

**Response (200 OK)**
```json
{
  "users": [...],
  "total": 1250,
  "limit": 50,
  "offset": 0
}
```

---

#### Get User

```http
GET /admin/users/{user_id}
Authorization: Bearer <admin_token>
```

---

#### Update User

```http
PUT /admin/users/{user_id}
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "status": "suspended",
  "email_verified": true
}
```

---

#### Delete User

```http
DELETE /admin/users/{user_id}
Authorization: Bearer <admin_token>
```

---

#### Suspend User

```http
POST /admin/users/{user_id}/suspend
Authorization: Bearer <admin_token>
```

---

#### Activate User

```http
POST /admin/users/{user_id}/activate
Authorization: Bearer <admin_token>
```

---

### Session Management (Admin)

#### List Sessions

```http
GET /admin/sessions?user_id=user-123&realm_id=realm-123
Authorization: Bearer <admin_token>
```

---

#### Revoke Session

```http
DELETE /admin/sessions/{session_id}
Authorization: Bearer <admin_token>
```

---

#### Revoke All User Sessions

```http
DELETE /admin/users/{user_id}/sessions
Authorization: Bearer <admin_token>
```

---

### SSO Endpoints

#### Initiate SSO

```http
GET /sso/authorize?realm_id=realm-123&redirect_uri=https://app.example.com/callback
```

---

#### SSO Callback

```http
POST /sso/callback
Content-Type: application/json

{
  "code": "authorization_code",
  "state": "state_value"
}
```

---

#### Validate SSO Token

```http
POST /sso/validate
Content-Type: application/json

{
  "token": "sso_token"
}
```

---

## Error Response Format

All errors follow this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "details": {
      "field": "email",
      "reason": "Invalid format"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_abc123"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Invalid email or password |
| `TOKEN_EXPIRED` | 401 | Access token has expired |
| `TOKEN_INVALID` | 401 | Token is malformed or invalid |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `RATE_LIMITED` | 429 | Too many requests |
| `ACCOUNT_LOCKED` | 423 | Account temporarily locked |
| `INTERNAL_ERROR` | 500 | Internal server error |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/auth/login` | 10 requests/minute per IP |
| `/auth/register` | 5 requests/minute per IP |
| `/auth/refresh` | 30 requests/minute per user |
| Admin endpoints | 100 requests/minute per admin |

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1705315800
```

---

## Webhooks

Configure webhooks in the dashboard to receive notifications for:

- `user.created` - New user registration
- `user.updated` - User profile updated
- `user.deleted` - User deleted
- `user.login` - Successful login
- `user.login_failed` - Failed login attempt
- `session.created` - New session created
- `session.revoked` - Session revoked

Webhook payload:
```json
{
  "event": "user.created",
  "timestamp": "2024-01-15T10:30:00Z",
  "realm_id": "realm-123",
  "data": {
    "user_id": "user-abc123",
    "email": "user@example.com"
  }
}
```
