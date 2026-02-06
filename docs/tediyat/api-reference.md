# Tediyat API Reference

## Base URL
```
https://api.zalt.io/v1/tediyat
```

## Authentication

### Register
```http
POST /auth/register
Content-Type: application/json

{
  "email": "muhasebeci@example.com",
  "password": "SecurePass123!",
  "first_name": "Ahmet",
  "last_name": "Yılmaz",
  "company_name": "Yılmaz Muhasebe Ltd. Şti."
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "user": { "id": "user_xxx", "email": "...", "first_name": "Ahmet" },
    "tenant": { "id": "tenant_xxx", "name": "Yılmaz Muhasebe Ltd. Şti.", "slug": "yilmaz-muhasebe" },
    "tokens": { "access_token": "...", "refresh_token": "...", "expires_in": 3600 }
  }
}
```

### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "muhasebeci@example.com",
  "password": "SecurePass123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "user": { "id": "user_xxx", "email": "..." },
    "tenants": [
      { "id": "tenant_xxx", "name": "Şirket A", "slug": "sirket-a", "role": "owner" },
      { "id": "tenant_yyy", "name": "Şirket B", "slug": "sirket-b", "role": "accountant" }
    ],
    "tokens": { "access_token": "...", "refresh_token": "...", "expires_in": 3600 }
  }
}
```


### Switch Tenant
```http
POST /auth/switch/{tenantId}
Authorization: Bearer {access_token}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "tenant_id": "tenant_xxx",
    "role": "owner",
    "permissions": ["users:*", "invoices:*", "reports:read"],
    "tokens": { "access_token": "...", "refresh_token": "...", "expires_in": 3600 }
  }
}
```

## Tenant Management

### Create Tenant
```http
POST /tenants
Authorization: Bearer {access_token}
Content-Type: application/json

{ "name": "Yeni Şirket A.Ş." }
```

### List User Tenants
```http
GET /tenants
Authorization: Bearer {access_token}
```

## Member Management

### List Members
```http
GET /tenants/{tenantId}/members
Authorization: Bearer {access_token}
```

### Invite Member
```http
POST /tenants/{tenantId}/invitations
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "email": "yeni@example.com",
  "role_id": "accountant"
}
```

### Accept Invitation
```http
POST /invitations/{token}/accept
Content-Type: application/json

{
  "password": "SecurePass123!",
  "first_name": "Mehmet",
  "last_name": "Demir"
}
```

## Session Management

### List Sessions
```http
GET /auth/sessions
Authorization: Bearer {access_token}
```

### Terminate Session
```http
DELETE /auth/sessions/{sessionId}
Authorization: Bearer {access_token}
```

### Terminate All Sessions
```http
DELETE /auth/sessions?all=true
Authorization: Bearer {access_token}
```

## Roles

### List Roles
```http
GET /tenants/{tenantId}/roles
Authorization: Bearer {access_token}
```

**System Roles:** owner, admin, accountant, viewer, external_accountant

## Token Configuration
- Access Token: 1 hour (Tediyat-specific)
- Refresh Token: 30 days
- Algorithm: RS256

## Rate Limits
| Endpoint | Limit |
|----------|-------|
| Login | 5/15min/IP |
| Register | 3/hour/IP |
| API | 100/min/user |
