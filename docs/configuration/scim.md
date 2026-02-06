# SCIM 2.0 Provisioning Configuration

Enable automated user and group provisioning from enterprise identity providers using SCIM 2.0 (System for Cross-domain Identity Management).

## Overview

SCIM 2.0 enables:
- **User Provisioning** - Automatically create users when added in IdP
- **User Deprovisioning** - Automatically suspend/delete users when removed from IdP
- **Group Sync** - Sync groups from IdP for automatic role assignment
- **Attribute Mapping** - Map IdP attributes to Zalt user profiles
- **Real-time Sync** - Immediate updates via SCIM 2.0 protocol

**Validates: Requirements 9.9** (SCIM provisioning for user/group sync from IdP)

## Supported Identity Providers

| Provider | Status | Notes |
|----------|--------|-------|
| Okta | ✅ Tested | Full SCIM 2.0 support |
| Microsoft Entra ID (Azure AD) | ✅ Tested | Full SCIM 2.0 support |
| OneLogin | ✅ Tested | Full SCIM 2.0 support |
| Google Workspace | ✅ Tested | Full SCIM 2.0 support |
| Ping Identity | ✅ Tested | Full SCIM 2.0 support |
| JumpCloud | ✅ Tested | Full SCIM 2.0 support |
| Custom SCIM | ✅ Supported | Any SCIM 2.0 compliant IdP |

## SCIM Endpoints

Base URL: `https://api.zalt.io/scim/v2`

### User Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/Users` | Create a new user |
| GET | `/Users/{id}` | Get user by ID |
| GET | `/Users` | List/search users |
| PUT | `/Users/{id}` | Replace user |
| PATCH | `/Users/{id}` | Update user attributes |
| DELETE | `/Users/{id}` | Deactivate user |

### Group Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/Groups` | Create a new group |
| GET | `/Groups/{id}` | Get group by ID |
| GET | `/Groups` | List/search groups |
| PUT | `/Groups/{id}` | Replace group |
| PATCH | `/Groups/{id}` | Update group membership |
| DELETE | `/Groups/{id}` | Delete group |

### Discovery Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ServiceProviderConfig` | Get SCIM capabilities |
| GET | `/ResourceTypes` | Get supported resource types |
| GET | `/Schemas` | Get SCIM schemas |
| POST | `/Bulk` | Bulk operations |

## Authentication

SCIM endpoints require Bearer token authentication:

```http
Authorization: Bearer <scim_token>
```

### Generating SCIM Token

1. Go to **Zalt Dashboard** → **Settings** → **Identity Providers**
2. Click **Add SCIM Connection**
3. Copy the generated Bearer token
4. Store securely in your IdP configuration

```bash
# Example: Test SCIM connection
curl -X GET https://api.zalt.io/scim/v2/ServiceProviderConfig \
  -H "Authorization: Bearer <scim_token>" \
  -H "Accept: application/scim+json"
```

## User Provisioning

### User Schema

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "john.doe@company.com",
  "name": {
    "givenName": "John",
    "familyName": "Doe",
    "formatted": "John Doe"
  },
  "displayName": "John Doe",
  "emails": [
    {
      "value": "john.doe@company.com",
      "type": "work",
      "primary": true
    }
  ],
  "phoneNumbers": [
    {
      "value": "+1234567890",
      "type": "work",
      "primary": true
    }
  ],
  "active": true,
  "externalId": "idp-user-12345"
}
```

### Enterprise User Extension

Zalt supports the Enterprise User extension for additional attributes:

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  ],
  "userName": "john.doe@company.com",
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    "employeeNumber": "EMP001",
    "department": "Engineering",
    "organization": "Zalt Inc",
    "division": "Platform",
    "costCenter": "CC-100",
    "manager": {
      "value": "manager-user-id",
      "displayName": "Jane Manager"
    }
  }
}
```

### Creating a User

```bash
curl -X POST https://api.zalt.io/scim/v2/Users \
  -H "Authorization: Bearer <scim_token>" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "john.doe@company.com",
    "name": {
      "givenName": "John",
      "familyName": "Doe"
    },
    "emails": [
      {
        "value": "john.doe@company.com",
        "type": "work",
        "primary": true
      }
    ],
    "active": true,
    "externalId": "okta-user-123"
  }'
```

**Response:**
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "user_abc123",
  "externalId": "okta-user-123",
  "userName": "john.doe@company.com",
  "name": {
    "givenName": "John",
    "familyName": "Doe",
    "formatted": "John Doe"
  },
  "active": true,
  "meta": {
    "resourceType": "User",
    "created": "2024-01-20T10:00:00Z",
    "lastModified": "2024-01-20T10:00:00Z",
    "location": "https://api.zalt.io/scim/v2/Users/user_abc123",
    "version": "W/\"abc123\""
  }
}
```

## User Deprovisioning

When a user is removed from the IdP, SCIM sends a DELETE or PATCH request to deactivate the user.

### Soft Delete (Recommended)

```bash
# PATCH to deactivate
curl -X PATCH https://api.zalt.io/scim/v2/Users/{userId} \
  -H "Authorization: Bearer <scim_token>" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "replace",
        "path": "active",
        "value": false
      }
    ]
  }'
```

### Hard Delete

```bash
curl -X DELETE https://api.zalt.io/scim/v2/Users/{userId} \
  -H "Authorization: Bearer <scim_token>"
```

**Deprovisioning Behavior:**
- User status set to `suspended` or `deleted`
- All active sessions are revoked
- User cannot login until reactivated
- User data is retained for audit purposes

## Group Sync

### Group Schema

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName": "Engineering",
  "externalId": "okta-group-eng",
  "members": [
    {
      "value": "user_abc123",
      "$ref": "https://api.zalt.io/scim/v2/Users/user_abc123",
      "display": "John Doe",
      "type": "User"
    }
  ]
}
```

### Creating a Group

```bash
curl -X POST https://api.zalt.io/scim/v2/Groups \
  -H "Authorization: Bearer <scim_token>" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Engineering",
    "externalId": "okta-group-eng",
    "members": [
      { "value": "user_abc123" }
    ]
  }'
```

### Updating Group Membership

```bash
# Add members
curl -X PATCH https://api.zalt.io/scim/v2/Groups/{groupId} \
  -H "Authorization: Bearer <scim_token>" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "add",
        "path": "members",
        "value": [{ "value": "user_xyz789" }]
      }
    ]
  }'

# Remove members
curl -X PATCH https://api.zalt.io/scim/v2/Groups/{groupId} \
  -H "Authorization: Bearer <scim_token>" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "remove",
        "path": "members[value eq \"user_abc123\"]"
      }
    ]
  }'
```

## Attribute Mapping

### Default Mappings

| SCIM Attribute | Zalt Attribute |
|----------------|----------------|
| `userName` | `email` |
| `externalId` | `external_id` |
| `name.givenName` | `profile.first_name` |
| `name.familyName` | `profile.last_name` |
| `emails[primary].value` | `email` |
| `phoneNumbers[primary].value` | `profile.phone` |
| `active` | `status` (active/suspended) |
| `enterprise.employeeNumber` | `profile.metadata.employee_number` |
| `enterprise.department` | `profile.metadata.department` |
| `enterprise.organization` | `profile.metadata.organization` |

### Custom Attribute Mapping

Configure custom mappings in the Dashboard:

1. Go to **Settings** → **SCIM** → **Attribute Mappings**
2. Add custom mappings for your IdP attributes
3. Map to Zalt user profile fields or metadata

## Group-to-Role Mapping

Automatically assign Zalt roles based on IdP group membership:

| IdP Group | Zalt Role |
|-----------|-----------|
| `Admins` | `role_admin` |
| `Developers` | `role_member` |
| `Viewers` | `role_viewer` |

### Configuring Group Mappings

```bash
curl -X POST https://api.zalt.io/v1/admin/scim/group-mappings \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "mappings": [
      { "idpGroup": "Admins", "zaltRole": "role_admin" },
      { "idpGroup": "Developers", "zaltRole": "role_member" },
      { "idpGroup": "Viewers", "zaltRole": "role_viewer" }
    ]
  }'
```

## Filtering

SCIM supports filtering users and groups:

```http
GET /scim/v2/Users?filter=userName eq "john@example.com"
GET /scim/v2/Users?filter=active eq true
GET /scim/v2/Users?filter=emails.value co "@company.com"
GET /scim/v2/Groups?filter=displayName eq "Engineering"
```

### Supported Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equal | `userName eq "john"` |
| `ne` | Not equal | `active ne false` |
| `co` | Contains | `emails.value co "@company.com"` |
| `sw` | Starts with | `userName sw "john"` |
| `ew` | Ends with | `userName ew "@company.com"` |
| `pr` | Present | `name.familyName pr` |
| `gt` | Greater than | `meta.created gt "2024-01-01"` |
| `ge` | Greater or equal | `meta.created ge "2024-01-01"` |
| `lt` | Less than | `meta.created lt "2024-12-31"` |
| `le` | Less or equal | `meta.created le "2024-12-31"` |

## Pagination

```http
GET /scim/v2/Users?startIndex=1&count=100
```

**Response:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 250,
  "startIndex": 1,
  "itemsPerPage": 100,
  "Resources": [...]
}
```

## Bulk Operations

Process multiple operations in a single request:

```bash
curl -X POST https://api.zalt.io/scim/v2/Bulk \
  -H "Authorization: Bearer <scim_token>" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user1",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "user1@company.com"
        }
      },
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user2",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "user2@company.com"
        }
      }
    ],
    "failOnErrors": 1
  }'
```

### Bulk Limits

- Maximum operations per request: **1000**
- Maximum payload size: **1MB**

## IdP Configuration Examples

### Okta

1. In Okta Admin Console, go to **Applications** → **Applications**
2. Click **Create App Integration** → **SCIM 2.0**
3. Configure:
   - SCIM connector base URL: `https://api.zalt.io/scim/v2`
   - Authentication mode: HTTP Header
   - Authorization: `Bearer <your-scim-token>`
4. Enable provisioning features:
   - ✅ Create Users
   - ✅ Update User Attributes
   - ✅ Deactivate Users
   - ✅ Push Groups

### Microsoft Entra ID (Azure AD)

1. In Azure Portal, go to **Enterprise Applications**
2. Select your application → **Provisioning**
3. Set Provisioning Mode to **Automatic**
4. Configure Admin Credentials:
   - Tenant URL: `https://api.zalt.io/scim/v2`
   - Secret Token: `<your-scim-token>`
5. Test connection and save
6. Enable provisioning

### Google Workspace

1. In Google Admin Console, go to **Apps** → **SAML Apps**
2. Select your app → **Auto-provisioning**
3. Configure:
   - Endpoint URL: `https://api.zalt.io/scim/v2`
   - Authorization: Bearer Token
4. Enable user provisioning

### OneLogin

1. In OneLogin Admin, go to **Applications**
2. Select your app → **Provisioning**
3. Enable SCIM provisioning
4. Configure:
   - SCIM Base URL: `https://api.zalt.io/scim/v2`
   - SCIM Bearer Token: `<your-scim-token>`

## Error Handling

SCIM errors follow RFC 7644 format:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "User with this userName already exists"
}
```

### Common Error Codes

| Status | scimType | Description |
|--------|----------|-------------|
| 400 | invalidValue | Invalid attribute value |
| 401 | - | Authentication required |
| 403 | - | Insufficient permissions |
| 404 | noTarget | Resource not found |
| 409 | uniqueness | Duplicate resource |
| 413 | tooLarge | Bulk request too large |
| 429 | - | Rate limit exceeded |

## Security Considerations

### Token Security
- Store SCIM tokens securely
- Rotate tokens regularly (recommended: every 90 days)
- Use separate tokens for different IdPs

### IP Allowlisting
Restrict SCIM access to IdP IP ranges:

```bash
curl -X POST https://api.zalt.io/v1/admin/scim/ip-allowlist \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "allowedIPs": [
      "52.0.0.0/8",      // Okta
      "20.0.0.0/8",      // Azure
      "35.0.0.0/8"       // Google
    ]
  }'
```

### Audit Logging
All SCIM operations are logged for compliance:
- User creation/update/deletion
- Group membership changes
- Authentication attempts
- Error events

### Rate Limiting
- **100 requests/minute** per SCIM token
- Bulk operations count as single request

## Service Provider Configuration

Get SCIM capabilities:

```bash
curl -X GET https://api.zalt.io/scim/v2/ServiceProviderConfig \
  -H "Authorization: Bearer <scim_token>"
```

**Response:**
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "documentationUri": "https://docs.zalt.io/scim",
  "patch": { "supported": true },
  "bulk": {
    "supported": true,
    "maxOperations": 1000,
    "maxPayloadSize": 1048576
  },
  "filter": {
    "supported": true,
    "maxResults": 200
  },
  "changePassword": { "supported": false },
  "sort": { "supported": true },
  "etag": { "supported": true },
  "authenticationSchemes": [
    {
      "type": "oauthbearertoken",
      "name": "OAuth Bearer Token",
      "description": "Authentication using OAuth 2.0 Bearer Token",
      "primary": true
    }
  ]
}
```

## Troubleshooting

### User Not Provisioned

1. Check SCIM token is valid
2. Verify userName (email) format
3. Check for duplicate externalId
4. Review error response details

### Group Sync Not Working

1. Verify group exists in IdP
2. Check member IDs are valid Zalt user IDs
3. Review group mapping configuration
4. Check SCIM token has group permissions

### Deprovisioning Not Working

1. Confirm user exists in Zalt
2. Check `active: false` is being sent
3. Verify SCIM token has delete permissions
4. Check audit logs for errors

### Connection Issues

1. Verify SCIM endpoint URL is correct
2. Check Bearer token is properly formatted
3. Ensure IP is in allowlist (if configured)
4. Test with ServiceProviderConfig endpoint

## API Reference

For complete API documentation, see:
- [SCIM 2.0 Core Schema (RFC 7643)](https://datatracker.ietf.org/doc/html/rfc7643)
- [SCIM 2.0 Protocol (RFC 7644)](https://datatracker.ietf.org/doc/html/rfc7644)
- [Zalt SCIM Guide](/docs/guides/scim.md)
