# SCIM 2.0 Provisioning Guide

Zalt supports SCIM 2.0 (System for Cross-domain Identity Management) for automated user provisioning and deprovisioning from enterprise identity providers.

## Overview

SCIM 2.0 enables:
- **Automatic User Provisioning**: Users created in your IdP are automatically created in Zalt
- **Automatic Deprovisioning**: Users disabled/deleted in your IdP are automatically suspended in Zalt
- **Group Sync**: Groups from your IdP sync to Zalt for automatic role assignment
- **Attribute Mapping**: User attributes from your IdP map to Zalt user profiles

## Supported Identity Providers

- Okta
- Microsoft Entra ID (Azure AD)
- OneLogin
- Google Workspace
- Ping Identity
- JumpCloud
- Any SCIM 2.0 compliant IdP

## SCIM Endpoints

Base URL: `https://api.zalt.io/scim/v2`

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/Users` | Create a new user |
| GET | `/Users/{id}` | Get user by ID |
| GET | `/Users` | List/search users |
| PUT | `/Users/{id}` | Replace user |
| PATCH | `/Users/{id}` | Update user attributes |
| DELETE | `/Users/{id}` | Deactivate user |

### Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/Groups` | Create a new group |
| GET | `/Groups/{id}` | Get group by ID |
| GET | `/Groups` | List/search groups |
| PUT | `/Groups/{id}` | Replace group |
| PATCH | `/Groups/{id}` | Update group membership |
| DELETE | `/Groups/{id}` | Delete group |

### Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ServiceProviderConfig` | Get SCIM capabilities |
| GET | `/ResourceTypes` | Get supported resource types |
| GET | `/Schemas` | Get SCIM schemas |

## Authentication

SCIM endpoints require Bearer token authentication:

```http
Authorization: Bearer <scim_token>
```

Generate a SCIM token from your Zalt Dashboard:
1. Go to **Settings** → **Identity Providers**
2. Click **Add SCIM Connection**
3. Copy the generated Bearer token


## User Schema

### Core User Attributes

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

## Attribute Mapping

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

Response includes pagination metadata:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 250,
  "startIndex": 1,
  "itemsPerPage": 100,
  "Resources": [...]
}
```


## PATCH Operations

Update specific attributes without replacing the entire resource:

```http
PATCH /scim/v2/Users/{id}
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "active",
      "value": false
    },
    {
      "op": "add",
      "path": "phoneNumbers",
      "value": [{"value": "+1234567890", "type": "work"}]
    },
    {
      "op": "remove",
      "path": "name.middleName"
    }
  ]
}
```

### Group Membership Updates

Add members to a group:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "add",
      "path": "members",
      "value": [{"value": "user-id-123"}]
    }
  ]
}
```

Remove members from a group:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "remove",
      "path": "members[value eq \"user-id-123\"]"
    }
  ]
}
```

## Bulk Operations

Process multiple operations in a single request:

```http
POST /scim/v2/Bulk
Content-Type: application/scim+json

{
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
}
```

### Bulk Limits

- Maximum operations per request: 1000
- Maximum payload size: 1MB

## IdP Configuration Examples

### Okta

1. In Okta Admin Console, go to **Applications** → **Applications**
2. Click **Create App Integration** → **SCIM 2.0**
3. Configure:
   - SCIM connector base URL: `https://api.zalt.io/scim/v2`
   - Authentication mode: HTTP Header
   - Authorization: `Bearer <your-scim-token>`

### Microsoft Entra ID (Azure AD)

1. In Azure Portal, go to **Enterprise Applications**
2. Select your application → **Provisioning**
3. Set Provisioning Mode to **Automatic**
4. Configure Admin Credentials:
   - Tenant URL: `https://api.zalt.io/scim/v2`
   - Secret Token: `<your-scim-token>`

### Google Workspace

1. In Google Admin Console, go to **Apps** → **SAML Apps**
2. Select your app → **Auto-provisioning**
3. Configure:
   - Endpoint URL: `https://api.zalt.io/scim/v2`
   - Authorization: Bearer Token

## Group-to-Role Mapping

Configure automatic role assignment based on IdP groups:

| IdP Group | Zalt Role |
|-----------|-----------|
| `Admins` | `role_admin` |
| `Developers` | `role_member` |
| `Viewers` | `role_viewer` |

Configure in Dashboard: **Settings** → **SCIM** → **Group Mappings**

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

1. **Token Security**: Store SCIM tokens securely; rotate regularly
2. **IP Allowlisting**: Restrict SCIM access to IdP IP ranges
3. **Audit Logging**: All SCIM operations are logged for compliance
4. **Rate Limiting**: 100 requests/minute per SCIM token

## Troubleshooting

### User Not Provisioned

1. Check SCIM token is valid
2. Verify userName (email) format
3. Check for duplicate externalId

### Group Sync Not Working

1. Verify group exists in IdP
2. Check member IDs are valid
3. Review group mapping configuration

### Deprovisioning Not Working

1. Confirm user exists in Zalt
2. Check `active: false` is being sent
3. Verify SCIM token has delete permissions

## API Reference

For complete API documentation, see:
- [SCIM 2.0 Core Schema (RFC 7643)](https://datatracker.ietf.org/doc/html/rfc7643)
- [SCIM 2.0 Protocol (RFC 7644)](https://datatracker.ietf.org/doc/html/rfc7644)
