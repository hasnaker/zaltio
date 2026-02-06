# Realm Configuration

Realms are isolated tenant environments with their own users, settings, and policies.

## Overview

Each realm provides:
- Isolated user database
- Custom authentication policies
- Branded login experience
- Separate API credentials
- Independent audit logs

## Creating a Realm

Contact support@zalt.io to create a new realm. You'll receive:
- `realm_id` - Unique identifier
- `api_key` - For server-side operations
- `public_key` - For JWT verification

## Realm Settings

### General Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `name` | Display name | Required |
| `description` | Internal description | - |
| `status` | `active`, `suspended`, `maintenance` | `active` |
| `tier` | `free`, `pro`, `enterprise` | `free` |

### Authentication Settings

```json
{
  "auth": {
    "allow_registration": true,
    "require_email_verification": true,
    "password_policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_symbols": true,
      "max_age_days": 90,
      "history_count": 12
    },
    "session": {
      "access_token_ttl": 900,
      "refresh_token_ttl": 604800,
      "max_concurrent_sessions": 5,
      "idle_timeout": 1800
    }
  }
}
```

### MFA Settings

```json
{
  "mfa": {
    "policy": "optional",
    "methods": ["totp", "webauthn"],
    "grace_period_days": 7,
    "remember_device_days": 30
  }
}
```

**MFA Policies:**
- `disabled` - MFA not available
- `optional` - Users can enable MFA
- `encouraged` - Prompt users to enable
- `required` - Must enable MFA to use app
- `required_for_admins` - Required for admin roles only

### Security Settings

```json
{
  "security": {
    "rate_limiting": {
      "login_attempts": 5,
      "login_window_minutes": 15,
      "register_attempts": 3,
      "register_window_minutes": 60
    },
    "lockout": {
      "enabled": true,
      "threshold": 5,
      "duration_minutes": 15,
      "notify_user": true
    },
    "password_breach_check": true,
    "device_fingerprinting": true,
    "geo_velocity_check": true
  }
}
```

### Session Limits

Configure maximum concurrent sessions per user within a realm.

```json
{
  "session_limits": {
    "max_concurrent_sessions": 5,
    "limit_exceeded_action": "revoke_oldest",
    "notify_on_revoke": true,
    "enabled": true
  }
}
```

**Session Limits Configuration:**

| Setting | Description | Default |
|---------|-------------|---------|
| `max_concurrent_sessions` | Maximum active sessions per user (0 = unlimited) | `5` |
| `limit_exceeded_action` | Action when limit exceeded: `revoke_oldest` or `block_new` | `revoke_oldest` |
| `notify_on_revoke` | Send notification when session is revoked due to limit | `true` |
| `enabled` | Whether session limits are enforced | `true` |

**Limit Exceeded Actions:**
- `revoke_oldest` - Automatically revoke the oldest session to make room for the new one
- `block_new` - Block new session creation and return an error

**Healthcare Realm Defaults:**
Healthcare realms (e.g., Clinisyn) have stricter session limits for HIPAA compliance:
- `max_concurrent_sessions`: 3 (vs. 5 for standard realms)
- All other settings remain the same

**Example: Strict Session Limits**
```json
{
  "session_limits": {
    "max_concurrent_sessions": 2,
    "limit_exceeded_action": "block_new",
    "notify_on_revoke": true,
    "enabled": true
  }
}
```

**Session Revocation Webhook:**
When a session is revoked due to limit exceeded, a `session.revoked` webhook is triggered with:
```json
{
  "event": "session.revoked",
  "data": {
    "session_id": "session_xxx",
    "user_id": "user_xxx",
    "realm_id": "realm_xxx",
    "reason": "session_limit_exceeded"
  }
}
```

### Allowed Origins (CORS)

```json
{
  "allowed_origins": [
    "https://app.yourcompany.com",
    "https://admin.yourcompany.com",
    "http://localhost:3000"
  ]
}
```

### Email Settings

```json
{
  "email": {
    "from_name": "Your Company",
    "from_email": "noreply@yourcompany.com",
    "reply_to": "support@yourcompany.com",
    "templates": {
      "verification": "custom-template-id",
      "password_reset": "custom-template-id",
      "welcome": "custom-template-id"
    }
  }
}
```

### Branding

```json
{
  "branding": {
    "logo_url": "https://yourcompany.com/logo.png",
    "primary_color": "#0066FF",
    "company_name": "Your Company"
  }
}
```

### Data Residency

```json
{
  "data_residency": {
    "region": "EU",
    "allowed_regions": ["eu-central-1", "eu-west-1"]
  }
}
```

**Available Regions:**
- `EU` - European Union (Frankfurt, Ireland)
- `US` - United States (Virginia, Oregon)
- `ASIA` - Asia Pacific (Singapore, Tokyo)

## Environment-Specific Realms

Best practice: Create separate realms for each environment.

```
yourcompany-dev      → Development
yourcompany-staging  → Staging/QA
yourcompany-prod     → Production
```

## Realm Limits by Tier

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Monthly Active Users | 1,000 | 10,000 | Unlimited |
| API Requests/month | 10,000 | 100,000 | Unlimited |
| Custom Domain | ❌ | ✅ | ✅ |
| SSO/SAML | ❌ | ✅ | ✅ |
| Audit Log Retention | 7 days | 30 days | 1 year |
| Support | Community | Email | Dedicated |
| SLA | - | 99.9% | 99.99% |

## Updating Realm Settings

Settings can be updated via:
1. Admin Dashboard (coming soon)
2. Admin API
3. Contact support

```bash
# Via Admin API
curl -X PATCH https://api.zalt.io/v1/admin/realms/your-realm-id \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "settings": {
      "mfa": {
        "policy": "required"
      }
    }
  }'
```
