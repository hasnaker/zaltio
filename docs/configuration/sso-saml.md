# SSO & SAML Integration

Enable Single Sign-On for enterprise customers with organization-level SSO configuration.

## Overview

Zalt.io supports:
- **SAML 2.0** - Enterprise identity providers (per-organization)
- **OAuth 2.0 / OIDC** - Social and custom providers (per-organization)
- **Magic Links** - Passwordless email login
- **Domain Verification** - Enforce SSO for verified domains
- **JIT Provisioning** - Just-In-Time user creation from IdP

## Organization-Level SSO

Each organization (tenant) can configure their own SSO provider, enabling:
- **Isolated IdP Configuration** - Each tenant has their own IdP settings
- **Domain Enforcement** - Block password login for verified domains
- **JIT User Provisioning** - Automatically create users on first SSO login
- **Attribute Mapping** - Map IdP attributes to Zalt user profile

### SSO Configuration Model

```typescript
interface OrgSSOConfig {
  id: string;                    // sso_config_xxx
  tenantId: string;              // Tenant this config belongs to
  realmId: string;               // Realm for this tenant
  ssoType: 'saml' | 'oidc';      // SSO protocol
  enabled: boolean;              // Is SSO enabled
  status: 'active' | 'inactive' | 'pending_verification' | 'deleted';
  providerName: string;          // e.g., "Okta", "Azure AD"
  
  // SP Configuration (Zalt.io side)
  spEntityId: string;            // Service Provider Entity ID
  acsUrl: string;                // Assertion Consumer Service URL
  sloUrl?: string;               // Single Logout URL
  
  // Domain verification
  domains: VerifiedDomain[];     // Verified domains for SSO
  enforced: boolean;             // Block password login for domain users
  
  // JIT Provisioning
  jitProvisioning: {
    enabled: boolean;
    defaultRole?: string;
    autoVerifyEmail?: boolean;
    syncGroups?: boolean;
    groupRoleMapping?: Record<string, string>;
  };
}
```

### Creating SSO Configuration

```bash
# Create SAML SSO configuration for a tenant
curl -X POST https://api.zalt.io/v1/tenants/{tenantId}/sso \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ssoType": "saml",
    "providerName": "Okta",
    "samlConfig": {
      "idpEntityId": "http://www.okta.com/exk123",
      "idpSsoUrl": "https://yourcompany.okta.com/app/.../sso",
      "idpSloUrl": "https://yourcompany.okta.com/app/.../slo",
      "idpCertificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    },
    "domains": ["acme.com"],
    "enforced": true,
    "jitProvisioning": {
      "enabled": true,
      "defaultRole": "member",
      "autoVerifyEmail": true
    }
  }'
```

### Domain Verification (Task 19.4)

Domain verification proves ownership of email domains before SSO can be enforced. This prevents unauthorized organizations from claiming domains they don't own.

#### Verification Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Admin     │     │  Zalt.io    │     │  DNS Server │     │   Admin     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │ 1. Add Domain     │                   │                   │
       │──────────────────>│                   │                   │
       │                   │                   │                   │
       │ 2. Token Response │                   │                   │
       │<──────────────────│                   │                   │
       │                   │                   │                   │
       │ 3. Add DNS TXT Record                 │                   │
       │───────────────────────────────────────>                   │
       │                   │                   │                   │
       │ 4. Verify Domain  │                   │                   │
       │──────────────────>│                   │                   │
       │                   │                   │                   │
       │                   │ 5. DNS Lookup     │                   │
       │                   │──────────────────>│                   │
       │                   │                   │                   │
       │                   │ 6. TXT Records    │                   │
       │                   │<──────────────────│                   │
       │                   │                   │                   │
       │ 7. Verified!      │                   │                   │
       │<──────────────────│                   │                   │
```

#### Domain Verification Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/tenants/{tenantId}/sso/domains` | POST | Add domain for verification |
| `/tenants/{tenantId}/sso/domains` | GET | List all domains |
| `/tenants/{tenantId}/sso/domains/{domain}` | GET | Get domain status |
| `/tenants/{tenantId}/sso/domains/{domain}/verify` | POST | Verify domain ownership |
| `/tenants/{tenantId}/sso/domains/{domain}` | DELETE | Remove domain |
| `/tenants/{tenantId}/sso/domains/{domain}/regenerate` | POST | Regenerate verification token |
| `/tenants/{tenantId}/sso/enforcement/enable` | POST | Enable SSO enforcement |
| `/tenants/{tenantId}/sso/enforcement/disable` | POST | Disable SSO enforcement |

#### Step 1: Add Domain

```bash
# Add domain to SSO configuration
curl -X POST https://api.zalt.io/v1/tenants/{tenantId}/sso/domains \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{ "domain": "acme.com" }'

# Response includes verification token and instructions
{
  "success": true,
  "domain": {
    "domain": "acme.com",
    "verificationStatus": "pending",
    "verificationToken": "zalt-verify=abc123def456789...",
    "verificationMethod": "dns_txt",
    "dnsRecordName": "_zalt-verify.acme.com",
    "dnsRecordValue": "zalt-verify=abc123def456789...",
    "expiresAt": "2024-01-27T10:00:00Z"
  },
  "instructions": {
    "step1": "Add a DNS TXT record to your domain",
    "recordName": "_zalt-verify.acme.com",
    "recordValue": "zalt-verify=abc123def456789...",
    "step2": "Wait for DNS propagation (may take up to 48 hours)",
    "step3": "Call POST /tenants/{tenantId}/sso/domains/acme.com/verify to complete verification"
  }
}
```

#### Step 2: Add DNS TXT Record

Add a TXT record to your domain's DNS configuration:

| Record Type | Name | Value |
|-------------|------|-------|
| TXT | `_zalt-verify.acme.com` | `zalt-verify=abc123def456789...` |

**DNS Provider Examples:**

**Cloudflare:**
1. Go to DNS settings
2. Add record: Type=TXT, Name=`_zalt-verify`, Content=`zalt-verify=abc123...`

**AWS Route 53:**
1. Go to Hosted Zone
2. Create Record: Type=TXT, Name=`_zalt-verify.acme.com`, Value=`"zalt-verify=abc123..."`

**GoDaddy:**
1. Go to DNS Management
2. Add TXT Record: Host=`_zalt-verify`, TXT Value=`zalt-verify=abc123...`

#### Step 3: Verify Domain

After DNS propagation (usually 5-30 minutes, up to 48 hours):

```bash
# Verify domain ownership
curl -X POST https://api.zalt.io/v1/tenants/{tenantId}/sso/domains/acme.com/verify \
  -H "Authorization: Bearer <admin_token>"

# Success response
{
  "success": true,
  "domain": "acme.com",
  "status": "verified",
  "verifiedAt": "2024-01-20T10:00:00Z",
  "message": "Domain verified successfully. You can now enable SSO enforcement."
}

# Failure response (DNS record not found)
{
  "error": "verification_failed",
  "error_description": "DNS TXT record not found. Expected record at _zalt-verify.acme.com with value: zalt-verify=abc123...",
  "details": {
    "domain": "acme.com",
    "status": "failed",
    "dnsRecordName": "_zalt-verify.acme.com",
    "hint": "Ensure the DNS TXT record is properly configured and has propagated"
  }
}
```

#### Domain Status Values

| Status | Description |
|--------|-------------|
| `pending` | Domain added, awaiting DNS verification |
| `verified` | Domain ownership confirmed |
| `failed` | Verification attempted but DNS record not found |

#### List Domains

```bash
# List all domains for a tenant
curl -X GET https://api.zalt.io/v1/tenants/{tenantId}/sso/domains \
  -H "Authorization: Bearer <admin_token>"

# Response
{
  "domains": [
    {
      "domain": "acme.com",
      "verificationStatus": "verified",
      "verificationMethod": "dns_txt",
      "dnsRecordName": "_zalt-verify.acme.com",
      "verifiedAt": "2024-01-20T10:00:00Z"
    },
    {
      "domain": "subsidiary.com",
      "verificationStatus": "pending",
      "verificationToken": "zalt-verify=xyz789...",
      "verificationMethod": "dns_txt",
      "dnsRecordName": "_zalt-verify.subsidiary.com",
      "dnsRecordValue": "zalt-verify=xyz789..."
    }
  ],
  "total": 2
}
```

#### Regenerate Verification Token

If the token expires or is compromised:

```bash
curl -X POST https://api.zalt.io/v1/tenants/{tenantId}/sso/domains/acme.com/regenerate \
  -H "Authorization: Bearer <admin_token>"
```

#### Remove Domain

```bash
curl -X DELETE https://api.zalt.io/v1/tenants/{tenantId}/sso/domains/acme.com \
  -H "Authorization: Bearer <admin_token>"
```

**Note:** Cannot remove the only verified domain while SSO enforcement is enabled.

#### Security Considerations

- **Token Uniqueness**: Each domain gets a unique verification token
- **Token Expiry**: Verification tokens expire after 7 days
- **Domain Hijacking Prevention**: Domains can only be claimed by one organization
- **Audit Logging**: All domain verification events are logged
- **DNS Propagation**: Allow up to 48 hours for DNS changes to propagate

### SSO Enforcement

SSO enforcement requires at least one verified domain. When enabled:
- Users with verified domain emails cannot use password login
- They are automatically redirected to the organization's IdP
- Password reset is disabled for these users
- New users with verified domain emails must use SSO

#### Enable SSO Enforcement

```bash
# Enable SSO enforcement (requires at least one verified domain)
curl -X POST https://api.zalt.io/v1/tenants/{tenantId}/sso/enforcement/enable \
  -H "Authorization: Bearer <admin_token>"

# Success response
{
  "success": true,
  "message": "SSO enforcement enabled. Users with verified domain emails must now use SSO to login.",
  "warning": "Password login is now blocked for users with emails matching verified domains."
}

# Error response (no verified domains)
{
  "error": "precondition_failed",
  "error_description": "At least one verified domain is required for SSO enforcement"
}
```

#### Disable SSO Enforcement

```bash
curl -X POST https://api.zalt.io/v1/tenants/{tenantId}/sso/enforcement/disable \
  -H "Authorization: Bearer <admin_token>"

# Response
{
  "success": true,
  "message": "SSO enforcement disabled. Users can now login with password or SSO."
}
```

#### Enforcement Behavior

| User Action | SSO Enforced | SSO Not Enforced |
|-------------|--------------|------------------|
| Password Login | ❌ Blocked, redirect to IdP | ✅ Allowed |
| SSO Login | ✅ Allowed | ✅ Allowed |
| Password Reset | ❌ Blocked | ✅ Allowed |
| Registration | ❌ Must use SSO | ✅ Allowed |

#### Checking SSO Enforcement

The login handler automatically checks SSO enforcement:

```typescript
// In your login handler
import { checkSSOEnforcement } from '../services/domain-verification.service';

const enforcement = await checkSSOEnforcement(email);

if (enforcement.enforced) {
  // Redirect to SSO login
  return {
    statusCode: 403,
    body: JSON.stringify({
      error: 'sso_required',
      error_description: 'SSO is required for this domain',
      sso_type: enforcement.ssoType,
      provider: enforcement.providerName,
      tenant_id: enforcement.tenantId
    })
  };
}
```

## SAML 2.0 Configuration

### SAML 2.0 Per Organization (Task 19.2)

Zalt.io implements full SAML 2.0 Web Browser SSO Profile with SP-initiated flow:

**Features:**
- ✅ SP-initiated SSO flow
- ✅ IdP metadata parsing
- ✅ SAML assertion validation
- ✅ Attribute mapping
- ✅ Replay attack prevention (InResponseTo validation)
- ✅ Clock skew tolerance (5 minutes)
- ✅ JIT user provisioning
- ✅ Single Logout (SLO) support

### SAML Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sso/saml/{realmId}/{tenantId}/login` | GET | Initiate SP-initiated SSO |
| `/sso/saml/{realmId}/{tenantId}/acs` | POST | Assertion Consumer Service |
| `/sso/saml/{realmId}/{tenantId}/metadata` | GET | SP Metadata XML |
| `/sso/saml/{realmId}/{tenantId}/slo` | POST | Single Logout |
| `/sso/saml/{realmId}/{tenantId}/logout` | GET | Initiate SP-initiated logout |

### SP-Initiated SSO Flow

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  User   │     │Your App │     │ Zalt.io │     │   IdP   │
└────┬────┘     └────┬────┘     └────┬────┘     └────┬────┘
     │               │               │               │
     │ 1. Login      │               │               │
     │──────────────>│               │               │
     │               │               │               │
     │               │ 2. Redirect   │               │
     │               │──────────────>│               │
     │               │               │               │
     │               │               │ 3. AuthnRequest│
     │               │               │──────────────>│
     │               │               │               │
     │               │               │ 4. User Auth  │
     │<──────────────────────────────────────────────│
     │               │               │               │
     │ 5. Credentials│               │               │
     │──────────────────────────────────────────────>│
     │               │               │               │
     │               │               │ 6. SAML Response
     │               │               │<──────────────│
     │               │               │               │
     │               │ 7. JWT Tokens │               │
     │               │<──────────────│               │
     │               │               │               │
     │ 8. Logged In  │               │               │
     │<──────────────│               │               │
```

### Initiating SAML Login

```typescript
// Redirect user to SAML login
const loginUrl = `https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}/login`;
const params = new URLSearchParams({
  redirect_uri: 'https://yourapp.com/auth/callback',
  force_authn: 'false' // Set to 'true' to force re-authentication
});

window.location.href = `${loginUrl}?${params}`;
```

### Handling ACS Response

The ACS endpoint processes the SAML Response from the IdP:

**With redirect_uri (recommended):**
```
User is redirected to:
https://yourapp.com/auth/callback?access_token=xxx&token_type=Bearer&expires_in=900
```

**Without redirect_uri (JSON response):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "rt_xxx...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "user_xxx",
    "email": "user@acme.com",
    "firstName": "John",
    "lastName": "Doe"
  },
  "sso": {
    "provider": "Okta",
    "sessionIndex": "_session_xxx"
  }
}
```

### SP Metadata

Get the SP metadata XML to configure your IdP:

```bash
curl https://api.zalt.io/v1/sso/saml/{realmId}/{tenantId}/metadata
```

Response:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://api.zalt.io/v1/sso/saml/{realmId}/{tenantId}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://api.zalt.io/v1/sso/saml/{realmId}/{tenantId}/acs"
            index="0" isDefault="true"/>
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://api.zalt.io/v1/sso/saml/{realmId}/{tenantId}/slo"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
```

### Supported Identity Providers

| Provider | Status | Notes |
|----------|--------|-------|
| Okta | ✅ Tested | Full support |
| Azure AD | ✅ Tested | Full support |
| Google Workspace | ✅ Tested | Full support |
| OneLogin | ✅ Tested | Full support |
| Auth0 | ✅ Tested | Full support |
| PingIdentity | ✅ Tested | Full support |
| ADFS | ✅ Tested | Full support |
| Custom SAML | ✅ Supported | Any SAML 2.0 IdP |

### Zalt.io as Service Provider (SP)

**SP Metadata URL:**
```
https://api.zalt.io/v1/sso/saml/{realm_id}/metadata
```

**SP Configuration:**
| Setting | Value |
|---------|-------|
| Entity ID | `https://api.zalt.io/v1/sso/saml/{realm_id}` |
| ACS URL | `https://api.zalt.io/v1/sso/saml/{realm_id}/acs` |
| SLO URL | `https://api.zalt.io/v1/sso/saml/{realm_id}/slo` |
| Name ID Format | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |

### Setting Up SAML

#### Step 1: Get IdP Metadata

From your identity provider, obtain:
- IdP Entity ID
- SSO URL
- SLO URL (optional)
- X.509 Certificate

#### Step 2: Configure in Zalt.io

```bash
curl -X POST https://api.zalt.io/v1/admin/realms/your-realm/sso/saml \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Okta",
    "idp_entity_id": "http://www.okta.com/exk123",
    "idp_sso_url": "https://yourcompany.okta.com/app/...",
    "idp_slo_url": "https://yourcompany.okta.com/app/.../slo",
    "idp_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "attribute_mapping": {
      "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
      "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    },
    "auto_create_users": true,
    "default_role": "user"
  }'
```

#### Step 3: Configure Your IdP

Add Zalt.io as an application in your IdP:

**Okta:**
1. Admin → Applications → Create App Integration
2. Select SAML 2.0
3. Enter ACS URL and Entity ID from above
4. Configure attribute statements

**Azure AD:**
1. Azure Portal → Enterprise Applications → New Application
2. Create your own application → Non-gallery
3. Set up single sign-on → SAML
4. Enter Basic SAML Configuration

**Google Workspace:**
1. Admin Console → Apps → Web and mobile apps
2. Add App → Add custom SAML app
3. Enter SP details

### SAML Login Flow

```
User → Your App → Zalt.io → IdP → Zalt.io → Your App
         │                                      │
         └──────── SAML Request ───────────────┘
                                                │
         ┌──────── SAML Response ──────────────┘
         │
         └→ JWT Tokens
```

**Initiate SAML Login:**
```typescript
// Redirect user to SAML login
window.location.href = `https://api.zalt.io/v1/sso/saml/${realmId}/login?redirect_uri=${encodeURIComponent(callbackUrl)}`;
```

**Handle Callback:**
```typescript
// On your callback page
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');

// Exchange code for tokens
const response = await fetch('https://api.zalt.io/v1/sso/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: callbackUrl
  })
});

const { access_token, refresh_token } = await response.json();
```

## OAuth 2.0 / Social Login

### Supported Providers

| Provider | Scopes |
|----------|--------|
| Google | `email`, `profile` |
| Microsoft | `email`, `profile`, `openid` |
| Apple | `email`, `name` |
| GitHub | `user:email` |
| LinkedIn | `r_emailaddress`, `r_liteprofile` |

### Configuring Social Login

```bash
curl -X POST https://api.zalt.io/v1/admin/realms/your-realm/sso/oauth \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "google",
    "client_id": "your-google-client-id",
    "client_secret": "your-google-client-secret",
    "enabled": true
  }'
```

### OAuth Login Flow

```typescript
// Initiate OAuth login
const loginUrl = `https://api.zalt.io/v1/sso/oauth/${realmId}/google?redirect_uri=${encodeURIComponent(callbackUrl)}`;
window.location.href = loginUrl;

// Handle callback (same as SAML)
```

### Custom OAuth Provider

```bash
curl -X POST https://api.zalt.io/v1/admin/realms/your-realm/sso/oauth \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "custom",
    "name": "Corporate IdP",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "authorization_url": "https://idp.corp.com/oauth/authorize",
    "token_url": "https://idp.corp.com/oauth/token",
    "userinfo_url": "https://idp.corp.com/oauth/userinfo",
    "scopes": ["openid", "email", "profile"],
    "attribute_mapping": {
      "email": "email",
      "first_name": "given_name",
      "last_name": "family_name"
    }
  }'
```

## Magic Links (Passwordless)

### Enable Magic Links

```bash
curl -X PATCH https://api.zalt.io/v1/admin/realms/your-realm \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "settings": {
      "auth": {
        "magic_link_enabled": true,
        "magic_link_ttl": 600
      }
    }
  }'
```

### Request Magic Link

```bash
curl -X POST https://api.zalt.io/v1/auth/magic-link \
  -H "Content-Type: application/json" \
  -d '{
    "realm_id": "your-realm",
    "email": "user@example.com",
    "redirect_uri": "https://yourapp.com/auth/callback"
  }'
```

### Handle Magic Link Callback

```typescript
// User clicks link in email, lands on your callback
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get('token');

const response = await fetch('https://api.zalt.io/v1/auth/magic-link/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token })
});

const { user, tokens } = await response.json();
```

## Just-In-Time (JIT) Provisioning

Automatically create users on first SSO login:

```json
{
  "sso": {
    "jit_provisioning": {
      "enabled": true,
      "default_role": "user",
      "auto_verify_email": true,
      "attribute_mapping": {
        "email": "email",
        "first_name": "given_name",
        "last_name": "family_name",
        "department": "department",
        "employee_id": "employee_number"
      }
    }
  }
}
```

## Domain-Based SSO Routing

Automatically route users to their IdP based on email domain:

```bash
curl -X POST https://api.zalt.io/v1/admin/realms/your-realm/sso/domain-routing \
  -H "Authorization: Bearer <admin_token>" \
  -d '{
    "domain": "acme.com",
    "sso_connection_id": "sso_okta_123",
    "enforce": true
  }'
```

When a user with `@acme.com` email tries to login, they're automatically redirected to Okta.

## Security Considerations

### SAML Security

- ✅ Signed assertions required
- ✅ Encrypted assertions supported
- ✅ Replay attack prevention
- ✅ Clock skew tolerance (5 minutes)

### Session Linking

SSO sessions are linked to Zalt.io sessions:
- IdP logout triggers Zalt.io logout (if SLO configured)
- Zalt.io logout can trigger IdP logout

### MFA with SSO

Options for MFA when using SSO:
1. **IdP-side MFA** - MFA handled by identity provider
2. **Zalt.io MFA** - Additional MFA after SSO (step-up auth)
3. **Hybrid** - IdP MFA + Zalt.io WebAuthn for sensitive operations


## OIDC Per Organization (Task 19.3)

Zalt.io supports OpenID Connect 1.0 for organization-level SSO with the following providers:

### Supported OIDC Providers

| Provider | Status | Discovery URL |
|----------|--------|---------------|
| Google Workspace | ✅ Tested | `https://accounts.google.com/.well-known/openid-configuration` |
| Microsoft Entra (Azure AD) | ✅ Tested | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` |
| Okta | ✅ Tested | `https://{domain}/.well-known/openid-configuration` |
| Auth0 | ✅ Tested | `https://{domain}/.well-known/openid-configuration` |
| OneLogin | ✅ Tested | `https://{subdomain}.onelogin.com/oidc/2/.well-known/openid-configuration` |
| Custom OIDC | ✅ Supported | Any OIDC-compliant provider |

### OIDC Configuration

```typescript
interface OIDCConfig {
  providerPreset?: 'google_workspace' | 'microsoft_entra' | 'okta' | 'auth0' | 'onelogin' | 'custom';
  issuer: string;                      // OIDC issuer URL
  clientId: string;                    // OAuth client ID
  clientSecretEncrypted?: string;      // Encrypted client secret
  authorizationUrl?: string;           // Authorization endpoint (auto-discovered)
  tokenUrl?: string;                   // Token endpoint (auto-discovered)
  userinfoUrl?: string;                // Userinfo endpoint (auto-discovered)
  jwksUrl?: string;                    // JWKS endpoint (auto-discovered)
  scopes?: string[];                   // OAuth scopes (default: openid, email, profile)
}
```

### Creating OIDC SSO Configuration

```bash
# Create OIDC SSO configuration for Google Workspace
curl -X POST https://api.zalt.io/v1/tenants/{tenantId}/sso \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ssoType": "oidc",
    "providerName": "Google Workspace",
    "oidcConfig": {
      "providerPreset": "google_workspace",
      "issuer": "https://accounts.google.com",
      "clientId": "your-google-client-id.apps.googleusercontent.com",
      "clientSecretEncrypted": "your-encrypted-client-secret",
      "scopes": ["openid", "email", "profile"]
    },
    "domains": ["yourcompany.com"],
    "enforced": true,
    "jitProvisioning": {
      "enabled": true,
      "defaultRole": "member",
      "autoVerifyEmail": true
    }
  }'
```

### OIDC Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sso/oidc/{realmId}/{tenantId}/login` | GET | Initiate OIDC SSO |
| `/sso/oidc/{realmId}/{tenantId}/callback` | GET | OIDC callback (authorization code) |
| `/sso/oidc/{realmId}/{tenantId}/logout` | GET | Initiate logout |

### OIDC Authorization Code Flow with PKCE

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  User   │     │Your App │     │ Zalt.io │     │   IdP   │
└────┬────┘     └────┬────┘     └────┬────┘     └────┬────┘
     │               │               │               │
     │ 1. Login      │               │               │
     │──────────────>│               │               │
     │               │               │               │
     │               │ 2. Redirect   │               │
     │               │──────────────>│               │
     │               │               │               │
     │               │               │ 3. Auth URL   │
     │               │               │ (with PKCE)   │
     │               │               │──────────────>│
     │               │               │               │
     │               │               │ 4. User Auth  │
     │<──────────────────────────────────────────────│
     │               │               │               │
     │ 5. Credentials│               │               │
     │──────────────────────────────────────────────>│
     │               │               │               │
     │               │               │ 6. Auth Code  │
     │               │               │<──────────────│
     │               │               │               │
     │               │               │ 7. Token      │
     │               │               │ Exchange      │
     │               │               │──────────────>│
     │               │               │               │
     │               │               │ 8. ID Token   │
     │               │               │<──────────────│
     │               │               │               │
     │               │ 9. JWT Tokens │               │
     │               │<──────────────│               │
     │               │               │               │
     │ 10. Logged In │               │               │
     │<──────────────│               │               │
```

### Initiating OIDC Login

```typescript
// Redirect user to OIDC login
const loginUrl = `https://api.zalt.io/v1/sso/oidc/${realmId}/${tenantId}/login`;
const params = new URLSearchParams({
  redirect_uri: 'https://yourapp.com/auth/callback',
  force_login: 'false',  // Set to 'true' to force re-authentication
  login_hint: 'user@yourcompany.com'  // Optional: pre-fill email
});

window.location.href = `${loginUrl}?${params}`;
```

### Handling OIDC Callback

**With redirect_uri (recommended):**
```
User is redirected to:
https://yourapp.com/auth/callback?access_token=xxx&token_type=Bearer&expires_in=900
```

**Without redirect_uri (JSON response):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "rt_xxx...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "user_xxx",
    "email": "user@yourcompany.com",
    "firstName": "John",
    "lastName": "Doe"
  },
  "sso": {
    "provider": "Google Workspace",
    "providerType": "oidc"
  }
}
```

### Provider-Specific Configuration

#### Google Workspace

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create OAuth 2.0 credentials
3. Add authorized redirect URI: `https://api.zalt.io/v1/sso/oidc/{realmId}/{tenantId}/callback`
4. Enable Google Workspace domain restriction if needed

```json
{
  "ssoType": "oidc",
  "providerName": "Google Workspace",
  "oidcConfig": {
    "providerPreset": "google_workspace",
    "issuer": "https://accounts.google.com",
    "clientId": "xxx.apps.googleusercontent.com",
    "clientSecretEncrypted": "encrypted_secret",
    "scopes": ["openid", "email", "profile"]
  }
}
```

#### Microsoft Entra (Azure AD)

1. Go to [Azure Portal](https://portal.azure.com/) → Azure Active Directory
2. Register a new application
3. Add redirect URI: `https://api.zalt.io/v1/sso/oidc/{realmId}/{tenantId}/callback`
4. Create client secret

```json
{
  "ssoType": "oidc",
  "providerName": "Microsoft Entra",
  "oidcConfig": {
    "providerPreset": "microsoft_entra",
    "issuer": "https://login.microsoftonline.com/{tenant-id}/v2.0",
    "clientId": "your-application-id",
    "clientSecretEncrypted": "encrypted_secret",
    "scopes": ["openid", "email", "profile", "offline_access"]
  }
}
```

#### Okta

1. Go to Okta Admin Console
2. Create a new OIDC application
3. Add redirect URI: `https://api.zalt.io/v1/sso/oidc/{realmId}/{tenantId}/callback`
4. Note the client ID and secret

```json
{
  "ssoType": "oidc",
  "providerName": "Okta",
  "oidcConfig": {
    "providerPreset": "okta",
    "issuer": "https://yourcompany.okta.com",
    "clientId": "your-client-id",
    "clientSecretEncrypted": "encrypted_secret",
    "scopes": ["openid", "email", "profile", "groups"]
  }
}
```

#### Custom OIDC Provider

For any OIDC-compliant provider:

```json
{
  "ssoType": "oidc",
  "providerName": "Custom IdP",
  "oidcConfig": {
    "providerPreset": "custom",
    "issuer": "https://idp.yourcompany.com",
    "clientId": "your-client-id",
    "clientSecretEncrypted": "encrypted_secret",
    "authorizationUrl": "https://idp.yourcompany.com/oauth/authorize",
    "tokenUrl": "https://idp.yourcompany.com/oauth/token",
    "userinfoUrl": "https://idp.yourcompany.com/oauth/userinfo",
    "jwksUrl": "https://idp.yourcompany.com/.well-known/jwks.json",
    "scopes": ["openid", "email", "profile"]
  }
}
```

### Attribute Mapping

Map IdP claims to Zalt user profile:

```json
{
  "attributeMapping": {
    "email": "email",
    "firstName": "given_name",
    "lastName": "family_name",
    "displayName": "name",
    "groups": "groups"
  }
}
```

### Security Features

- **PKCE (Proof Key for Code Exchange)**: All OIDC flows use PKCE with S256 challenge method
- **State Parameter**: Encrypted state for CSRF protection
- **Nonce**: ID token replay protection
- **ID Token Validation**: Signature, issuer, audience, expiration validation
- **Clock Skew Tolerance**: 5 minutes for time-based validations

### Error Handling

| Error | Description |
|-------|-------------|
| `invalid_request` | Missing required parameters |
| `not_found` | SSO not configured for organization |
| `sso_disabled` | SSO is disabled for organization |
| `authentication_failed` | OIDC authentication failed |
| `user_creation_failed` | JIT provisioning failed |


## SSO Enforcement Middleware (Task 19.5)

The SSO enforcement middleware automatically blocks password login when SSO is enforced for an organization's verified domain.

### How It Works

When a user attempts to login with email/password:

1. **Email Domain Check**: The middleware extracts the email domain from the login request
2. **SSO Enforcement Lookup**: Checks if SSO is enforced for that domain
3. **Block or Allow**: If enforced, returns 403 with redirect URL; otherwise allows password login

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐
│   User      │     │  SSO Enforcement    │     │   Login     │
│   Login     │────>│    Middleware       │────>│   Handler   │
└─────────────┘     └─────────────────────┘     └─────────────┘
                            │
                            │ SSO Enforced?
                            │
                    ┌───────┴───────┐
                    │               │
                   YES              NO
                    │               │
                    ▼               ▼
            ┌───────────────┐  ┌───────────────┐
            │ 403 Response  │  │ Continue to   │
            │ + Redirect    │  │ Password Auth │
            └───────────────┘  └───────────────┘
```

### Response When SSO is Enforced

```json
{
  "error": {
    "code": "SSO_REQUIRED",
    "message": "Password login is not allowed for this organization. Please use SSO.",
    "sso_required": true,
    "sso_type": "saml",
    "provider_name": "Okta",
    "redirect_url": "https://api.zalt.io/v1/sso/saml/initiate?tenant_id=tenant_123&login_hint=user%40acme.com",
    "tenant_id": "tenant_123"
  }
}
```

### Client-Side Handling

```typescript
// Handle login response
const response = await fetch('/v1/auth/login', {
  method: 'POST',
  body: JSON.stringify({ email, password, realm_id })
});

if (response.status === 403) {
  const data = await response.json();
  
  if (data.error.code === 'SSO_REQUIRED') {
    // Redirect to SSO login
    window.location.href = data.error.redirect_url;
    return;
  }
}

// Handle normal login response
```

### SDK Integration

The Zalt SDK automatically handles SSO enforcement:

```typescript
import { ZaltAuth } from '@zalt/auth-sdk';

const auth = new ZaltAuth({ realmId: 'your-realm' });

try {
  const result = await auth.login({ email, password });
  // Login successful
} catch (error) {
  if (error.code === 'SSO_REQUIRED') {
    // SDK automatically redirects to SSO
    // Or you can handle manually:
    window.location.href = error.redirectUrl;
  }
}
```

### Middleware Options

The middleware supports several configuration options:

```typescript
interface SSOEnforcementMiddlewareOptions {
  /** Skip enforcement check (for testing) */
  skipEnforcement?: boolean;
  
  /** Custom realm ID (if not in request body) */
  realmId?: string;
  
  /** Allow bypass for specific emails (admin override) */
  bypassEmails?: string[];
}
```

### Bypass Emails

For emergency access or admin accounts, you can configure bypass emails:

```typescript
// In your login handler
import { ssoEnforcementMiddleware } from '../middleware/sso-enforcement.middleware';

const enforcementResponse = await ssoEnforcementMiddleware(event, {
  bypassEmails: ['admin@acme.com', 'emergency@acme.com']
});
```

**⚠️ Security Warning**: Use bypass emails sparingly and only for emergency access. All bypasses are logged for audit purposes.

### Audit Logging

All SSO enforcement events are logged:

| Event | Description |
|-------|-------------|
| `password_login_blocked_sso_enforced` | Password login blocked, user redirected to SSO |
| `sso_enforcement_bypassed` | Login allowed via bypass email |
| `sso_enforcement_check_error` | Error during enforcement check (fail-open) |

### Error Handling

The middleware follows a **fail-open** strategy:
- If the SSO enforcement check fails (database error, etc.), password login is allowed
- All errors are logged for investigation
- This prevents SSO configuration issues from locking out all users

### Requirements

For SSO enforcement to work:
1. ✅ SSO must be configured for the tenant
2. ✅ SSO must be enabled (`enabled: true`)
3. ✅ At least one domain must be verified
4. ✅ Enforcement must be enabled (`enforced: true`)

### Related Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /tenants/{tenantId}/sso/enforcement/enable` | Enable SSO enforcement |
| `POST /tenants/{tenantId}/sso/enforcement/disable` | Disable SSO enforcement |
| `GET /tenants/{tenantId}/sso` | Get SSO configuration including enforcement status |

### Validates

- **Requirement 9.4**: WHEN user from SSO domain signs in THEN redirect to org's IdP
- **Requirement 9.6**: WHEN SSO enforced THEN block password login for org members
