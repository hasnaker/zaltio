# Email Templates

Customize transactional emails sent to your users.

## Available Templates

| Template | Trigger | Variables |
|----------|---------|-----------|
| `verification` | User registration | `{{user.email}}`, `{{verification_url}}`, `{{expires_in}}` |
| `password_reset` | Password reset request | `{{user.email}}`, `{{reset_url}}`, `{{expires_in}}` |
| `welcome` | Email verified | `{{user.first_name}}`, `{{user.email}}` |
| `login_alert` | New device login | `{{user.email}}`, `{{device}}`, `{{location}}`, `{{time}}` |
| `mfa_enabled` | MFA activated | `{{user.email}}`, `{{method}}` |
| `account_locked` | Too many failed attempts | `{{user.email}}`, `{{unlock_time}}` |
| `password_changed` | Password updated | `{{user.email}}`, `{{time}}` |
| `invitation` | Team member invitation | `{{tenant_name}}`, `{{inviter_name}}`, `{{role}}`, `{{accept_url}}` |

## Default Templates

### Email Verification

**Subject:** Verify your email address

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    .container { max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; }
    .button { background: #0066FF; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; }
    .footer { color: #666; font-size: 12px; margin-top: 40px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Verify your email</h1>
    <p>Click the button below to verify your email address:</p>
    <p><a href="{{verification_url}}" class="button">Verify Email</a></p>
    <p>This link expires in {{expires_in}}.</p>
    <p>If you didn't create an account, you can ignore this email.</p>
    <div class="footer">
      <p>{{company_name}}</p>
    </div>
  </div>
</body>
</html>
```

### Password Reset

**Subject:** Reset your password

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    .container { max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; }
    .button { background: #0066FF; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; }
    .warning { background: #FFF3CD; padding: 12px; border-radius: 4px; margin: 20px 0; }
    .footer { color: #666; font-size: 12px; margin-top: 40px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Reset your password</h1>
    <p>We received a request to reset your password. Click the button below:</p>
    <p><a href="{{reset_url}}" class="button">Reset Password</a></p>
    <p>This link expires in {{expires_in}}.</p>
    <div class="warning">
      <strong>Didn't request this?</strong> Someone may be trying to access your account. 
      If you didn't request a password reset, please ignore this email and consider enabling MFA.
    </div>
    <div class="footer">
      <p>{{company_name}}</p>
    </div>
  </div>
</body>
</html>
```

### New Device Login Alert

**Subject:** New sign-in to your account

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    .container { max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; }
    .alert { background: #F8D7DA; padding: 16px; border-radius: 4px; margin: 20px 0; }
    .details { background: #F5F5F5; padding: 16px; border-radius: 4px; }
    .footer { color: #666; font-size: 12px; margin-top: 40px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>New sign-in detected</h1>
    <p>Your account was accessed from a new device:</p>
    <div class="details">
      <p><strong>Device:</strong> {{device}}</p>
      <p><strong>Location:</strong> {{location}}</p>
      <p><strong>Time:</strong> {{time}}</p>
      <p><strong>IP Address:</strong> {{ip_address}}</p>
    </div>
    <div class="alert">
      <strong>Wasn't you?</strong> 
      <a href="{{secure_account_url}}">Secure your account immediately</a>
    </div>
    <div class="footer">
      <p>{{company_name}}</p>
    </div>
  </div>
</body>
</html>
```

### Team Member Invitation

**Subject:** {{inviter_name}} invited you to join {{tenant_name}}

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    .container { max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; }
    .button { 
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
      color: white; 
      padding: 16px 32px; 
      text-decoration: none; 
      border-radius: 8px; 
      display: inline-block;
      font-weight: 600;
    }
    .invitation-card {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border-radius: 12px;
      padding: 24px;
      color: white;
    }
    .details { background: rgba(255, 255, 255, 0.15); padding: 16px; border-radius: 8px; }
    .expiry { color: #dc2626; font-weight: 500; }
    .footer { color: #666; font-size: 12px; margin-top: 40px; }
  </style>
</head>
<body>
  <div class="container">
    {{#if logo_url}}
    <div style="text-align: center; margin-bottom: 30px;">
      <img src="{{logo_url}}" alt="{{tenant_name}}" style="max-height: 50px;" />
    </div>
    {{/if}}
    
    <h1>You're Invited! 🎉</h1>
    <p>Join {{tenant_name}} on Zalt</p>
    
    <div class="invitation-card">
      <h2>Invitation Details</h2>
      <div class="details">
        <p><strong>Organization:</strong> {{tenant_name}}</p>
        <p><strong>Role:</strong> {{role}}</p>
        <p><strong>Invited by:</strong> {{inviter_name}}</p>
      </div>
    </div>
    
    {{#if custom_message}}
    <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; margin: 20px 0;">
      <p style="font-style: italic;">"{{custom_message}}"</p>
    </div>
    {{/if}}
    
    <p style="text-align: center;">
      <a href="{{accept_url}}" class="button">Accept Invitation</a>
    </p>
    
    <p class="expiry">⏰ This invitation expires in {{expires_in_days}} days</p>
    
    <div class="footer">
      <p>If you didn't expect this invitation, you can safely ignore this email.</p>
      <p>{{company_name}}</p>
    </div>
  </div>
</body>
</html>
```

**Variables:**
- `{{tenant_name}}` - Name of the organization/tenant
- `{{inviter_name}}` - Name of the person who sent the invitation
- `{{role}}` - Role being assigned (e.g., "admin", "member")
- `{{accept_url}}` - URL to accept the invitation (includes token)
- `{{custom_message}}` - Optional personal message from inviter
- `{{expires_in_days}}` - Number of days until expiration (default: 7)
- `{{logo_url}}` - Organization logo URL (optional)

**Security Notes:**
- Accept URL format: `{app_url}/invitations/accept?token={token}`
- Token is a secure, single-use cryptographic token
- Invitation expires after 7 days by default
- HTML content is escaped to prevent XSS attacks

## Custom Templates

### Using Custom Templates

1. Create your HTML template
2. Upload via Admin API or Dashboard
3. Reference in realm settings

```bash
# Upload custom template
curl -X POST https://api.zalt.io/v1/admin/realms/your-realm/email-templates \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "verification",
    "subject": "Welcome to {{company_name}} - Verify your email",
    "html": "<html>...</html>",
    "text": "Plain text version..."
  }'
```

### Template Variables

**User Variables:**
- `{{user.id}}` - User ID
- `{{user.email}}` - Email address
- `{{user.first_name}}` - First name
- `{{user.last_name}}` - Last name
- `{{user.full_name}}` - Full name

**Action Variables:**
- `{{verification_url}}` - Email verification link
- `{{reset_url}}` - Password reset link
- `{{magic_link_url}}` - Magic link login URL
- `{{expires_in}}` - Link expiration time

**Context Variables:**
- `{{device}}` - Device name/type
- `{{browser}}` - Browser name
- `{{location}}` - City, Country
- `{{ip_address}}` - IP address
- `{{time}}` - Formatted timestamp

**Branding Variables:**
- `{{company_name}}` - Your company name
- `{{logo_url}}` - Your logo URL
- `{{primary_color}}` - Brand color
- `{{support_email}}` - Support email

### Conditional Content

```html
{{#if user.first_name}}
  <p>Hi {{user.first_name}},</p>
{{else}}
  <p>Hi there,</p>
{{/if}}

{{#if mfa_enabled}}
  <p>Your account is protected with MFA.</p>
{{/if}}
```

### Localization

```json
{
  "templates": {
    "verification": {
      "en": "template-id-en",
      "de": "template-id-de",
      "fr": "template-id-fr",
      "tr": "template-id-tr"
    }
  }
}
```

## Email Delivery

### Sender Configuration

```json
{
  "email": {
    "provider": "ses",
    "from_name": "Your Company",
    "from_email": "noreply@yourcompany.com",
    "reply_to": "support@yourcompany.com"
  }
}
```

### Custom Domain (Enterprise)

Use your own domain for sending emails:

1. Add DNS records (SPF, DKIM, DMARC)
2. Verify domain in AWS SES
3. Update realm email settings

### Delivery Status

Track email delivery via webhooks:

```json
{
  "event": "email.delivered",
  "data": {
    "template": "verification",
    "recipient": "user@example.com",
    "message_id": "...",
    "timestamp": "2026-01-16T00:00:00Z"
  }
}
```

## Testing Templates

```bash
# Send test email
curl -X POST https://api.zalt.io/v1/admin/realms/your-realm/email-templates/test \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "template": "verification",
    "to": "test@yourcompany.com",
    "variables": {
      "user": {
        "first_name": "Test",
        "email": "test@example.com"
      },
      "verification_url": "https://example.com/verify?token=test"
    }
  }'
```
