# Passwordless Authentication Guide

Zalt.io supports multiple passwordless authentication methods that provide enhanced security and improved user experience. This guide covers all available passwordless options.

## Overview

Passwordless authentication eliminates the need for users to remember and manage passwords, reducing:
- Password-related security vulnerabilities
- Account recovery burden
- User friction during authentication

### Available Methods

| Method | Security Level | Best For |
|--------|---------------|----------|
| **Passkeys (WebAuthn)** | Highest | All users, especially healthcare |
| **Magic Links** | High | Email-based workflows |
| **Push Notifications** | High | Mobile-first applications |

## Passkeys (WebAuthn) - Recommended

Passkeys are the most secure passwordless option, providing phishing-proof authentication using biometrics or hardware security keys.

### Why Passkeys?

- **Phishing-proof**: Cryptographically bound to the origin
- **No shared secrets**: Private keys never leave the device
- **Biometric support**: Touch ID, Face ID, Windows Hello
- **HIPAA compliant**: Mandatory for healthcare realms

### Registration Flow

```typescript
import { ZaltClient } from '@zalt/core';

const client = new ZaltClient({
  realmId: 'your-realm-id',
  publishableKey: 'pk_...'
});

// 1. Get registration options from server
const options = await client.passkeys.getRegistrationOptions();

// 2. Create credential using browser API
const credential = await navigator.credentials.create({
  publicKey: options
});

// 3. Verify and store credential
const result = await client.passkeys.verifyRegistration(credential);

if (result.success) {
  console.log('Passkey registered successfully!');
}
```

### Authentication Flow

```typescript
// 1. Get authentication options (can be empty for discoverable credentials)
const options = await client.passkeys.getAuthenticationOptions();

// 2. Get assertion from authenticator
const assertion = await navigator.credentials.get({
  publicKey: options
});

// 3. Verify and complete login
const result = await client.passkeys.verifyAuthentication(assertion);

if (result.success) {
  console.log('Logged in with passkey!');
  // Access tokens available in result.tokens
}
```

### Supported Authenticators

| Type | Examples | Use Case |
|------|----------|----------|
| Platform | Touch ID, Face ID, Windows Hello | Personal devices |
| Roaming | YubiKey, Titan Key | Shared devices, high security |

### Configuration

```typescript
// Realm-level passkey configuration
const config = {
  passkeyEnabled: true,
  passkeyRequired: false,  // Set true for healthcare realms
  customRpId: 'auth.yourcompany.com',  // Optional custom RP ID
  customRpName: 'Your Company'
};
```

## Magic Link Authentication

Magic links provide passwordless login via email. Users click a secure link to authenticate.

### How It Works

1. User enters email address
2. Zalt sends a secure magic link to their email
3. User clicks the link
4. User is authenticated and redirected to your app

### Security Features

- **Single-use tokens**: Each link can only be used once
- **15-minute expiry**: Links expire after 15 minutes
- **Rate limiting**: 5 requests per hour per email
- **IP tracking**: Request origin is logged for security

### Implementation

```typescript
// Request magic link
const result = await client.magicLink.send({
  email: 'user@example.com'
});

if (result.success) {
  console.log('Magic link sent! Check your email.');
}

// On your callback page (/auth/magic-link)
const token = new URLSearchParams(window.location.search).get('token');
const realm = new URLSearchParams(window.location.search).get('realm');

const authResult = await client.magicLink.verify({
  token,
  realmId: realm
});

if (authResult.valid) {
  // User is authenticated
  console.log('Welcome!', authResult.user);
}
```

### Email Template Customization

Magic link emails can be customized with your branding:

```typescript
// Realm branding configuration
const branding = {
  display_name: 'Your Company',
  email_from_address: 'noreply@yourcompany.com',
  email_from_name: 'Your Company',
  logo_url: 'https://yourcompany.com/logo.png',
  primary_color: '#2563eb',
  app_url: 'https://app.yourcompany.com'
};
```

### Rate Limiting

| Action | Limit | Window |
|--------|-------|--------|
| Send magic link | 5 requests | 1 hour per email |
| Verify token | 3 attempts | Per token |
| Cooldown | 60 seconds | Between requests |

## Push Notification Authentication

Push notifications allow users to approve login requests on their mobile devices.

### How It Works

1. User initiates login on web/desktop
2. Push notification sent to registered mobile device
3. User approves or denies on mobile app
4. Web/desktop session is authenticated

### Security Features

- **2-minute timeout**: Notifications expire quickly
- **Device binding**: Only registered devices receive notifications
- **Location display**: Shows request origin for verification
- **Deny option**: Users can explicitly deny suspicious requests

### Implementation

```typescript
// Initiate push authentication
const result = await client.pushAuth.send({
  userId: 'user_123',
  deviceId: 'device_456'  // Target device
});

// Poll for response
const pollResult = await client.pushAuth.poll({
  notificationId: result.notificationId
});

if (pollResult.approved) {
  console.log('Login approved!');
} else if (pollResult.denied) {
  console.log('Login denied by user');
} else if (pollResult.expired) {
  console.log('Request expired');
}
```

### Mobile App Integration

Your mobile app needs to handle push notifications:

```typescript
// Handle incoming push notification
function handlePushNotification(payload) {
  if (payload.data.type === 'auth_request') {
    // Show approval UI
    showAuthApprovalDialog({
      notificationId: payload.data.notificationId,
      location: payload.data.location,
      deviceInfo: payload.data.deviceInfo,
      expiresAt: payload.data.expiresAt
    });
  }
}

// User approves
async function approveAuth(notificationId) {
  await client.pushAuth.respond({
    notificationId,
    approved: true
  });
}

// User denies
async function denyAuth(notificationId) {
  await client.pushAuth.respond({
    notificationId,
    approved: false
  });
}
```

## Configuration

### Enabling Passwordless Methods

Configure passwordless authentication at the realm level:

```typescript
// API: Update realm passwordless config
PUT /api/v1/realms/{realmId}/passwordless

{
  "enabled": true,
  "methods": ["magic_link", "push_notification", "passkey"],
  "magicLinkEnabled": true,
  "pushAuthEnabled": true,
  "passkeyEnabled": true,
  "passkeyRequired": false,  // Set true for healthcare
  "allowedDomains": ["yourcompany.com"]
}
```

### Healthcare Realms

For HIPAA-compliant healthcare applications, passkeys are mandatory:

```typescript
const healthcareConfig = {
  enabled: true,
  passkeyEnabled: true,
  passkeyRequired: true,  // MANDATORY for healthcare
  magicLinkEnabled: false,  // Optional fallback
  pushAuthEnabled: false
};
```

## Best Practices

### 1. Offer Multiple Methods

Allow users to choose their preferred method:

```typescript
// Check available methods for user
const methods = await client.passwordless.getAvailableMethods();

// methods = ['passkey', 'magic_link', 'push_notification']
```

### 2. Graceful Fallbacks

Implement fallback authentication for edge cases:

```typescript
try {
  // Try passkey first
  await client.passkeys.authenticate();
} catch (error) {
  if (error.code === 'PASSKEY_NOT_AVAILABLE') {
    // Fall back to magic link
    await client.magicLink.send({ email: user.email });
  }
}
```

### 3. Device Registration

Encourage users to register multiple devices:

```typescript
// List registered passkeys
const passkeys = await client.passkeys.list();

if (passkeys.length < 2) {
  // Prompt user to add backup passkey
  showAddBackupPasskeyPrompt();
}
```

### 4. Security Notifications

Notify users of new device registrations:

```typescript
// Webhook: passkey.registered
{
  "event": "passkey.registered",
  "data": {
    "userId": "user_123",
    "deviceName": "Chrome on macOS",
    "timestamp": "2026-01-25T10:00:00Z"
  }
}
```

## Troubleshooting

### Passkey Issues

| Issue | Solution |
|-------|----------|
| "Authenticator not supported" | Ensure browser supports WebAuthn |
| "Origin mismatch" | Check RP ID matches your domain |
| "User verification failed" | Ensure biometrics are set up |

### Magic Link Issues

| Issue | Solution |
|-------|----------|
| "Link expired" | Request a new magic link |
| "Link already used" | Request a new magic link |
| "Rate limited" | Wait 1 hour before retrying |

### Push Notification Issues

| Issue | Solution |
|-------|----------|
| "No registered devices" | Register device in mobile app |
| "Notification expired" | Initiate new login request |
| "Device offline" | Use alternative auth method |

## API Reference

### Magic Link Endpoints

```
POST /api/v1/auth/magic-link/send
POST /api/v1/auth/magic-link/verify
```

### Push Auth Endpoints

```
POST /api/v1/auth/push/send
POST /api/v1/auth/push/respond
GET  /api/v1/auth/push/{notificationId}/status
```

### Passkey Endpoints

```
POST /api/v1/auth/passkey/register/options
POST /api/v1/auth/passkey/register/verify
POST /api/v1/auth/passkey/authenticate/options
POST /api/v1/auth/passkey/authenticate/verify
GET  /api/v1/auth/passkey/credentials
DELETE /api/v1/auth/passkey/credentials/{credentialId}
```

## Security Considerations

### No SMS MFA

⚠️ **Important**: Zalt does not support SMS-based authentication due to SS7 vulnerabilities. Use push notifications instead for mobile-based authentication.

### Audit Logging

All passwordless authentication events are logged:

- `magic_link.sent`
- `magic_link.verified`
- `magic_link.expired`
- `push_auth.sent`
- `push_auth.approved`
- `push_auth.denied`
- `passkey.registered`
- `passkey.authenticated`
- `passkey.removed`

### Rate Limiting

All passwordless endpoints are rate-limited to prevent abuse:

| Endpoint | Limit |
|----------|-------|
| Magic link send | 5/hour/email |
| Push auth send | 10/hour/user |
| Passkey operations | 100/min/user |

## Related Documentation

- [WebAuthn Guide](./webauthn.md)
- [MFA Setup Guide](./mfa-setup.md)
- [Security Best Practices](../security.md)
- [API Reference](../api-reference.md)
