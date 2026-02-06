# Getting Started with Zalt.io

Get your application authenticated in 5 minutes.

## Prerequisites

- Node.js 16+ or any HTTP client
- Your Realm ID (provided by Zalt.io)

## Installation

```bash
# NPM
npm install @zalt/auth-sdk

# Yarn
yarn add @zalt/auth-sdk

# Or use the API directly - no SDK required
```

## Quick Start

### 1. Initialize the Client

```typescript
import { ZaltAuth } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  autoRefresh: true
});
```

### 2. Register a User

```typescript
const result = await auth.register({
  email: 'user@example.com',
  password: 'SecurePassword123!',
  profile: {
    first_name: 'John',
    last_name: 'Doe'
  }
});

// User receives verification email
console.log('User ID:', result.user.id);
```

### 3. Login

```typescript
const result = await auth.login({
  email: 'user@example.com',
  password: 'SecurePassword123!'
});

if (result.mfa_required) {
  // Handle MFA challenge
  const mfaResult = await auth.verifyMFA({
    mfa_session_id: result.mfa_session_id,
    code: '123456' // From authenticator app
  });
}

// Store tokens securely
console.log('Access Token:', result.tokens.access_token);
```

### 4. Make Authenticated Requests

```typescript
// SDK handles token refresh automatically
const user = await auth.getCurrentUser();

// Or manually include the token
fetch('https://your-api.com/protected', {
  headers: {
    'Authorization': `Bearer ${result.tokens.access_token}`
  }
});
```

### 5. Logout

```typescript
await auth.logout();
```

## Without SDK (Direct API)

```bash
# Register
curl -X POST https://api.zalt.io/register \
  -H "Content-Type: application/json" \
  -d '{
    "realm_id": "your-realm-id",
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "profile": {"first_name": "John", "last_name": "Doe"}
  }'

# Login
curl -X POST https://api.zalt.io/login \
  -H "Content-Type: application/json" \
  -d '{
    "realm_id": "your-realm-id",
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

## Next Steps

- [API Reference](./api-reference.md) - Full endpoint documentation
- [SDK Guide](./sdk-guide.md) - Advanced SDK features
- [Security](./security.md) - MFA, WebAuthn setup
