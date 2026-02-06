# @zalt.io/core

Headless TypeScript client for Zalt.io authentication. Zero dependencies, works everywhere.

## Installation

```bash
npm install @zalt.io/core
```

## Quick Start

```typescript
import { createZaltClient } from '@zalt.io/core';

// Initialize with your publishable key from the Zalt.io dashboard
const zalt = createZaltClient({
  publishableKey: 'pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456',
});

// Login
const result = await zalt.login({
  email: 'user@example.com',
  password: 'SecurePassword123!',
});

if (result.mfaRequired) {
  // Handle MFA
  await zalt.mfa.verify(result.mfaSessionId, '123456');
}

// Get current user
const user = zalt.getUser();
console.log('Logged in as:', user.email);

// Logout
await zalt.logout();
```

## Features

- 🔐 **Secure by default** - httpOnly cookies, RS256 JWT
- 🔄 **Auto token refresh** - Seamless token management
- 🛡️ **MFA support** - TOTP, WebAuthn (NO SMS - SS7 vulnerability)
- 📦 **Zero dependencies** - < 5KB gzipped
- 🌐 **Universal** - Works in browser, Node.js, edge runtimes
- 🔑 **API Key based** - Simple publishableKey initialization

## API Reference

### ZaltClient

```typescript
import { createZaltClient } from '@zalt.io/core';

const zalt = createZaltClient({
  publishableKey: string;    // Required: Your publishable key (pk_live_xxx or pk_test_xxx)
  baseUrl?: string;          // Default: 'https://api.zalt.io'
  storage?: TokenStorage;    // Custom storage implementation
  autoRefresh?: boolean;     // Default: true
  debug?: boolean;           // Default: false
  timeout?: number;          // Default: 30000ms
});

// Check if running in test mode
const isTest = zalt.isTestMode(); // true if pk_test_xxx
```

### Authentication

```typescript
// Login
const result = await zalt.login({
  email: 'user@example.com',
  password: 'SecurePassword123!',
});
// Returns: { user, tokens, mfaRequired?, mfaSessionId?, mfaMethods? }

// Register
const result = await zalt.register({
  email: 'user@example.com',
  password: 'SecurePassword123!',
  profile: {
    firstName: 'John',
    lastName: 'Doe',
  },
});

// Logout
await zalt.logout();

// Get current user
const user = zalt.getUser();

// Initialize and restore session
const user = await zalt.initialize();
```

### MFA

```typescript
// Setup TOTP
const { qrCode, secret, backupCodes } = await zalt.mfa.setup('totp');

// Verify code
await zalt.mfa.verify(code);

// Get status
const status = await zalt.mfa.getStatus();

// Disable MFA
await zalt.mfa.disable(code);
```

### WebAuthn

```typescript
// Check support
const supported = await zalt.webauthn.isSupported();

// Register passkey
await zalt.webauthn.register({ name: 'My Laptop' });

// Authenticate with passkey
await zalt.webauthn.authenticate();

// List credentials
const credentials = await zalt.webauthn.listCredentials();

// Remove credential
await zalt.webauthn.removeCredential(credentialId);
```

### SMS MFA (Not Recommended)

⚠️ SMS MFA is vulnerable to SS7 attacks. Use TOTP or WebAuthn instead.

```typescript
// Setup with explicit risk acceptance
await zalt.sms.setup(phoneNumber, {
  acceptRisk: true,
  riskAcknowledgement: 'I understand SS7 vulnerabilities',
});

// Verify
await zalt.sms.verify(code);
```

### Events

```typescript
// Subscribe to auth state changes
const unsubscribe = zalt.onAuthStateChange((event, user) => {
  console.log('Auth event:', event); // 'login' | 'logout' | 'refresh' | 'error'
  console.log('User:', user);
});

// Unsubscribe
unsubscribe();
```

### Error Handling

```typescript
import { 
  ZaltError, 
  AuthenticationError, 
  RateLimitError,
  NetworkError,
  MFARequiredError 
} from '@zalt/core';

try {
  await zalt.login(email, password);
} catch (error) {
  if (error instanceof RateLimitError) {
    console.log('Retry after:', error.retryAfter, 'seconds');
  } else if (error instanceof AuthenticationError) {
    console.log('Invalid credentials');
  } else if (error instanceof MFARequiredError) {
    console.log('MFA required, session:', error.sessionId);
  }
}
```

## Security

- Tokens stored in httpOnly cookies by default
- RS256 JWT algorithm (FIPS-compliant)
- Automatic token refresh
- Rate limiting awareness
- No sensitive data logging

## License

MIT
