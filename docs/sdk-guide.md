# Zalt.io SDK Guide

Official TypeScript/JavaScript SDK for Zalt.io Authentication.

## Installation

```bash
npm install @zalt/auth-sdk
```

## Configuration

```typescript
import { ZaltAuth } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  
  // Optional settings
  autoRefresh: true,           // Auto-refresh tokens before expiry
  refreshThreshold: 300,       // Refresh 5 min before expiry
  storage: 'localStorage',     // 'localStorage' | 'sessionStorage' | 'memory'
  timeout: 10000               // Request timeout in ms
});
```

## Authentication

### Register

```typescript
const result = await auth.register({
  email: 'user@example.com',
  password: 'SecurePassword123!',
  profile: {
    first_name: 'John',
    last_name: 'Doe',
    metadata: {
      role: 'admin',
      department: 'Engineering'
    }
  }
});

console.log(result.user.id);
// User receives verification email
```

### Login

```typescript
const result = await auth.login({
  email: 'user@example.com',
  password: 'SecurePassword123!'
});

if (result.mfa_required) {
  // Redirect to MFA page
  // Store mfa_session_id for verification
  sessionStorage.setItem('mfa_session', result.mfa_session_id);
} else {
  // Login complete
  console.log('Welcome', result.user.profile.first_name);
}
```

### MFA Verification

```typescript
const mfaSessionId = sessionStorage.getItem('mfa_session');

const result = await auth.verifyMFA({
  mfa_session_id: mfaSessionId,
  code: '123456' // From authenticator app
});

console.log('Login complete', result.user);
```

### Logout

```typescript
await auth.logout();
// Tokens cleared, session invalidated
```

## User Management

### Get Current User

```typescript
const user = await auth.getCurrentUser();

if (user) {
  console.log(`Hello ${user.profile.first_name}`);
  console.log(`MFA enabled: ${user.mfa_enabled}`);
}
```

### Check Authentication Status

```typescript
const isLoggedIn = await auth.isAuthenticated();

if (!isLoggedIn) {
  window.location.href = '/login';
}
```

### Get Access Token

```typescript
// For making authenticated API calls
const token = await auth.getAccessToken();

fetch('https://your-api.com/data', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

## MFA Setup

### Enable TOTP

```typescript
// 1. Get setup data
const setup = await auth.setupMFA();

// 2. Display QR code to user
// Use setup.otpauth_url with a QR library
console.log('Secret:', setup.secret);
console.log('QR URL:', setup.otpauth_url);

// 3. User scans QR and enters code
const result = await auth.verifyMFASetup({
  code: '123456',
  secret: setup.secret
});

// 4. Store backup codes securely!
console.log('Backup codes:', result.backup_codes);
```

### Disable MFA

```typescript
await auth.disableMFA({
  code: '123456' // Current TOTP code
});
```

## WebAuthn (Passkeys)

### Register a Passkey

```typescript
// 1. Get registration options
const options = await auth.webauthn.getRegistrationOptions();

// 2. Create credential using browser API
const credential = await navigator.credentials.create({
  publicKey: options
});

// 3. Register with Zalt.io
await auth.webauthn.register(credential, 'My MacBook Pro');
```

### Login with Passkey

```typescript
// 1. Get authentication options
const options = await auth.webauthn.getAuthenticationOptions({
  email: 'user@example.com'
});

// 2. Get credential from browser
const credential = await navigator.credentials.get({
  publicKey: options
});

// 3. Authenticate
const result = await auth.webauthn.authenticate(credential);
console.log('Logged in:', result.user);
```

### Manage Passkeys

```typescript
// List all passkeys
const credentials = await auth.webauthn.listCredentials();

// Delete a passkey
await auth.webauthn.deleteCredential('credential-id');
```

## Password Management

### Request Reset

```typescript
await auth.requestPasswordReset({
  email: 'user@example.com'
});
// Email sent with reset link
```

### Confirm Reset

```typescript
// On password reset page, get token from URL
const token = new URLSearchParams(window.location.search).get('token');

await auth.confirmPasswordReset({
  token: token,
  new_password: 'NewSecurePassword456!'
});
```

## Email Verification

```typescript
// Send verification email
await auth.sendVerificationEmail();

// On verification page
const token = new URLSearchParams(window.location.search).get('token');
await auth.verifyEmail(token);
```

## Error Handling

```typescript
import { ZaltAuth, ZaltError, ZaltErrorCode } from '@zalt/auth-sdk';

try {
  await auth.login({ email, password });
} catch (error) {
  if (error instanceof ZaltError) {
    switch (error.code) {
      case ZaltErrorCode.INVALID_CREDENTIALS:
        showError('Wrong email or password');
        break;
      case ZaltErrorCode.ACCOUNT_LOCKED:
        showError('Account locked. Try again later.');
        break;
      case ZaltErrorCode.MFA_REQUIRED:
        // This shouldn't throw, handled in response
        break;
      case ZaltErrorCode.RATE_LIMITED:
        showError('Too many attempts. Please wait.');
        break;
      default:
        showError('An error occurred');
    }
  }
}
```

## React Integration

```tsx
import { ZaltAuth } from '@zalt/auth-sdk';
import { createContext, useContext, useState, useEffect } from 'react';

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id'
});

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    auth.getCurrentUser()
      .then(setUser)
      .finally(() => setLoading(false));
  }, []);

  const login = async (email, password) => {
    const result = await auth.login({ email, password });
    if (!result.mfa_required) {
      setUser(result.user);
    }
    return result;
  };

  const logout = async () => {
    await auth.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, auth }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
```

## Session Management

```typescript
// Auto-refresh is enabled by default
// Tokens refresh automatically before expiry

// Manual refresh if needed
await auth.refreshTokens();

// Listen for auth state changes
auth.onAuthStateChange((user) => {
  if (user) {
    console.log('User logged in');
  } else {
    console.log('User logged out');
  }
});
```

## TypeScript Types

```typescript
import type {
  User,
  AuthTokens,
  LoginResult,
  RegisterResult,
  MFASetupResult,
  ZaltAuthConfig
} from '@zalt/auth-sdk';
```
