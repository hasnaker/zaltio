# @zalt/auth-sdk

Official JavaScript/TypeScript SDK for Zalt - Authentication-as-a-Service platform.

## Installation

```bash
npm install @zalt/auth-sdk
# or
yarn add @zalt/auth-sdk
# or
pnpm add @zalt/auth-sdk
```

## Quick Start

```typescript
import { ZaltAuth } from '@zalt/auth-sdk';

// Create client instance
const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id'
});

// Register a new user
const result = await auth.register({
  email: 'user@example.com',
  password: 'securePassword123',
  profile: {
    first_name: 'John',
    last_name: 'Doe'
  }
});

// Login
const loginResult = await auth.login({
  email: 'user@example.com',
  password: 'securePassword123'
});

// Get current user
const user = await auth.getCurrentUser();

// Logout
await auth.logout();
```

## Configuration

```typescript
import { ZaltAuth, BrowserStorage } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  // Required
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  
  // Optional
  timeout: 10000,           // Request timeout in ms (default: 10000)
  retryAttempts: 3,         // Number of retry attempts (default: 3)
  retryDelay: 1000,         // Delay between retries in ms (default: 1000)
  autoRefresh: true,        // Enable automatic token refresh (default: true)
  refreshThreshold: 300,    // Refresh token 5 min before expiry (default: 300)
  storage: new BrowserStorage() // Custom token storage
});
```

## API Reference

### Authentication Methods

#### `register(data: RegisterData): Promise<AuthResult>`

Register a new user account.

```typescript
const result = await auth.register({
  email: 'user@example.com',
  password: 'securePassword123',
  profile: {
    first_name: 'John',
    last_name: 'Doe',
    metadata: { role: 'developer' }
  }
});
```

#### `login(credentials: LoginCredentials): Promise<AuthResult>`

Authenticate with email and password.

```typescript
const result = await auth.login({
  email: 'user@example.com',
  password: 'securePassword123'
});
```

#### `logout(): Promise<void>`

End the current session and clear tokens.

```typescript
await auth.logout();
```

#### `refreshToken(): Promise<TokenResult>`

Manually refresh the access token.

```typescript
const tokens = await auth.refreshToken();
```

#### `getCurrentUser(): Promise<User | null>`

Get the currently authenticated user.

```typescript
const user = await auth.getCurrentUser();
if (user) {
  console.log(`Logged in as ${user.email}`);
}
```

#### `isAuthenticated(): Promise<boolean>`

Check if user is authenticated.

```typescript
if (await auth.isAuthenticated()) {
  // User is logged in
}
```

### Profile Methods

#### `updateProfile(data: ProfileUpdateData): Promise<User>`

Update user profile information.

```typescript
const updatedUser = await auth.updateProfile({
  first_name: 'Jane',
  last_name: 'Smith',
  avatar_url: 'https://example.com/avatar.jpg'
});
```

#### `changePassword(data: PasswordChangeData): Promise<void>`

Change user password.

```typescript
await auth.changePassword({
  current_password: 'oldPassword123',
  new_password: 'newSecurePassword456'
});
```

## Token Storage

The SDK provides two built-in storage implementations:

### MemoryStorage (Default)

Stores tokens in memory. Suitable for server-side applications.

```typescript
import { ZaltAuth, MemoryStorage } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  storage: new MemoryStorage()
});
```

### BrowserStorage

Stores tokens in localStorage. Suitable for browser applications.

```typescript
import { ZaltAuth, BrowserStorage } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  storage: new BrowserStorage('zalt_') // Optional prefix
});
```

### Custom Storage

Implement the `TokenStorage` interface for custom storage solutions:

```typescript
import { TokenStorage, ZaltAuth } from '@zalt/auth-sdk';

class SecureStorage implements TokenStorage {
  async getAccessToken(): Promise<string | null> {
    // Your implementation
  }
  
  async getRefreshToken(): Promise<string | null> {
    // Your implementation
  }
  
  async setTokens(accessToken: string, refreshToken: string, expiresIn: number): Promise<void> {
    // Your implementation
  }
  
  async clearTokens(): Promise<void> {
    // Your implementation
  }
}

const auth = new ZaltAuth({
  baseUrl: 'https://api.zalt.io',
  realmId: 'your-realm-id',
  storage: new SecureStorage()
});
```

## Error Handling

The SDK provides typed error classes for different error scenarios:

```typescript
import {
  ZaltAuthError,
  AuthenticationError,
  ValidationError,
  RateLimitError,
  NetworkError,
  isZaltAuthError
} from '@zalt/auth-sdk';

try {
  await auth.login({ email: 'user@example.com', password: 'wrong' });
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.log('Invalid credentials');
  } else if (error instanceof ValidationError) {
    console.log('Invalid input:', error.details);
  } else if (error instanceof RateLimitError) {
    console.log(`Rate limited. Retry after ${error.retryAfter} seconds`);
  } else if (error instanceof NetworkError) {
    console.log('Network error:', error.message);
  } else if (isZaltAuthError(error)) {
    console.log(`Error ${error.code}: ${error.message}`);
  }
}
```

## React Integration

```typescript
import { ZaltAuth } from '@zalt/auth-sdk';
import { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext<ZaltAuth | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [auth] = useState(() => new ZaltAuth({
    baseUrl: 'https://api.zalt.io',
    realmId: process.env.NEXT_PUBLIC_ZALT_REALM_ID!
  }));

  return (
    <AuthContext.Provider value={auth}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const auth = useContext(AuthContext);
  if (!auth) throw new Error('useAuth must be used within AuthProvider');
  return auth;
}
```

## TypeScript Support

The SDK is written in TypeScript and provides full type definitions:

```typescript
import type {
  User,
  AuthResult,
  TokenResult,
  RegisterData,
  LoginCredentials,
  ZaltAuthConfig
} from '@zalt/auth-sdk';
```

## License

MIT - Zalt
