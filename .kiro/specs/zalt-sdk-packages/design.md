# Design Document

## Overview

Zalt SDK Packages provide an Apple-level developer experience for authentication. The architecture follows a layered approach: a headless core client that can be used standalone, framework-specific adapters (React, Next.js), and premium UI components. The design prioritizes type safety, security, minimal bundle size, and "it just works" simplicity.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Developer Application                     │
├─────────────────────────────────────────────────────────────┤
│  @zalt/next                    │  @zalt/react               │
│  ┌─────────────────────────┐   │  ┌─────────────────────┐   │
│  │ zaltMiddleware()        │   │  │ <ZaltProvider>      │   │
│  │ getAuth()               │   │  │ useAuth()           │   │
│  │ currentUser()           │   │  │ useUser()           │   │
│  │ withAuth() HOC          │   │  │ <SignedIn/Out>      │   │
│  └─────────────────────────┘   │  │ <UserButton>        │   │
│                                │  └─────────────────────┘   │
├────────────────────────────────┴────────────────────────────┤
│                        @zalt/core                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  ZaltClient                                           │   │
│  │  ├── auth: login, register, logout, refresh          │   │
│  │  ├── mfa: setup, verify, disable                     │   │
│  │  ├── webauthn: register, authenticate                │   │
│  │  ├── user: getProfile, updateProfile                 │   │
│  │  └── events: onAuthStateChange                       │   │
│  ├──────────────────────────────────────────────────────┤   │
│  │  TokenManager          │  Storage Adapters            │   │
│  │  ├── store()           │  ├── MemoryStorage          │   │
│  │  ├── get()             │  ├── BrowserStorage         │   │
│  │  ├── refresh()         │  ├── CookieStorage          │   │
│  │  └── clear()           │  └── CustomStorage          │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                     Zalt API (api.zalt.io)                   │
└─────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### @zalt/core

```typescript
// Configuration
interface ZaltConfig {
  realmId: string;
  baseUrl?: string;  // default: https://api.zalt.io
  storage?: TokenStorage;
  autoRefresh?: boolean;  // default: true
  debug?: boolean;
}

// Main Client
interface ZaltClient {
  // Auth
  login(credentials: LoginCredentials): Promise<AuthResult>;
  register(data: RegisterData): Promise<AuthResult>;
  logout(): Promise<void>;
  refreshToken(): Promise<TokenResult>;
  
  // User
  getUser(): User | null;
  updateProfile(data: ProfileUpdate): Promise<User>;
  
  // MFA
  mfa: {
    setup(method: 'totp'): Promise<MFASetupResult>;
    verify(code: string): Promise<MFAVerifyResult>;
    disable(code: string): Promise<void>;
    getStatus(): Promise<MFAStatus>;
  };
  
  // WebAuthn
  webauthn: {
    register(): Promise<WebAuthnCredential>;
    authenticate(): Promise<AuthResult>;
    listCredentials(): Promise<WebAuthnCredential[]>;
    removeCredential(id: string): Promise<void>;
  };
  
  // Events
  onAuthStateChange(callback: (state: AuthState) => void): () => void;
}

// Factory
function createZaltClient(config: ZaltConfig): ZaltClient;
```

### @zalt/react

```typescript
// Provider
interface ZaltProviderProps {
  realmId: string;
  children: React.ReactNode;
  baseUrl?: string;
  appearance?: AppearanceConfig;
}

function ZaltProvider(props: ZaltProviderProps): JSX.Element;

// Hooks
function useAuth(): {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  signIn: (email: string, password: string) => Promise<AuthResult>;
  signUp: (data: RegisterData) => Promise<AuthResult>;
  signOut: () => Promise<void>;
};

function useUser(): User | null;

function useMFA(): {
  isRequired: boolean;
  sessionId: string | null;
  verify: (code: string) => Promise<void>;
  methods: MFAMethod[];
};

function useZaltClient(): ZaltClient;

// Components
function SignedIn(props: { children: React.ReactNode }): JSX.Element | null;
function SignedOut(props: { children: React.ReactNode }): JSX.Element | null;
function UserButton(props: UserButtonProps): JSX.Element;
function SignInButton(props: ButtonProps): JSX.Element;
function SignUpButton(props: ButtonProps): JSX.Element;
function PasskeyButton(props: ButtonProps): JSX.Element;
```

### @zalt/next

```typescript
// Middleware
function zaltMiddleware(config?: MiddlewareConfig): NextMiddleware;

interface MiddlewareConfig {
  publicRoutes?: string[];
  ignoredRoutes?: string[];
  signInUrl?: string;
  afterSignInUrl?: string;
}

// Server Helpers
function getAuth(): Promise<{ userId: string | null; sessionId: string | null }>;
function currentUser(): Promise<User | null>;

// Route Protection
function withAuth<P>(
  Component: React.ComponentType<P>,
  options?: { redirectTo?: string }
): React.ComponentType<P>;
```

## Data Models

```typescript
// User
interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  profile: {
    firstName?: string;
    lastName?: string;
    avatarUrl?: string;
    metadata?: Record<string, unknown>;
  };
  mfaEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

// Auth Result
interface AuthResult {
  user: User;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  mfaRequired?: boolean;
  mfaSessionId?: string;
}

// Auth State
interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: ZaltError | null;
}

// Tokens
interface TokenResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// Storage
interface TokenStorage {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
  remove(key: string): void | Promise<void>;
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Token Storage Round-Trip
*For any* valid token string, storing it via TokenStorage and then retrieving it SHALL return the exact same string.
**Validates: Requirements 1.7, 7.4**

### Property 2: Auth State Consistency
*For any* sequence of auth operations (login, logout, refresh), the auth state SHALL always reflect the actual authentication status (user present iff tokens valid).
**Validates: Requirements 2.3, 2.5**

### Property 3: Error Type Discrimination
*For any* API error response, the SDK SHALL throw a correctly typed error that can be discriminated using `instanceof` checks.
**Validates: Requirements 1.6, 6.2, 6.3, 6.4**

### Property 4: Auto-Refresh Idempotence
*For any* expired access token, calling multiple API methods concurrently SHALL result in exactly one refresh request (not multiple).
**Validates: Requirements 1.8, 6.1**

### Property 5: Provider Context Propagation
*For any* component tree wrapped in ZaltProvider, all useAuth/useUser hooks SHALL return the same auth state reference.
**Validates: Requirements 2.1, 2.2**

### Property 6: Signed Components Exclusivity
*For any* auth state, exactly one of SignedIn or SignedOut children SHALL be rendered (never both, never neither when not loading).
**Validates: Requirements 2.6, 2.7**

### Property 7: Middleware Route Protection
*For any* request to a protected route without valid tokens, the middleware SHALL redirect to signInUrl (never allow access).
**Validates: Requirements 3.3, 3.1**

### Property 8: Type Safety Preservation
*For any* TypeScript compilation of SDK usage, all public APIs SHALL have complete type definitions (no `any` leakage).
**Validates: Requirements 5.1, 5.2, 5.6**

## Error Handling

```typescript
// Error Hierarchy
class ZaltError extends Error {
  code: string;
  statusCode?: number;
}

class AuthenticationError extends ZaltError {
  code: 'INVALID_CREDENTIALS' | 'EMAIL_NOT_VERIFIED' | 'SESSION_EXPIRED';
}

class MFARequiredError extends ZaltError {
  code: 'MFA_REQUIRED';
  sessionId: string;
  methods: MFAMethod[];
}

class AccountLockedError extends ZaltError {
  code: 'ACCOUNT_LOCKED';
  unlockAt?: string;
}

class RateLimitError extends ZaltError {
  code: 'RATE_LIMITED';
  retryAfter: number;
}

class NetworkError extends ZaltError {
  code: 'NETWORK_ERROR';
  retryable: boolean;
}

class ValidationError extends ZaltError {
  code: 'VALIDATION_ERROR';
  fields: Record<string, string[]>;
}
```

### Error Handling Pattern

```typescript
try {
  await zalt.login(email, password);
} catch (error) {
  if (error instanceof MFARequiredError) {
    // Show MFA input
    setMfaSessionId(error.sessionId);
  } else if (error instanceof AccountLockedError) {
    // Show locked message
    showError(`Account locked until ${error.unlockAt}`);
  } else if (error instanceof RateLimitError) {
    // Wait and retry
    await delay(error.retryAfter * 1000);
  } else if (error instanceof AuthenticationError) {
    // Show generic error (no email enumeration)
    showError('Invalid credentials');
  }
}
```

## Testing Strategy

### Unit Tests
- Test each SDK method in isolation
- Mock API responses for deterministic testing
- Test error handling for all error types
- Test storage adapters (memory, browser, cookie)

### Property-Based Tests (fast-check)
- Token storage round-trip property
- Auth state consistency after operations
- Error type discrimination
- Concurrent refresh deduplication

### Integration Tests
- Full auth flow (register → login → refresh → logout)
- MFA flow (setup → verify → login with MFA)
- WebAuthn flow (register → authenticate)
- Next.js middleware protection

### E2E Tests
- React app with ZaltProvider
- Next.js app with middleware
- Real API calls to staging environment

## Package Structure

```
packages/
├── core/
│   ├── src/
│   │   ├── client.ts
│   │   ├── token-manager.ts
│   │   ├── storage/
│   │   │   ├── memory.ts
│   │   │   ├── browser.ts
│   │   │   └── cookie.ts
│   │   ├── errors.ts
│   │   ├── types.ts
│   │   └── index.ts
│   ├── package.json
│   └── tsconfig.json
├── react/
│   ├── src/
│   │   ├── provider.tsx
│   │   ├── hooks/
│   │   │   ├── useAuth.ts
│   │   │   ├── useUser.ts
│   │   │   └── useMFA.ts
│   │   ├── components/
│   │   │   ├── SignedIn.tsx
│   │   │   ├── SignedOut.tsx
│   │   │   ├── UserButton.tsx
│   │   │   └── buttons.tsx
│   │   └── index.ts
│   ├── package.json
│   └── tsconfig.json
└── next/
    ├── src/
    │   ├── middleware.ts
    │   ├── server.ts
    │   ├── client.ts
    │   └── index.ts
    ├── package.json
    └── tsconfig.json
```

## Bundle Size Targets

| Package | Target | Max |
|---------|--------|-----|
| @zalt/core | < 5KB gzipped | 8KB |
| @zalt/react | < 3KB gzipped | 5KB |
| @zalt/next | < 2KB gzipped | 4KB |

## Security Considerations

1. **No sensitive logging**: Tokens and passwords never logged
2. **Secure defaults**: httpOnly cookies, secure flag in production
3. **Input validation**: All user input sanitized before API calls
4. **PKCE support**: For OAuth flows (future)
5. **CSP compatible**: No inline scripts or eval
