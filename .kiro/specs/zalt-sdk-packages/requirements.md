# Requirements Document

## Introduction

Zalt.io SDK Packages - Apple-level developer experience for authentication. A suite of npm packages that make Zalt integration effortless across all JavaScript/TypeScript frameworks. The goal is to surpass Clerk in both security and developer experience.

## Glossary

- **Zalt_Core**: The headless TypeScript client (`@zalt/core`) that wraps the Zalt REST API
- **Zalt_React**: React-specific hooks and components (`@zalt/react`)
- **Zalt_Next**: Next.js middleware, SSR support, and App Router integration (`@zalt/next`)
- **Zalt_Provider**: Context provider component that manages auth state globally
- **Token_Storage**: Abstraction for storing tokens (memory, localStorage, cookies)
- **Auth_State**: Current authentication state (user, tokens, loading, error)
- **Realm**: Multi-tenant isolation unit for customers

## Requirements

### Requirement 1: Core SDK Package (@zalt/core)

**User Story:** As a developer, I want a lightweight TypeScript client to interact with Zalt API, so that I can integrate authentication without framework dependencies.

#### Acceptance Criteria

1. THE Zalt_Core SHALL export a `createZaltClient` factory function that accepts configuration options
2. WHEN a developer calls `client.login(email, password)`, THE Zalt_Core SHALL return user data and tokens on success
3. WHEN a developer calls `client.register(data)`, THE Zalt_Core SHALL create a new user and return the result
4. WHEN a developer calls `client.logout()`, THE Zalt_Core SHALL invalidate the current session
5. WHEN a developer calls `client.refreshToken()`, THE Zalt_Core SHALL obtain new tokens using the refresh token
6. WHEN an API call fails, THE Zalt_Core SHALL throw typed errors (AuthenticationError, NetworkError, RateLimitError)
7. THE Zalt_Core SHALL support configurable Token_Storage implementations (memory, browser, custom)
8. WHEN tokens expire, THE Zalt_Core SHALL automatically attempt refresh before failing
9. THE Zalt_Core SHALL expose TypeScript types for all API responses and configurations
10. THE Zalt_Core SHALL have zero runtime dependencies for minimal bundle size

### Requirement 2: React SDK Package (@zalt/react)

**User Story:** As a React developer, I want hooks and components to manage authentication, so that I can add auth to my app with minimal code.

#### Acceptance Criteria

1. THE Zalt_React SHALL export a `ZaltProvider` component that wraps the application
2. WHEN `ZaltProvider` mounts, THE Zalt_React SHALL initialize auth state from stored tokens
3. THE Zalt_React SHALL export a `useAuth` hook returning `{ user, isLoading, isAuthenticated, signIn, signOut, signUp }`
4. THE Zalt_React SHALL export a `useUser` hook returning the current user or null
5. WHEN `signIn` is called, THE Zalt_React SHALL update auth state and trigger re-renders
6. THE Zalt_React SHALL export `<SignedIn>` component that renders children only when authenticated
7. THE Zalt_React SHALL export `<SignedOut>` component that renders children only when not authenticated
8. THE Zalt_React SHALL export `<ZaltButton>` component with automatic theming and animations
9. WHEN MFA is required during login, THE Zalt_React SHALL expose MFA state via `useMFA` hook
10. THE Zalt_React SHALL support React 18+ with concurrent rendering compatibility

### Requirement 3: Next.js SDK Package (@zalt/next)

**User Story:** As a Next.js developer, I want middleware and SSR support, so that I can protect routes and access user data server-side.

#### Acceptance Criteria

1. THE Zalt_Next SHALL export `zaltMiddleware()` function for route protection
2. WHEN middleware runs, THE Zalt_Next SHALL validate tokens from cookies
3. WHEN an unauthenticated user accesses a protected route, THE Zalt_Next SHALL redirect to sign-in
4. THE Zalt_Next SHALL export `getAuth()` helper for Server Components
5. THE Zalt_Next SHALL export `currentUser()` helper for Server Components
6. WHEN used in App Router, THE Zalt_Next SHALL support React Server Components
7. WHEN used in Pages Router, THE Zalt_Next SHALL support `getServerSideProps`
8. THE Zalt_Next SHALL automatically handle token refresh on the server
9. THE Zalt_Next SHALL set secure httpOnly cookies for token storage
10. THE Zalt_Next SHALL export route matcher utilities for flexible protection patterns

### Requirement 4: Premium UI Components

**User Story:** As a developer, I want beautiful, accessible UI components, so that I can ship a polished auth experience without custom design work.

#### Acceptance Criteria

1. THE Zalt_React SHALL export `<SignInButton>` with customizable appearance
2. THE Zalt_React SHALL export `<SignUpButton>` with customizable appearance
3. THE Zalt_React SHALL export `<UserButton>` showing avatar with dropdown menu
4. WHEN `<UserButton>` is clicked, THE Zalt_React SHALL show account management options
5. THE Zalt_React SHALL support automatic dark mode detection and theming
6. THE Zalt_React SHALL include micro-animations using CSS transitions (no heavy dependencies)
7. THE Zalt_React SHALL meet WCAG 2.1 AA accessibility standards
8. WHEN brand colors are configured, THE Zalt_React SHALL apply them consistently
9. THE Zalt_React SHALL export `<MFASetup>` component for TOTP configuration
10. THE Zalt_React SHALL export `<PasskeyButton>` for WebAuthn registration/login

### Requirement 5: Type Safety and Developer Experience

**User Story:** As a TypeScript developer, I want full type safety and excellent autocomplete, so that I can develop faster with fewer errors.

#### Acceptance Criteria

1. THE Zalt_Core SHALL export all types from a single entry point
2. WHEN using hooks, THE Zalt_React SHALL provide accurate return types
3. THE Zalt_Core SHALL use discriminated unions for error handling
4. WHEN configuration is invalid, THE Zalt_Core SHALL provide helpful error messages at runtime
5. THE Zalt_Core SHALL include JSDoc comments for all public APIs
6. THE Zalt_Next SHALL provide typed middleware configuration
7. WHEN tokens are decoded, THE Zalt_Core SHALL return typed JWT claims
8. THE Zalt_Core SHALL export utility types for extending user metadata

### Requirement 6: Error Handling and Resilience

**User Story:** As a developer, I want clear error handling and automatic retries, so that my app handles edge cases gracefully.

#### Acceptance Criteria

1. WHEN a network error occurs, THE Zalt_Core SHALL retry with exponential backoff (max 3 attempts)
2. WHEN rate limited, THE Zalt_Core SHALL throw `RateLimitError` with retry-after information
3. WHEN MFA is required, THE Zalt_Core SHALL throw `MFARequiredError` with session ID
4. WHEN account is locked, THE Zalt_Core SHALL throw `AccountLockedError` with unlock time
5. IF token refresh fails, THEN THE Zalt_Core SHALL clear auth state and emit logout event
6. THE Zalt_Core SHALL expose an event emitter for auth state changes
7. WHEN offline, THE Zalt_Core SHALL queue operations and retry when online

### Requirement 7: SMS MFA (Optional with Risk Acceptance)

**User Story:** As a developer, I want to optionally enable SMS MFA for users who prefer it, so that I can offer flexibility while informing users of security risks.

#### Acceptance Criteria

1. THE Zalt_Core SHALL support SMS MFA as an optional method (disabled by default)
2. WHEN SMS MFA is enabled for a realm, THE Zalt_Core SHALL require explicit risk acceptance from the realm admin
3. WHEN a user enables SMS MFA, THE Zalt_React SHALL display a security warning about SS7 vulnerabilities
4. THE Zalt_Core SHALL rate limit SMS sending to 3 codes per hour per phone number
5. WHEN SMS MFA is used, THE Zalt_Core SHALL log it as "reduced_security_mfa" in audit logs
6. THE Zalt_Core SHALL recommend TOTP or WebAuthn as more secure alternatives in the UI
7. WHERE SMS MFA is enabled, THE Zalt_Core SHALL still require phone number verification before use

### Requirement 8: Security Best Practices

**User Story:** As a security-conscious developer, I want the SDK to enforce security best practices, so that I don't accidentally introduce vulnerabilities.

#### Acceptance Criteria

1. THE Zalt_Core SHALL never log sensitive data (tokens, passwords)
2. THE Zalt_Next SHALL use httpOnly cookies for token storage by default
3. THE Zalt_Core SHALL validate all API responses before processing
4. WHEN in browser, THE Zalt_Core SHALL use secure storage with encryption option
5. THE Zalt_Core SHALL support PKCE for OAuth flows
6. THE Zalt_Next SHALL set appropriate CORS and CSP headers
7. THE Zalt_Core SHALL sanitize user input before API calls

### Requirement 9: IDE Extensions & AI Tool Integration

**User Story:** As a developer using modern AI-powered IDEs (Cursor, Kiro, VS Code, Claude Code), I want Zalt to integrate directly into my development environment, so that I can implement auth without leaving my IDE.

#### Acceptance Criteria

1. THE Zalt_IDE_Extension SHALL provide a VS Code / Cursor extension for auth scaffolding
2. WHEN a developer types "zalt" in their IDE, THE extension SHALL offer code snippets and completions
3. THE Zalt_IDE_Extension SHALL provide a "Zalt: Add Auth" command that scaffolds complete auth setup
4. WHEN integrated with Kiro, THE extension SHALL provide steering files for auth best practices
5. THE Zalt_IDE_Extension SHALL offer inline documentation and type hints
6. WHEN a developer makes auth-related errors, THE extension SHALL provide fix suggestions
7. THE Zalt_IDE_Extension SHALL support MCP (Model Context Protocol) for AI assistants
8. WHEN used with Claude Code or Cursor AI, THE MCP server SHALL provide auth context to the AI
9. THE Zalt_MCP_Server SHALL expose tools for: createRealm, addUser, generateAPIKey, checkAuthStatus
10. THE Zalt_IDE_Extension SHALL provide a sidebar panel showing realm status, users, and logs

### Requirement 10: Kiro-Specific Integration

**User Story:** As a Kiro user, I want Zalt to provide steering files and hooks, so that Kiro can help me implement auth correctly.

#### Acceptance Criteria

1. THE Zalt_Kiro_Integration SHALL provide steering files for auth implementation patterns
2. THE Zalt_Kiro_Integration SHALL provide hooks for auto-generating auth tests
3. WHEN a developer creates a new project, THE Kiro hook SHALL offer to add Zalt auth
4. THE Zalt_Kiro_Integration SHALL provide spec templates for common auth flows
5. WHEN auth code is modified, THE Kiro hook SHALL validate security best practices

### Requirement 11: npm Package Publishing

**User Story:** As a developer, I want to install Zalt packages from npm, so that I can easily add them to my project.

#### Acceptance Criteria

1. THE Zalt_Core SHALL be published as `@zalt/core` on npm
2. THE Zalt_React SHALL be published as `@zalt/react` on npm
3. THE Zalt_Next SHALL be published as `@zalt/next` on npm
4. WHEN installed, THE packages SHALL include source maps for debugging
5. THE packages SHALL support both ESM and CommonJS imports
6. THE packages SHALL have minimal peer dependencies
7. THE packages SHALL include README with quick start examples
