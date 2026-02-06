# Implementation Plan: Zalt SDK Packages

## Overview

Build Apple-level SDK packages for Zalt authentication. Start with core client, then React hooks/components, then Next.js integration. Each package builds on the previous, with property-based tests validating correctness.

## Tasks

- [x] 1. Set up monorepo structure
  - Create `packages/` directory with core, react, next subdirectories
  - Configure TypeScript project references
  - Set up shared tsconfig base
  - Configure npm workspaces in root package.json
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki task'a geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
  - _Requirements: 8.1, 8.2, 8.3_

- [x] 2. Implement @zalt/core package
  - [x] 2.1 Create core types and interfaces
    - Define ZaltConfig, User, AuthResult, TokenResult types
    - Define TokenStorage interface
    - Define all error types (ZaltError hierarchy)
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Types
    - _Requirements: 1.9, 5.1_

  - [x] 2.2 Implement storage adapters
    - Create MemoryStorage class
    - Create BrowserStorage class (localStorage)
    - Create CookieStorage class
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Storage
    - _Requirements: 1.7_

  - [x] 2.3 Write property test for token storage round-trip
    - **Property 1: Token Storage Round-Trip**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 1.7, 7.4**

  - [x] 2.4 Implement TokenManager
    - Store/retrieve/clear tokens
    - Auto-refresh logic with deduplication
    - Expiry checking
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - TokenManager
    - _Requirements: 1.5, 1.8_

  - [x] 2.5 Write property test for auto-refresh idempotence
    - **Property 4: Auto-Refresh Idempotence**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 1.8, 6.1**

  - [x] 2.6 Implement ZaltClient core methods
    - login() - call API, store tokens, return result
    - register() - call API, store tokens, return result
    - logout() - clear tokens, call API
    - refreshToken() - refresh and store new tokens
    - getUser() - return current user from state
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Client methods
    - _Requirements: 1.2, 1.3, 1.4, 1.5_

  - [x] 2.7 Implement error handling
    - Create typed error classes
    - Map API errors to SDK errors
    - Implement retry with exponential backoff
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Error handling
    - _Requirements: 1.6, 6.1, 6.2, 6.3, 6.4_

  - [x] 2.8 Write property test for error type discrimination
    - **Property 3: Error Type Discrimination**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 1.6, 6.2, 6.3, 6.4**

  - [x] 2.9 Implement event emitter for auth state changes
    - onAuthStateChange() subscription
    - Emit on login, logout, refresh, error
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Events
    - _Requirements: 6.5, 6.6_

  - [x] 2.10 Implement MFA methods
    - mfa.setup() - initiate TOTP setup
    - mfa.verify() - verify code
    - mfa.disable() - disable MFA
    - mfa.getStatus() - check MFA status
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - MFA
    - _Requirements: 2.9_

  - [x] 2.11 Implement WebAuthn methods
    - webauthn.register() - register passkey
    - webauthn.authenticate() - login with passkey
    - webauthn.listCredentials() - list registered passkeys
    - webauthn.removeCredential() - remove passkey
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - WebAuthn
    - _Requirements: 4.10_

  - [x] 2.12 Implement SMS MFA (optional with risk acceptance)
    - sms.setup() - initiate SMS MFA with phone number
    - sms.verify() - verify SMS code
    - sms.disable() - disable SMS MFA
    - Display security warning about SS7 vulnerabilities
    - Rate limit: 3 codes per hour per phone
    - Log as "reduced_security_mfa" in audit
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - SMS MFA
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

  - [x] 2.13 Create package.json and build config
    - Zero dependencies
    - ESM + CJS dual export
    - Source maps included
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 1.10, 8.4, 8.5_

- [x] 3. Checkpoint - Core SDK complete
  - Ensure all tests pass, ask the user if questions arise.
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki task'a geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

- [x] 4. Implement @zalt/react package
  - [x] 4.1 Create ZaltProvider component
    - Initialize ZaltClient
    - Restore auth state from storage on mount
    - Provide context to children
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - Provider
    - _Requirements: 2.1, 2.2_

  - [x] 4.2 Implement useAuth hook
    - Return user, isLoading, isAuthenticated
    - Expose signIn, signUp, signOut methods
    - Subscribe to auth state changes
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useAuth
    - _Requirements: 2.3, 2.5_

  - [x] 4.3 Write property test for auth state consistency
    - **Property 2: Auth State Consistency**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 2.3, 2.5**

  - [x] 4.4 Implement useUser hook
    - Return current user or null
    - Re-render on user change
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useUser
    - _Requirements: 2.4_

  - [x] 4.5 Implement useMFA hook
    - Expose isRequired, sessionId, verify, methods
    - Handle MFA flow state
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useMFA
    - _Requirements: 2.9_

  - [x] 4.6 Implement useZaltClient hook
    - Return raw ZaltClient instance
    - For advanced use cases
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useZaltClient
    - _Requirements: 2.3_

  - [x] 4.7 Implement SignedIn component
    - Render children only when authenticated
    - Handle loading state
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - SignedIn
    - _Requirements: 2.6_

  - [x] 4.8 Implement SignedOut component
    - Render children only when not authenticated
    - Handle loading state
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - SignedOut
    - _Requirements: 2.7_

  - [x] 4.9 Write property test for SignedIn/SignedOut exclusivity
    - **Property 6: Signed Components Exclusivity**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 2.6, 2.7**

  - [x] 4.10 Write property test for provider context propagation
    - **Property 5: Provider Context Propagation**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 2.1, 2.2**

  - [x] 4.11 Implement UI components
    - SignInButton with customizable appearance
    - SignUpButton with customizable appearance
    - UserButton with avatar and dropdown
    - PasskeyButton for WebAuthn
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - UI Components
    - _Requirements: 4.1, 4.2, 4.3, 4.10_

  - [x] 4.12 Implement theming system
    - Appearance config for colors, fonts
    - Auto dark mode detection
    - CSS-in-JS with zero runtime (CSS variables)
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - Theming
    - _Requirements: 4.5, 4.6, 4.8_

  - [x] 4.13 Create package.json and build config
    - Peer dependency on react 18+
    - Dependency on @zalt/core
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 2.10, 8.6_

- [x] 5. Checkpoint - React SDK complete
  - Ensure all tests pass, ask the user if questions arise.
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki task'a geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

- [x] 6. Implement @zalt/next package
  - [x] 6.1 Implement zaltMiddleware
    - Validate tokens from cookies
    - Redirect unauthenticated to signInUrl
    - Support publicRoutes and ignoredRoutes config
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/next/README.md` - Middleware
    - _Requirements: 3.1, 3.2, 3.3_

  - [x] 6.2 Write property test for middleware route protection
    - **Property 7: Middleware Route Protection**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 3.3, 3.1**

  - [x] 6.3 Implement route matcher utilities
    - Pattern matching for routes
    - Wildcard support
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/next/README.md` - Route matching
    - _Requirements: 3.10_

  - [x] 6.4 Implement getAuth() server helper
    - Read tokens from cookies
    - Validate and decode JWT
    - Return userId and sessionId
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/next/README.md` - getAuth
    - _Requirements: 3.4_

  - [x] 6.5 Implement currentUser() server helper
    - Call getAuth()
    - Fetch full user from API if needed
    - Cache result for request duration
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/next/README.md` - currentUser
    - _Requirements: 3.5_

  - [x] 6.6 Implement server-side token refresh
    - Auto-refresh expired tokens
    - Set new cookies in response
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/next/README.md` - Token refresh
    - _Requirements: 3.8_

  - [x] 6.7 Implement secure cookie handling
    - httpOnly flag
    - secure flag in production
    - sameSite lax
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/next/README.md` - Cookie security
    - _Requirements: 3.9, 7.2_

  - [x] 6.8 Write property test for secure cookie flags
    - **Property: Secure Cookie Flags**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 3.9, 7.2**

  - [x] 6.9 Create package.json and build config
    - Peer dependency on next 13+
    - Dependency on @zalt/core
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 8.6_

- [x] 7. Checkpoint - Next.js SDK complete
  - Ensure all tests pass, ask the user if questions arise.
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki task'a geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

- [x] 8. Documentation and examples
  - [x] 8.1 Write README for each package
    - `packages/core/README.md` - Full API reference
    - `packages/react/README.md` - Hooks and components guide
    - `packages/next/README.md` - Middleware and SSR guide
    - `packages/mcp-server/README.md` - AI assistant integration
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 11.7_

  - [x] 8.2 Create example Next.js app
    - `packages/example-nextjs/` - Complete example app
    - Full auth flow (sign-in, sign-up, sign-out)
    - MFA setup demo with QR code
    - WebAuthn/Passkeys demo
    - Session management
    - Onboarding flow
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

- [x] 9. IDE Extensions & AI Integration
  - [x] 9.1 Create VS Code / Cursor extension
    - `packages/vscode-extension/` - Full extension
    - Extension manifest and activation
    - Code snippets for Zalt SDK (TypeScript + TSX)
    - "Zalt: Add Auth" command for scaffolding
    - Sidebar panel for realm status
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 9.1, 9.2, 9.3, 9.10_

  - [x] 9.2 Implement MCP Server for AI assistants
    - Create @zalt/mcp-server package
    - Expose tools: createRealm, addUser, generateAPIKey, checkAuthStatus
    - Provide auth context to Claude Code, Cursor AI
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 9.7, 9.8, 9.9_

  - [x] 9.3 Create Kiro steering files
    - `.kiro/steering/zalt-sdk-patterns.md` - SDK implementation patterns
    - `.kiro/steering/zalt-security-best-practices.md` - Security guidelines
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 10.1, 10.5_

  - [x] 9.4 Create Kiro hooks
    - `.kiro/hooks/zalt-security-validator.kiro.hook` - Security validation on save
    - `.kiro/hooks/zalt-new-project-setup.kiro.hook` - New project auth setup
    - `.kiro/hooks/zalt-auth-test-generator.kiro.hook` - Auto-generate tests
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 10.2, 10.3, 10.4_

  - [x] 9.5 Create Kiro spec templates
    - `.kiro/specs/templates/user-authentication/` - Full auth spec template
    - `.kiro/specs/templates/mfa-setup/` - MFA implementation template
    - `.kiro/specs/templates/social-login/` - OAuth/social login template
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 10.4_

- [x] 10. npm publish preparation
  - [x] 10.1 Configure npm publishing
    - `scripts/publish-sdk.sh` - Automated publish script
    - Package.json files configured for @zalt org
    - Public access configured
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 11.1, 11.2, 11.3_

  - [x] 10.2 Build and publish packages
    - tsconfig.json for each package
    - Build scripts configured
    - Publish order: core → react → next → mcp-server
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - _Requirements: 11.1, 11.2, 11.3_

- [x] 11. VS Code Marketplace publish
  - `scripts/publish-vscode.sh` - Automated publish script
  - vsce package command configured
  - Open VSX support for Cursor
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki task'a geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
  - _Requirements: 9.1_

- [x] 12. Final checkpoint
  - All packages implemented and documented
  - Example app with full auth flow
  - IDE extensions ready
  - Kiro integration complete
  - Publish scripts ready
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Production publish'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

## Notes

- All tasks are REQUIRED (no optional tests)
- Each package depends on the previous (core → react → next)
- Bundle size targets: core < 5KB, react < 3KB, next < 2KB gzipped
- Zero runtime dependencies for core package
- Property tests use fast-check library
- IDE extensions differentiate Zalt from Clerk