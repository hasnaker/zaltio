# Design Document: Customer OAuth Integration

## Overview

Bu doküman, müşteri uygulamasının Zalt.io OAuth 2.0 ile entegrasyonunu tanımlar. NextAuth.js kullanılarak standart OAuth flow implementasyonu yapılacak.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Customer App   │────▶│   Zalt.io API   │────▶│   DynamoDB      │
│  (Next.js)      │◀────│   (OAuth 2.0)   │◀────│   (Users/Realms)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │
        ▼
┌─────────────────┐
│   NextAuth.js   │
│   (Session)     │
└─────────────────┘
```

## Components

### 1. Zalt OAuth Provider (NextAuth.js)

```typescript
// lib/auth/zalt-provider.ts
import type { OAuthConfig } from "next-auth/providers/oauth"

interface ZaltProfile {
  sub: string
  email: string
  email_verified: boolean
  name?: string
  given_name?: string
  family_name?: string
  realm_id: string
  mfa_enabled: boolean
}

export function ZaltProvider(options: {
  clientId: string
  clientSecret: string
  realmId: string
}): OAuthConfig<ZaltProfile> {
  return {
    id: "zalt",
    name: "Zalt",
    type: "oauth",
    wellKnown: "https://api.zalt.io/.well-known/openid-configuration",
    authorization: {
      params: {
        scope: "openid profile email",
        realm_id: options.realmId
      }
    },
    idToken: true,
    checks: ["pkce", "state"],
    profile(profile) {
      return {
        id: profile.sub,
        email: profile.email,
        emailVerified: profile.email_verified,
        name: profile.name || `${profile.given_name} ${profile.family_name}`,
        realmId: profile.realm_id,
        mfaEnabled: profile.mfa_enabled
      }
    },
    clientId: options.clientId,
    clientSecret: options.clientSecret
  }
}
```

### 2. NextAuth Configuration

```typescript
// app/api/auth/[...nextauth]/route.ts
import NextAuth from "next-auth"
import { ZaltProvider } from "@/lib/auth/zalt-provider"

const handler = NextAuth({
  providers: [
    ZaltProvider({
      clientId: process.env.ZALT_CLIENT_ID!,
      clientSecret: process.env.ZALT_CLIENT_SECRET!,
      realmId: process.env.ZALT_REALM_ID!
    })
  ],
  callbacks: {
    async jwt({ token, account, profile }) {
      if (account && profile) {
        token.accessToken = account.access_token
        token.refreshToken = account.refresh_token
        token.realmId = (profile as any).realm_id
        token.mfaEnabled = (profile as any).mfa_enabled
      }
      return token
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string
      session.user.realmId = token.realmId as string
      session.user.mfaEnabled = token.mfaEnabled as boolean
      return session
    }
  },
  pages: {
    signIn: "/login",
    error: "/auth/error"
  }
})

export { handler as GET, handler as POST }
```

### 3. Middleware for Protected Routes

```typescript
// middleware.ts
import { withAuth } from "next-auth/middleware"

export default withAuth({
  pages: {
    signIn: "/login"
  }
})

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/settings/:path*",
    "/api/protected/:path*"
  ]
}
```

### 4. Environment Variables

```env
# .env.local
ZALT_CLIENT_ID=your_client_id
ZALT_CLIENT_SECRET=your_client_secret
ZALT_REALM_ID=your_realm_id
NEXTAUTH_URL=https://your-app.com
NEXTAUTH_SECRET=your_nextauth_secret
```

## Data Models

### User Session

```typescript
interface ZaltSession {
  user: {
    id: string
    email: string
    name: string
    realmId: string
    mfaEnabled: boolean
  }
  accessToken: string
  refreshToken: string
  expiresAt: number
}
```

### OAuth Client (Zalt tarafında)

```typescript
interface OAuthClient {
  client_id: string
  client_secret_hash: string
  client_name: string
  realm_id: string
  redirect_uris: string[]
  allowed_scopes: string[]
  grant_types: string[]
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system.*

### Property 1: OAuth State Validation
*For any* OAuth authorization request, the state parameter returned in the callback SHALL match the state sent in the authorization request.
**Validates: Requirements 2.4, 5.2**

### Property 2: Token Exchange Idempotency
*For any* authorization code, exchanging it for tokens SHALL succeed exactly once; subsequent attempts SHALL fail.
**Validates: Requirements 2.5, 5.3**

### Property 3: Session Consistency
*For any* authenticated session, the user information SHALL match the claims in the id_token.
**Validates: Requirements 4.1, 4.4**

### Property 4: Protected Route Access Control
*For any* protected route, unauthenticated requests SHALL be redirected to login; authenticated requests SHALL be allowed.
**Validates: Requirements 3.2, 3.3**

## Error Handling

| Error | Cause | Action |
|-------|-------|--------|
| invalid_client | Wrong client_id/secret | Check credentials |
| invalid_grant | Expired/used auth code | Restart OAuth flow |
| access_denied | User denied consent | Show error message |
| invalid_scope | Unsupported scope | Check allowed scopes |

## Testing Strategy

### Unit Tests
- OAuth provider configuration
- Token parsing and validation
- Session creation from tokens

### Integration Tests
- Full OAuth flow (mock Zalt API)
- Protected route middleware
- Token refresh flow

### E2E Tests
- Login flow with real Zalt API
- Logout and session cleanup
- Error handling scenarios
