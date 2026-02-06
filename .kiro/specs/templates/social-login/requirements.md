# Social Login Requirements Template

## Overview
Requirements for implementing social/OAuth login with Zalt.

## Functional Requirements

### 1. OAuth Providers
- [ ] 1.1 Google OAuth
- [ ] 1.2 GitHub OAuth
- [ ] 1.3 Microsoft OAuth
- [ ] 1.4 Apple Sign In
- [ ] 1.5 Custom OIDC provider

### 2. OAuth Flow
- [ ] 2.1 Initiate OAuth redirect
- [ ] 2.2 Handle callback
- [ ] 2.3 Create/link user account
- [ ] 2.4 Issue Zalt tokens

### 3. Account Linking
- [ ] 3.1 Link social account to existing user
- [ ] 3.2 Unlink social account
- [ ] 3.3 View linked accounts
- [ ] 3.4 Prevent orphan accounts

### 4. UI Components
- [ ] 4.1 Social login buttons
- [ ] 4.2 Account linking UI
- [ ] 4.3 Provider icons

## Configuration

```typescript
// Realm OAuth configuration (in Zalt Dashboard)
{
  providers: {
    google: {
      clientId: 'YOUR_GOOGLE_CLIENT_ID',
      clientSecret: 'YOUR_GOOGLE_CLIENT_SECRET',
    },
    github: {
      clientId: 'YOUR_GITHUB_CLIENT_ID',
      clientSecret: 'YOUR_GITHUB_CLIENT_SECRET',
    },
  },
  callbackUrl: 'https://yourapp.com/api/auth/callback',
}
```

## Security Requirements

- [ ] S1. State parameter for CSRF protection
- [ ] S2. PKCE for public clients
- [ ] S3. Validate redirect URIs
- [ ] S4. Secure token exchange

## User Stories

### US1: Google Login
As a user, I want to sign in with Google so I don't need another password.

### US2: Link Accounts
As a user, I want to link my GitHub account so I can sign in either way.

### US3: Unlink Account
As a user, I want to remove a linked social account from my profile.
