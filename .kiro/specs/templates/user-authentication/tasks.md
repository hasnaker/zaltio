# User Authentication Implementation Tasks

## Overview
Implementation tasks for adding Zalt authentication to your application.

## Tasks

- [ ] 1. Project Setup
  - [ ] 1.1 Install Zalt packages
    ```bash
    npm install @zalt/core @zalt/react @zalt/next
    ```
  - [ ] 1.2 Add environment variables
    - Create `.env.local` with `NEXT_PUBLIC_ZALT_REALM_ID`
  - [ ] 1.3 Configure TypeScript (if needed)
    - Add Zalt types to tsconfig.json

- [ ] 2. Provider Setup
  - [ ] 2.1 Wrap app with ZaltProvider
    - Add to `app/layout.tsx` or `_app.tsx`
  - [ ] 2.2 Configure realm ID from environment
  - [ ] 2.3 Test provider initialization

- [ ] 3. Authentication Pages
  - [ ] 3.1 Create login page
    - Form with email/password
    - Error handling
    - Loading states
  - [ ] 3.2 Create register page
    - Form with email/password/name
    - Password strength indicator
    - Terms acceptance
  - [ ] 3.3 Create forgot password page
    - Email input
    - Success message
  - [ ] 3.4 Create reset password page
    - New password form
    - Token validation

- [ ] 4. Route Protection
  - [ ] 4.1 Create middleware.ts
    - Configure public routes
    - Set sign-in URL
  - [ ] 4.2 Test protected routes
    - Verify redirect for unauthenticated users
    - Verify access for authenticated users

- [ ] 5. User Interface Components
  - [ ] 5.1 Create Header with auth state
    - SignedIn: Show user info + logout
    - SignedOut: Show login/register links
  - [ ] 5.2 Create UserButton component
    - Avatar with dropdown
    - Profile link
    - Logout option

- [ ] 6. MFA Setup (Optional)
  - [ ] 6.1 Create MFA setup page
    - QR code display
    - Code verification
  - [ ] 6.2 Create MFA verification page
    - Code input
    - Backup code option
  - [ ] 6.3 Add MFA to login flow
    - Detect mfaRequired response
    - Redirect to verification

- [ ] 7. Testing
  - [ ] 7.1 Unit tests for auth components
  - [ ] 7.2 Integration tests for auth flow
  - [ ] 7.3 E2E tests for complete user journey

- [ ] 8. Documentation
  - [ ] 8.1 Update README with auth setup
  - [ ] 8.2 Document environment variables
  - [ ] 8.3 Add troubleshooting guide

## Checkpoint
- [ ] All auth pages working
- [ ] Route protection active
- [ ] Tests passing
- [ ] Documentation complete
