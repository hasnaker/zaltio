# User Authentication Design Template

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Application                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Login Page  │  │ Register    │  │ Protected   │         │
│  │             │  │ Page        │  │ Routes      │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                 │
│  ┌──────┴────────────────┴────────────────┴──────┐         │
│  │              @zalt/react                       │         │
│  │  ZaltProvider, useAuth, SignedIn/Out          │         │
│  └──────────────────────┬────────────────────────┘         │
│                         │                                   │
│  ┌──────────────────────┴────────────────────────┐         │
│  │              @zalt/core                        │         │
│  │  ZaltClient, TokenManager, Storage            │         │
│  └──────────────────────┬────────────────────────┘         │
└─────────────────────────┼───────────────────────────────────┘
                          │ HTTPS
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Zalt.io API                               │
│                  api.zalt.io                                 │
└─────────────────────────────────────────────────────────────┘
```

## Component Design

### 1. Provider Setup
```tsx
// app/layout.tsx or _app.tsx
import { ZaltProvider } from '@zalt/react';

export default function RootLayout({ children }) {
  return (
    <ZaltProvider realmId={process.env.NEXT_PUBLIC_ZALT_REALM_ID}>
      {children}
    </ZaltProvider>
  );
}
```

### 2. Login Page
```tsx
// app/login/page.tsx
import { useAuth } from '@zalt/react';

export default function LoginPage() {
  const { signIn, isLoading } = useAuth();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await signIn(email, password);
    if (result.mfaRequired) {
      // Redirect to MFA page
    }
  };
  
  return <LoginForm onSubmit={handleSubmit} loading={isLoading} />;
}
```

### 3. Protected Routes
```tsx
// middleware.ts (Next.js)
import { zaltMiddleware } from '@zalt/next';

export default zaltMiddleware({
  publicRoutes: ['/', '/login', '/register'],
  signInUrl: '/login',
});
```

## Data Flow

### Login Flow
```
1. User enters credentials
2. ZaltClient.login(email, password)
3. API validates credentials
4. If MFA required → return mfaRequired: true
5. If success → return tokens
6. TokenManager stores tokens
7. ZaltProvider updates auth state
8. UI re-renders with authenticated state
```

### Token Refresh Flow
```
1. Access token expires (15 min)
2. TokenManager detects expiry
3. Automatic refresh using refresh token
4. New tokens stored
5. Original request retried
```

## Security Considerations

### Token Storage
- Use httpOnly cookies for web apps
- Use secure storage for mobile apps
- Never store in localStorage for production

### Error Handling
- Generic error messages (no user enumeration)
- Rate limiting on all auth endpoints
- Audit logging for security events

## Environment Variables

```env
# Required
NEXT_PUBLIC_ZALT_REALM_ID=your-realm-id

# Optional
ZALT_API_URL=https://api.zalt.io
```

## File Structure

```
src/
├── app/
│   ├── layout.tsx          # ZaltProvider wrapper
│   ├── login/
│   │   └── page.tsx        # Login page
│   ├── register/
│   │   └── page.tsx        # Register page
│   └── dashboard/
│       └── page.tsx        # Protected page
├── components/
│   ├── auth/
│   │   ├── LoginForm.tsx
│   │   ├── RegisterForm.tsx
│   │   └── MFAForm.tsx
│   └── layout/
│       └── Header.tsx      # SignedIn/SignedOut
└── middleware.ts           # Route protection
```
