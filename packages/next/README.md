# @zalt/next

Next.js integration for Zalt.io authentication. Middleware, SSR, and server components.

## Installation

```bash
npm install @zalt/core @zalt/react @zalt/next
```

## Quick Start

### 1. Add Provider

```tsx
// app/layout.tsx
import { ZaltProvider } from '@zalt/react';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <ZaltProvider realmId={process.env.NEXT_PUBLIC_ZALT_REALM_ID!}>
          {children}
        </ZaltProvider>
      </body>
    </html>
  );
}
```

### 2. Add Middleware

```typescript
// middleware.ts
import { zaltMiddleware } from '@zalt/next';

export default zaltMiddleware({
  publicRoutes: ['/', '/sign-in', '/sign-up'],
  signInUrl: '/sign-in',
});

export const config = {
  matcher: ['/((?!_next|.*\\..*).*)'],
};
```

### 3. Use Server Helpers

```tsx
// app/dashboard/page.tsx
import { getAuth, currentUser } from '@zalt/next';

export default async function DashboardPage() {
  const { userId } = await getAuth();
  const user = await currentUser();

  return <h1>Welcome, {user?.email}</h1>;
}
```

## Features

- 🛡️ **Middleware** - Protect routes automatically
- 🖥️ **SSR** - Server-side authentication
- 🍪 **Secure Cookies** - httpOnly, secure, sameSite
- ⚡ **Edge Runtime** - Works on Vercel Edge
- 📦 **Lightweight** - < 2KB gzipped

## API Reference

### zaltMiddleware

Protect routes with middleware.

```typescript
import { zaltMiddleware } from '@zalt/next';

export default zaltMiddleware({
  // Routes that don't require authentication
  publicRoutes: ['/', '/sign-in', '/sign-up', '/api/webhooks(.*)'],
  
  // Where to redirect unauthenticated users
  signInUrl: '/sign-in',
  
  // Routes to completely ignore (static files, etc.)
  ignoredRoutes: ['/api/health'],
  
  // Custom redirect after sign in
  afterSignInUrl: '/dashboard',
});
```

### Route Patterns

```typescript
publicRoutes: [
  '/',                    // Exact match
  '/blog/(.*)',          // Regex: all blog routes
  '/api/public/(.*)',    // Regex: public API routes
]
```

### getAuth

Get authentication state on the server.

```typescript
import { getAuth } from '@zalt/next';

export default async function Page() {
  const { userId, sessionId } = await getAuth();
  
  if (!userId) {
    redirect('/sign-in');
  }
  
  return <div>User ID: {userId}</div>;
}
```

### currentUser

Get full user object on the server.

```typescript
import { currentUser } from '@zalt/next';

export default async function Page() {
  const user = await currentUser();
  
  return (
    <div>
      <p>Email: {user?.email}</p>
      <p>Name: {user?.profile?.firstName}</p>
    </div>
  );
}
```

### API Route Protection

```typescript
// app/api/protected/route.ts
import { getAuth } from '@zalt/next';
import { NextResponse } from 'next/server';

export async function GET() {
  const { userId } = await getAuth();
  
  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  
  return NextResponse.json({ userId });
}
```

## Environment Variables

```env
# Required
NEXT_PUBLIC_ZALT_REALM_ID=your-realm-id

# Optional
ZALT_API_URL=https://api.zalt.io
```

## Cookie Configuration

Cookies are automatically configured for security:

```typescript
{
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
  maxAge: 7 * 24 * 60 * 60, // 7 days
}
```

## Edge Runtime

Works with Next.js Edge Runtime:

```typescript
// middleware.ts
export const config = {
  matcher: ['/((?!_next|.*\\..*).*)'],
  runtime: 'edge',
};
```

## TypeScript

```typescript
import type { ZaltMiddlewareConfig } from '@zalt/next';

const config: ZaltMiddlewareConfig = {
  publicRoutes: ['/'],
  signInUrl: '/sign-in',
};
```

## License

MIT
