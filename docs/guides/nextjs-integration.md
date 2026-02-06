# Next.js Integration Guide

Complete guide for integrating Zalt.io with Next.js 14+ (App Router).

## Installation

```bash
npm install @zalt/auth-sdk
```

## Project Structure

```
app/
├── (auth)/
│   ├── login/page.tsx
│   ├── register/page.tsx
│   ├── mfa/page.tsx
│   └── layout.tsx
├── (dashboard)/
│   ├── dashboard/page.tsx
│   ├── settings/page.tsx
│   └── layout.tsx
├── api/
│   └── auth/
│       ├── login/route.ts
│       ├── logout/route.ts
│       └── refresh/route.ts
├── layout.tsx
└── middleware.ts
lib/
├── auth.ts
└── auth-context.tsx
```

## Server-Side Setup

### Auth Library

```typescript
// lib/auth.ts
import { cookies } from 'next/headers';
import { jwtVerify } from 'jose';

const ZALT_PUBLIC_KEY = process.env.ZALT_PUBLIC_KEY!;

export async function getSession() {
  const cookieStore = cookies();
  const token = cookieStore.get('access_token')?.value;
  
  if (!token) return null;
  
  try {
    const { payload } = await jwtVerify(
      token,
      new TextEncoder().encode(ZALT_PUBLIC_KEY),
      { algorithms: ['RS256'] }
    );
    
    return {
      userId: payload.sub as string,
      email: payload.email as string,
      realmId: payload.realm_id as string
    };
  } catch {
    return null;
  }
}

export async function requireAuth() {
  const session = await getSession();
  if (!session) {
    redirect('/login');
  }
  return session;
}
```

### Middleware

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { jwtVerify } from 'jose';

const publicPaths = ['/login', '/register', '/forgot-password', '/verify-email'];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  
  // Allow public paths
  if (publicPaths.some(path => pathname.startsWith(path))) {
    return NextResponse.next();
  }
  
  // Check for access token
  const token = request.cookies.get('access_token')?.value;
  
  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  
  try {
    await jwtVerify(
      token,
      new TextEncoder().encode(process.env.ZALT_PUBLIC_KEY!),
      { algorithms: ['RS256'] }
    );
    return NextResponse.next();
  } catch {
    // Token expired - try refresh
    const refreshToken = request.cookies.get('refresh_token')?.value;
    
    if (refreshToken) {
      // Redirect to refresh endpoint
      const refreshUrl = new URL('/api/auth/refresh', request.url);
      refreshUrl.searchParams.set('redirect', pathname);
      return NextResponse.redirect(refreshUrl);
    }
    
    return NextResponse.redirect(new URL('/login', request.url));
  }
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|api/auth).*)']
};
```

### API Routes

```typescript
// app/api/auth/login/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

const ZALT_API = 'https://api.zalt.io';
const REALM_ID = process.env.ZALT_REALM_ID!;

export async function POST(request: NextRequest) {
  const { email, password } = await request.json();
  
  const response = await fetch(`${ZALT_API}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ realm_id: REALM_ID, email, password })
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    return NextResponse.json(data, { status: response.status });
  }
  
  // MFA required
  if (data.mfa_required) {
    return NextResponse.json({
      mfa_required: true,
      mfa_session_id: data.mfa_session_id
    });
  }
  
  // Set cookies
  const cookieStore = cookies();
  
  cookieStore.set('access_token', data.tokens.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: data.tokens.expires_in
  });
  
  cookieStore.set('refresh_token', data.tokens.refresh_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 // 7 days
  });
  
  return NextResponse.json({ user: data.user });
}
```

```typescript
// app/api/auth/logout/route.ts
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function POST() {
  const cookieStore = cookies();
  const token = cookieStore.get('access_token')?.value;
  
  // Invalidate session on Zalt.io
  if (token) {
    await fetch('https://api.zalt.io/logout', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });
  }
  
  // Clear cookies
  cookieStore.delete('access_token');
  cookieStore.delete('refresh_token');
  
  return NextResponse.json({ success: true });
}
```

```typescript
// app/api/auth/refresh/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function GET(request: NextRequest) {
  const cookieStore = cookies();
  const refreshToken = cookieStore.get('refresh_token')?.value;
  const redirect = request.nextUrl.searchParams.get('redirect') || '/dashboard';
  
  if (!refreshToken) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  
  const response = await fetch('https://api.zalt.io/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken })
  });
  
  if (!response.ok) {
    cookieStore.delete('access_token');
    cookieStore.delete('refresh_token');
    return NextResponse.redirect(new URL('/login', request.url));
  }
  
  const data = await response.json();
  
  cookieStore.set('access_token', data.tokens.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: data.tokens.expires_in
  });
  
  cookieStore.set('refresh_token', data.tokens.refresh_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60
  });
  
  return NextResponse.redirect(new URL(redirect, request.url));
}
```

## Client Components

### Auth Context

```typescript
// lib/auth-context.tsx
'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useRouter } from 'next/navigation';

interface User {
  id: string;
  email: string;
  profile: any;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<{ mfa_required?: boolean; mfa_session_id?: string }>;
  logout: () => Promise<void>;
  verifyMFA: (sessionId: string, code: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children, initialUser }: { children: ReactNode; initialUser: User | null }) {
  const [user, setUser] = useState<User | null>(initialUser);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const login = async (email: string, password: string) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await res.json();
    
    if (!res.ok) {
      throw new Error(data.error?.message || 'Login failed');
    }
    
    if (data.mfa_required) {
      return { mfa_required: true, mfa_session_id: data.mfa_session_id };
    }
    
    setUser(data.user);
    router.push('/dashboard');
    return {};
  };

  const logout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    setUser(null);
    router.push('/login');
  };

  const verifyMFA = async (sessionId: string, code: string) => {
    const res = await fetch('/api/auth/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_session_id: sessionId, code })
    });
    
    const data = await res.json();
    
    if (!res.ok) {
      throw new Error(data.error?.message || 'MFA verification failed');
    }
    
    setUser(data.user);
    router.push('/dashboard');
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, verifyMFA }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
```

### Root Layout

```typescript
// app/layout.tsx
import { AuthProvider } from '@/lib/auth-context';
import { getSession } from '@/lib/auth';

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession();
  
  // Fetch full user if session exists
  let user = null;
  if (session) {
    const res = await fetch('https://api.zalt.io/me', {
      headers: { 'Authorization': `Bearer ${cookies().get('access_token')?.value}` }
    });
    if (res.ok) {
      const data = await res.json();
      user = data.user;
    }
  }

  return (
    <html lang="en">
      <body>
        <AuthProvider initialUser={user}>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
```

### Login Page

```typescript
// app/(auth)/login/page.tsx
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const { login } = useAuth();
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const result = await login(email, password);
      
      if (result.mfa_required) {
        sessionStorage.setItem('mfa_session_id', result.mfa_session_id!);
        router.push('/mfa');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center">
      <form onSubmit={handleSubmit} className="w-full max-w-md p-8 space-y-6">
        <h1 className="text-2xl font-bold">Sign In</h1>
        
        {error && (
          <div className="bg-red-50 text-red-600 p-3 rounded">{error}</div>
        )}
        
        <div>
          <label className="block text-sm font-medium">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 block w-full rounded border p-2"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 block w-full rounded border p-2"
            required
          />
        </div>
        
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
      </form>
    </div>
  );
}
```

## Server Actions (Next.js 14+)

```typescript
// app/actions/auth.ts
'use server';

import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

export async function loginAction(formData: FormData) {
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;
  
  const response = await fetch('https://api.zalt.io/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      realm_id: process.env.ZALT_REALM_ID,
      email,
      password
    })
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    return { error: data.error?.message || 'Login failed' };
  }
  
  if (data.mfa_required) {
    return { mfa_required: true, mfa_session_id: data.mfa_session_id };
  }
  
  const cookieStore = cookies();
  cookieStore.set('access_token', data.tokens.access_token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: data.tokens.expires_in
  });
  
  redirect('/dashboard');
}
```

## Environment Variables

```env
# .env.local
ZALT_REALM_ID=your-realm-id
ZALT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"
```

## Security Best Practices

1. **HttpOnly Cookies** - Tokens stored in HttpOnly cookies, not accessible to JavaScript
2. **CSRF Protection** - Use Next.js built-in CSRF protection
3. **Secure Flag** - Cookies only sent over HTTPS in production
4. **SameSite** - Prevents CSRF attacks
5. **Server-Side Validation** - Always validate tokens server-side
