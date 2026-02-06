/**
 * Zalt Next.js Server Helpers
 * @zalt/next
 */

import { cookies } from 'next/headers';
import type { User, JWTClaims } from '@zalt.io/core';

/**
 * Auth result from getAuth()
 */
export interface AuthResult {
  userId: string | null;
  sessionId: string | null;
  realmId: string | null;
  claims: JWTClaims | null;
}

/**
 * Server configuration
 */
export interface ServerConfig {
  /** Cookie name for access token */
  tokenCookieName?: string;
  /** API base URL for fetching user */
  apiBaseUrl?: string;
  /** Realm ID */
  realmId?: string;
}

const DEFAULT_CONFIG: Required<ServerConfig> = {
  tokenCookieName: 'zalt_access_token',
  apiBaseUrl: 'https://api.zalt.io',
  realmId: '',
};

// Cache for user data within a request
const userCache = new Map<string, User>();

/**
 * Get authentication info from cookies (Server Component)
 * 
 * @example
 * ```tsx
 * // app/dashboard/page.tsx
 * import { getAuth } from '@zalt/next/server';
 * 
 * export default async function DashboardPage() {
 *   const { userId } = await getAuth();
 *   
 *   if (!userId) {
 *     redirect('/sign-in');
 *   }
 *   
 *   return <Dashboard userId={userId} />;
 * }
 * ```
 */
export async function getAuth(config: ServerConfig = {}): Promise<AuthResult> {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };

  try {
    const cookieStore = await cookies();
    const token = cookieStore.get(mergedConfig.tokenCookieName)?.value;

    if (!token) {
      return { userId: null, sessionId: null, realmId: null, claims: null };
    }

    const claims = decodeToken(token);
    if (!claims) {
      return { userId: null, sessionId: null, realmId: null, claims: null };
    }

    // Check expiry
    if (claims.exp && Date.now() >= claims.exp * 1000) {
      return { userId: null, sessionId: null, realmId: null, claims: null };
    }

    return {
      userId: claims.sub,
      sessionId: claims.jti || null,
      realmId: claims.realm_id,
      claims,
    };
  } catch {
    return { userId: null, sessionId: null, realmId: null, claims: null };
  }
}

/**
 * Get current user from API (Server Component)
 * 
 * @example
 * ```tsx
 * // app/profile/page.tsx
 * import { currentUser } from '@zalt/next/server';
 * 
 * export default async function ProfilePage() {
 *   const user = await currentUser();
 *   
 *   if (!user) {
 *     redirect('/sign-in');
 *   }
 *   
 *   return <Profile user={user} />;
 * }
 * ```
 */
export async function currentUser(config: ServerConfig = {}): Promise<User | null> {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };

  try {
    const cookieStore = await cookies();
    const token = cookieStore.get(mergedConfig.tokenCookieName)?.value;

    if (!token) {
      return null;
    }

    // Check cache first
    if (userCache.has(token)) {
      return userCache.get(token)!;
    }

    // Fetch user from API
    const response = await fetch(`${mergedConfig.apiBaseUrl}/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      cache: 'no-store',
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    const user = data.user as User;

    // Cache for this request
    userCache.set(token, user);

    return user;
  } catch {
    return null;
  }
}

/**
 * Protect a server action or route handler
 * 
 * @example
 * ```ts
 * // app/api/protected/route.ts
 * import { withAuth } from '@zalt/next/server';
 * 
 * export const GET = withAuth(async (request, { userId }) => {
 *   return Response.json({ userId });
 * });
 * ```
 */
export function withAuth<T extends (...args: unknown[]) => Promise<Response>>(
  handler: (request: Request, auth: AuthResult) => Promise<Response>,
  config: ServerConfig = {}
): T {
  return (async (request: Request) => {
    const auth = await getAuth(config);

    if (!auth.userId) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return handler(request, auth);
  }) as T;
}

/**
 * Decode JWT payload (without verification)
 */
function decodeToken(token: string): JWTClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const payload = parts[1];
    const decoded = Buffer.from(payload, 'base64url').toString('utf-8');
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

/**
 * Clear auth cookies (for sign out)
 */
export async function clearAuthCookies(config: ServerConfig = {}): Promise<void> {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };
  const cookieStore = await cookies();
  
  cookieStore.delete(mergedConfig.tokenCookieName);
  cookieStore.delete('zalt_refresh_token');
  cookieStore.delete('zalt_user_role');
  cookieStore.delete('zalt_realm');
}

/**
 * Set auth cookies (for sign in)
 */
export async function setAuthCookies(
  tokens: { accessToken: string; refreshToken: string; expiresIn: number },
  config: ServerConfig = {}
): Promise<void> {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };
  const cookieStore = await cookies();
  
  cookieStore.set(mergedConfig.tokenCookieName, tokens.accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: tokens.expiresIn,
    path: '/',
  });

  cookieStore.set('zalt_refresh_token', tokens.refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60, // 7 days
    path: '/',
  });
}
