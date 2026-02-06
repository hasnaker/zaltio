/**
 * Zalt Next.js Middleware
 * @zalt/next
 */

import { NextResponse, type NextRequest, type NextMiddleware } from 'next/server';

/**
 * Middleware configuration
 */
export interface MiddlewareConfig {
  /** Routes that don't require authentication */
  publicRoutes?: string[];
  /** Routes to ignore completely (static files, etc.) */
  ignoredRoutes?: string[];
  /** URL to redirect unauthenticated users */
  signInUrl?: string;
  /** URL to redirect after sign in */
  afterSignInUrl?: string;
  /** Cookie name for access token */
  tokenCookieName?: string;
  /** Enable debug logging */
  debug?: boolean;
}

const DEFAULT_CONFIG: Required<MiddlewareConfig> = {
  publicRoutes: ['/', '/sign-in', '/sign-up', '/api/auth/*'],
  ignoredRoutes: ['/_next/*', '/favicon.ico', '/*.svg', '/*.png', '/*.jpg'],
  signInUrl: '/sign-in',
  afterSignInUrl: '/dashboard',
  tokenCookieName: 'zalt_access_token',
  debug: false,
};

/**
 * Create Zalt middleware for Next.js
 * 
 * @example
 * ```ts
 * // middleware.ts
 * import { zaltMiddleware } from '@zalt/next';
 * 
 * export default zaltMiddleware({
 *   publicRoutes: ['/', '/sign-in', '/sign-up'],
 *   signInUrl: '/sign-in',
 * });
 * 
 * export const config = {
 *   matcher: ['/((?!_next|.*\\..*).*)'],
 * };
 * ```
 */
export function zaltMiddleware(config: MiddlewareConfig = {}): NextMiddleware {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };

  return async function middleware(request: NextRequest): Promise<NextResponse> {
    const { pathname } = request.nextUrl;

    // Check if route should be ignored
    if (isMatchingRoute(pathname, mergedConfig.ignoredRoutes)) {
      if (mergedConfig.debug) {
        console.log('[Zalt Middleware] Ignored route:', pathname);
      }
      return NextResponse.next();
    }

    // Check if route is public
    if (isMatchingRoute(pathname, mergedConfig.publicRoutes)) {
      if (mergedConfig.debug) {
        console.log('[Zalt Middleware] Public route:', pathname);
      }
      return NextResponse.next();
    }

    // Get token from cookies
    const token = request.cookies.get(mergedConfig.tokenCookieName)?.value;

    if (!token) {
      if (mergedConfig.debug) {
        console.log('[Zalt Middleware] No token, redirecting to:', mergedConfig.signInUrl);
      }

      // Redirect to sign in
      const signInUrl = new URL(mergedConfig.signInUrl, request.url);
      signInUrl.searchParams.set('redirect_url', pathname);
      return NextResponse.redirect(signInUrl);
    }

    // Validate token (basic check - full validation on server)
    if (!isValidTokenFormat(token)) {
      if (mergedConfig.debug) {
        console.log('[Zalt Middleware] Invalid token format');
      }

      // Clear invalid token and redirect
      const response = NextResponse.redirect(new URL(mergedConfig.signInUrl, request.url));
      response.cookies.delete(mergedConfig.tokenCookieName);
      return response;
    }

    // Check token expiry (client-side check)
    const claims = decodeToken(token);
    if (claims && isTokenExpired(claims)) {
      if (mergedConfig.debug) {
        console.log('[Zalt Middleware] Token expired');
      }

      // Token expired - let the page handle refresh or redirect
      // Don't redirect here to allow client-side refresh
    }

    if (mergedConfig.debug) {
      console.log('[Zalt Middleware] Authenticated request:', pathname);
    }

    return NextResponse.next();
  };
}

/**
 * Check if pathname matches any of the patterns
 */
function isMatchingRoute(pathname: string, patterns: string[]): boolean {
  return patterns.some(pattern => {
    // Exact match
    if (pattern === pathname) return true;

    // Wildcard match
    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -2);
      return pathname.startsWith(prefix);
    }

    // Glob pattern (simple)
    if (pattern.includes('*')) {
      const regex = new RegExp(
        '^' + pattern.replace(/\*/g, '.*').replace(/\//g, '\\/') + '$'
      );
      return regex.test(pathname);
    }

    return false;
  });
}

/**
 * Basic JWT format validation
 */
function isValidTokenFormat(token: string): boolean {
  const parts = token.split('.');
  return parts.length === 3;
}

/**
 * Decode JWT payload (without verification)
 */
function decodeToken(token: string): { exp?: number } | null {
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
 * Check if token is expired
 */
function isTokenExpired(claims: { exp?: number }): boolean {
  if (!claims.exp) return false;
  return Date.now() >= claims.exp * 1000;
}

/**
 * Route matcher helper for Next.js config
 */
export function createRouteMatcher(patterns: string[]): (pathname: string) => boolean {
  return (pathname: string) => isMatchingRoute(pathname, patterns);
}

export default zaltMiddleware;
