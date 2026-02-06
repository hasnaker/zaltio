/**
 * Zalt.io Next.js SDK
 * @zalt/next
 * 
 * Next.js middleware and server helpers for Zalt.io Authentication
 * 
 * @packageDocumentation
 * 
 * @example
 * ```ts
 * // middleware.ts
 * import { zaltMiddleware } from '@zalt/next';
 * 
 * export default zaltMiddleware({
 *   publicRoutes: ['/', '/sign-in', '/sign-up'],
 * });
 * 
 * export const config = {
 *   matcher: ['/((?!_next|.*\\..*).*)'],
 * };
 * ```
 * 
 * @example
 * ```tsx
 * // app/dashboard/page.tsx
 * import { getAuth, currentUser } from '@zalt/next/server';
 * import { redirect } from 'next/navigation';
 * 
 * export default async function DashboardPage() {
 *   const user = await currentUser();
 *   
 *   if (!user) {
 *     redirect('/sign-in');
 *   }
 *   
 *   return <Dashboard user={user} />;
 * }
 * ```
 */

// Middleware
export {
  zaltMiddleware,
  createRouteMatcher,
  type MiddlewareConfig,
} from './middleware';

// Server helpers
export {
  getAuth,
  currentUser,
  withAuth,
  clearAuthCookies,
  setAuthCookies,
  type AuthResult,
  type ServerConfig,
} from './server';

// Re-export useful types from core
export type { User, JWTClaims } from '@zalt.io/core';

// Default export for convenience
export { zaltMiddleware as default } from './middleware';
