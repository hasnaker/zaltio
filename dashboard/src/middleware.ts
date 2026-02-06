/**
 * Next.js Middleware for HSD Auth Dashboard
 * Validates: Requirements 3.1 (responsive web interface)
 * 
 * Handles authentication and security headers
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { authMiddleware } from '@/middleware/auth';

export async function middleware(request: NextRequest) {
  // Run authentication middleware
  const authResponse = await authMiddleware(request);
  if (authResponse) {
    return authResponse;
  }
  
  // Continue with the request
  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
