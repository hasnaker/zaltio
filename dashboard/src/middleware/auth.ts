/**
 * Authentication Middleware for HSD Auth Dashboard
 * Validates: Requirements 3.1, 3.2, 3.5
 * 
 * Provides authentication and authorization for admin access
 */

import { NextRequest, NextResponse } from 'next/server';
import { AdminUser, AdminRole, AdminPermission, ROLE_PERMISSIONS, AdminTokenPayload } from '@/types/auth';

// JWT secret should be loaded from environment
const JWT_SECRET = process.env.JWT_SECRET || 'zalt-dashboard-secret';

/**
 * Verify JWT token and extract payload
 */
export function verifyToken(token: string): AdminTokenPayload | null {
  try {
    // In production, use proper JWT verification
    // For now, decode the base64 payload
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    
    // Check expiration
    if (payload.exp && payload.exp < Date.now() / 1000) {
      return null;
    }
    
    return payload as AdminTokenPayload;
  } catch {
    return null;
  }
}

/**
 * Extract admin user from token payload
 */
export function extractAdminUser(payload: AdminTokenPayload): AdminUser {
  return {
    id: payload.sub,
    email: payload.email,
    role: payload.role,
    realm_access: payload.realm_access,
    created_at: new Date(payload.iat * 1000).toISOString(),
    updated_at: new Date().toISOString()
  };
}

/**
 * Check if admin has a specific permission
 */
export function hasPermission(admin: AdminUser, permission: AdminPermission): boolean {
  const rolePermissions = ROLE_PERMISSIONS[admin.role];
  return rolePermissions.includes(permission);
}

/**
 * Check if admin has access to a specific realm
 */
export function hasRealmAccess(admin: AdminUser, realmId: string): boolean {
  if (admin.role === 'super_admin') {
    return true;
  }
  return admin.realm_access.includes(realmId);
}

/**
 * Get all permissions for an admin user
 */
export function getAdminPermissions(admin: AdminUser): AdminPermission[] {
  return [...ROLE_PERMISSIONS[admin.role]];
}

/**
 * Get accessible realms for an admin user
 */
export function getAccessibleRealms(admin: AdminUser, allRealmIds: string[]): string[] {
  if (admin.role === 'super_admin') {
    return [...allRealmIds];
  }
  return admin.realm_access.filter(realmId => allRealmIds.includes(realmId));
}

/**
 * Check if admin can perform a specific action on a realm
 */
export function canPerformAction(
  admin: AdminUser,
  permission: AdminPermission,
  realmId?: string
): boolean {
  if (!hasPermission(admin, permission)) {
    return false;
  }
  
  if (realmId) {
    return hasRealmAccess(admin, realmId);
  }
  
  return true;
}

/**
 * Protected routes that require authentication
 */
const PROTECTED_ROUTES = [
  '/dashboard',
  '/realms',
  '/users',
  '/sessions',
  '/analytics',
  '/settings',
  '/api/realms',
  '/api/users',
  '/api/sessions',
  '/api/analytics'
];

/**
 * Public routes that don't require authentication
 */
const PUBLIC_ROUTES = [
  '/',
  '/login',
  '/signup',
  '/docs',
  '/forgot-password',
  '/api/auth/login',
  '/api/auth/signup',
  '/api/auth/refresh'
];

/**
 * Check if a path is protected
 */
export function isProtectedRoute(pathname: string): boolean {
  return PROTECTED_ROUTES.some(route => pathname.startsWith(route));
}

/**
 * Check if a path is public
 */
export function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some(route => pathname.startsWith(route));
}

/**
 * Authentication middleware for Next.js
 */
export async function authMiddleware(request: NextRequest): Promise<NextResponse | null> {
  const { pathname } = request.nextUrl;
  
  // Allow public routes
  if (isPublicRoute(pathname)) {
    return null;
  }
  
  // Check protected routes
  if (isProtectedRoute(pathname)) {
    const token = request.cookies.get('auth_token')?.value;
    
    if (!token) {
      // Redirect to login for page requests
      if (!pathname.startsWith('/api/')) {
        return NextResponse.redirect(new URL('/login', request.url));
      }
      // Return 401 for API requests
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const payload = verifyToken(token);
    if (!payload) {
      // Clear invalid token and redirect
      const response = pathname.startsWith('/api/')
        ? NextResponse.json({ error: 'Invalid token' }, { status: 401 })
        : NextResponse.redirect(new URL('/login', request.url));
      
      response.cookies.delete('auth_token');
      return response;
    }
  }
  
  return null;
}

/**
 * Permission check middleware for API routes
 */
export function requirePermission(permission: AdminPermission) {
  return async (request: NextRequest): Promise<NextResponse | null> => {
    const token = request.cookies.get('auth_token')?.value;
    
    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const payload = verifyToken(token);
    if (!payload) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }
    
    const admin = extractAdminUser(payload);
    if (!hasPermission(admin, permission)) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }
    
    return null;
  };
}

/**
 * Realm access check middleware for API routes
 */
export function requireRealmAccess(realmIdParam: string = 'realmId') {
  return async (request: NextRequest): Promise<NextResponse | null> => {
    const token = request.cookies.get('auth_token')?.value;
    
    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const payload = verifyToken(token);
    if (!payload) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }
    
    const admin = extractAdminUser(payload);
    
    // Extract realm ID from URL or body
    const url = new URL(request.url);
    const realmId = url.searchParams.get(realmIdParam);
    
    if (realmId && !hasRealmAccess(admin, realmId)) {
      return NextResponse.json({ error: 'Forbidden - No realm access' }, { status: 403 });
    }
    
    return null;
  };
}
