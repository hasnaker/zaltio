/**
 * Authentication types for HSD Auth Dashboard
 * Validates: Requirements 3.1, 3.2, 3.5
 */

/**
 * Admin permission types for dashboard operations
 */
export type AdminPermission = 
  | 'realm:read'
  | 'realm:write'
  | 'realm:delete'
  | 'user:read'
  | 'user:write'
  | 'user:delete'
  | 'session:read'
  | 'session:revoke'
  | 'analytics:read'
  | 'settings:read'
  | 'settings:write';

/**
 * Admin role definitions
 */
export type AdminRole = 'super_admin' | 'realm_admin' | 'realm_viewer' | 'analytics_viewer';

/**
 * Role permission mappings
 */
export const ROLE_PERMISSIONS: Record<AdminRole, AdminPermission[]> = {
  super_admin: [
    'realm:read', 'realm:write', 'realm:delete',
    'user:read', 'user:write', 'user:delete',
    'session:read', 'session:revoke',
    'analytics:read',
    'settings:read', 'settings:write'
  ],
  realm_admin: [
    'realm:read', 'realm:write',
    'user:read', 'user:write', 'user:delete',
    'session:read', 'session:revoke',
    'analytics:read',
    'settings:read', 'settings:write'
  ],
  realm_viewer: [
    'realm:read',
    'user:read',
    'session:read',
    'analytics:read',
    'settings:read'
  ],
  analytics_viewer: [
    'analytics:read'
  ]
};

/**
 * Admin user model for dashboard access
 */
export interface AdminUser {
  id: string;
  email: string;
  role: AdminRole;
  realm_access: string[];
  created_at: string;
  updated_at: string;
}

/**
 * Dashboard capability
 */
export interface DashboardCapability {
  id: string;
  name: string;
  description: string;
  required_permission: AdminPermission;
  realm_specific: boolean;
}

/**
 * Authentication session
 */
export interface AuthSession {
  user: AdminUser;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

/**
 * Login credentials
 */
export interface LoginCredentials {
  email: string;
  password: string;
}

/**
 * JWT payload for admin tokens
 */
export interface AdminTokenPayload {
  sub: string;
  email: string;
  role: AdminRole;
  realm_access: string[];
  iat: number;
  exp: number;
}
