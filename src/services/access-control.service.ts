/**
 * Access Control Service for HSD Auth Platform Dashboard
 * Validates: Requirements 3.2, 3.5
 * 
 * Implements role-based access control for administrative dashboard
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
 * Admin role definitions with associated permissions
 */
export type AdminRole = 'super_admin' | 'realm_admin' | 'realm_viewer' | 'analytics_viewer';

/**
 * Role permission mappings
 * Validates: Requirements 3.5 (role-based access control)
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
  realm_access: string[]; // List of realm IDs the admin can access
  created_at: string;
  updated_at: string;
}

/**
 * Dashboard capability that can be displayed
 */
export interface DashboardCapability {
  id: string;
  name: string;
  description: string;
  required_permission: AdminPermission;
  realm_specific: boolean;
}

/**
 * All available dashboard capabilities
 */
export const DASHBOARD_CAPABILITIES: DashboardCapability[] = [
  {
    id: 'realm_list',
    name: 'View Realms',
    description: 'View list of all realms',
    required_permission: 'realm:read',
    realm_specific: false
  },
  {
    id: 'realm_create',
    name: 'Create Realm',
    description: 'Create new authentication realms',
    required_permission: 'realm:write',
    realm_specific: false
  },
  {
    id: 'realm_edit',
    name: 'Edit Realm',
    description: 'Modify realm configuration',
    required_permission: 'realm:write',
    realm_specific: true
  },
  {
    id: 'realm_delete',
    name: 'Delete Realm',
    description: 'Delete realms and all associated data',
    required_permission: 'realm:delete',
    realm_specific: true
  },
  {
    id: 'user_list',
    name: 'View Users',
    description: 'View users in a realm',
    required_permission: 'user:read',
    realm_specific: true
  },
  {
    id: 'user_create',
    name: 'Create User',
    description: 'Create new users in a realm',
    required_permission: 'user:write',
    realm_specific: true
  },
  {
    id: 'user_edit',
    name: 'Edit User',
    description: 'Modify user profiles and settings',
    required_permission: 'user:write',
    realm_specific: true
  },
  {
    id: 'user_delete',
    name: 'Delete User',
    description: 'Remove users from a realm',
    required_permission: 'user:delete',
    realm_specific: true
  },
  {
    id: 'session_list',
    name: 'View Sessions',
    description: 'View active sessions in a realm',
    required_permission: 'session:read',
    realm_specific: true
  },
  {
    id: 'session_revoke',
    name: 'Revoke Sessions',
    description: 'Terminate user sessions',
    required_permission: 'session:revoke',
    realm_specific: true
  },
  {
    id: 'analytics_view',
    name: 'View Analytics',
    description: 'View authentication analytics and statistics',
    required_permission: 'analytics:read',
    realm_specific: true
  },
  {
    id: 'settings_view',
    name: 'View Settings',
    description: 'View realm settings and configuration',
    required_permission: 'settings:read',
    realm_specific: true
  },
  {
    id: 'settings_edit',
    name: 'Edit Settings',
    description: 'Modify realm settings and configuration',
    required_permission: 'settings:write',
    realm_specific: true
  }
];

/**
 * Check if an admin has a specific permission
 * Validates: Requirements 3.5 (role-based access control)
 */
export function hasPermission(admin: AdminUser, permission: AdminPermission): boolean {
  const rolePermissions = ROLE_PERMISSIONS[admin.role];
  return rolePermissions.includes(permission);
}

/**
 * Check if an admin has access to a specific realm
 * Validates: Requirements 3.2 (realm-specific management)
 */
export function hasRealmAccess(admin: AdminUser, realmId: string): boolean {
  // Super admins have access to all realms
  if (admin.role === 'super_admin') {
    return true;
  }
  
  // Other roles must have explicit realm access
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
 * Validates: Requirements 3.2 (realm-specific management)
 */
export function getAccessibleRealms(admin: AdminUser, allRealmIds: string[]): string[] {
  // Super admins can access all realms
  if (admin.role === 'super_admin') {
    return [...allRealmIds];
  }
  
  // Other roles can only access their assigned realms
  return admin.realm_access.filter(realmId => allRealmIds.includes(realmId));
}

/**
 * Get dashboard capabilities available to an admin for a specific realm
 * Validates: Requirements 3.2, 3.5 (realm-specific + role-based access)
 */
export function getDashboardCapabilities(
  admin: AdminUser,
  realmId?: string
): DashboardCapability[] {
  const permissions = getAdminPermissions(admin);
  
  return DASHBOARD_CAPABILITIES.filter(capability => {
    // Check if admin has the required permission
    if (!permissions.includes(capability.required_permission)) {
      return false;
    }
    
    // For realm-specific capabilities, check realm access
    if (capability.realm_specific && realmId) {
      return hasRealmAccess(admin, realmId);
    }
    
    // Non-realm-specific capabilities are available if permission exists
    return !capability.realm_specific || !realmId;
  });
}

/**
 * Check if admin can perform a specific action on a realm
 * Validates: Requirements 3.2, 3.5
 */
export function canPerformAction(
  admin: AdminUser,
  permission: AdminPermission,
  realmId?: string
): boolean {
  // First check if admin has the permission
  if (!hasPermission(admin, permission)) {
    return false;
  }
  
  // If realm is specified, check realm access
  if (realmId) {
    return hasRealmAccess(admin, realmId);
  }
  
  return true;
}

/**
 * Filter capabilities by realm access
 * Returns only capabilities the admin can use for the given realms
 */
export function filterCapabilitiesByRealmAccess(
  admin: AdminUser,
  capabilities: DashboardCapability[],
  realmIds: string[]
): Map<string, DashboardCapability[]> {
  const result = new Map<string, DashboardCapability[]>();
  
  for (const realmId of realmIds) {
    if (hasRealmAccess(admin, realmId)) {
      const realmCapabilities = capabilities.filter(cap => {
        if (!cap.realm_specific) {
          return hasPermission(admin, cap.required_permission);
        }
        return hasPermission(admin, cap.required_permission);
      });
      result.set(realmId, realmCapabilities);
    }
  }
  
  return result;
}

/**
 * Validate admin access for dashboard display
 * Returns the complete access context for rendering the dashboard
 * Validates: Requirements 3.2, 3.5
 */
export interface DashboardAccessContext {
  admin: AdminUser;
  permissions: AdminPermission[];
  accessibleRealms: string[];
  capabilities: DashboardCapability[];
  realmCapabilities: Map<string, DashboardCapability[]>;
}

export function getDashboardAccessContext(
  admin: AdminUser,
  allRealmIds: string[]
): DashboardAccessContext {
  const permissions = getAdminPermissions(admin);
  const accessibleRealms = getAccessibleRealms(admin, allRealmIds);
  const capabilities = getDashboardCapabilities(admin);
  
  // Get capabilities for each accessible realm
  const realmCapabilities = new Map<string, DashboardCapability[]>();
  for (const realmId of accessibleRealms) {
    realmCapabilities.set(realmId, getDashboardCapabilities(admin, realmId));
  }
  
  return {
    admin,
    permissions,
    accessibleRealms,
    capabilities,
    realmCapabilities
  };
}
