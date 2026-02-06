/**
 * Permission System - Parser, Matcher, and Checker
 * Validates: Requirements 4.1, 4.2, 4.3, 4.4
 * 
 * Permission Format: resource:action[:scope]
 * Examples:
 *   - users:read        (read users, any scope)
 *   - users:read:own    (read own user only)
 *   - users:read:org    (read users in organization)
 *   - users:*           (all actions on users)
 *   - *                 (superadmin - all permissions)
 */

export type PermissionScope = 'own' | 'org' | 'realm' | '*';

export interface ParsedPermission {
  resource: string;
  action: string;
  scope: PermissionScope;
  raw: string;
}

/**
 * Scope hierarchy: own < org < realm < *
 * Higher scope includes lower scopes
 */
const SCOPE_HIERARCHY: Record<PermissionScope, number> = {
  'own': 1,
  'org': 2,
  'realm': 3,
  '*': 4,
};

/**
 * Parse a permission string into components
 */
export function parsePermission(permission: string): ParsedPermission {
  const trimmed = permission.trim();
  
  // Handle superadmin wildcard
  if (trimmed === '*') {
    return {
      resource: '*',
      action: '*',
      scope: '*',
      raw: trimmed,
    };
  }

  const parts = trimmed.split(':');
  
  if (parts.length < 2) {
    throw new Error(`Invalid permission format: ${permission}. Expected resource:action[:scope]`);
  }

  const resource = parts[0];
  const action = parts[1];
  const scope = (parts[2] as PermissionScope) || '*';

  // Validate scope
  if (!['own', 'org', 'realm', '*'].includes(scope)) {
    throw new Error(`Invalid scope: ${scope}. Expected own, org, realm, or *`);
  }

  return {
    resource,
    action,
    scope,
    raw: trimmed,
  };
}

/**
 * Check if a scope satisfies another scope requirement
 * e.g., 'realm' scope satisfies 'org' requirement
 */
export function scopeSatisfies(hasScope: PermissionScope, needsScope: PermissionScope): boolean {
  return SCOPE_HIERARCHY[hasScope] >= SCOPE_HIERARCHY[needsScope];
}

/**
 * Check if a permission matches a required permission
 * Supports wildcards and scope hierarchy
 */
export function matchPermission(
  hasPermission: ParsedPermission,
  needsPermission: ParsedPermission
): boolean {
  // Superadmin wildcard matches everything
  if (hasPermission.resource === '*' && hasPermission.action === '*') {
    return true;
  }

  // Check resource match (exact or wildcard)
  const resourceMatches = 
    hasPermission.resource === '*' || 
    hasPermission.resource === needsPermission.resource;

  if (!resourceMatches) {
    return false;
  }

  // Check action match (exact or wildcard)
  const actionMatches = 
    hasPermission.action === '*' || 
    hasPermission.action === needsPermission.action;

  if (!actionMatches) {
    return false;
  }

  // Check scope hierarchy
  return scopeSatisfies(hasPermission.scope, needsPermission.scope);
}

/**
 * Check if a user has a specific permission
 */
export function hasPermission(
  userPermissions: string[],
  requiredPermission: string
): boolean {
  const required = parsePermission(requiredPermission);

  for (const perm of userPermissions) {
    try {
      const parsed = parsePermission(perm);
      if (matchPermission(parsed, required)) {
        return true;
      }
    } catch {
      // Skip invalid permissions
      continue;
    }
  }

  return false;
}

/**
 * Check if user has any of the required permissions
 */
export function hasAnyPermission(
  userPermissions: string[],
  requiredPermissions: string[]
): boolean {
  return requiredPermissions.some(req => hasPermission(userPermissions, req));
}

/**
 * Check if user has all of the required permissions
 */
export function hasAllPermissions(
  userPermissions: string[],
  requiredPermissions: string[]
): boolean {
  return requiredPermissions.every(req => hasPermission(userPermissions, req));
}

/**
 * Filter permissions by resource
 */
export function filterPermissionsByResource(
  permissions: string[],
  resource: string
): string[] {
  return permissions.filter(perm => {
    try {
      const parsed = parsePermission(perm);
      return parsed.resource === '*' || parsed.resource === resource;
    } catch {
      return false;
    }
  });
}

/**
 * Get effective scope for a resource:action combination
 * Returns the highest scope the user has for that permission
 */
export function getEffectiveScope(
  userPermissions: string[],
  resource: string,
  action: string
): PermissionScope | null {
  let highestScope: PermissionScope | null = null;

  for (const perm of userPermissions) {
    try {
      const parsed = parsePermission(perm);
      
      // Check if this permission applies
      const resourceMatches = parsed.resource === '*' || parsed.resource === resource;
      const actionMatches = parsed.action === '*' || parsed.action === action;

      if (resourceMatches && actionMatches) {
        if (!highestScope || SCOPE_HIERARCHY[parsed.scope] > SCOPE_HIERARCHY[highestScope]) {
          highestScope = parsed.scope;
        }
      }
    } catch {
      continue;
    }
  }

  return highestScope;
}

/**
 * Normalize and deduplicate permissions
 * Removes redundant permissions (e.g., users:read when users:* exists)
 */
export function normalizePermissions(permissions: string[]): string[] {
  const parsed = permissions
    .map(p => {
      try {
        return parsePermission(p);
      } catch {
        return null;
      }
    })
    .filter((p): p is ParsedPermission => p !== null);

  // Check for superadmin
  if (parsed.some(p => p.resource === '*' && p.action === '*')) {
    return ['*'];
  }

  // Remove redundant permissions
  const normalized: ParsedPermission[] = [];

  for (const perm of parsed) {
    // Check if this permission is already covered by another
    const isCovered = normalized.some(existing => 
      matchPermission(existing, perm) && existing.raw !== perm.raw
    );

    if (!isCovered) {
      // Remove any permissions that this one covers
      const filtered = normalized.filter(existing => 
        !matchPermission(perm, existing) || existing.raw === perm.raw
      );
      filtered.push(perm);
      normalized.length = 0;
      normalized.push(...filtered);
    }
  }

  return normalized.map(p => p.raw);
}

/**
 * Common permission constants
 */
export const PERMISSIONS = {
  // User management
  USERS_CREATE: 'users:create',
  USERS_READ: 'users:read',
  USERS_READ_OWN: 'users:read:own',
  USERS_UPDATE: 'users:update',
  USERS_UPDATE_OWN: 'users:update:own',
  USERS_DELETE: 'users:delete',
  USERS_ALL: 'users:*',

  // Role management
  ROLES_CREATE: 'roles:create',
  ROLES_READ: 'roles:read',
  ROLES_UPDATE: 'roles:update',
  ROLES_DELETE: 'roles:delete',
  ROLES_ASSIGN: 'roles:assign',
  ROLES_ALL: 'roles:*',

  // Organization management
  ORGS_CREATE: 'organizations:create',
  ORGS_READ: 'organizations:read',
  ORGS_UPDATE: 'organizations:update',
  ORGS_DELETE: 'organizations:delete',
  ORGS_ALL: 'organizations:*',

  // Membership management
  MEMBERS_INVITE: 'members:invite',
  MEMBERS_REMOVE: 'members:remove',
  MEMBERS_READ: 'members:read',
  MEMBERS_ALL: 'members:*',

  // Settings
  SETTINGS_READ: 'settings:read',
  SETTINGS_UPDATE: 'settings:update',
  SETTINGS_ALL: 'settings:*',

  // Audit
  AUDIT_READ: 'audit:read',

  // Superadmin
  SUPERADMIN: '*',
} as const;
