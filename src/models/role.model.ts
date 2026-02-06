/**
 * Role Model - RBAC role definitions
 * Validates: Requirements 3.1, 3.2, 3.3
 */

export type RoleScope = 'system' | 'realm' | 'organization';

export interface Role {
  id: string;
  realm_id: string;
  org_id?: string;           // null for realm-level roles
  name: string;
  description?: string;
  permissions: string[];
  is_system: boolean;        // System roles cannot be modified/deleted
  inherits_from?: string[];  // Role inheritance
  created_at: string;
  updated_at: string;
}

export interface CreateRoleInput {
  realm_id: string;
  org_id?: string;
  name: string;
  description?: string;
  permissions: string[];
  inherits_from?: string[];
}

export interface UpdateRoleInput {
  name?: string;
  description?: string;
  permissions?: string[];
  inherits_from?: string[];
}

export interface RoleListOptions {
  realm_id: string;
  org_id?: string;
  include_system?: boolean;
  limit?: number;
  cursor?: string;
}

export interface RoleListResult {
  roles: Role[];
  next_cursor?: string;
}

/**
 * DynamoDB record structure for roles
 */
export interface RoleRecord {
  PK: string;              // ROLE#<role_id>
  SK: string;              // METADATA
  role_id: string;
  realm_id: string;
  org_id?: string;
  name: string;
  description?: string;
  permissions: string[];
  is_system: boolean;
  inherits_from?: string[];
  created_at: number;
  updated_at: number;
  
  // GSI attributes
  GSI1PK?: string;         // REALM#<realm_id> or ORG#<org_id>
  GSI1SK?: string;         // ROLE#<name>
}

/**
 * Convert DynamoDB record to Role model
 */
export function recordToRole(record: RoleRecord): Role {
  return {
    id: record.role_id,
    realm_id: record.realm_id,
    org_id: record.org_id,
    name: record.name,
    description: record.description,
    permissions: record.permissions || [],
    is_system: record.is_system || false,
    inherits_from: record.inherits_from,
    created_at: new Date(record.created_at).toISOString(),
    updated_at: new Date(record.updated_at).toISOString(),
  };
}

/**
 * System roles - predefined and immutable
 */
export const SYSTEM_ROLES = {
  OWNER: {
    id: 'role_owner',
    name: 'Owner',
    description: 'Full access to organization',
    permissions: ['*'],
  },
  ADMIN: {
    id: 'role_admin',
    name: 'Admin',
    description: 'Administrative access',
    permissions: [
      'users:*',
      'roles:read',
      'roles:assign',
      'settings:*',
      'audit:read',
    ],
  },
  MEMBER: {
    id: 'role_member',
    name: 'Member',
    description: 'Standard member access',
    permissions: [
      'users:read:own',
      'users:update:own',
    ],
  },
  VIEWER: {
    id: 'role_viewer',
    name: 'Viewer',
    description: 'Read-only access',
    permissions: [
      'users:read:own',
    ],
  },
} as const;

export type SystemRoleId = typeof SYSTEM_ROLES[keyof typeof SYSTEM_ROLES]['id'];

/**
 * Check if role ID is a system role
 */
export function isSystemRole(roleId: string): boolean {
  return Object.values(SYSTEM_ROLES).some(r => r.id === roleId);
}

/**
 * Get system role by ID
 */
export function getSystemRole(roleId: string): typeof SYSTEM_ROLES[keyof typeof SYSTEM_ROLES] | null {
  const role = Object.values(SYSTEM_ROLES).find(r => r.id === roleId);
  return role || null;
}
