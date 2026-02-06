/**
 * Tediyat Role Model
 * Rol ve yetki yönetimi modeli
 * 
 * Validates: Requirements 16.1-16.6, 17.1-17.4, 18.1-18.3
 */

export interface Role {
  id: string;                       // role_xxx format
  tenant_id?: string;               // null for system roles
  name: string;                     // Role name
  description?: string;             // Role description
  permissions: string[];            // Permission list
  inherits_from?: string;           // Parent role ID for inheritance
  is_system: boolean;               // System role (cannot be modified)
  created_at: string;               // Creation timestamp
  updated_at: string;               // Last update timestamp
}

export interface CreateRoleInput {
  tenant_id: string;
  name: string;
  description?: string;
  permissions: string[];
  inherits_from?: string;
}

export interface UpdateRoleInput {
  name?: string;
  description?: string;
  permissions?: string[];
  inherits_from?: string;
}

/**
 * DynamoDB Schema:
 * 
 * Primary Key:
 *   PK: ROLE#{role_id}
 *   SK: METADATA
 * 
 * GSI1 (TenantRoles):
 *   GSI1PK: TENANT#{tenant_id}#ROLES
 *   GSI1SK: ROLE#{role_id}
 * 
 * GSI2 (SystemRoles):
 *   GSI2PK: SYSTEM#ROLES
 *   GSI2SK: ROLE#{role_id}
 */

export interface RoleDynamoDBItem {
  PK: string;                       // ROLE#{role_id}
  SK: string;                       // METADATA
  GSI1PK: string;                   // TENANT#{tenant_id}#ROLES or SYSTEM#ROLES
  GSI1SK: string;                   // ROLE#{role_id}
  
  // Entity data
  id: string;
  tenant_id?: string;
  name: string;
  description?: string;
  permissions: string[];
  inherits_from?: string;
  is_system: boolean;
  created_at: string;
  updated_at: string;
  
  // Entity type for filtering
  entity_type: 'ROLE';
}

/**
 * Tediyat System Roles
 * These are predefined and cannot be modified
 */
export const TEDIYAT_SYSTEM_ROLES: Record<string, Role> = {
  owner: {
    id: 'role_owner',
    name: 'Şirket Sahibi',
    description: 'Tüm yetkilere sahip şirket sahibi',
    permissions: ['*'],
    is_system: true,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z'
  },
  admin: {
    id: 'role_admin',
    name: 'Yönetici',
    description: 'Kullanıcı yönetimi hariç tüm yetkiler',
    permissions: [
      'invoices:*', 'accounts:*', 'cash:*', 'bank:*',
      'reports:*', 'inventory:*', 'e-invoice:*',
      'settings:*', 'quotes:*', 'payments:*'
    ],
    is_system: true,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z'
  },
  accountant: {
    id: 'role_accountant',
    name: 'Muhasebeci',
    description: 'Fatura, hesap ve raporlama yetkileri',
    permissions: [
      'invoices:read', 'invoices:create', 'invoices:update',
      'accounts:read', 'accounts:create', 'accounts:update',
      'cash:read', 'cash:write', 'bank:read', 'bank:write',
      'reports:read', 'reports:export',
      'quotes:read', 'quotes:create', 'quotes:update',
      'payments:read', 'payments:create'
    ],
    is_system: true,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z'
  },
  viewer: {
    id: 'role_viewer',
    name: 'Görüntüleyici',
    description: 'Sadece okuma yetkisi',
    permissions: [
      'invoices:read', 'accounts:read', 'cash:read',
      'bank:read', 'reports:read', 'inventory:read',
      'quotes:read', 'payments:read'
    ],
    is_system: true,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z'
  },
  external_accountant: {
    id: 'role_external_accountant',
    name: 'Mali Müşavir',
    description: 'Dış muhasebeci için sınırlı okuma ve export yetkileri',
    permissions: [
      'invoices:read', 'accounts:read', 'reports:read',
      'reports:export', 'e-invoice:read'
    ],
    is_system: true,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z'
  }
};

/**
 * Tediyat Permission Categories
 */
export const TEDIYAT_PERMISSION_CATEGORIES = {
  invoices: {
    name: 'Faturalar',
    actions: ['read', 'create', 'update', 'delete', '*']
  },
  accounts: {
    name: 'Hesaplar',
    actions: ['read', 'create', 'update', 'delete', '*']
  },
  cash: {
    name: 'Kasa',
    actions: ['read', 'write']
  },
  bank: {
    name: 'Banka',
    actions: ['read', 'write']
  },
  reports: {
    name: 'Raporlar',
    actions: ['read', 'export']
  },
  inventory: {
    name: 'Stok',
    actions: ['read', 'write']
  },
  'e-invoice': {
    name: 'E-Fatura',
    actions: ['read', 'send']
  },
  settings: {
    name: 'Ayarlar',
    actions: ['read', 'write']
  },
  users: {
    name: 'Kullanıcılar',
    actions: ['read', 'invite', 'manage']
  },
  quotes: {
    name: 'Teklifler',
    actions: ['read', 'create', 'update', 'delete', '*']
  },
  payments: {
    name: 'Ödemeler',
    actions: ['read', 'create', 'refund']
  }
};

/**
 * Generate custom role ID
 */
export function generateRoleId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `role_${timestamp}${random}`;
}

/**
 * Validate permission format
 * Format: resource:action (e.g., invoices:read)
 */
export function isValidPermission(permission: string): boolean {
  // Wildcard for all permissions
  if (permission === '*') {
    return true;
  }
  
  const parts = permission.split(':');
  if (parts.length !== 2) {
    return false;
  }
  
  const [resource, action] = parts;
  
  // Check if resource exists
  if (!(resource in TEDIYAT_PERMISSION_CATEGORIES)) {
    return false;
  }
  
  // Check if action is valid for resource
  const category = TEDIYAT_PERMISSION_CATEGORIES[resource as keyof typeof TEDIYAT_PERMISSION_CATEGORIES];
  return category.actions.includes(action);
}

/**
 * Expand wildcard permissions
 * e.g., invoices:* → [invoices:read, invoices:create, ...]
 */
export function expandWildcardPermission(permission: string): string[] {
  if (permission === '*') {
    // Return all permissions
    const allPermissions: string[] = [];
    for (const [resource, category] of Object.entries(TEDIYAT_PERMISSION_CATEGORIES)) {
      for (const action of category.actions) {
        if (action !== '*') {
          allPermissions.push(`${resource}:${action}`);
        }
      }
    }
    return allPermissions;
  }
  
  const [resource, action] = permission.split(':');
  
  if (action === '*') {
    const category = TEDIYAT_PERMISSION_CATEGORIES[resource as keyof typeof TEDIYAT_PERMISSION_CATEGORIES];
    if (!category) {
      return [permission];
    }
    return category.actions
      .filter(a => a !== '*')
      .map(a => `${resource}:${a}`);
  }
  
  return [permission];
}

/**
 * Get effective permissions for a role (including inherited)
 */
export function getEffectiveRolePermissions(
  role: Role,
  allRoles: Record<string, Role>
): string[] {
  const permissions = new Set<string>();
  
  // Add role's own permissions
  for (const perm of role.permissions) {
    const expanded = expandWildcardPermission(perm);
    for (const p of expanded) {
      permissions.add(p);
    }
  }
  
  // Add inherited permissions
  if (role.inherits_from && allRoles[role.inherits_from]) {
    const parentPermissions = getEffectiveRolePermissions(
      allRoles[role.inherits_from],
      allRoles
    );
    for (const perm of parentPermissions) {
      permissions.add(perm);
    }
  }
  
  return Array.from(permissions);
}

/**
 * Check if role is a system role
 */
export function isSystemRole(roleId: string): boolean {
  return Object.values(TEDIYAT_SYSTEM_ROLES).some(r => r.id === roleId);
}

/**
 * Get system role by ID
 */
export function getSystemRole(roleId: string): Role | undefined {
  return Object.values(TEDIYAT_SYSTEM_ROLES).find(r => r.id === roleId);
}

/**
 * Get all system roles
 */
export function getAllSystemRoles(): Role[] {
  return Object.values(TEDIYAT_SYSTEM_ROLES);
}
