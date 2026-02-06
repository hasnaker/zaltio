/**
 * Tediyat Membership Model
 * Kullanıcı-Tenant ilişkisi modeli
 * 
 * Validates: Requirements 14.1-14.4, 15.1-15.4, 19.1-19.4
 */

export type MembershipStatus = 'active' | 'invited' | 'suspended';

export interface Membership {
  user_id: string;                  // User ID
  tenant_id: string;                // Tenant ID
  realm_id: string;                 // tediyat
  role_id: string;                  // role_owner, role_admin, etc.
  role_name: string;                // Human-readable role name (denormalized)
  direct_permissions?: string[];    // Additional permissions beyond role
  status: MembershipStatus;         // Membership status
  is_default: boolean;              // Is this user's default tenant
  invited_by?: string;              // Who invited this user
  invited_at?: string;              // When invitation was sent
  joined_at: string;                // When user joined
  updated_at: string;               // Last update timestamp
}

export interface CreateMembershipInput {
  user_id: string;
  tenant_id: string;
  realm_id: string;
  role_id: string;
  role_name: string;
  direct_permissions?: string[];
  is_default?: boolean;
  invited_by?: string;
}

export interface UpdateMembershipInput {
  role_id?: string;
  role_name?: string;
  direct_permissions?: string[];
  status?: MembershipStatus;
  is_default?: boolean;
}

export interface MemberWithUser extends Membership {
  user: {
    id: string;
    email: string;
    first_name: string;
    last_name: string;
    avatar_url?: string;
  };
}

export interface PaginatedMembers {
  members: MemberWithUser[];
  total: number;
  page: number;
  page_size: number;
  has_more: boolean;
  next_cursor?: string;
}

/**
 * DynamoDB Schema:
 * 
 * Primary Key:
 *   PK: USER#{user_id}#TENANT#{tenant_id}
 *   SK: MEMBERSHIP
 * 
 * GSI1 (TenantMembers):
 *   GSI1PK: TENANT#{tenant_id}#MEMBERS
 *   GSI1SK: USER#{user_id}
 * 
 * GSI2 (UserMemberships):
 *   GSI2PK: USER#{user_id}#MEMBERSHIPS
 *   GSI2SK: TENANT#{tenant_id}
 * 
 * GSI3 (RoleMembers):
 *   GSI3PK: TENANT#{tenant_id}#ROLE#{role_id}
 *   GSI3SK: USER#{user_id}
 */

export interface MembershipDynamoDBItem {
  PK: string;                       // USER#{user_id}#TENANT#{tenant_id}
  SK: string;                       // MEMBERSHIP
  GSI1PK: string;                   // TENANT#{tenant_id}#MEMBERS
  GSI1SK: string;                   // USER#{user_id}
  GSI2PK: string;                   // USER#{user_id}#MEMBERSHIPS
  GSI2SK: string;                   // TENANT#{tenant_id}
  GSI3PK: string;                   // TENANT#{tenant_id}#ROLE#{role_id}
  GSI3SK: string;                   // USER#{user_id}
  
  // Entity data
  user_id: string;
  tenant_id: string;
  realm_id: string;
  role_id: string;
  role_name: string;
  direct_permissions?: string[];
  status: MembershipStatus;
  is_default: boolean;
  invited_by?: string;
  invited_at?: string;
  joined_at: string;
  updated_at: string;
  
  // Entity type for filtering
  entity_type: 'MEMBERSHIP';
}

/**
 * Check if user has specific permission
 */
export function hasPermission(
  membership: Membership,
  rolePermissions: string[],
  requiredPermission: string
): boolean {
  // Combine role permissions with direct permissions
  const allPermissions = [
    ...rolePermissions,
    ...(membership.direct_permissions || [])
  ];
  
  // Check for wildcard (owner has all)
  if (allPermissions.includes('*')) {
    return true;
  }
  
  // Parse required permission
  const [resource, action] = requiredPermission.split(':');
  
  // Check for exact match
  if (allPermissions.includes(requiredPermission)) {
    return true;
  }
  
  // Check for resource wildcard (e.g., invoices:* grants invoices:read)
  if (allPermissions.includes(`${resource}:*`)) {
    return true;
  }
  
  return false;
}

/**
 * Get effective permissions for a membership
 */
export function getEffectivePermissions(
  rolePermissions: string[],
  directPermissions?: string[]
): string[] {
  const permissions = new Set<string>();
  
  // Add role permissions
  for (const perm of rolePermissions) {
    permissions.add(perm);
  }
  
  // Add direct permissions
  if (directPermissions) {
    for (const perm of directPermissions) {
      permissions.add(perm);
    }
  }
  
  return Array.from(permissions);
}
