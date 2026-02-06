/**
 * Membership Model - User-Organization relationship
 * Validates: Requirements 2.1, 2.3
 */

export type MembershipStatus = 'active' | 'invited' | 'suspended';

export interface Membership {
  user_id: string;
  org_id: string;
  realm_id: string;
  role_ids: string[];
  direct_permissions: string[];
  is_default: boolean;
  status: MembershipStatus;
  invited_by?: string;
  invited_at?: string;
  joined_at?: string;
  created_at: string;
  updated_at: string;
}

export interface MembershipWithUser extends Membership {
  user?: {
    id: string;
    email: string;
    name?: string;
    avatar_url?: string;
  };
}

export interface CreateMembershipInput {
  user_id: string;
  org_id: string;
  realm_id: string;
  role_ids?: string[];
  direct_permissions?: string[];
  is_default?: boolean;
  invited_by?: string;
}

export interface UpdateMembershipInput {
  role_ids?: string[];
  direct_permissions?: string[];
  is_default?: boolean;
  status?: MembershipStatus;
}

export interface MembershipListOptions {
  org_id: string;
  status?: MembershipStatus;
  limit?: number;
  cursor?: string;
}

export interface UserMembershipsOptions {
  user_id: string;
  realm_id?: string;
  status?: MembershipStatus;
}

export interface MembershipListResult {
  memberships: MembershipWithUser[];
  next_cursor?: string;
}

/**
 * DynamoDB record structure for memberships
 */
export interface MembershipRecord {
  PK: string;              // MEMBERSHIP#<user_id>
  SK: string;              // ORG#<org_id>
  user_id: string;
  org_id: string;
  realm_id: string;
  role_ids: string[];
  direct_permissions: string[];
  is_default: boolean;
  status: MembershipStatus;
  invited_by?: string;
  invited_at?: number;
  joined_at?: number;
  created_at: number;
  updated_at: number;
  
  // GSI attributes
  GSI1PK?: string;         // ORG#<org_id>
  GSI1SK?: string;         // USER#<user_id>
  GSI2PK?: string;         // REALM#<realm_id>
  GSI2SK?: string;         // USER#<user_id>#ORG#<org_id>
}

/**
 * Convert DynamoDB record to Membership model
 */
export function recordToMembership(record: MembershipRecord): Membership {
  return {
    user_id: record.user_id,
    org_id: record.org_id,
    realm_id: record.realm_id,
    role_ids: record.role_ids || [],
    direct_permissions: record.direct_permissions || [],
    is_default: record.is_default || false,
    status: record.status,
    invited_by: record.invited_by,
    invited_at: record.invited_at ? new Date(record.invited_at).toISOString() : undefined,
    joined_at: record.joined_at ? new Date(record.joined_at).toISOString() : undefined,
    created_at: new Date(record.created_at).toISOString(),
    updated_at: new Date(record.updated_at).toISOString(),
  };
}
