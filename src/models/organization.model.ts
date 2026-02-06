/**
 * Organization Model - Multi-tenant organization structure
 * Validates: Requirements 1.1, 1.2, 1.6
 */

export interface OrganizationSettings {
  user_limit?: number;
  mfa_required?: boolean;
  allowed_domains?: string[];
  default_role_id?: string;
  features?: {
    webhooks_enabled?: boolean;
    api_access_enabled?: boolean;
    sso_enabled?: boolean;
  };
}

export interface Organization {
  id: string;
  realm_id: string;
  name: string;
  slug: string;
  logo_url?: string;
  custom_data?: Record<string, unknown>;
  settings: OrganizationSettings;
  status: OrganizationStatus;
  member_count: number;
  created_at: string;
  updated_at: string;
  deleted_at?: string;
}

export type OrganizationStatus = 'active' | 'suspended' | 'deleted';

export interface CreateOrganizationInput {
  realm_id: string;
  name: string;
  slug?: string;
  logo_url?: string;
  custom_data?: Record<string, unknown>;
  settings?: Partial<OrganizationSettings>;
}

export interface UpdateOrganizationInput {
  name?: string;
  slug?: string;
  logo_url?: string;
  custom_data?: Record<string, unknown>;
  settings?: Partial<OrganizationSettings>;
  status?: OrganizationStatus;
}

export interface OrganizationListOptions {
  realm_id: string;
  status?: OrganizationStatus;
  limit?: number;
  cursor?: string;
}

export interface OrganizationListResult {
  organizations: Organization[];
  next_cursor?: string;
  total_count: number;
}

/**
 * DynamoDB record structure for organizations
 */
export interface OrganizationRecord {
  PK: string;              // ORG#<org_id>
  SK: string;              // METADATA
  org_id: string;
  realm_id: string;
  name: string;
  slug: string;
  logo_url?: string;
  custom_data?: Record<string, unknown>;
  settings: OrganizationSettings;
  status: OrganizationStatus;
  member_count: number;
  created_at: number;
  updated_at: number;
  deleted_at?: number;
  
  // GSI attributes
  GSI1PK?: string;         // REALM#<realm_id>
  GSI1SK?: string;         // ORG#<created_at>#<org_id>
}

/**
 * Convert DynamoDB record to Organization model
 */
export function recordToOrganization(record: OrganizationRecord): Organization {
  return {
    id: record.org_id,
    realm_id: record.realm_id,
    name: record.name,
    slug: record.slug,
    logo_url: record.logo_url,
    custom_data: record.custom_data,
    settings: record.settings || {},
    status: record.status,
    member_count: record.member_count || 0,
    created_at: new Date(record.created_at).toISOString(),
    updated_at: new Date(record.updated_at).toISOString(),
    deleted_at: record.deleted_at ? new Date(record.deleted_at).toISOString() : undefined,
  };
}

/**
 * Generate URL-friendly slug from name
 */
export function generateSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 50);
}
