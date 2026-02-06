/**
 * Tediyat Tenant Model
 * Multi-tenant şirket/organizasyon modeli
 * 
 * Validates: Requirements 9.1-9.5, 16.1-16.6
 */

export interface TenantMetadata {
  taxNumber?: string;      // Vergi numarası
  address?: string;        // Adres
  phone?: string;          // Telefon
  email?: string;          // İletişim email
  city?: string;           // Şehir
  country?: string;        // Ülke (default: TR)
}

export interface TenantSettings {
  mfa_required?: boolean;           // Tenant-level MFA zorunluluğu
  session_timeout?: number;         // Custom session timeout (saniye)
  allowed_domains?: string[];       // Email domain kısıtlaması
  max_members?: number;             // Maksimum üye sayısı
  webhook_url?: string;             // Webhook endpoint
  webhook_secret?: string;          // Webhook HMAC secret
}

export type TenantStatus = 'active' | 'suspended' | 'deleted';

export interface Tenant {
  id: string;                       // ten_xxx format
  realm_id: string;                 // tediyat
  name: string;                     // Şirket adı (Turkish chars supported)
  slug: string;                     // URL-safe slug (abc-sirketi)
  logo_url?: string;                // Logo URL
  metadata?: TenantMetadata;        // Ek bilgiler
  settings?: TenantSettings;        // Tenant ayarları
  status: TenantStatus;             // Durum
  member_count: number;             // Üye sayısı (denormalized)
  created_at: string;               // ISO timestamp
  updated_at: string;               // ISO timestamp
  created_by: string;               // Owner user_id
}

export interface CreateTenantInput {
  name: string;
  slug?: string;                    // Optional, auto-generated if not provided
  logo_url?: string;
  metadata?: TenantMetadata;
  settings?: TenantSettings;
  created_by: string;               // Owner user_id
}

export interface UpdateTenantInput {
  name?: string;
  logo_url?: string;
  metadata?: TenantMetadata;
  settings?: TenantSettings;
  status?: TenantStatus;
}

export interface TenantWithRole extends Tenant {
  role: string;                     // User's role in this tenant
  role_name: string;                // Human-readable role name
  is_default: boolean;              // Is this user's default tenant
}

/**
 * DynamoDB Schema:
 * 
 * Primary Key:
 *   PK: TENANT#{tenant_id}
 *   SK: METADATA
 * 
 * GSI1 (RealmTenants):
 *   GSI1PK: REALM#{realm_id}#TENANTS
 *   GSI1SK: TENANT#{tenant_id}
 * 
 * GSI2 (SlugLookup):
 *   GSI2PK: SLUG#{slug}
 *   GSI2SK: TENANT
 * 
 * GSI3 (OwnerTenants):
 *   GSI3PK: OWNER#{user_id}
 *   GSI3SK: TENANT#{tenant_id}
 */

export interface TenantDynamoDBItem {
  PK: string;                       // TENANT#{tenant_id}
  SK: string;                       // METADATA
  GSI1PK: string;                   // REALM#{realm_id}#TENANTS
  GSI1SK: string;                   // TENANT#{tenant_id}
  GSI2PK: string;                   // SLUG#{slug}
  GSI2SK: string;                   // TENANT
  GSI3PK: string;                   // OWNER#{user_id}
  GSI3SK: string;                   // TENANT#{tenant_id}
  
  // Entity data
  id: string;
  realm_id: string;
  name: string;
  slug: string;
  logo_url?: string;
  metadata?: TenantMetadata;
  settings?: TenantSettings;
  status: TenantStatus;
  member_count: number;
  created_at: string;
  updated_at: string;
  created_by: string;
  
  // Entity type for filtering
  entity_type: 'TENANT';
}

/**
 * Generate tenant ID
 */
export function generateTenantId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `ten_${timestamp}${random}`;
}

/**
 * Generate URL-safe slug from company name
 * Supports Turkish characters
 */
export function generateSlug(name: string): string {
  // Turkish character mapping
  const turkishMap: Record<string, string> = {
    'ç': 'c', 'Ç': 'c',
    'ğ': 'g', 'Ğ': 'g',
    'ı': 'i', 'İ': 'i',
    'ö': 'o', 'Ö': 'o',
    'ş': 's', 'Ş': 's',
    'ü': 'u', 'Ü': 'u'
  };
  
  let slug = name.toLowerCase();
  
  // Replace Turkish characters
  for (const [turkish, latin] of Object.entries(turkishMap)) {
    slug = slug.replace(new RegExp(turkish, 'g'), latin);
  }
  
  // Replace spaces and special chars with hyphens
  slug = slug
    .replace(/[^a-z0-9\s-]/g, '')  // Remove non-alphanumeric except spaces and hyphens
    .replace(/\s+/g, '-')           // Replace spaces with hyphens
    .replace(/-+/g, '-')            // Replace multiple hyphens with single
    .replace(/^-|-$/g, '');         // Remove leading/trailing hyphens
  
  return slug;
}

/**
 * Validate slug format
 */
export function isValidSlug(slug: string): boolean {
  // Must be lowercase alphanumeric with hyphens, 3-50 chars
  const slugRegex = /^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$/;
  return slugRegex.test(slug) && !slug.includes('--');
}
