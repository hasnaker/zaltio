/**
 * User-Generated API Key Model - Personal API keys for Zalt.io users
 * 
 * User API keys allow end users to create their own API keys for
 * programmatic access. These keys inherit the user's permissions
 * and tenant context.
 * 
 * Key Format: zalt_key_{32 alphanumeric chars}
 * Example: zalt_key_abc123def456ghi789jkl012mno345pq
 * 
 * Validates: Requirements 2.1, 2.2 (User-Generated API Keys)
 */

export type UserAPIKeyStatus = 'active' | 'revoked' | 'expired';

/**
 * User-generated API key entity
 */
export interface UserAPIKey {
  id: string;                    // key_xxx format
  user_id: string;               // Owner user
  realm_id: string;              // Realm context
  tenant_id?: string;            // Optional tenant context
  
  // Key identification
  name: string;                  // User-friendly name
  description?: string;          // Optional description
  key_prefix: string;            // First 12 chars for display (zalt_key_xxx...)
  key_hash: string;              // SHA-256 hash of full key (for lookup)
  
  // Permissions
  scopes: string[];              // Allowed scopes (subset of user's permissions)
  
  // Status
  status: UserAPIKeyStatus;
  
  // Timestamps
  created_at: string;
  updated_at: string;
  expires_at?: string;           // Optional expiration
  last_used_at?: string;
  revoked_at?: string;
  revoked_by?: string;
  
  // Metadata
  usage_count: number;
  ip_restrictions?: string[];    // Optional IP allowlist (CIDR)
}

/**
 * Input for creating a new user API key
 */
export interface CreateUserAPIKeyInput {
  user_id: string;
  realm_id: string;
  tenant_id?: string;
  name: string;
  description?: string;
  scopes?: string[];             // Optional: defaults to user's full permissions
  expires_at?: string;           // Optional: ISO date string
  ip_restrictions?: string[];    // Optional: CIDR notation
}

/**
 * Response when creating a user API key (includes full key once)
 */
export interface UserAPIKeyWithSecret {
  key: UserAPIKeyResponse;
  full_key: string;              // Only returned once on creation
}

/**
 * User API key response (excludes sensitive data)
 */
export interface UserAPIKeyResponse {
  id: string;
  user_id: string;
  realm_id: string;
  tenant_id?: string;
  name: string;
  description?: string;
  key_prefix: string;
  scopes: string[];
  status: UserAPIKeyStatus;
  created_at: string;
  updated_at: string;
  expires_at?: string;
  last_used_at?: string;
  usage_count: number;
  ip_restrictions?: string[];
}

/**
 * User context returned when validating an API key
 */
export interface UserAPIKeyContext {
  key: UserAPIKey;
  user_id: string;
  realm_id: string;
  tenant_id?: string;
  scopes: string[];
}

/**
 * Key prefix for user-generated API keys
 */
export const USER_API_KEY_PREFIX = 'zalt_key_';

/**
 * Key length (prefix + 32 alphanumeric chars)
 */
export const USER_API_KEY_LENGTH = USER_API_KEY_PREFIX.length + 32;

/**
 * Available scopes for user API keys
 * These are a subset of what users can do
 */
export const USER_API_KEY_SCOPES = {
  // User profile
  'profile:read': 'Read own profile',
  'profile:write': 'Update own profile',
  
  // Sessions
  'sessions:read': 'Read own sessions',
  'sessions:revoke': 'Revoke own sessions',
  
  // Tenants (if user has access)
  'tenants:read': 'Read tenant data',
  'tenants:write': 'Update tenant data',
  
  // Members (if user has permission)
  'members:read': 'Read tenant members',
  'members:invite': 'Invite members',
  'members:remove': 'Remove members',
  
  // Roles (if user has permission)
  'roles:read': 'Read roles',
  'roles:write': 'Manage roles',
  
  // API access
  'api:read': 'Read API data',
  'api:write': 'Write API data',
  
  // Full access (inherits all user permissions)
  'full:access': 'Full access (all user permissions)'
} as const;

export type UserAPIKeyScope = keyof typeof USER_API_KEY_SCOPES;

/**
 * Validate user API key format
 */
export function isValidUserAPIKeyFormat(key: string): boolean {
  if (!key.startsWith(USER_API_KEY_PREFIX)) {
    return false;
  }
  
  if (key.length !== USER_API_KEY_LENGTH) {
    return false;
  }
  
  // Check that the suffix is alphanumeric
  const suffix = key.substring(USER_API_KEY_PREFIX.length);
  return /^[a-zA-Z0-9]{32}$/.test(suffix);
}

/**
 * Validate scope string
 */
export function isValidUserAPIKeyScope(scope: string): scope is UserAPIKeyScope {
  return scope in USER_API_KEY_SCOPES;
}

/**
 * Validate all scopes in array
 */
export function validateUserAPIKeyScopes(scopes: string[]): { valid: boolean; invalid: string[] } {
  const invalid = scopes.filter(s => !isValidUserAPIKeyScope(s));
  return {
    valid: invalid.length === 0,
    invalid
  };
}

/**
 * Check if requested scopes are subset of allowed scopes
 */
export function userAPIKeyScopesAllowed(requested: string[], allowed: string[]): boolean {
  // full:access grants all scopes
  if (allowed.includes('full:access')) {
    return true;
  }
  return requested.every(scope => allowed.includes(scope));
}

/**
 * Get key prefix for display (first 12 chars)
 */
export function getKeyDisplayPrefix(fullKey: string): string {
  return fullKey.substring(0, 12) + '...';
}
