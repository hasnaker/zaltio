/**
 * Machine Model - M2M (Machine-to-Machine) authentication for Zalt.io
 * 
 * Machine authentication allows backend services to authenticate
 * without user context for service-to-service communication.
 * 
 * Key Format: machine_xxx (24 char hex ID)
 * Client ID: zalt_m2m_xxx (public identifier)
 * Client Secret: Argon2id hashed (never stored in plain text)
 * 
 * Validates: Requirements 1.1, 1.2, 1.3, 1.4 (M2M Authentication)
 */

export type MachineStatus = 'active' | 'disabled' | 'deleted';

/**
 * Machine entity for M2M authentication
 */
export interface Machine {
  id: string;                    // machine_xxx format
  realm_id: string;              // Realm isolation
  
  // Identity
  name: string;                  // Human-readable name
  description?: string;          // Optional description
  client_id: string;             // Public identifier (zalt_m2m_xxx)
  client_secret_hash: string;    // Argon2id hashed secret
  
  // Permissions
  scopes: string[];              // Allowed scopes ['read:users', 'write:sessions']
  allowed_targets: string[];     // Other machine IDs that can be called
  
  // Status
  status: MachineStatus;
  
  // Metadata
  created_at: string;
  updated_at: string;
  last_used_at?: string;
  created_by?: string;           // Admin who created this machine
  
  // Rate limiting
  rate_limit?: number;           // Requests per minute (default: 1000)
  
  // IP restrictions (optional)
  allowed_ips?: string[];        // CIDR notation
}

/**
 * M2M Token payload (JWT claims)
 */
export interface M2MToken {
  machine_id: string;            // Machine identifier
  realm_id: string;              // Realm context
  scopes: string[];              // Granted scopes
  target_machines: string[];     // Allowed target machines
  type: 'm2m';                   // Token type identifier
  iat: number;                   // Issued at
  exp: number;                   // Expiration
  iss: string;                   // Issuer (zalt.io)
  jti: string;                   // Unique token ID
}

/**
 * Input for creating a new machine
 */
export interface CreateMachineInput {
  realm_id: string;
  name: string;
  description?: string;
  scopes: string[];
  allowed_targets?: string[];
  rate_limit?: number;
  allowed_ips?: string[];
  created_by?: string;
}

/**
 * Response when creating a machine (includes secret once)
 */
export interface MachineWithSecret {
  machine: MachineResponse;
  client_secret: string;         // Only returned once on creation
}

/**
 * Machine response (excludes sensitive data)
 */
export interface MachineResponse {
  id: string;
  realm_id: string;
  name: string;
  description?: string;
  client_id: string;
  scopes: string[];
  allowed_targets: string[];
  status: MachineStatus;
  created_at: string;
  updated_at: string;
  last_used_at?: string;
  rate_limit?: number;
  allowed_ips?: string[];
}

/**
 * Input for authenticating a machine
 */
export interface MachineAuthInput {
  client_id: string;
  client_secret: string;
  scopes?: string[];             // Optional: request subset of scopes
}

/**
 * M2M token response
 */
export interface M2MTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;            // Seconds until expiration
  scope: string;                 // Space-separated scopes
}

/**
 * Available M2M scopes
 */
export const M2M_SCOPES = {
  // User management
  'read:users': 'Read user information',
  'write:users': 'Create and update users',
  'delete:users': 'Delete users',
  
  // Session management
  'read:sessions': 'Read session information',
  'write:sessions': 'Create and manage sessions',
  'revoke:sessions': 'Revoke user sessions',
  
  // Tenant management
  'read:tenants': 'Read tenant information',
  'write:tenants': 'Create and update tenants',
  
  // Role management
  'read:roles': 'Read role information',
  'write:roles': 'Create and update roles',
  
  // Audit logs
  'read:audit': 'Read audit logs',
  
  // Webhooks
  'read:webhooks': 'Read webhook configurations',
  'write:webhooks': 'Manage webhooks',
  
  // Analytics
  'read:analytics': 'Read analytics data',
  
  // Admin operations
  'admin:all': 'Full administrative access'
} as const;

export type M2MScope = keyof typeof M2M_SCOPES;

/**
 * Validate scope string
 */
export function isValidScope(scope: string): scope is M2MScope {
  return scope in M2M_SCOPES;
}

/**
 * Validate all scopes in array
 */
export function validateScopes(scopes: string[]): { valid: boolean; invalid: string[] } {
  const invalid = scopes.filter(s => !isValidScope(s));
  return {
    valid: invalid.length === 0,
    invalid
  };
}

/**
 * Check if requested scopes are subset of allowed scopes
 */
export function scopesAllowed(requested: string[], allowed: string[]): boolean {
  // admin:all grants all scopes
  if (allowed.includes('admin:all')) {
    return true;
  }
  return requested.every(scope => allowed.includes(scope));
}

/**
 * M2M token expiration time (1 hour)
 */
export const M2M_TOKEN_EXPIRY_SECONDS = 3600;

/**
 * Client ID prefix
 */
export const CLIENT_ID_PREFIX = 'zalt_m2m_';

/**
 * Validate client ID format
 */
export function isValidClientId(clientId: string): boolean {
  return clientId.startsWith(CLIENT_ID_PREFIX) && clientId.length === CLIENT_ID_PREFIX.length + 24;
}
