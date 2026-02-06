/**
 * Session Model - User session management
 * Validates: Requirements 9.5 (session management)
 */

export interface Session {
  id: string;
  user_id: string;
  realm_id: string;
  access_token: string;
  refresh_token: string;
  refresh_token_hash: string;
  expires_at: string;
  created_at: string;
  last_used_at: string;
  ip_address: string;
  user_agent: string;
  device_fingerprint?: string;
  revoked: boolean;
  revoked_at?: string;
  // Grace period fields (Siberci recommendation: 30 seconds)
  old_refresh_token_hash?: string;  // Previous token hash for grace period
  rotated_at?: string;              // When token was last rotated
}

export interface CreateSessionInput {
  user_id: string;
  realm_id: string;
  ip_address: string;
  user_agent: string;
  device_fingerprint?: string;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

export interface JWTPayload {
  sub: string;
  realm_id: string;
  email: string;
  iat: number;
  exp: number;
  type: 'access' | 'refresh';
  jti?: string; // JWT ID for tracking/revocation
  is_admin?: boolean; // Admin flag for admin API access
  iss?: string; // Issuer (https://api.zalt.io)
  aud?: string; // Audience (https://api.zalt.io)
  
  // RBAC Claims (additive - backward compatible)
  org_id?: string;           // Current organization ID
  org_ids?: string[];        // All user's organization IDs
  roles?: string[];          // Role IDs in current organization
  permissions?: string[];    // Permissions (if <= 50, otherwise use permissions_url)
  permissions_url?: string;  // URL to fetch permissions if > 50
}
