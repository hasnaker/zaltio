/**
 * API Key Model - SDK authentication keys for Zalt.io platform
 * 
 * Key Types:
 * - pk_live_xxx: Publishable key (frontend SDK, safe to expose)
 * - sk_live_xxx: Secret key (backend only, never expose)
 * - pk_test_xxx: Test publishable key
 * - sk_test_xxx: Test secret key
 * 
 * Validates: Requirements 4.1, 4.2 (API Key system)
 */

export type APIKeyType = 'publishable' | 'secret';
export type APIKeyEnvironment = 'live' | 'test';
export type APIKeyStatus = 'active' | 'revoked' | 'expired';

export interface APIKey {
  id: string;                    // key_xxx format
  customer_id: string;           // Owner customer
  realm_id: string;              // Associated realm
  
  // Key identification
  type: APIKeyType;              // publishable or secret
  environment: APIKeyEnvironment; // live or test
  key_prefix: string;            // pk_live_, sk_live_, pk_test_, sk_test_
  key_hash: string;              // SHA-256 hash of full key (for lookup)
  key_hint: string;              // Last 4 chars for display (e.g., "...abc1")
  
  // Metadata
  name: string;                  // User-friendly name
  description?: string;
  
  // Security
  status: APIKeyStatus;
  last_used_at?: string;
  usage_count: number;
  
  // Timestamps
  created_at: string;
  updated_at: string;
  expires_at?: string;           // Optional expiration
  revoked_at?: string;
  revoked_by?: string;
  revoked_reason?: string;
}

export interface CreateAPIKeyInput {
  customer_id: string;
  realm_id: string;
  type: APIKeyType;
  environment: APIKeyEnvironment;
  name: string;
  description?: string;
  expires_at?: string;
}

export interface APIKeyResponse {
  id: string;
  type: APIKeyType;
  environment: APIKeyEnvironment;
  key_prefix: string;
  key_hint: string;
  name: string;
  description?: string;
  status: APIKeyStatus;
  last_used_at?: string;
  usage_count: number;
  created_at: string;
  expires_at?: string;
}

export interface APIKeyWithSecret extends APIKeyResponse {
  // Full key is only returned once on creation
  full_key: string;
}

/**
 * Key prefix format: {type}_{environment}_
 * Examples: pk_live_, sk_live_, pk_test_, sk_test_
 */
export function getKeyPrefix(type: APIKeyType, environment: APIKeyEnvironment): string {
  const typePrefix = type === 'publishable' ? 'pk' : 'sk';
  return `${typePrefix}_${environment}_`;
}

/**
 * Validate key format
 */
export function isValidKeyFormat(key: string): boolean {
  // Format: {pk|sk}_{live|test}_{32 alphanumeric chars}
  const regex = /^(pk|sk)_(live|test)_[a-zA-Z0-9]{32}$/;
  return regex.test(key);
}

/**
 * Extract key type and environment from key string
 */
export function parseKeyPrefix(key: string): { type: APIKeyType; environment: APIKeyEnvironment } | null {
  const match = key.match(/^(pk|sk)_(live|test)_/);
  if (!match) return null;
  
  return {
    type: match[1] === 'pk' ? 'publishable' : 'secret',
    environment: match[2] as APIKeyEnvironment
  };
}
