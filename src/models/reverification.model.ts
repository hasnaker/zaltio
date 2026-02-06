/**
 * Reverification Model - Step-Up Authentication
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5 (Reverification)
 * 
 * Reverification is used for sensitive operations that require
 * the user to re-authenticate even if they have a valid session.
 * 
 * Levels (in order of strength):
 * - password: Re-enter password
 * - mfa: Verify with TOTP/SMS
 * - webauthn: Verify with WebAuthn (strongest, phishing-proof)
 * 
 * Higher levels satisfy lower level requirements.
 */

/**
 * Reverification levels in order of strength
 */
export type ReverificationLevel = 'password' | 'mfa' | 'webauthn';

/**
 * Reverification level hierarchy (higher index = stronger)
 */
export const REVERIFICATION_LEVEL_HIERARCHY: ReverificationLevel[] = [
  'password',
  'mfa',
  'webauthn'
];

/**
 * Default validity periods for each level (in minutes)
 */
export const DEFAULT_REVERIFICATION_VALIDITY: Record<ReverificationLevel, number> = {
  password: 10,    // 10 minutes
  mfa: 15,         // 15 minutes
  webauthn: 30     // 30 minutes (strongest, longer validity)
};

/**
 * Reverification configuration for an endpoint
 */
export interface ReverificationConfig {
  level: ReverificationLevel;
  validityMinutes: number;
}

/**
 * Session reverification status
 * Stored in session to track reverification state
 */
export interface SessionReverification {
  sessionId: string;
  level: ReverificationLevel;
  verifiedAt: string;
  expiresAt: string;
  method?: string;  // How verification was done (password, totp, webauthn)
}

/**
 * Reverification requirement for an endpoint
 */
export interface ReverificationRequirement {
  endpoint: string;
  method: string;
  level: ReverificationLevel;
  validityMinutes?: number;
}

/**
 * Default endpoint reverification requirements
 * These can be overridden per-realm
 */
export const DEFAULT_REVERIFICATION_REQUIREMENTS: ReverificationRequirement[] = [
  // Account security operations
  { endpoint: '/me/password', method: 'PUT', level: 'password', validityMinutes: 5 },
  { endpoint: '/me/email', method: 'PUT', level: 'password', validityMinutes: 5 },
  { endpoint: '/me/delete', method: 'DELETE', level: 'mfa', validityMinutes: 5 },
  
  // MFA management
  { endpoint: '/mfa/disable', method: 'POST', level: 'mfa', validityMinutes: 5 },
  { endpoint: '/mfa/recovery-codes', method: 'POST', level: 'mfa', validityMinutes: 5 },
  
  // API key management
  { endpoint: '/api-keys', method: 'POST', level: 'password', validityMinutes: 10 },
  { endpoint: '/api-keys/*', method: 'DELETE', level: 'password', validityMinutes: 10 },
  
  // Session management
  { endpoint: '/sessions', method: 'DELETE', level: 'password', validityMinutes: 5 },
  
  // Organization admin operations
  { endpoint: '/organizations/*/members/*/remove', method: 'POST', level: 'mfa', validityMinutes: 5 },
  { endpoint: '/organizations/*/delete', method: 'DELETE', level: 'webauthn', validityMinutes: 5 },
  
  // Billing operations
  { endpoint: '/billing/cancel', method: 'POST', level: 'mfa', validityMinutes: 5 },
  { endpoint: '/billing/payment-method', method: 'PUT', level: 'password', validityMinutes: 10 }
];

/**
 * Reverification proof types
 */
export type ReverificationProofType = 'password' | 'totp' | 'webauthn' | 'backup_code';

/**
 * Reverification proof submitted by user
 */
export interface ReverificationProof {
  type: ReverificationProofType;
  value: string;  // Password, TOTP code, WebAuthn assertion, or backup code
  challenge?: string;  // For WebAuthn
}

/**
 * Check if a level satisfies a required level
 * Higher levels satisfy lower level requirements
 */
export function levelSatisfiesRequirement(
  currentLevel: ReverificationLevel,
  requiredLevel: ReverificationLevel
): boolean {
  const currentIndex = REVERIFICATION_LEVEL_HIERARCHY.indexOf(currentLevel);
  const requiredIndex = REVERIFICATION_LEVEL_HIERARCHY.indexOf(requiredLevel);
  
  if (currentIndex === -1 || requiredIndex === -1) {
    return false;
  }
  
  return currentIndex >= requiredIndex;
}

/**
 * Get the validity period for a reverification level
 */
export function getValidityMinutes(
  level: ReverificationLevel,
  customValidity?: number
): number {
  if (customValidity !== undefined && customValidity > 0) {
    return customValidity;
  }
  return DEFAULT_REVERIFICATION_VALIDITY[level];
}

/**
 * Check if a reverification is still valid
 */
export function isReverificationValid(reverification: SessionReverification): boolean {
  const now = new Date();
  const expiresAt = new Date(reverification.expiresAt);
  return now < expiresAt;
}

/**
 * Check if a reverification satisfies a requirement
 */
export function reverificationSatisfiesRequirement(
  reverification: SessionReverification | null | undefined,
  requiredLevel: ReverificationLevel
): boolean {
  if (!reverification) {
    return false;
  }
  
  if (!isReverificationValid(reverification)) {
    return false;
  }
  
  return levelSatisfiesRequirement(reverification.level, requiredLevel);
}

/**
 * Map proof type to reverification level
 */
export function proofTypeToLevel(proofType: ReverificationProofType): ReverificationLevel {
  switch (proofType) {
    case 'password':
      return 'password';
    case 'totp':
    case 'backup_code':
      return 'mfa';
    case 'webauthn':
      return 'webauthn';
    default:
      return 'password';
  }
}

/**
 * Validate reverification level string
 */
export function isValidReverificationLevel(level: string): level is ReverificationLevel {
  return REVERIFICATION_LEVEL_HIERARCHY.includes(level as ReverificationLevel);
}

/**
 * Match endpoint against pattern (supports wildcards)
 */
export function matchEndpoint(pattern: string, endpoint: string): boolean {
  // Exact match
  if (pattern === endpoint) {
    return true;
  }
  
  // Wildcard match
  if (pattern.includes('*')) {
    const regex = new RegExp('^' + pattern.replace(/\*/g, '[^/]+') + '$');
    return regex.test(endpoint);
  }
  
  return false;
}

/**
 * Find reverification requirement for an endpoint
 */
export function findReverificationRequirement(
  endpoint: string,
  method: string,
  customRequirements?: ReverificationRequirement[]
): ReverificationRequirement | null {
  const requirements = customRequirements || DEFAULT_REVERIFICATION_REQUIREMENTS;
  
  for (const req of requirements) {
    if (req.method === method && matchEndpoint(req.endpoint, endpoint)) {
      return req;
    }
  }
  
  return null;
}
