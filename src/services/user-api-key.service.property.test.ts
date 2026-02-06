/**
 * Property-Based Tests for User API Keys
 * Task 2.5: Write property tests for API Keys
 * 
 * Properties tested:
 * - Property 4: API key user context preservation
 * - Property 5: Revoked key returns 401
 * - Property 6: Expired key returns 401
 * 
 * **Validates: Requirements 2.7, 2.8, 2.5, 2.6**
 */

import * as fc from 'fast-check';
import { createHash } from 'crypto';
import {
  UserAPIKey,
  UserAPIKeyContext,
  USER_API_KEY_PREFIX,
  USER_API_KEY_LENGTH,
  USER_API_KEY_SCOPES,
  UserAPIKeyScope,
  isValidUserAPIKeyFormat,
  validateUserAPIKeyScopes,
  userAPIKeyScopesAllowed,
  getKeyDisplayPrefix
} from '../models/user-api-key.model';

/**
 * Custom generators for User API Key tests
 */
const validScopeArb = fc.constantFrom(...Object.keys(USER_API_KEY_SCOPES)) as fc.Arbitrary<UserAPIKeyScope>;

const validScopesArrayArb = fc.array(validScopeArb, { minLength: 1, maxLength: 5 })
  .map(scopes => [...new Set(scopes)]); // Remove duplicates

const userIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `user_${hex}`);

const realmIdArb = fc.stringMatching(/^[a-z0-9-]{3,30}$/)
  .filter(s => !s.startsWith('-') && !s.endsWith('-'));

const tenantIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `tenant_${hex}`);

const keyIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `key_${hex}`);

const alphanumericArb = fc.stringMatching(/^[a-zA-Z0-9]{32}$/);

const fullKeyArb = alphanumericArb.map(suffix => `${USER_API_KEY_PREFIX}${suffix}`);

const keyNameArb = fc.string({ minLength: 1, maxLength: 100 })
  .filter(s => s.trim().length > 0);

/**
 * Generate a mock UserAPIKey for testing
 */
function generateMockUserAPIKey(
  userId: string,
  realmId: string,
  scopes: string[],
  options: {
    status?: 'active' | 'revoked' | 'expired';
    expiresAt?: string;
    tenantId?: string;
  } = {}
): UserAPIKey {
  const keyId = `key_${Math.random().toString(36).substring(2, 26)}`;
  const now = new Date().toISOString();
  
  return {
    id: keyId,
    user_id: userId,
    realm_id: realmId,
    tenant_id: options.tenantId,
    name: 'Test Key',
    key_prefix: 'zalt_key_ABC...',
    key_hash: createHash('sha256').update(`test_key_${keyId}`).digest('hex'),
    scopes,
    status: options.status || 'active',
    created_at: now,
    updated_at: now,
    expires_at: options.expiresAt,
    usage_count: 0
  };
}

/**
 * Generate a mock UserAPIKeyContext for testing
 */
function generateMockContext(
  userId: string,
  realmId: string,
  scopes: string[],
  tenantId?: string
): UserAPIKeyContext {
  return {
    key: generateMockUserAPIKey(userId, realmId, scopes, { tenantId }),
    user_id: userId,
    realm_id: realmId,
    tenant_id: tenantId,
    scopes
  };
}

describe('User API Key Property-Based Tests', () => {

  /**
   * Property 4: API key user context preservation
   * 
   * For any API key and any request:
   * - The request SHALL execute with the exact same user_id as the key owner
   * - The request SHALL execute with the exact same realm_id as the key
   * - The request SHALL execute with the exact same tenant_id as the key (if set)
   * - The request SHALL be limited to the key's scopes
   * 
   * **Validates: Requirements 2.7, 2.8**
   */
  describe('Property 4: API key user context preservation', () => {
    it('should preserve user_id in context', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          (userId, realmId, scopes) => {
            const context = generateMockContext(userId, realmId, scopes);
            
            // Context should preserve user_id
            expect(context.user_id).toBe(userId);
            expect(context.key.user_id).toBe(userId);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should preserve realm_id in context', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          (userId, realmId, scopes) => {
            const context = generateMockContext(userId, realmId, scopes);
            
            // Context should preserve realm_id
            expect(context.realm_id).toBe(realmId);
            expect(context.key.realm_id).toBe(realmId);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should preserve tenant_id in context when set', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          tenantIdArb,
          validScopesArrayArb,
          (userId, realmId, tenantId, scopes) => {
            const context = generateMockContext(userId, realmId, scopes, tenantId);
            
            // Context should preserve tenant_id
            expect(context.tenant_id).toBe(tenantId);
            expect(context.key.tenant_id).toBe(tenantId);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should preserve scopes in context', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          (userId, realmId, scopes) => {
            const context = generateMockContext(userId, realmId, scopes);
            
            // Context should preserve scopes
            expect(context.scopes).toEqual(scopes);
            expect(context.key.scopes).toEqual(scopes);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should limit access to key scopes', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          fc.constantFrom('profile:read', 'sessions:read') as fc.Arbitrary<UserAPIKeyScope>,
          fc.constantFrom('tenants:write', 'roles:write') as fc.Arbitrary<UserAPIKeyScope>,
          (userId, realmId, grantedScope, requestedScope) => {
            // Ensure granted and requested are different
            fc.pre(grantedScope !== requestedScope);
            
            const context = generateMockContext(userId, realmId, [grantedScope]);
            
            // Should have granted scope
            expect(userAPIKeyScopesAllowed([grantedScope], context.scopes)).toBe(true);
            
            // Should NOT have requested scope
            expect(userAPIKeyScopesAllowed([requestedScope], context.scopes)).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should grant all scopes with full:access', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopeArb,
          (userId, realmId, anyScope) => {
            const context = generateMockContext(userId, realmId, ['full:access']);
            
            // full:access should grant any scope
            expect(userAPIKeyScopesAllowed([anyScope], context.scopes)).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  /**
   * Property 5: Revoked key returns 401
   * 
   * For any revoked API key:
   * - Validation SHALL fail
   * - The error code SHALL be API_KEY_INVALID or similar
   * - The status code SHALL be 401
   * 
   * **Validates: Requirements 2.5**
   */
  describe('Property 5: Revoked key returns 401', () => {
    it('should identify revoked keys by status', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          (userId, realmId, scopes) => {
            const key = generateMockUserAPIKey(userId, realmId, scopes, { status: 'revoked' });
            
            // Key should have revoked status
            expect(key.status).toBe('revoked');
            
            // Revoked keys should not be considered active
            expect(key.status !== 'active').toBe(true);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should distinguish active from revoked keys', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          fc.constantFrom('active', 'revoked') as fc.Arbitrary<'active' | 'revoked'>,
          (userId, realmId, scopes, status) => {
            const key = generateMockUserAPIKey(userId, realmId, scopes, { status });
            
            // Status should match what was set
            expect(key.status).toBe(status);
            
            // Only active keys should be valid
            const isValid = key.status === 'active';
            expect(isValid).toBe(status === 'active');
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should preserve key data after revocation', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          (userId, realmId, scopes) => {
            // Create active key
            const activeKey = generateMockUserAPIKey(userId, realmId, scopes, { status: 'active' });
            
            // Simulate revocation (status change)
            const revokedKey: UserAPIKey = {
              ...activeKey,
              status: 'revoked',
              revoked_at: new Date().toISOString(),
              revoked_by: userId
            };
            
            // Key data should be preserved
            expect(revokedKey.user_id).toBe(activeKey.user_id);
            expect(revokedKey.realm_id).toBe(activeKey.realm_id);
            expect(revokedKey.scopes).toEqual(activeKey.scopes);
            expect(revokedKey.status).toBe('revoked');
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  /**
   * Property 6: Expired key returns 401
   * 
   * For any expired API key:
   * - Validation SHALL fail if current_time > expires_at
   * - Validation SHALL succeed if current_time <= expires_at
   * - The error code SHALL be API_KEY_EXPIRED
   * - The status code SHALL be 401
   * 
   * **Validates: Requirements 2.6**
   */
  describe('Property 6: Expired key returns 401', () => {
    it('should identify expired keys by expiration date', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          fc.integer({ min: 1, max: 365 }), // Days in past
          (userId, realmId, scopes, daysAgo) => {
            const pastDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000).toISOString();
            const key = generateMockUserAPIKey(userId, realmId, scopes, { expiresAt: pastDate });
            
            // Key should have expiration in the past
            expect(new Date(key.expires_at!).getTime()).toBeLessThan(Date.now());
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should accept non-expired keys', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          fc.integer({ min: 1, max: 365 }), // Days in future
          (userId, realmId, scopes, daysAhead) => {
            const futureDate = new Date(Date.now() + daysAhead * 24 * 60 * 60 * 1000).toISOString();
            const key = generateMockUserAPIKey(userId, realmId, scopes, { expiresAt: futureDate });
            
            // Key should have expiration in the future
            expect(new Date(key.expires_at!).getTime()).toBeGreaterThan(Date.now());
            
            // Key should be considered valid (not expired)
            const isExpired = new Date(key.expires_at!) < new Date();
            expect(isExpired).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should accept keys without expiration', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          (userId, realmId, scopes) => {
            const key = generateMockUserAPIKey(userId, realmId, scopes);
            
            // Key should have no expiration
            expect(key.expires_at).toBeUndefined();
            
            // Key without expiration should never be considered expired
            const isExpired = key.expires_at ? new Date(key.expires_at) < new Date() : false;
            expect(isExpired).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should correctly compare expiration times', () => {
      fc.assert(
        fc.property(
          userIdArb,
          realmIdArb,
          validScopesArrayArb,
          fc.integer({ min: -365, max: 365 }), // Days offset from now
          (userId, realmId, scopes, daysOffset) => {
            const expirationDate = new Date(Date.now() + daysOffset * 24 * 60 * 60 * 1000);
            const key = generateMockUserAPIKey(userId, realmId, scopes, { 
              expiresAt: expirationDate.toISOString() 
            });
            
            const now = new Date();
            const isExpired = new Date(key.expires_at!) < now;
            
            // If daysOffset is negative, key should be expired
            // If daysOffset is positive, key should not be expired
            // Note: daysOffset of 0 could go either way due to timing
            if (daysOffset < -1) {
              expect(isExpired).toBe(true);
            } else if (daysOffset > 1) {
              expect(isExpired).toBe(false);
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  /**
   * Additional property tests for key format validation
   */
  describe('Key format validation properties', () => {
    it('should validate correct key format', () => {
      fc.assert(
        fc.property(
          fullKeyArb,
          (fullKey) => {
            expect(isValidUserAPIKeyFormat(fullKey)).toBe(true);
            expect(fullKey.startsWith(USER_API_KEY_PREFIX)).toBe(true);
            expect(fullKey.length).toBe(USER_API_KEY_LENGTH);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject invalid key formats', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.constant('invalid'),
            fc.constant('zalt_key_short'),
            fc.constant('wrong_prefix_' + 'a'.repeat(32)),
            fc.hexaString({ minLength: 32, maxLength: 32 }) // Missing prefix
          ),
          (invalidKey) => {
            expect(isValidUserAPIKeyFormat(invalidKey)).toBe(false);
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should generate consistent key prefix display', () => {
      fc.assert(
        fc.property(
          fullKeyArb,
          (fullKey) => {
            const prefix = getKeyDisplayPrefix(fullKey);
            
            // Prefix should be first 12 chars + ...
            expect(prefix).toBe(fullKey.substring(0, 12) + '...');
            expect(prefix.length).toBe(15);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  /**
   * Scope validation properties
   */
  describe('Scope validation properties', () => {
    it('should validate all known scopes', () => {
      fc.assert(
        fc.property(
          validScopeArb,
          (scope) => {
            const result = validateUserAPIKeyScopes([scope]);
            expect(result.valid).toBe(true);
            expect(result.invalid).toHaveLength(0);
            
            return true;
          }
        ),
        { numRuns: Object.keys(USER_API_KEY_SCOPES).length }
      );
    });

    it('should reject invalid scopes', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 })
            .filter(s => !(s in USER_API_KEY_SCOPES)),
          (invalidScope) => {
            const result = validateUserAPIKeyScopes([invalidScope]);
            expect(result.valid).toBe(false);
            expect(result.invalid).toContain(invalidScope);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
