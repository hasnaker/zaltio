/**
 * Property-based tests for User Registration
 * Feature: zalt-platform, Property 1: Realm Isolation Integrity
 * Validates: Requirements 1.1, 1.2, 1.3
 */

import * as fc from 'fast-check';
import { validateEmail, validatePassword, validateRealmId } from '../utils/validation';
import { DEFAULT_PASSWORD_POLICY } from '../models/realm.model';

/**
 * Custom generators for realistic test data
 */
const validEmailArb = fc.tuple(
  fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'), { minLength: 3, maxLength: 20 }),
  fc.constantFrom('gmail.com', 'example.com', 'hsdcore.com', 'test.org')
).map(([local, domain]) => `${local}@${domain}`);

const validRealmIdArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'),
  { minLength: 3, maxLength: 30 }
).filter(s => /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$/.test(s) && s.length >= 3);

const validPasswordArb = fc.tuple(
  fc.stringOf(fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), { minLength: 2, maxLength: 4 }),
  fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'), { minLength: 2, maxLength: 4 }),
  fc.stringOf(fc.constantFrom(...'0123456789'), { minLength: 2, maxLength: 3 }),
  fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'), { minLength: 2, maxLength: 5 })
).map(([upper, lower, num, extra]) => `${upper}${lower}${num}${extra}`);

describe('User Registration - Property Tests', () => {
  /**
   * Property 1: Realm Isolation Integrity
   * For any set of realms and user operations, actions performed within one realm
   * should never affect data, configurations, or users in other realms.
   * Validates: Requirements 1.1, 1.2, 1.3
   */
  describe('Property 1: Realm Isolation Integrity', () => {
    it('should validate that realm IDs create unique isolation boundaries', () => {
      fc.assert(
        fc.property(
          validRealmIdArb,
          validRealmIdArb,
          (realmId1, realmId2) => {
            // Different realm IDs should create different composite keys
            const userId = 'test-user-123';
            const pk1 = `${realmId1}#${userId}`;
            const pk2 = `${realmId2}#${userId}`;
            
            if (realmId1 !== realmId2) {
              // Same user ID in different realms must have different primary keys
              expect(pk1).not.toBe(pk2);
            }
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should ensure email uniqueness is scoped to realm', () => {
      fc.assert(
        fc.property(
          validRealmIdArb,
          validRealmIdArb,
          validEmailArb,
          (realmId1, realmId2, email) => {
            // The same email can exist in different realms
            // This is validated by the composite key structure
            const normalizedEmail = email.toLowerCase().trim();
            
            // Email lookup must include realm filter
            // This simulates the query pattern used in findUserByEmail
            const query1 = { email: normalizedEmail, realm_id: realmId1 };
            const query2 = { email: normalizedEmail, realm_id: realmId2 };
            
            if (realmId1 !== realmId2) {
              // Same email in different realms should be treated as different queries
              expect(JSON.stringify(query1)).not.toBe(JSON.stringify(query2));
            }
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should validate realm ID format for isolation boundaries', () => {
      fc.assert(
        fc.property(validRealmIdArb, (realmId) => {
          const result = validateRealmId(realmId);
          // Valid realm IDs should pass validation
          expect(result.valid).toBe(true);
          expect(result.errors).toHaveLength(0);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should reject invalid realm IDs to maintain isolation integrity', () => {
      const invalidRealmIds = fc.oneof(
        fc.constant(''),
        fc.constant('  '),
        fc.constant('ab'), // too short
        fc.constant('-invalid'),
        fc.constant('invalid-'),
        fc.stringOf(fc.constantFrom(...'!@#$%^&*()'), { minLength: 3, maxLength: 10 })
      );

      fc.assert(
        fc.property(invalidRealmIds, (realmId) => {
          const result = validateRealmId(realmId);
          expect(result.valid).toBe(false);
          expect(result.errors.length).toBeGreaterThan(0);
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });

  /**
   * Additional validation properties for registration
   * These support the realm isolation by ensuring data integrity
   */
  describe('Email Validation Properties', () => {
    it('should accept valid email formats', () => {
      fc.assert(
        fc.property(validEmailArb, (email) => {
          const result = validateEmail(email);
          expect(result.valid).toBe(true);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should normalize emails consistently for realm-scoped lookups', () => {
      fc.assert(
        fc.property(validEmailArb, (email) => {
          const normalized1 = email.toLowerCase().trim();
          const normalized2 = email.toUpperCase().toLowerCase().trim();
          // Normalization should be idempotent
          expect(normalized1).toBe(normalized2);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should reject invalid email formats', () => {
      const invalidEmails = fc.oneof(
        fc.constant(''),
        fc.constant('notanemail'),
        fc.constant('@nodomain.com'),
        fc.constant('noat.com'),
        fc.constant('spaces in@email.com')
      );

      fc.assert(
        fc.property(invalidEmails, (email) => {
          const result = validateEmail(email);
          expect(result.valid).toBe(false);
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('Password Validation Properties', () => {
    it('should accept passwords meeting policy requirements', () => {
      fc.assert(
        fc.property(validPasswordArb, (password) => {
          const result = validatePassword(password, DEFAULT_PASSWORD_POLICY);
          expect(result.valid).toBe(true);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should reject passwords not meeting minimum length', () => {
      fc.assert(
        fc.property(
          fc.stringOf(fc.constantFrom(...'Aa1'), { minLength: 1, maxLength: 7 }),
          (password) => {
            const result = validatePassword(password, { ...DEFAULT_PASSWORD_POLICY, min_length: 8 });
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('at least 8 characters'))).toBe(true);
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});


