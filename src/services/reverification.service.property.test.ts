/**
 * Property-Based Tests for Reverification (Step-Up Authentication)
 * Task 4.5: Write property tests for Reverification
 * 
 * Properties tested:
 * - Property 7: Reverification expiry is enforced
 * - Property 8: Higher level satisfies lower level requirements
 * - Property 9: Reverification status persists across requests
 * 
 * **Validates: Requirements 3.4, 3.5**
 */

import * as fc from 'fast-check';
import {
  ReverificationService,
  ReverificationError,
  ReverificationLevel,
  SessionReverification,
  REVERIFICATION_LEVEL_HIERARCHY,
  DEFAULT_REVERIFICATION_VALIDITY
} from './reverification.service';
import {
  levelSatisfiesRequirement,
  isReverificationValid,
  reverificationSatisfiesRequirement,
  getValidityMinutes,
  proofTypeToLevel,
  ReverificationProofType
} from '../models/reverification.model';

/**
 * Custom generators for Reverification tests
 */
const sessionIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `session_${hex}`);

const userIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `user_${hex}`);

const reverificationLevelArb = fc.constantFrom(...REVERIFICATION_LEVEL_HIERARCHY) as fc.Arbitrary<ReverificationLevel>;

const proofTypeArb = fc.constantFrom('password', 'totp', 'webauthn', 'backup_code') as fc.Arbitrary<ReverificationProofType>;

const validityMinutesArb = fc.integer({ min: 1, max: 60 });

/**
 * Generate a valid proof for a given type
 */
function generateValidProof(type: ReverificationProofType): { type: ReverificationProofType; value: string; challenge?: string } {
  switch (type) {
    case 'password':
      return { type, value: 'valid-password-123' };
    case 'totp':
      return { type, value: '123456' };
    case 'backup_code':
      return { type, value: 'ABCD1234EFGH' };
    case 'webauthn':
      return { type, value: 'webauthn-assertion-data', challenge: 'challenge-123' };
    default:
      return { type: 'password', value: 'valid-password-123' };
  }
}

/**
 * Generate a mock SessionReverification for testing
 */
function generateMockReverification(
  sessionId: string,
  level: ReverificationLevel,
  options: {
    expired?: boolean;
    validityMinutes?: number;
    method?: string;
  } = {}
): SessionReverification {
  const now = new Date();
  const validityMinutes = options.validityMinutes || DEFAULT_REVERIFICATION_VALIDITY[level];
  
  let verifiedAt: Date;
  let expiresAt: Date;
  
  if (options.expired) {
    // Set verification time in the past so it's expired
    verifiedAt = new Date(now.getTime() - (validityMinutes + 10) * 60 * 1000);
    expiresAt = new Date(now.getTime() - 10 * 60 * 1000);
  } else {
    verifiedAt = now;
    expiresAt = new Date(now.getTime() + validityMinutes * 60 * 1000);
  }
  
  return {
    sessionId,
    level,
    verifiedAt: verifiedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    method: options.method || level
  };
}

describe('Reverification Property-Based Tests', () => {
  let service: ReverificationService;

  beforeEach(() => {
    service = new ReverificationService();
  });

  /**
   * Property 7: Reverification expiry is enforced
   * 
   * For any reverification completion, the reverification status SHALL expire
   * after the configured validity period.
   * 
   * Properties:
   * - Reverification with future expiresAt is valid
   * - Reverification with past expiresAt is invalid
   * - Expiry time is exactly validityMinutes from verifiedAt
   * 
   * **Validates: Requirements 3.4, 3.5**
   */
  describe('Property 7: Reverification expiry is enforced', () => {
    it('should accept non-expired reverification', () => {
      fc.assert(
        fc.property(
          sessionIdArb,
          reverificationLevelArb,
          validityMinutesArb,
          (sessionId, level, validityMinutes) => {
            const reverification = generateMockReverification(sessionId, level, {
              expired: false,
              validityMinutes
            });
            
            // Non-expired reverification should be valid
            expect(isReverificationValid(reverification)).toBe(true);
            
            // Expiry should be in the future
            expect(new Date(reverification.expiresAt).getTime()).toBeGreaterThan(Date.now());
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject expired reverification', () => {
      fc.assert(
        fc.property(
          sessionIdArb,
          reverificationLevelArb,
          validityMinutesArb,
          (sessionId, level, validityMinutes) => {
            const reverification = generateMockReverification(sessionId, level, {
              expired: true,
              validityMinutes
            });
            
            // Expired reverification should be invalid
            expect(isReverificationValid(reverification)).toBe(false);
            
            // Expiry should be in the past
            expect(new Date(reverification.expiresAt).getTime()).toBeLessThan(Date.now());
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should enforce exact expiry time based on validity period', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          validityMinutesArb,
          async (sessionId, userId, proofType, validityMinutes) => {
            const proof = generateValidProof(proofType);
            
            const beforeTime = Date.now();
            const result = await service.completeReverification(
              sessionId,
              userId,
              proof,
              { validityMinutes }
            );
            const afterTime = Date.now();
            
            // Calculate expected expiry range
            const expectedExpiryMin = beforeTime + validityMinutes * 60 * 1000;
            const expectedExpiryMax = afterTime + validityMinutes * 60 * 1000;
            const actualExpiry = new Date(result.expiresAt).getTime();
            
            // Expiry should be within expected range
            expect(actualExpiry).toBeGreaterThanOrEqual(expectedExpiryMin);
            expect(actualExpiry).toBeLessThanOrEqual(expectedExpiryMax);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should use default validity when not specified', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          async (sessionId, userId, proofType) => {
            const proof = generateValidProof(proofType);
            const expectedLevel = proofTypeToLevel(proofType);
            const expectedValidity = DEFAULT_REVERIFICATION_VALIDITY[expectedLevel];
            
            const beforeTime = Date.now();
            const result = await service.completeReverification(
              sessionId,
              userId,
              proof
            );
            const afterTime = Date.now();
            
            // Calculate expected expiry range using default validity
            const expectedExpiryMin = beforeTime + expectedValidity * 60 * 1000;
            const expectedExpiryMax = afterTime + expectedValidity * 60 * 1000;
            const actualExpiry = new Date(result.expiresAt).getTime();
            
            // Expiry should be within expected range
            expect(actualExpiry).toBeGreaterThanOrEqual(expectedExpiryMin);
            expect(actualExpiry).toBeLessThanOrEqual(expectedExpiryMax);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject expired reverification in checkReverification', () => {
      fc.assert(
        fc.property(
          sessionIdArb,
          reverificationLevelArb,
          reverificationLevelArb,
          (sessionId, actualLevel, requiredLevel) => {
            const expiredReverification = generateMockReverification(sessionId, actualLevel, {
              expired: true
            });
            
            // Expired reverification should not satisfy any requirement
            expect(reverificationSatisfiesRequirement(expiredReverification, requiredLevel)).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have consistent expiry across all proof types', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          validityMinutesArb,
          async (sessionId, userId, validityMinutes) => {
            const proofTypes: ReverificationProofType[] = ['password', 'totp', 'webauthn', 'backup_code'];
            const results: SessionReverification[] = [];
            
            for (const proofType of proofTypes) {
              const proof = generateValidProof(proofType);
              const uniqueSessionId = `${sessionId}_${proofType}`;
              
              const result = await service.completeReverification(
                uniqueSessionId,
                userId,
                proof,
                { validityMinutes }
              );
              results.push(result);
            }
            
            // All results should have expiry approximately validityMinutes from now
            const now = Date.now();
            const expectedExpiry = now + validityMinutes * 60 * 1000;
            
            results.forEach(result => {
              const actualExpiry = new Date(result.expiresAt).getTime();
              // Allow 2 second tolerance for test execution time
              expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(2000);
            });
            
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * Property 8: Higher level satisfies lower level requirements
   * 
   * For example, webauthn verification satisfies mfa and password requirements.
   * 
   * Level hierarchy: password < mfa < webauthn
   * 
   * Properties:
   * - webauthn satisfies all levels (password, mfa, webauthn)
   * - mfa satisfies password and mfa, but not webauthn
   * - password satisfies only password
   * 
   * **Validates: Requirements 3.4, 3.5**
   */
  describe('Property 8: Higher level satisfies lower level requirements', () => {
    it('should satisfy same level requirement', () => {
      fc.assert(
        fc.property(
          reverificationLevelArb,
          (level) => {
            // Same level should always satisfy itself
            expect(levelSatisfiesRequirement(level, level)).toBe(true);
            
            return true;
          }
        ),
        { numRuns: REVERIFICATION_LEVEL_HIERARCHY.length * 10 }
      );
    });

    it('should satisfy lower level requirements', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: REVERIFICATION_LEVEL_HIERARCHY.length - 1 }),
          fc.integer({ min: 0, max: REVERIFICATION_LEVEL_HIERARCHY.length - 1 }),
          (actualIndex, requiredIndex) => {
            const actualLevel = REVERIFICATION_LEVEL_HIERARCHY[actualIndex];
            const requiredLevel = REVERIFICATION_LEVEL_HIERARCHY[requiredIndex];
            
            const satisfies = levelSatisfiesRequirement(actualLevel, requiredLevel);
            
            // Higher or equal index should satisfy lower or equal index
            if (actualIndex >= requiredIndex) {
              expect(satisfies).toBe(true);
            } else {
              expect(satisfies).toBe(false);
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should enforce webauthn satisfies all levels', () => {
      fc.assert(
        fc.property(
          reverificationLevelArb,
          (requiredLevel) => {
            // webauthn (highest) should satisfy any level
            expect(levelSatisfiesRequirement('webauthn', requiredLevel)).toBe(true);
            
            return true;
          }
        ),
        { numRuns: REVERIFICATION_LEVEL_HIERARCHY.length * 10 }
      );
    });

    it('should enforce mfa satisfies password and mfa only', () => {
      fc.assert(
        fc.property(
          reverificationLevelArb,
          (requiredLevel) => {
            const satisfies = levelSatisfiesRequirement('mfa', requiredLevel);
            
            if (requiredLevel === 'password' || requiredLevel === 'mfa') {
              expect(satisfies).toBe(true);
            } else {
              expect(satisfies).toBe(false);
            }
            
            return true;
          }
        ),
        { numRuns: REVERIFICATION_LEVEL_HIERARCHY.length * 10 }
      );
    });

    it('should enforce password satisfies only password', () => {
      fc.assert(
        fc.property(
          reverificationLevelArb,
          (requiredLevel) => {
            const satisfies = levelSatisfiesRequirement('password', requiredLevel);
            
            if (requiredLevel === 'password') {
              expect(satisfies).toBe(true);
            } else {
              expect(satisfies).toBe(false);
            }
            
            return true;
          }
        ),
        { numRuns: REVERIFICATION_LEVEL_HIERARCHY.length * 10 }
      );
    });

    it('should enforce hierarchy in reverificationSatisfiesRequirement', () => {
      fc.assert(
        fc.property(
          sessionIdArb,
          reverificationLevelArb,
          reverificationLevelArb,
          (sessionId, actualLevel, requiredLevel) => {
            const reverification = generateMockReverification(sessionId, actualLevel, {
              expired: false
            });
            
            const satisfies = reverificationSatisfiesRequirement(reverification, requiredLevel);
            const expectedSatisfies = levelSatisfiesRequirement(actualLevel, requiredLevel);
            
            expect(satisfies).toBe(expectedSatisfies);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should enforce hierarchy through service methods', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          reverificationLevelArb,
          async (sessionId, userId, proofType, requiredLevel) => {
            const proof = generateValidProof(proofType);
            const actualLevel = proofTypeToLevel(proofType);
            
            await service.completeReverification(sessionId, userId, proof);
            
            const satisfies = await service.checkReverification(sessionId, requiredLevel);
            const expectedSatisfies = levelSatisfiesRequirement(actualLevel, requiredLevel);
            
            expect(satisfies).toBe(expectedSatisfies);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should map proof types to correct levels', () => {
      fc.assert(
        fc.property(
          proofTypeArb,
          (proofType) => {
            const level = proofTypeToLevel(proofType);
            
            switch (proofType) {
              case 'password':
                expect(level).toBe('password');
                break;
              case 'totp':
              case 'backup_code':
                expect(level).toBe('mfa');
                break;
              case 'webauthn':
                expect(level).toBe('webauthn');
                break;
            }
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  /**
   * Property 9: Reverification status persists across requests
   * 
   * Once verified, the status should persist for the validity period.
   * 
   * Properties:
   * - After completion, checkReverification returns true for valid period
   * - Multiple checks within validity period all return true
   * - Status is associated with correct session
   * - Different sessions have independent reverification status
   * 
   * **Validates: Requirements 3.4, 3.5**
   */
  describe('Property 9: Reverification status persists across requests', () => {
    it('should persist reverification status after completion', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          async (sessionId, userId, proofType) => {
            const proof = generateValidProof(proofType);
            const expectedLevel = proofTypeToLevel(proofType);
            
            // Complete reverification
            await service.completeReverification(sessionId, userId, proof);
            
            // Check should return true for same or lower level
            const checkResult = await service.checkReverification(sessionId, expectedLevel);
            expect(checkResult).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should persist across multiple checks', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          fc.integer({ min: 2, max: 10 }),
          async (sessionId, userId, proofType, checkCount) => {
            const proof = generateValidProof(proofType);
            const expectedLevel = proofTypeToLevel(proofType);
            
            // Complete reverification
            await service.completeReverification(sessionId, userId, proof);
            
            // Multiple checks should all return true
            for (let i = 0; i < checkCount; i++) {
              const checkResult = await service.checkReverification(sessionId, expectedLevel);
              expect(checkResult).toBe(true);
            }
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should maintain independent status per session', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(sessionIdArb, { minLength: 2, maxLength: 5 }),
          userIdArb,
          proofTypeArb,
          async (sessionIds, userId, proofType) => {
            // Ensure unique session IDs
            const uniqueSessionIds = [...new Set(sessionIds)];
            fc.pre(uniqueSessionIds.length >= 2);
            
            const proof = generateValidProof(proofType);
            const expectedLevel = proofTypeToLevel(proofType);
            
            // Complete reverification for first session only
            await service.completeReverification(uniqueSessionIds[0], userId, proof);
            
            // First session should have reverification
            const firstCheck = await service.checkReverification(uniqueSessionIds[0], expectedLevel);
            expect(firstCheck).toBe(true);
            
            // Other sessions should NOT have reverification
            for (let i = 1; i < uniqueSessionIds.length; i++) {
              const otherCheck = await service.checkReverification(uniqueSessionIds[i], expectedLevel);
              expect(otherCheck).toBe(false);
            }
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should return correct status via getReverificationStatus', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          async (sessionId, userId, proofType) => {
            const proof = generateValidProof(proofType);
            const expectedLevel = proofTypeToLevel(proofType);
            
            // Complete reverification
            await service.completeReverification(sessionId, userId, proof);
            
            // Get status
            const status = await service.getReverificationStatus(sessionId);
            
            expect(status.hasReverification).toBe(true);
            expect(status.isValid).toBe(true);
            expect(status.reverification).not.toBeNull();
            expect(status.reverification?.level).toBe(expectedLevel);
            expect(status.reverification?.sessionId).toBe(sessionId);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should clear reverification when explicitly cleared', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          async (sessionId, userId, proofType) => {
            const proof = generateValidProof(proofType);
            const expectedLevel = proofTypeToLevel(proofType);
            
            // Complete reverification
            await service.completeReverification(sessionId, userId, proof);
            
            // Verify it exists
            let checkResult = await service.checkReverification(sessionId, expectedLevel);
            expect(checkResult).toBe(true);
            
            // Clear reverification
            await service.clearReverification(sessionId);
            
            // Verify it's gone
            checkResult = await service.checkReverification(sessionId, expectedLevel);
            expect(checkResult).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should update reverification when completed again', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          proofTypeArb,
          async (sessionId, userId, firstProofType, secondProofType) => {
            const firstProof = generateValidProof(firstProofType);
            const secondProof = generateValidProof(secondProofType);
            const secondLevel = proofTypeToLevel(secondProofType);
            
            // Complete first reverification
            await service.completeReverification(sessionId, userId, firstProof);
            
            // Complete second reverification (should update)
            await service.completeReverification(sessionId, userId, secondProof);
            
            // Status should reflect second reverification
            const status = await service.getReverificationStatus(sessionId);
            expect(status.reverification?.level).toBe(secondLevel);
            expect(status.reverification?.method).toBe(secondProofType);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should preserve session association correctly', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          userIdArb,
          proofTypeArb,
          async (sessionId, userId, proofType) => {
            const proof = generateValidProof(proofType);
            
            // Complete reverification
            const result = await service.completeReverification(sessionId, userId, proof);
            
            // Result should have correct session ID
            expect(result.sessionId).toBe(sessionId);
            
            // Status should have correct session ID
            const status = await service.getReverificationStatus(sessionId);
            expect(status.reverification?.sessionId).toBe(sessionId);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  /**
   * Additional property tests for level hierarchy validation
   */
  describe('Level hierarchy validation properties', () => {
    it('should have correct hierarchy order', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: REVERIFICATION_LEVEL_HIERARCHY.length - 2 }),
          (index) => {
            const lowerLevel = REVERIFICATION_LEVEL_HIERARCHY[index];
            const higherLevel = REVERIFICATION_LEVEL_HIERARCHY[index + 1];
            
            // Higher level should satisfy lower level
            expect(levelSatisfiesRequirement(higherLevel, lowerLevel)).toBe(true);
            
            // Lower level should NOT satisfy higher level
            expect(levelSatisfiesRequirement(lowerLevel, higherLevel)).toBe(false);
            
            return true;
          }
        ),
        { numRuns: REVERIFICATION_LEVEL_HIERARCHY.length - 1 }
      );
    });

    it('should have transitive hierarchy', () => {
      // If A >= B and B >= C, then A >= C
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: REVERIFICATION_LEVEL_HIERARCHY.length - 1 }),
          fc.integer({ min: 0, max: REVERIFICATION_LEVEL_HIERARCHY.length - 1 }),
          fc.integer({ min: 0, max: REVERIFICATION_LEVEL_HIERARCHY.length - 1 }),
          (aIndex, bIndex, cIndex) => {
            const levelA = REVERIFICATION_LEVEL_HIERARCHY[aIndex];
            const levelB = REVERIFICATION_LEVEL_HIERARCHY[bIndex];
            const levelC = REVERIFICATION_LEVEL_HIERARCHY[cIndex];
            
            const aSatisfiesB = levelSatisfiesRequirement(levelA, levelB);
            const bSatisfiesC = levelSatisfiesRequirement(levelB, levelC);
            const aSatisfiesC = levelSatisfiesRequirement(levelA, levelC);
            
            // If A satisfies B and B satisfies C, then A must satisfy C
            if (aSatisfiesB && bSatisfiesC) {
              expect(aSatisfiesC).toBe(true);
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have reflexive hierarchy', () => {
      // Every level satisfies itself
      fc.assert(
        fc.property(
          reverificationLevelArb,
          (level) => {
            expect(levelSatisfiesRequirement(level, level)).toBe(true);
            return true;
          }
        ),
        { numRuns: REVERIFICATION_LEVEL_HIERARCHY.length * 10 }
      );
    });
  });

  /**
   * Validity period properties
   */
  describe('Validity period properties', () => {
    it('should have positive default validity for all levels', () => {
      fc.assert(
        fc.property(
          reverificationLevelArb,
          (level) => {
            const validity = DEFAULT_REVERIFICATION_VALIDITY[level];
            expect(validity).toBeGreaterThan(0);
            return true;
          }
        ),
        { numRuns: REVERIFICATION_LEVEL_HIERARCHY.length * 10 }
      );
    });

    it('should use custom validity when provided', () => {
      fc.assert(
        fc.property(
          reverificationLevelArb,
          validityMinutesArb,
          (level, customValidity) => {
            const result = getValidityMinutes(level, customValidity);
            expect(result).toBe(customValidity);
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should use default validity when custom is invalid', () => {
      fc.assert(
        fc.property(
          reverificationLevelArb,
          fc.integer({ min: -100, max: 0 }),
          (level, invalidValidity) => {
            const result = getValidityMinutes(level, invalidValidity);
            expect(result).toBe(DEFAULT_REVERIFICATION_VALIDITY[level]);
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
