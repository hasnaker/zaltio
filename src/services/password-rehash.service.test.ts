/**
 * Password Rehashing Service Tests
 * 
 * Tests for automatic password rehashing on tier upgrade:
 * - Hash algorithm detection
 * - Parameter extraction
 * - Tier requirement checking
 * - Verify and rehash flow
 * - Statistics calculation
 * - Audit logging
 */

import {
  detectHashAlgorithm,
  getArgon2Params,
  getBcryptRounds,
  hashMeetsTierRequirements,
  verifyAndRehashIfNeeded,
  forceRehash,
  calculateRehashStats,
  getRecommendedTierForHash,
  estimateRehashTime,
  createRehashAuditEntry,
  validateTierUpgradeForPasswords
} from './password-rehash.service';
import { hashPasswordWithTier } from './security-tier.service';

describe('Password Rehashing Service', () => {
  describe('Hash Algorithm Detection', () => {
    it('should detect argon2id hash', () => {
      const hash = '$argon2id$v=19$m=32768,t=5,p=2$salt$hash';
      expect(detectHashAlgorithm(hash)).toBe('argon2id');
    });

    it('should detect bcrypt hash ($2a$)', () => {
      const hash = '$2a$12$saltsaltsaltsaltsaltsOhash';
      expect(detectHashAlgorithm(hash)).toBe('bcrypt');
    });

    it('should detect bcrypt hash ($2b$)', () => {
      const hash = '$2b$10$saltsaltsaltsaltsaltsOhash';
      expect(detectHashAlgorithm(hash)).toBe('bcrypt');
    });

    it('should detect scrypt hash', () => {
      const hash = '$scrypt$16384$8$1$salt$hash';
      expect(detectHashAlgorithm(hash)).toBe('scrypt');
    });

    it('should return null for unknown hash', () => {
      const hash = 'unknown_hash_format';
      expect(detectHashAlgorithm(hash)).toBeNull();
    });
  });

  describe('Argon2 Parameter Extraction', () => {
    it('should extract argon2 parameters', () => {
      const hash = '$argon2id$v=19$m=32768,t=5,p=2$salt$hash';
      const params = getArgon2Params(hash);
      
      expect(params).not.toBeNull();
      expect(params?.memory).toBe(32768);
      expect(params?.timeCost).toBe(5);
      expect(params?.parallelism).toBe(2);
    });

    it('should extract high memory argon2 parameters', () => {
      const hash = '$argon2id$v=19$m=131072,t=6,p=4$salt$hash';
      const params = getArgon2Params(hash);
      
      expect(params?.memory).toBe(131072);
      expect(params?.timeCost).toBe(6);
      expect(params?.parallelism).toBe(4);
    });

    it('should return null for non-argon2 hash', () => {
      const hash = '$2a$12$saltsaltsaltsaltsaltsOhash';
      expect(getArgon2Params(hash)).toBeNull();
    });
  });

  describe('Bcrypt Rounds Extraction', () => {
    it('should extract bcrypt rounds', () => {
      const hash = '$2a$12$saltsaltsaltsaltsaltsOhash';
      expect(getBcryptRounds(hash)).toBe(12);
    });

    it('should extract different bcrypt rounds', () => {
      const hash = '$2b$10$saltsaltsaltsaltsaltsOhash';
      expect(getBcryptRounds(hash)).toBe(10);
    });

    it('should return null for non-bcrypt hash', () => {
      const hash = '$argon2id$v=19$m=32768,t=5,p=2$salt$hash';
      expect(getBcryptRounds(hash)).toBeNull();
    });
  });

  describe('Tier Requirement Checking', () => {
    it('should pass when bcrypt hash meets basic tier requirements', async () => {
      const { hash } = await hashPasswordWithTier('TestPassword123!', 'basic');
      const result = hashMeetsTierRequirements(hash, 'basic');
      expect(result.meets).toBe(true);
    });

    it('should fail when bcrypt hash does not meet healthcare tier', async () => {
      const { hash } = await hashPasswordWithTier('TestPassword123!', 'basic');
      const result = hashMeetsTierRequirements(hash, 'healthcare');
      expect(result.meets).toBe(false);
      expect(result.reason).toContain('Algorithm mismatch');
    });

    it('should pass when argon2 hash meets healthcare tier', async () => {
      const { hash } = await hashPasswordWithTier('TestPassword123!', 'healthcare');
      const result = hashMeetsTierRequirements(hash, 'healthcare');
      expect(result.meets).toBe(true);
    });

    it('should fail for unknown hash algorithm', () => {
      const result = hashMeetsTierRequirements('unknown_hash', 'basic');
      expect(result.meets).toBe(false);
      expect(result.reason).toBe('Unknown hash algorithm');
    });
  });

  describe('Verify and Rehash', () => {
    const testPassword = 'TestPassword123!';

    it('should verify correct password without rehash when tier matches', async () => {
      const { hash } = await hashPasswordWithTier(testPassword, 'healthcare');
      const result = await verifyAndRehashIfNeeded(testPassword, hash, 'healthcare');
      
      expect(result.valid).toBe(true);
      expect(result.rehashResult).toBeUndefined();
    });

    it('should reject incorrect password', async () => {
      const { hash } = await hashPasswordWithTier(testPassword, 'basic');
      const result = await verifyAndRehashIfNeeded('WrongPassword', hash, 'basic');
      
      expect(result.valid).toBe(false);
      expect(result.rehashResult).toBeUndefined();
    });

    it('should rehash when upgrading from basic to healthcare', async () => {
      const { hash: basicHash } = await hashPasswordWithTier(testPassword, 'basic');
      const result = await verifyAndRehashIfNeeded(testPassword, basicHash, 'healthcare');
      
      expect(result.valid).toBe(true);
      expect(result.rehashResult).toBeDefined();
      expect(result.rehashResult?.rehashed).toBe(true);
      expect(result.rehashResult?.oldAlgorithm).toBe('bcrypt');
      expect(result.rehashResult?.newAlgorithm).toBe('argon2id');
    });

    it('should rehash when upgrading from standard to pro', async () => {
      const { hash: standardHash } = await hashPasswordWithTier(testPassword, 'standard');
      const result = await verifyAndRehashIfNeeded(testPassword, standardHash, 'pro');
      
      expect(result.valid).toBe(true);
      expect(result.rehashResult).toBeDefined();
      expect(result.rehashResult?.rehashed).toBe(true);
    });

    it('should produce valid new hash after rehash', async () => {
      const { hash: basicHash } = await hashPasswordWithTier(testPassword, 'basic');
      const result = await verifyAndRehashIfNeeded(testPassword, basicHash, 'healthcare');
      
      expect(result.rehashResult?.newHash).toBeDefined();
      
      // Verify new hash works
      const verifyResult = await verifyAndRehashIfNeeded(
        testPassword,
        result.rehashResult!.newHash!,
        'healthcare'
      );
      expect(verifyResult.valid).toBe(true);
    });
  });

  describe('Force Rehash', () => {
    const testPassword = 'TestPassword123!';

    it('should force rehash with correct password', async () => {
      const { hash } = await hashPasswordWithTier(testPassword, 'basic');
      const result = await forceRehash(testPassword, hash, 'healthcare');
      
      expect(result.rehashed).toBe(true);
      expect(result.newHash).toBeDefined();
      expect(result.newAlgorithm).toBe('argon2id');
    });

    it('should throw error with incorrect password', async () => {
      const { hash } = await hashPasswordWithTier(testPassword, 'basic');
      
      await expect(forceRehash('WrongPassword', hash, 'healthcare'))
        .rejects.toThrow('Invalid password');
    });
  });

  describe('Rehash Statistics', () => {
    it('should calculate stats for mixed hashes', async () => {
      const basicHash1 = (await hashPasswordWithTier('pass1', 'basic')).hash;
      const basicHash2 = (await hashPasswordWithTier('pass2', 'basic')).hash;
      const healthcareHash = (await hashPasswordWithTier('pass3', 'healthcare')).hash;
      
      const stats = calculateRehashStats(
        [basicHash1, basicHash2, healthcareHash],
        'healthcare'
      );
      
      expect(stats.totalUsers).toBe(3);
      expect(stats.usersNeedingRehash).toBe(2);
      expect(stats.usersRehashed).toBe(1);
      expect(stats.percentComplete).toBe(33);
    });

    it('should return 100% when all hashes meet requirements', async () => {
      const hash1 = (await hashPasswordWithTier('pass1', 'healthcare')).hash;
      const hash2 = (await hashPasswordWithTier('pass2', 'healthcare')).hash;
      
      const stats = calculateRehashStats([hash1, hash2], 'healthcare');
      
      expect(stats.usersNeedingRehash).toBe(0);
      expect(stats.percentComplete).toBe(100);
    });

    it('should handle empty array', () => {
      const stats = calculateRehashStats([], 'healthcare');
      
      expect(stats.totalUsers).toBe(0);
      expect(stats.percentComplete).toBe(100);
    });
  });

  describe('Recommended Tier for Hash', () => {
    it('should recommend basic for low-round bcrypt', async () => {
      const { hash } = await hashPasswordWithTier('test', 'basic');
      const tier = getRecommendedTierForHash(hash);
      // Basic uses 10 rounds, standard uses 12
      expect(['basic', 'standard']).toContain(tier);
    });

    it('should recommend pro or higher for argon2', async () => {
      const { hash } = await hashPasswordWithTier('test', 'pro');
      const tier = getRecommendedTierForHash(hash);
      expect(['pro', 'healthcare', 'enterprise', 'sovereign']).toContain(tier);
    });

    it('should recommend basic for unknown hash', () => {
      const tier = getRecommendedTierForHash('unknown_hash');
      expect(tier).toBe('basic');
    });
  });

  describe('Rehash Time Estimation', () => {
    it('should estimate time for basic tier', () => {
      const estimate = estimateRehashTime(1000, 'basic');
      
      expect(estimate.estimatedSeconds).toBeGreaterThan(0);
      expect(estimate.estimatedMinutes).toBeGreaterThan(0);
      expect(estimate.recommendation).toBeDefined();
    });

    it('should estimate longer time for healthcare tier', () => {
      const basicEstimate = estimateRehashTime(1000, 'basic');
      const healthcareEstimate = estimateRehashTime(1000, 'healthcare');
      
      expect(healthcareEstimate.estimatedSeconds).toBeGreaterThan(basicEstimate.estimatedSeconds);
    });

    it('should recommend gradual migration for large user counts', () => {
      const estimate = estimateRehashTime(100000, 'sovereign');
      
      expect(estimate.recommendation).toContain('gradual');
    });

    it('should recommend maintenance window for small user counts', () => {
      const estimate = estimateRehashTime(100, 'basic');
      
      expect(estimate.recommendation).toContain('maintenance');
    });
  });

  describe('Audit Entry Creation', () => {
    it('should create audit entry for rehash', () => {
      const result = {
        rehashed: true,
        newHash: 'new_hash',
        oldAlgorithm: 'bcrypt' as const,
        newAlgorithm: 'argon2id' as const,
        reason: 'Tier upgrade'
      };
      
      const entry = createRehashAuditEntry('user-123', 'realm-456', result);
      
      expect(entry.event).toBe('password_rehash');
      expect(entry.userId).toBe('user-123');
      expect(entry.realmId).toBe('realm-456');
      expect(entry.details.rehashed).toBe(true);
      expect(entry.details.oldAlgorithm).toBe('bcrypt');
      expect(entry.details.newAlgorithm).toBe('argon2id');
      expect(entry.timestamp).toBeDefined();
    });
  });

  describe('Tier Upgrade Validation', () => {
    it('should validate safe upgrade from basic to standard', () => {
      const result = validateTierUpgradeForPasswords('basic', 'standard');
      
      expect(result.safe).toBe(true);
    });

    it('should warn about algorithm change from standard to pro', () => {
      const result = validateTierUpgradeForPasswords('standard', 'pro');
      
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings.some(w => w.includes('Algorithm change'))).toBe(true);
    });

    it('should warn about downgrade from healthcare to basic', () => {
      const result = validateTierUpgradeForPasswords('healthcare', 'basic');
      
      expect(result.safe).toBe(false);
      expect(result.warnings.some(w => w.includes('Downgrading'))).toBe(true);
    });

    it('should warn about losing HIPAA compliance', () => {
      const result = validateTierUpgradeForPasswords('healthcare', 'pro');
      
      expect(result.warnings.some(w => w.includes('HIPAA'))).toBe(true);
    });

    it('should provide recommendations for algorithm changes', () => {
      const result = validateTierUpgradeForPasswords('basic', 'healthcare');
      
      expect(result.recommendations.length).toBeGreaterThan(0);
      expect(result.recommendations.some(r => r.includes('rehashed'))).toBe(true);
    });
  });

  describe('Integration: Full Upgrade Flow', () => {
    const testPassword = 'SecurePassword123!';

    it('should handle complete tier upgrade flow', async () => {
      // 1. Create user with basic tier
      const { hash: basicHash } = await hashPasswordWithTier(testPassword, 'basic');
      expect(detectHashAlgorithm(basicHash)).toBe('bcrypt');
      
      // 2. Validate upgrade
      const validation = validateTierUpgradeForPasswords('basic', 'healthcare');
      expect(validation.warnings.length).toBeGreaterThan(0);
      
      // 3. Check if rehash needed
      const meetsTier = hashMeetsTierRequirements(basicHash, 'healthcare');
      expect(meetsTier.meets).toBe(false);
      
      // 4. User logs in, password is rehashed
      const loginResult = await verifyAndRehashIfNeeded(testPassword, basicHash, 'healthcare');
      expect(loginResult.valid).toBe(true);
      expect(loginResult.rehashResult?.rehashed).toBe(true);
      
      // 5. New hash meets healthcare requirements
      const newHash = loginResult.rehashResult!.newHash!;
      const newMeetsTier = hashMeetsTierRequirements(newHash, 'healthcare');
      expect(newMeetsTier.meets).toBe(true);
      
      // 6. Create audit entry
      const auditEntry = createRehashAuditEntry('user-1', 'realm-1', loginResult.rehashResult!);
      expect(auditEntry.event).toBe('password_rehash');
    });
  });
});
