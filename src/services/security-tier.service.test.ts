/**
 * Security Tier Service Tests
 * 
 * Tests for configurable security tiers:
 * - Tier configuration retrieval
 * - Password hashing with tier-specific algorithms
 * - Tier comparison and upgrade validation
 * - Compliance checking
 * - Rate limit configuration
 */

import {
  SecurityTierLevel,
  SECURITY_TIERS,
  getSecurityTier,
  getAllSecurityTiers,
  checkTierCompliance,
  recommendSecurityTier,
  hashPasswordWithTier,
  verifyPasswordWithTier,
  needsRehashForTier,
  getTierRateLimits,
  getTierSessionConfig,
  isMFARequiredForTier,
  isWebAuthnRequiredForTier,
  getAuditRetentionDays,
  compareTiers,
  isValidTierUpgrade,
  getTierDisplayInfo
} from './security-tier.service';

describe('Security Tier Service', () => {
  describe('Tier Configuration', () => {
    it('should have 6 security tiers defined', () => {
      const tiers = getAllSecurityTiers();
      expect(tiers).toHaveLength(6);
    });

    it('should return correct tier configuration', () => {
      const basic = getSecurityTier('basic');
      expect(basic.tier).toBe('basic');
      expect(basic.displayName).toBe('Basic');
      expect(basic.passwordHash.algorithm).toBe('bcrypt');
    });

    it('should throw error for unknown tier', () => {
      expect(() => getSecurityTier('unknown' as SecurityTierLevel)).toThrow('Unknown security tier');
    });

    it('should have all required properties for each tier', () => {
      const tiers = getAllSecurityTiers();
      
      for (const tier of tiers) {
        expect(tier.tier).toBeDefined();
        expect(tier.displayName).toBeDefined();
        expect(tier.description).toBeDefined();
        expect(tier.passwordHash).toBeDefined();
        expect(tier.passwordHash.algorithm).toBeDefined();
        expect(tier.jwtAlgorithm).toBeDefined();
        expect(tier.kmsType).toBeDefined();
        expect(tier.session).toBeDefined();
        expect(tier.mfaRequirement).toBeDefined();
        expect(tier.features).toBeDefined();
        expect(tier.compliance).toBeDefined();
      }
    });
  });

  describe('Tier-Specific Configurations', () => {
    describe('Basic Tier', () => {
      const tier = getSecurityTier('basic');

      it('should use bcrypt with 10 rounds', () => {
        expect(tier.passwordHash.algorithm).toBe('bcrypt');
        expect(tier.passwordHash.bcryptRounds).toBe(10);
      });

      it('should use HS256 JWT algorithm', () => {
        expect(tier.jwtAlgorithm).toBe('HS256');
      });

      it('should have optional MFA', () => {
        expect(tier.mfaRequirement).toBe('optional');
      });

      it('should not have audit logging', () => {
        expect(tier.features.auditLogging).toBe(false);
      });

      it('should have no compliance certifications', () => {
        expect(tier.compliance.hipaa).toBe(false);
        expect(tier.compliance.gdpr).toBe(false);
        expect(tier.compliance.soc2).toBe(false);
      });
    });

    describe('Standard Tier', () => {
      const tier = getSecurityTier('standard');

      it('should use bcrypt with 12 rounds', () => {
        expect(tier.passwordHash.algorithm).toBe('bcrypt');
        expect(tier.passwordHash.bcryptRounds).toBe(12);
      });

      it('should use RS256 JWT algorithm', () => {
        expect(tier.jwtAlgorithm).toBe('RS256');
      });

      it('should have recommended MFA', () => {
        expect(tier.mfaRequirement).toBe('recommended');
      });

      it('should have audit logging enabled', () => {
        expect(tier.features.auditLogging).toBe(true);
      });

      it('should be GDPR compliant', () => {
        expect(tier.compliance.gdpr).toBe(true);
      });
    });

    describe('Pro Tier', () => {
      const tier = getSecurityTier('pro');

      it('should use Argon2id', () => {
        expect(tier.passwordHash.algorithm).toBe('argon2id');
        expect(tier.passwordHash.argon2Memory).toBe(32768);
      });

      it('should have dedicated KMS', () => {
        expect(tier.kmsType).toBe('dedicated');
      });

      it('should require MFA', () => {
        expect(tier.mfaRequirement).toBe('required');
      });

      it('should have geo-velocity check', () => {
        expect(tier.session.geoVelocityCheck).toBe(true);
      });

      it('should be PCI DSS compliant', () => {
        expect(tier.compliance.pciDss).toBe(true);
      });
    });

    describe('Enterprise Tier', () => {
      const tier = getSecurityTier('enterprise');

      it('should use Argon2id with higher memory', () => {
        expect(tier.passwordHash.algorithm).toBe('argon2id');
        expect(tier.passwordHash.argon2Memory).toBe(65536);
      });

      it('should use ES256 JWT algorithm', () => {
        expect(tier.jwtAlgorithm).toBe('ES256');
      });

      it('should have customer-managed KMS', () => {
        expect(tier.kmsType).toBe('customer_managed');
      });

      it('should have 2-year audit retention', () => {
        expect(tier.features.auditRetentionDays).toBe(730);
      });
    });

    describe('Healthcare Tier', () => {
      const tier = getSecurityTier('healthcare');

      it('should use Argon2id (Lambda-optimized)', () => {
        expect(tier.passwordHash.algorithm).toBe('argon2id');
        expect(tier.passwordHash.argon2Memory).toBe(32768);
      });

      it('should use RS256 (FIPS-compliant)', () => {
        expect(tier.jwtAlgorithm).toBe('RS256');
      });

      it('should have HIPAA-compliant KMS', () => {
        expect(tier.kmsType).toBe('hipaa_compliant');
      });

      it('should require WebAuthn only (phishing-resistant)', () => {
        expect(tier.mfaRequirement).toBe('webauthn_only');
      });

      it('should have no MFA grace period', () => {
        expect(tier.mfaGracePeriodDays).toBe(0);
      });

      it('should have 6-year audit retention (HIPAA)', () => {
        expect(tier.features.auditRetentionDays).toBe(2190);
      });

      it('should be HIPAA compliant', () => {
        expect(tier.compliance.hipaa).toBe(true);
        expect(tier.compliance.fips).toBe(true);
      });
    });

    describe('Sovereign Tier', () => {
      const tier = getSecurityTier('sovereign');

      it('should use Argon2id with maximum memory', () => {
        expect(tier.passwordHash.algorithm).toBe('argon2id');
        expect(tier.passwordHash.argon2Memory).toBe(131072);
      });

      it('should use EdDSA (quantum-resistant preparation)', () => {
        expect(tier.jwtAlgorithm).toBe('EdDSA');
      });

      it('should use FIPS 140-3 HSM', () => {
        expect(tier.kmsType).toBe('fips_140_3');
      });

      it('should have shortest session times', () => {
        expect(tier.session.accessTokenExpiry).toBe(5 * 60);
        expect(tier.session.idleTimeout).toBe(10 * 60);
      });

      it('should allow only 1 concurrent session', () => {
        expect(tier.session.maxConcurrentSessions).toBe(1);
      });

      it('should have all compliance certifications', () => {
        expect(tier.compliance.hipaa).toBe(true);
        expect(tier.compliance.gdpr).toBe(true);
        expect(tier.compliance.soc2).toBe(true);
        expect(tier.compliance.pciDss).toBe(true);
        expect(tier.compliance.fips).toBe(true);
      });
    });
  });

  describe('Compliance Checking', () => {
    it('should pass compliance check when tier meets requirements', () => {
      const result = checkTierCompliance('healthcare', { hipaa: true });
      expect(result.compliant).toBe(true);
      expect(result.missing).toHaveLength(0);
    });

    it('should fail compliance check when tier does not meet requirements', () => {
      const result = checkTierCompliance('basic', { hipaa: true });
      expect(result.compliant).toBe(false);
      expect(result.missing).toContain('HIPAA');
    });

    it('should list all missing compliance requirements', () => {
      const result = checkTierCompliance('basic', {
        hipaa: true,
        gdpr: true,
        soc2: true,
        pciDss: true,
        fips: true
      });
      expect(result.compliant).toBe(false);
      expect(result.missing).toContain('HIPAA');
      expect(result.missing).toContain('GDPR');
      expect(result.missing).toContain('SOC 2');
      expect(result.missing).toContain('PCI DSS');
      expect(result.missing).toContain('FIPS');
    });

    it('should pass when sovereign tier meets all requirements', () => {
      const result = checkTierCompliance('sovereign', {
        hipaa: true,
        gdpr: true,
        soc2: true,
        pciDss: true,
        fips: true
      });
      expect(result.compliant).toBe(true);
    });
  });

  describe('Tier Recommendation', () => {
    it('should recommend sovereign for FIPS requirements', () => {
      const tier = recommendSecurityTier({ fips: true });
      expect(tier).toBe('sovereign');
    });

    it('should recommend healthcare for HIPAA requirements', () => {
      const tier = recommendSecurityTier({ hipaa: true });
      expect(tier).toBe('healthcare');
    });

    it('should recommend enterprise for large organizations', () => {
      const tier = recommendSecurityTier({ maxUsers: 50000 });
      expect(tier).toBe('enterprise');
    });

    it('should recommend pro for PCI DSS requirements', () => {
      const tier = recommendSecurityTier({ pciDss: true });
      expect(tier).toBe('pro');
    });

    it('should recommend standard for GDPR requirements', () => {
      const tier = recommendSecurityTier({ gdpr: true });
      expect(tier).toBe('standard');
    });

    it('should recommend basic for no specific requirements', () => {
      const tier = recommendSecurityTier({});
      expect(tier).toBe('basic');
    });
  });

  describe('Password Hashing', () => {
    const testPassword = 'TestPassword123!';

    it('should hash password with bcrypt for basic tier', async () => {
      const result = await hashPasswordWithTier(testPassword, 'basic');
      expect(result.algorithm).toBe('bcrypt');
      expect(result.hash).toMatch(/^\$2[aby]\$/);
    });

    it('should hash password with bcrypt for standard tier', async () => {
      const result = await hashPasswordWithTier(testPassword, 'standard');
      expect(result.algorithm).toBe('bcrypt');
      expect(result.hash).toMatch(/^\$2[aby]\$12\$/);
    });

    it('should hash password with argon2id for pro tier', async () => {
      const result = await hashPasswordWithTier(testPassword, 'pro');
      expect(result.algorithm).toBe('argon2id');
      expect(result.hash).toMatch(/^\$argon2id\$/);
    });

    it('should hash password with argon2id for healthcare tier', async () => {
      const result = await hashPasswordWithTier(testPassword, 'healthcare');
      expect(result.algorithm).toBe('argon2id');
      expect(result.hash).toMatch(/^\$argon2id\$/);
    });

    it('should verify bcrypt password correctly', async () => {
      const result = await hashPasswordWithTier(testPassword, 'basic');
      const isValid = await verifyPasswordWithTier(testPassword, result.hash);
      expect(isValid).toBe(true);
    });

    it('should verify argon2id password correctly', async () => {
      const result = await hashPasswordWithTier(testPassword, 'healthcare');
      const isValid = await verifyPasswordWithTier(testPassword, result.hash);
      expect(isValid).toBe(true);
    });

    it('should reject wrong password', async () => {
      const result = await hashPasswordWithTier(testPassword, 'healthcare');
      const isValid = await verifyPasswordWithTier('WrongPassword', result.hash);
      expect(isValid).toBe(false);
    });

    it('should produce different hashes for same password', async () => {
      const result1 = await hashPasswordWithTier(testPassword, 'healthcare');
      const result2 = await hashPasswordWithTier(testPassword, 'healthcare');
      expect(result1.hash).not.toBe(result2.hash);
    });
  });

  describe('Password Rehashing', () => {
    it('should need rehash when upgrading from bcrypt to argon2id', async () => {
      const bcryptHash = await hashPasswordWithTier('test', 'basic');
      const needsRehash = needsRehashForTier(bcryptHash.hash, 'healthcare');
      expect(needsRehash).toBe(true);
    });

    it('should not need rehash when staying on same algorithm', async () => {
      const argon2Hash = await hashPasswordWithTier('test', 'healthcare');
      const needsRehash = needsRehashForTier(argon2Hash.hash, 'healthcare');
      expect(needsRehash).toBe(false);
    });

    it('should need rehash when argon2 parameters increase', async () => {
      const proHash = await hashPasswordWithTier('test', 'pro');
      // Enterprise has higher memory (65536 vs 32768)
      const needsRehash = needsRehashForTier(proHash.hash, 'enterprise');
      expect(needsRehash).toBe(true);
    });

    it('should need rehash for unknown hash format', () => {
      const needsRehash = needsRehashForTier('unknown_hash_format', 'healthcare');
      expect(needsRehash).toBe(true);
    });
  });

  describe('Rate Limits', () => {
    it('should return correct rate limits for basic tier', () => {
      const limits = getTierRateLimits('basic');
      expect(limits.login.limit).toBe(10);
      expect(limits.register.limit).toBe(5);
      expect(limits.api.limit).toBe(200);
    });

    it('should return stricter rate limits for sovereign tier', () => {
      const limits = getTierRateLimits('sovereign');
      expect(limits.login.limit).toBe(3);
      expect(limits.register.limit).toBe(1);
      expect(limits.api.limit).toBe(30);
    });

    it('should have correct window durations', () => {
      const limits = getTierRateLimits('standard');
      expect(limits.login.windowMs).toBe(15 * 60 * 1000);
      expect(limits.register.windowMs).toBe(60 * 60 * 1000);
      expect(limits.api.windowMs).toBe(60 * 1000);
    });
  });

  describe('Session Configuration', () => {
    it('should return correct session config for basic tier', () => {
      const session = getTierSessionConfig('basic');
      expect(session.accessTokenExpiry).toBe(30 * 60);
      expect(session.maxConcurrentSessions).toBe(10);
      expect(session.deviceTrustEnabled).toBe(false);
    });

    it('should return stricter session config for healthcare tier', () => {
      const session = getTierSessionConfig('healthcare');
      expect(session.accessTokenExpiry).toBe(15 * 60);
      expect(session.idleTimeout).toBe(30 * 60);
      expect(session.maxConcurrentSessions).toBe(2);
      expect(session.deviceTrustEnabled).toBe(true);
      expect(session.geoVelocityCheck).toBe(true);
    });
  });

  describe('MFA Requirements', () => {
    it('should not require MFA for basic tier', () => {
      expect(isMFARequiredForTier('basic')).toBe(false);
    });

    it('should not require MFA for standard tier (recommended)', () => {
      expect(isMFARequiredForTier('standard')).toBe(false);
    });

    it('should require MFA for pro tier', () => {
      expect(isMFARequiredForTier('pro')).toBe(true);
    });

    it('should require MFA for healthcare tier', () => {
      expect(isMFARequiredForTier('healthcare')).toBe(true);
    });

    it('should not require WebAuthn for pro tier', () => {
      expect(isWebAuthnRequiredForTier('pro')).toBe(false);
    });

    it('should require WebAuthn for healthcare tier', () => {
      expect(isWebAuthnRequiredForTier('healthcare')).toBe(true);
    });

    it('should require WebAuthn for sovereign tier', () => {
      expect(isWebAuthnRequiredForTier('sovereign')).toBe(true);
    });
  });

  describe('Audit Retention', () => {
    it('should return 30 days for basic tier', () => {
      expect(getAuditRetentionDays('basic')).toBe(30);
    });

    it('should return 90 days for standard tier', () => {
      expect(getAuditRetentionDays('standard')).toBe(90);
    });

    it('should return 6 years (2190 days) for healthcare tier', () => {
      expect(getAuditRetentionDays('healthcare')).toBe(2190);
    });

    it('should return 7 years (2555 days) for sovereign tier', () => {
      expect(getAuditRetentionDays('sovereign')).toBe(2555);
    });
  });

  describe('Tier Comparison', () => {
    it('should compare tiers correctly', () => {
      expect(compareTiers('basic', 'standard')).toBeLessThan(0);
      expect(compareTiers('standard', 'basic')).toBeGreaterThan(0);
      expect(compareTiers('healthcare', 'healthcare')).toBe(0);
    });

    it('should order tiers from basic to sovereign', () => {
      expect(compareTiers('basic', 'sovereign')).toBeLessThan(0);
      expect(compareTiers('sovereign', 'basic')).toBeGreaterThan(0);
    });

    it('should validate tier upgrades', () => {
      expect(isValidTierUpgrade('basic', 'standard')).toBe(true);
      expect(isValidTierUpgrade('standard', 'pro')).toBe(true);
      expect(isValidTierUpgrade('pro', 'basic')).toBe(false);
      expect(isValidTierUpgrade('healthcare', 'standard')).toBe(false);
    });
  });

  describe('Display Info', () => {
    it('should return display info for tier', () => {
      const info = getTierDisplayInfo('healthcare');
      expect(info.name).toBe('Healthcare');
      expect(info.description).toContain('HIPAA');
      expect(info.features).toContain('Audit Logging');
      expect(info.features).toContain('Device Trust');
      expect(info.compliance).toContain('HIPAA');
      expect(info.compliance).toContain('FIPS');
    });

    it('should list all features for sovereign tier', () => {
      const info = getTierDisplayInfo('sovereign');
      expect(info.features).toContain('Audit Logging');
      expect(info.features).toContain('IP Whitelisting');
      expect(info.features).toContain('Credential Stuffing Detection');
      expect(info.features).toContain('Impossible Travel Detection');
      expect(info.features).toContain('Breached Password Check');
      expect(info.features).toContain('Device Trust');
      expect(info.features).toContain('Geo-Velocity Check');
    });

    it('should list all compliance for sovereign tier', () => {
      const info = getTierDisplayInfo('sovereign');
      expect(info.compliance).toContain('HIPAA');
      expect(info.compliance).toContain('GDPR');
      expect(info.compliance).toContain('SOC 2');
      expect(info.compliance).toContain('PCI DSS');
      expect(info.compliance).toContain('FIPS');
    });
  });
});
