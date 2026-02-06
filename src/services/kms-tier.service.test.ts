/**
 * KMS Tier Integration Service Tests
 * 
 * Tests for tier-specific KMS configurations:
 * - Key alias generation
 * - KMS configuration per tier
 * - Encryption/decryption operations (mocked)
 * - Key rotation status
 */

import {
  getKMSKeyAlias,
  getKMSConfig,
  isKMSConfiguredForTier
} from './kms-tier.service';
import { SecurityTierLevel } from './security-tier.service';
import { OriginType, KeySpec, KeyUsageType } from '@aws-sdk/client-kms';

// Mock AWS KMS client
jest.mock('@aws-sdk/client-kms', () => {
  const actual = jest.requireActual('@aws-sdk/client-kms');
  return {
    ...actual,
    KMSClient: jest.fn().mockImplementation(() => ({
      send: jest.fn().mockResolvedValue({})
    }))
  };
});

describe('KMS Tier Integration Service', () => {
  describe('Key Alias Generation', () => {
    it('should generate shared alias for basic tier', () => {
      const alias = getKMSKeyAlias('basic');
      expect(alias).toBe('alias/zalt-shared-basic');
    });

    it('should generate shared alias for standard tier', () => {
      const alias = getKMSKeyAlias('standard');
      expect(alias).toBe('alias/zalt-shared-standard');
    });

    it('should generate dedicated alias for pro tier with customer ID', () => {
      const alias = getKMSKeyAlias('pro', 'customer-123');
      expect(alias).toBe('alias/zalt-dedicated-customer-123');
    });

    it('should throw error for pro tier without customer ID', () => {
      expect(() => getKMSKeyAlias('pro')).toThrow('Customer ID required for dedicated KMS');
    });

    it('should generate customer-managed alias for enterprise tier', () => {
      const alias = getKMSKeyAlias('enterprise', 'customer-456');
      expect(alias).toBe('alias/zalt-customer-customer-456');
    });

    it('should throw error for enterprise tier without customer ID', () => {
      expect(() => getKMSKeyAlias('enterprise')).toThrow('Customer ID required for customer-managed KMS');
    });

    it('should generate HIPAA alias for healthcare tier with realm ID', () => {
      const alias = getKMSKeyAlias('healthcare', undefined, 'clinisyn-psychologists');
      expect(alias).toBe('alias/zalt-hipaa-clinisyn-psychologists');
    });

    it('should throw error for healthcare tier without realm ID', () => {
      expect(() => getKMSKeyAlias('healthcare')).toThrow('Realm ID required for HIPAA-compliant KMS');
    });

    it('should generate FIPS alias for sovereign tier', () => {
      const alias = getKMSKeyAlias('sovereign', 'gov-agency-789');
      expect(alias).toBe('alias/zalt-fips-gov-agency-789');
    });

    it('should throw error for sovereign tier without customer ID', () => {
      expect(() => getKMSKeyAlias('sovereign')).toThrow('Customer ID required for FIPS KMS');
    });
  });

  describe('KMS Configuration', () => {
    describe('Basic Tier', () => {
      const config = getKMSConfig('basic');

      it('should use symmetric default key spec', () => {
        expect(config.keySpec).toBe(KeySpec.SYMMETRIC_DEFAULT);
      });

      it('should use encrypt/decrypt key usage', () => {
        expect(config.keyUsage).toBe(KeyUsageType.ENCRYPT_DECRYPT);
      });

      it('should use AWS KMS origin', () => {
        expect(config.origin).toBe(OriginType.AWS_KMS);
      });

      it('should not be multi-region', () => {
        expect(config.multiRegion).toBe(false);
      });

      it('should have 90-day rotation period', () => {
        expect(config.rotationPeriodDays).toBe(90);
      });
    });

    describe('Standard Tier', () => {
      const config = getKMSConfig('standard');

      it('should use AWS KMS origin', () => {
        expect(config.origin).toBe(OriginType.AWS_KMS);
      });

      it('should not be multi-region', () => {
        expect(config.multiRegion).toBe(false);
      });

      it('should have 60-day rotation period', () => {
        expect(config.rotationPeriodDays).toBe(60);
      });
    });

    describe('Pro Tier', () => {
      const config = getKMSConfig('pro');

      it('should use AWS KMS origin', () => {
        expect(config.origin).toBe(OriginType.AWS_KMS);
      });

      it('should be multi-region', () => {
        expect(config.multiRegion).toBe(true);
      });

      it('should have 30-day rotation period', () => {
        expect(config.rotationPeriodDays).toBe(30);
      });
    });

    describe('Enterprise Tier', () => {
      const config = getKMSConfig('enterprise');

      it('should use external origin (customer-managed)', () => {
        expect(config.origin).toBe(OriginType.EXTERNAL);
      });

      it('should be multi-region', () => {
        expect(config.multiRegion).toBe(true);
      });

      it('should have 30-day rotation period', () => {
        expect(config.rotationPeriodDays).toBe(30);
      });
    });

    describe('Healthcare Tier', () => {
      const config = getKMSConfig('healthcare');

      it('should use AWS KMS origin', () => {
        expect(config.origin).toBe(OriginType.AWS_KMS);
      });

      it('should be multi-region', () => {
        expect(config.multiRegion).toBe(true);
      });

      it('should have 30-day rotation period (HIPAA requirement)', () => {
        expect(config.rotationPeriodDays).toBe(30);
      });
    });

    describe('Sovereign Tier', () => {
      const config = getKMSConfig('sovereign');

      it('should use CloudHSM origin (FIPS 140-3)', () => {
        expect(config.origin).toBe(OriginType.AWS_CLOUDHSM);
      });

      it('should be multi-region', () => {
        expect(config.multiRegion).toBe(true);
      });

      it('should have 14-day rotation period (most frequent)', () => {
        expect(config.rotationPeriodDays).toBe(14);
      });
    });
  });

  describe('Tier-Specific Key Requirements', () => {
    it('should require different key configurations per tier', () => {
      const tiers: SecurityTierLevel[] = ['basic', 'standard', 'pro', 'enterprise', 'healthcare', 'sovereign'];
      const configs = tiers.map(tier => getKMSConfig(tier));
      
      // Basic and Standard should have same origin
      expect(configs[0].origin).toBe(configs[1].origin);
      
      // Enterprise should have external origin
      expect(configs[3].origin).toBe(OriginType.EXTERNAL);
      
      // Sovereign should have CloudHSM origin
      expect(configs[5].origin).toBe(OriginType.AWS_CLOUDHSM);
    });

    it('should have progressively shorter rotation periods for higher tiers', () => {
      const basic = getKMSConfig('basic');
      const standard = getKMSConfig('standard');
      const pro = getKMSConfig('pro');
      const sovereign = getKMSConfig('sovereign');
      
      expect(basic.rotationPeriodDays).toBeGreaterThan(standard.rotationPeriodDays);
      expect(standard.rotationPeriodDays).toBeGreaterThan(pro.rotationPeriodDays);
      expect(pro.rotationPeriodDays).toBeGreaterThan(sovereign.rotationPeriodDays);
    });

    it('should enable multi-region for higher tiers', () => {
      const basic = getKMSConfig('basic');
      const pro = getKMSConfig('pro');
      const healthcare = getKMSConfig('healthcare');
      
      expect(basic.multiRegion).toBe(false);
      expect(pro.multiRegion).toBe(true);
      expect(healthcare.multiRegion).toBe(true);
    });
  });

  describe('Key Alias Patterns', () => {
    it('should use consistent naming convention', () => {
      const aliases = [
        getKMSKeyAlias('basic'),
        getKMSKeyAlias('standard'),
        getKMSKeyAlias('pro', 'cust-1'),
        getKMSKeyAlias('enterprise', 'cust-2'),
        getKMSKeyAlias('healthcare', undefined, 'realm-1'),
        getKMSKeyAlias('sovereign', 'cust-3')
      ];
      
      // All should start with alias/zalt-
      aliases.forEach(alias => {
        expect(alias).toMatch(/^alias\/zalt-/);
      });
    });

    it('should include tier type in alias', () => {
      expect(getKMSKeyAlias('basic')).toContain('shared');
      expect(getKMSKeyAlias('pro', 'cust')).toContain('dedicated');
      expect(getKMSKeyAlias('enterprise', 'cust')).toContain('customer');
      expect(getKMSKeyAlias('healthcare', undefined, 'realm')).toContain('hipaa');
      expect(getKMSKeyAlias('sovereign', 'cust')).toContain('fips');
    });
  });

  describe('KMS Configuration Check', () => {
    it('should return false when KMS is not configured', async () => {
      // With mocked KMS client that returns empty response
      const isConfigured = await isKMSConfiguredForTier('basic');
      expect(isConfigured).toBe(false);
    });
  });

  describe('Security Compliance', () => {
    it('should use FIPS-compliant origin for sovereign tier', () => {
      const config = getKMSConfig('sovereign');
      expect(config.origin).toBe(OriginType.AWS_CLOUDHSM);
    });

    it('should use customer-managed keys for enterprise tier', () => {
      const config = getKMSConfig('enterprise');
      expect(config.origin).toBe(OriginType.EXTERNAL);
    });

    it('should enable multi-region for disaster recovery in healthcare', () => {
      const config = getKMSConfig('healthcare');
      expect(config.multiRegion).toBe(true);
    });
  });
});
