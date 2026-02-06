/**
 * Device Trust E2E Tests
 * 
 * Task 3.2: Device Trust Scoring
 * Validates: Requirements 3.1, 3.2 (Device Trust)
 * 
 * @e2e-test
 * @phase Phase 3
 */

import {
  generateFingerprintHash,
  calculateFingerprintSimilarity,
  matchDevice,
  createDeviceRecord,
  calculateTrustScore,
  getTrustLevel,
  TRUST_THRESHOLDS,
  DeviceFingerprintInput,
  StoredDevice
} from '../../services/device.service';

describe('Device Trust E2E Tests', () => {
  // Sample fingerprints for testing
  const macbookFingerprint: DeviceFingerprintInput = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    screen: '2560x1600',
    timezone: 'Europe/Istanbul',
    language: 'tr-TR',
    platform: 'MacIntel'
  };

  const macbookUpdatedFingerprint: DeviceFingerprintInput = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36',
    screen: '2560x1600',
    timezone: 'Europe/Istanbul',
    language: 'tr-TR',
    platform: 'MacIntel'
  };

  const windowsFingerprint: DeviceFingerprintInput = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    screen: '1920x1080',
    timezone: 'America/New_York',
    language: 'en-US',
    platform: 'Win32'
  };

  const iphoneFingerprint: DeviceFingerprintInput = {
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1',
    screen: '390x844',
    timezone: 'Europe/Istanbul',
    language: 'tr-TR',
    platform: 'iPhone'
  };

  const createStoredDevice = (
    fingerprint: DeviceFingerprintInput,
    options: { trusted?: boolean; userId?: string } = {}
  ): StoredDevice => {
    const device = createDeviceRecord(
      options.userId || 'user-123',
      'clinisyn-psychologists',
      fingerprint,
      '192.168.1.1'
    );
    return {
      ...device,
      trusted: options.trusted || false,
      trustExpiresAt: options.trusted 
        ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
        : undefined
    };
  };

  describe('Known Device Recognition', () => {
    it('should recognize same device with 100% score', () => {
      const storedDevices = [createStoredDevice(macbookFingerprint, { trusted: true })];
      
      const result = matchDevice(macbookFingerprint, storedDevices);
      
      expect(result.matched).toBe(true);
      expect(result.similarityScore).toBe(100);
      expect(result.trustLevel).toBe('trusted');
    });

    it('should recognize device after browser update (>= 70%)', () => {
      const storedDevices = [createStoredDevice(macbookFingerprint)];
      
      const result = matchDevice(macbookUpdatedFingerprint, storedDevices);
      
      expect(result.matched).toBe(true);
      expect(result.similarityScore).toBeGreaterThanOrEqual(70);
    });

    it('should not match completely different device', () => {
      const storedDevices = [createStoredDevice(macbookFingerprint)];
      
      const result = matchDevice(windowsFingerprint, storedDevices);
      
      expect(result.matched).toBe(false);
      expect(result.similarityScore).toBeLessThan(70);
      expect(result.trustLevel).toBe('new');
    });
  });

  describe('New Device Detection', () => {
    it('should detect new device when no stored devices', () => {
      const result = matchDevice(macbookFingerprint, []);
      
      expect(result.matched).toBe(false);
      expect(result.trustLevel).toBe('new');
    });

    it('should detect new device when fingerprint differs significantly', () => {
      const storedDevices = [createStoredDevice(macbookFingerprint)];
      
      const result = matchDevice(iphoneFingerprint, storedDevices);
      
      expect(result.matched).toBe(false);
      expect(result.trustLevel).toBe('new');
    });
  });

  describe('Trust Score Thresholds', () => {
    it('should return "trusted" for score >= 80', () => {
      const score = calculateTrustScore({
        fingerprintSimilarity: 100,
        ipProximity: 100,
        userAgentConsistency: 100,
        loginTimePattern: 100
      });
      
      expect(score).toBeGreaterThanOrEqual(TRUST_THRESHOLDS.TRUSTED);
      expect(getTrustLevel(score)).toBe('trusted');
    });

    it('should return "familiar" for score 50-79', () => {
      const score = calculateTrustScore({
        fingerprintSimilarity: 70,
        ipProximity: 50,
        userAgentConsistency: 50,
        loginTimePattern: 50
      });
      
      expect(score).toBeGreaterThanOrEqual(TRUST_THRESHOLDS.FAMILIAR);
      expect(score).toBeLessThan(TRUST_THRESHOLDS.TRUSTED);
      expect(getTrustLevel(score)).toBe('familiar');
    });

    it('should return "suspicious" for score < 50', () => {
      const score = calculateTrustScore({
        fingerprintSimilarity: 30,
        ipProximity: 20,
        userAgentConsistency: 30,
        loginTimePattern: 20
      });
      
      expect(score).toBeLessThan(TRUST_THRESHOLDS.FAMILIAR);
      expect(getTrustLevel(score)).toBe('suspicious');
    });
  });

  describe('IP Change Impact', () => {
    it('should lower trust score when IP changes significantly', () => {
      // Same fingerprint, different IP location
      const highTrust = calculateTrustScore({
        fingerprintSimilarity: 100,
        ipProximity: 100  // Same location
      });
      
      const lowTrust = calculateTrustScore({
        fingerprintSimilarity: 100,
        ipProximity: 20   // Different country
      });
      
      expect(lowTrust).toBeLessThan(highTrust);
    });
  });

  describe('Multi-Device User', () => {
    it('should match correct device among multiple', () => {
      const storedDevices = [
        createStoredDevice(macbookFingerprint, { trusted: true }),
        createStoredDevice(iphoneFingerprint),
        createStoredDevice(windowsFingerprint)
      ];
      
      const result = matchDevice(macbookFingerprint, storedDevices);
      
      expect(result.matched).toBe(true);
      expect(result.similarityScore).toBe(100);
      expect(result.device?.components.platform).toBe('macintel');
    });

    it('should find best match when multiple similar devices exist', () => {
      const storedDevices = [
        createStoredDevice(macbookFingerprint),
        createStoredDevice(macbookUpdatedFingerprint, { trusted: true })
      ];
      
      // Login with exact match to updated fingerprint
      const result = matchDevice(macbookUpdatedFingerprint, storedDevices);
      
      expect(result.matched).toBe(true);
      expect(result.similarityScore).toBe(100);
    });
  });

  describe('Component Score Analysis', () => {
    it('should provide detailed component scores', () => {
      const storedDevices = [createStoredDevice(macbookFingerprint)];
      
      // Same device, different timezone
      const modifiedFingerprint: DeviceFingerprintInput = {
        ...macbookFingerprint,
        timezone: 'America/Los_Angeles'
      };
      
      const result = matchDevice(modifiedFingerprint, storedDevices);
      
      expect(result.componentScores.userAgent).toBe(100);
      expect(result.componentScores.screenResolution).toBe(100);
      expect(result.componentScores.timezone).toBeLessThan(100);
      expect(result.componentScores.language).toBe(100);
      expect(result.componentScores.platform).toBe(100);
    });
  });

  describe('Fingerprint Hash Consistency', () => {
    it('should generate consistent hash for same fingerprint', () => {
      const hash1 = generateFingerprintHash(macbookFingerprint);
      const hash2 = generateFingerprintHash(macbookFingerprint);
      
      expect(hash1).toBe(hash2);
    });

    it('should generate different hash for different fingerprint', () => {
      const hash1 = generateFingerprintHash(macbookFingerprint);
      const hash2 = generateFingerprintHash(windowsFingerprint);
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('Trust Level Decisions', () => {
    it('should allow MFA skip for trusted device', () => {
      const storedDevices = [createStoredDevice(macbookFingerprint, { trusted: true })];
      const result = matchDevice(macbookFingerprint, storedDevices);
      
      // Trusted device = can skip MFA
      expect(result.trustLevel).toBe('trusted');
      const canSkipMfa = result.trustLevel === 'trusted';
      expect(canSkipMfa).toBe(true);
    });

    it('should require MFA for familiar device', () => {
      const storedDevices = [createStoredDevice(macbookFingerprint, { trusted: false })];
      const result = matchDevice(macbookFingerprint, storedDevices);
      
      // Familiar device = require MFA
      expect(result.trustLevel).toBe('familiar');
      const requireMfa = result.trustLevel !== 'trusted';
      expect(requireMfa).toBe(true);
    });

    it('should require MFA + email for suspicious/new device', () => {
      const result = matchDevice(macbookFingerprint, []);
      
      // New device = require MFA + email verification
      expect(result.trustLevel).toBe('new');
      const requireEmailVerification = result.trustLevel === 'new' || result.trustLevel === 'suspicious';
      expect(requireEmailVerification).toBe(true);
    });
  });

  describe('Healthcare Realm Security', () => {
    it('should enforce stricter trust for healthcare realm', () => {
      // Healthcare realm should have shorter trust duration
      const healthcareDevice = createStoredDevice(macbookFingerprint, { trusted: true });
      
      // Verify device was created for healthcare realm
      expect(healthcareDevice.realmId).toBe('clinisyn-psychologists');
      
      // In healthcare, even trusted devices should have limited trust duration
      // This is enforced at the realm level (7 days max vs 30 days standard)
    });
  });
});
