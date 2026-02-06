/**
 * Device Fingerprinting Service Unit Tests
 * 
 * Task 3.1: Device Fingerprinting Service
 * Tests fingerprint generation, fuzzy matching, and trust scoring
 */

import {
  generateFingerprintHash,
  normalizeFingerprint,
  calculateFingerprintSimilarity,
  matchDevice,
  createDeviceRecord,
  generateDeviceName,
  calculateTrustScore,
  getTrustLevel,
  isDeviceTrustExpired,
  updateDeviceOnLogin,
  FINGERPRINT_WEIGHTS,
  TRUST_THRESHOLDS,
  DeviceFingerprintInput,
  StoredDevice
} from './device.service';

describe('Device Fingerprinting Service', () => {
  const sampleFingerprint: DeviceFingerprintInput = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    screen: '1920x1080',
    timezone: 'Europe/Istanbul',
    language: 'tr-TR',
    platform: 'MacIntel'
  };

  const similarFingerprint: DeviceFingerprintInput = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36',
    screen: '1920x1080',
    timezone: 'Europe/Istanbul',
    language: 'tr-TR',
    platform: 'MacIntel'
  };

  const differentFingerprint: DeviceFingerprintInput = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    screen: '2560x1440',
    timezone: 'America/New_York',
    language: 'en-US',
    platform: 'Win32'
  };

  describe('generateFingerprintHash', () => {
    it('should generate consistent hash for same fingerprint', () => {
      const hash1 = generateFingerprintHash(sampleFingerprint);
      const hash2 = generateFingerprintHash(sampleFingerprint);
      
      expect(hash1).toBe(hash2);
    });

    it('should generate different hash for different fingerprint', () => {
      const hash1 = generateFingerprintHash(sampleFingerprint);
      const hash2 = generateFingerprintHash(differentFingerprint);
      
      expect(hash1).not.toBe(hash2);
    });

    it('should generate 64 character hex hash (SHA-256)', () => {
      const hash = generateFingerprintHash(sampleFingerprint);
      
      expect(hash).toHaveLength(64);
      expect(/^[a-f0-9]+$/.test(hash)).toBe(true);
    });

    it('should handle empty fingerprint', () => {
      const hash = generateFingerprintHash({});
      
      expect(hash).toHaveLength(64);
    });
  });

  describe('normalizeFingerprint', () => {
    it('should normalize user agent by removing version numbers', () => {
      const normalized = normalizeFingerprint(sampleFingerprint);
      
      expect(normalized.userAgent).not.toContain('120.0.0.0');
      expect(normalized.userAgent).toContain('x.x');
    });

    it('should lowercase and trim values', () => {
      const fingerprint: DeviceFingerprintInput = {
        screen: '  1920X1080  ',
        language: 'TR-TR, en-US',
        platform: '  MacIntel  '
      };
      
      const normalized = normalizeFingerprint(fingerprint);
      
      expect(normalized.screen).toBe('1920x1080');
      expect(normalized.language).toBe('tr-tr');
      expect(normalized.platform).toBe('macintel');
    });

    it('should extract primary language', () => {
      const fingerprint: DeviceFingerprintInput = {
        language: 'tr-TR, en-US, de-DE'
      };
      
      const normalized = normalizeFingerprint(fingerprint);
      
      expect(normalized.language).toBe('tr-tr');
    });
  });

  describe('calculateFingerprintSimilarity', () => {
    it('should return 100 for identical fingerprints', () => {
      const { totalScore } = calculateFingerprintSimilarity(
        sampleFingerprint,
        sampleFingerprint
      );
      
      expect(totalScore).toBe(100);
    });

    it('should return high score for similar fingerprints (version change)', () => {
      const { totalScore } = calculateFingerprintSimilarity(
        sampleFingerprint,
        similarFingerprint
      );
      
      // Should be very high since only browser version changed
      expect(totalScore).toBeGreaterThanOrEqual(95);
    });

    it('should return low score for different fingerprints', () => {
      const { totalScore } = calculateFingerprintSimilarity(
        sampleFingerprint,
        differentFingerprint
      );
      
      expect(totalScore).toBeLessThan(50);
    });

    it('should return component scores', () => {
      const { componentScores } = calculateFingerprintSimilarity(
        sampleFingerprint,
        sampleFingerprint
      );
      
      expect(componentScores.userAgent).toBe(100);
      expect(componentScores.screenResolution).toBe(100);
      expect(componentScores.timezone).toBe(100);
      expect(componentScores.language).toBe(100);
      expect(componentScores.platform).toBe(100);
    });

    it('should weight components correctly', () => {
      // Verify weights sum to 100
      const totalWeight = Object.values(FINGERPRINT_WEIGHTS).reduce((a, b) => a + b, 0);
      expect(totalWeight).toBe(100);
    });

    it('should handle partial fingerprints', () => {
      const partial: DeviceFingerprintInput = {
        userAgent: sampleFingerprint.userAgent
      };
      
      const { totalScore } = calculateFingerprintSimilarity(partial, sampleFingerprint);
      
      // Should get partial score (userAgent matches = 30%)
      expect(totalScore).toBeGreaterThan(0);
      expect(totalScore).toBeLessThan(100);
    });
  });

  describe('matchDevice', () => {
    const createStoredDevice = (fingerprint: DeviceFingerprintInput, trusted = false): StoredDevice => ({
      id: 'device-1',
      userId: 'user-1',
      realmId: 'realm-1',
      fingerprintHash: generateFingerprintHash(fingerprint),
      components: normalizeFingerprint(fingerprint),
      trusted,
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      loginCount: 5
    });

    it('should match same device with high score', () => {
      const storedDevices = [createStoredDevice(sampleFingerprint, true)];
      
      const result = matchDevice(sampleFingerprint, storedDevices);
      
      expect(result.matched).toBe(true);
      expect(result.similarityScore).toBe(100);
      expect(result.device).toBeDefined();
    });

    it('should match similar device (70% threshold)', () => {
      const storedDevices = [createStoredDevice(sampleFingerprint)];
      
      const result = matchDevice(similarFingerprint, storedDevices);
      
      expect(result.matched).toBe(true);
      expect(result.similarityScore).toBeGreaterThanOrEqual(70);
    });

    it('should not match different device', () => {
      const storedDevices = [createStoredDevice(sampleFingerprint)];
      
      const result = matchDevice(differentFingerprint, storedDevices);
      
      expect(result.matched).toBe(false);
      expect(result.similarityScore).toBeLessThan(70);
    });

    it('should return "new" trust level for no stored devices', () => {
      const result = matchDevice(sampleFingerprint, []);
      
      expect(result.matched).toBe(false);
      expect(result.trustLevel).toBe('new');
    });

    it('should return "trusted" for trusted device with high score', () => {
      const storedDevices = [createStoredDevice(sampleFingerprint, true)];
      
      const result = matchDevice(sampleFingerprint, storedDevices);
      
      expect(result.trustLevel).toBe('trusted');
    });

    it('should return "familiar" for known but untrusted device', () => {
      const storedDevices = [createStoredDevice(sampleFingerprint, false)];
      
      const result = matchDevice(sampleFingerprint, storedDevices);
      
      expect(result.trustLevel).toBe('familiar');
    });

    it('should find best match among multiple devices', () => {
      const storedDevices = [
        createStoredDevice(differentFingerprint),
        createStoredDevice(sampleFingerprint, true)
      ];
      
      const result = matchDevice(sampleFingerprint, storedDevices);
      
      expect(result.matched).toBe(true);
      expect(result.similarityScore).toBe(100);
    });
  });

  describe('createDeviceRecord', () => {
    it('should create device with all fields', () => {
      const device = createDeviceRecord(
        'user-123',
        'realm-456',
        sampleFingerprint,
        '192.168.1.1',
        'My MacBook'
      );
      
      expect(device.id).toBeDefined();
      expect(device.userId).toBe('user-123');
      expect(device.realmId).toBe('realm-456');
      expect(device.fingerprintHash).toHaveLength(64);
      expect(device.name).toBe('My MacBook');
      expect(device.trusted).toBe(false);
      expect(device.lastIpAddress).toBe('192.168.1.1');
      expect(device.loginCount).toBe(1);
    });

    it('should auto-generate device name if not provided', () => {
      const device = createDeviceRecord('user-123', 'realm-456', sampleFingerprint);
      
      expect(device.name).toContain('Chrome');
      expect(device.name).toContain('macOS');
    });
  });

  describe('generateDeviceName', () => {
    it('should detect Chrome on macOS', () => {
      const name = generateDeviceName({
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
        platform: 'MacIntel'
      });
      
      expect(name).toBe('Chrome on macOS');
    });

    it('should detect Firefox on Windows', () => {
      const name = generateDeviceName({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Firefox/121.0',
        platform: 'Win32'
      });
      
      expect(name).toBe('Firefox on Windows');
    });

    it('should detect Safari on iOS', () => {
      const name = generateDeviceName({
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1',
        platform: 'iPhone'
      });
      
      expect(name).toBe('Safari on iOS');
    });

    it('should detect Edge on Windows', () => {
      const name = generateDeviceName({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/120.0.0.0',
        platform: 'Win32'
      });
      
      expect(name).toBe('Edge on Windows');
    });

    it('should handle unknown browser/OS', () => {
      const name = generateDeviceName({});
      
      expect(name).toBe('Unknown Browser on Unknown OS');
    });
  });

  describe('calculateTrustScore', () => {
    it('should calculate score with all components', () => {
      const score = calculateTrustScore({
        fingerprintSimilarity: 100,
        ipProximity: 100,
        userAgentConsistency: 100,
        loginTimePattern: 100
      });
      
      expect(score).toBe(100);
    });

    it('should calculate score with only fingerprint', () => {
      const score = calculateTrustScore({
        fingerprintSimilarity: 80
      });
      
      expect(score).toBe(80);
    });

    it('should weight components correctly', () => {
      // Only fingerprint (50% weight) at 100%
      const score = calculateTrustScore({
        fingerprintSimilarity: 100,
        ipProximity: 0,
        userAgentConsistency: 0,
        loginTimePattern: 0
      });
      
      expect(score).toBe(50);
    });

    it('should return 0-100 range', () => {
      const lowScore = calculateTrustScore({ fingerprintSimilarity: 0 });
      const highScore = calculateTrustScore({ fingerprintSimilarity: 100 });
      
      expect(lowScore).toBeGreaterThanOrEqual(0);
      expect(highScore).toBeLessThanOrEqual(100);
    });
  });

  describe('getTrustLevel', () => {
    it('should return "trusted" for score >= 80', () => {
      expect(getTrustLevel(80)).toBe('trusted');
      expect(getTrustLevel(100)).toBe('trusted');
    });

    it('should return "familiar" for score 50-79', () => {
      expect(getTrustLevel(50)).toBe('familiar');
      expect(getTrustLevel(79)).toBe('familiar');
    });

    it('should return "suspicious" for score < 50', () => {
      expect(getTrustLevel(0)).toBe('suspicious');
      expect(getTrustLevel(49)).toBe('suspicious');
    });

    it('should use correct thresholds', () => {
      expect(TRUST_THRESHOLDS.TRUSTED).toBe(80);
      expect(TRUST_THRESHOLDS.FAMILIAR).toBe(50);
      expect(TRUST_THRESHOLDS.SUSPICIOUS).toBe(0);
    });
  });

  describe('isDeviceTrustExpired', () => {
    it('should return true for untrusted device', () => {
      const device: StoredDevice = {
        id: 'device-1',
        userId: 'user-1',
        realmId: 'realm-1',
        fingerprintHash: 'hash',
        components: {},
        trusted: false,
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        loginCount: 1
      };
      
      expect(isDeviceTrustExpired(device)).toBe(true);
    });

    it('should return true for expired trust', () => {
      const device: StoredDevice = {
        id: 'device-1',
        userId: 'user-1',
        realmId: 'realm-1',
        fingerprintHash: 'hash',
        components: {},
        trusted: true,
        trustExpiresAt: new Date(Date.now() - 1000).toISOString(), // 1 second ago
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        loginCount: 1
      };
      
      expect(isDeviceTrustExpired(device)).toBe(true);
    });

    it('should return false for valid trust', () => {
      const device: StoredDevice = {
        id: 'device-1',
        userId: 'user-1',
        realmId: 'realm-1',
        fingerprintHash: 'hash',
        components: {},
        trusted: true,
        trustExpiresAt: new Date(Date.now() + 86400000).toISOString(), // 1 day from now
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        loginCount: 1
      };
      
      expect(isDeviceTrustExpired(device)).toBe(false);
    });
  });

  describe('updateDeviceOnLogin', () => {
    it('should update lastSeenAt and increment loginCount', () => {
      const device: StoredDevice = {
        id: 'device-1',
        userId: 'user-1',
        realmId: 'realm-1',
        fingerprintHash: 'hash',
        components: {},
        trusted: false,
        firstSeenAt: '2026-01-01T00:00:00.000Z',
        lastSeenAt: '2026-01-01T00:00:00.000Z',
        loginCount: 5
      };
      
      const updated = updateDeviceOnLogin(device, '10.0.0.1');
      
      expect(updated.loginCount).toBe(6);
      expect(updated.lastIpAddress).toBe('10.0.0.1');
      expect(new Date(updated.lastSeenAt).getTime()).toBeGreaterThan(
        new Date(device.lastSeenAt).getTime()
      );
    });

    it('should preserve other fields', () => {
      const device: StoredDevice = {
        id: 'device-1',
        userId: 'user-1',
        realmId: 'realm-1',
        fingerprintHash: 'hash',
        components: { userAgent: 'test' },
        name: 'My Device',
        trusted: true,
        trustExpiresAt: '2026-02-01T00:00:00.000Z',
        firstSeenAt: '2026-01-01T00:00:00.000Z',
        lastSeenAt: '2026-01-01T00:00:00.000Z',
        loginCount: 5
      };
      
      const updated = updateDeviceOnLogin(device);
      
      expect(updated.id).toBe(device.id);
      expect(updated.name).toBe(device.name);
      expect(updated.trusted).toBe(device.trusted);
      expect(updated.firstSeenAt).toBe(device.firstSeenAt);
    });
  });
});
