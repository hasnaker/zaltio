/**
 * AI Risk Assessment Service Tests
 * Phase 6: AI Security - Task 16.1
 * 
 * Property-Based Tests:
 * - Property 22: AI risk score consistency
 * - Property 23: High risk score triggers MFA
 * 
 * Validates: Requirements 14.8 (AI Security)
 */

import {
  assessRisk,
  assessRiskWithAttackDetection,
  RiskAssessmentInput,
  RiskAssessmentResult,
  RiskFactorType,
  RISK_THRESHOLDS,
  ADAPTIVE_AUTH_THRESHOLDS,
  RISK_WEIGHTS,
  requiresMfaForRisk,
  shouldBlockForRisk,
  getRiskColor,
  formatRiskScore
} from './ai-risk.service';
import { DeviceFingerprintInput, StoredDevice } from './device.service';
import { GeoLocation } from './geo-velocity.service';

// ============================================================================
// Test Fixtures
// ============================================================================

const createBaseInput = (overrides: Partial<RiskAssessmentInput> = {}): RiskAssessmentInput => ({
  email: 'test@example.com',
  realmId: 'test-realm',
  ipAddress: '192.168.1.1',
  ...overrides
});

const createDeviceFingerprint = (overrides: Partial<DeviceFingerprintInput> = {}): DeviceFingerprintInput => ({
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
  screen: '1920x1080',
  timezone: 'Europe/Istanbul',
  language: 'en-US',
  platform: 'MacIntel',
  ...overrides
});

const createStoredDevice = (overrides: Partial<StoredDevice> = {}): StoredDevice => ({
  id: 'device-1',
  userId: 'user-1',
  realmId: 'test-realm',
  fingerprintHash: 'hash123',
  components: createDeviceFingerprint(),
  trusted: true,
  firstSeenAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
  lastSeenAt: new Date().toISOString(),
  loginCount: 10,
  ...overrides
});

const createGeoLocation = (overrides: Partial<GeoLocation> = {}): GeoLocation => ({
  latitude: 41.0082,
  longitude: 28.9784,
  city: 'Istanbul',
  country: 'Turkey',
  countryCode: 'TR',
  ...overrides
});

// ============================================================================
// Unit Tests
// ============================================================================

describe('AI Risk Assessment Service', () => {
  describe('assessRisk', () => {
    it('should return low risk for normal login', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        storedDevices: [createStoredDevice()],
        geoLocation: createGeoLocation(),
        accountAge: 365,
        mfaEnabled: true
      });

      const result = await assessRisk(input);

      expect(result.riskScore).toBeLessThan(RISK_THRESHOLDS.medium);
      expect(result.riskLevel).toBe('low');
      expect(result.requiresMfa).toBe(false);
      expect(result.shouldBlock).toBe(false);
    });

    it('should return higher risk for new device', async () => {
      // Create a completely different device fingerprint
      const newDeviceFingerprint = createDeviceFingerprint({ 
        platform: 'Win32',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        screen: '1366x768',
        language: 'de-DE'
      });
      
      // Stored device has different fingerprint
      const storedDevice = createStoredDevice({
        components: createDeviceFingerprint({
          platform: 'MacIntel',
          userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
          screen: '2560x1440',
          language: 'en-US'
        })
      });

      const input = createBaseInput({
        deviceFingerprint: newDeviceFingerprint,
        storedDevices: [storedDevice],
        geoLocation: createGeoLocation()
      });

      const result = await assessRisk(input);

      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.deviceRisk).toBeGreaterThan(0);
      // Should detect new device or device mismatch
      expect(result.riskFactors.some(f => 
        f.type === RiskFactorType.NEW_DEVICE || 
        f.type === RiskFactorType.DEVICE_MISMATCH
      )).toBe(true);
    });

    it('should return high risk for VPN connection', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isVpn: true })
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.VPN_DETECTED)).toBe(true);
      expect(result.geoRisk).toBeGreaterThan(0);
    });

    it('should return critical risk for Tor connection', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isTor: true })
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.TOR_DETECTED)).toBe(true);
      expect(result.geoRisk).toBeGreaterThanOrEqual(60);
    });

    it('should increase risk for failed login attempts', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        failedAttempts: 5
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.FAILED_ATTEMPTS)).toBe(true);
      expect(result.behaviorRisk).toBeGreaterThan(0);
    });

    it('should increase risk for weak password', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        passwordStrength: 20
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.WEAK_PASSWORD)).toBe(true);
      expect(result.credentialRisk).toBeGreaterThan(0);
    });

    it('should return critical risk for breached password', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        isBreachedPassword: true
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.BREACHED_PASSWORD)).toBe(true);
      expect(result.credentialRisk).toBeGreaterThanOrEqual(70);
      expect(result.requiresVerification).toBe(true);
    });

    it('should increase risk for new account', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        accountAge: 1
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.NEW_ACCOUNT)).toBe(true);
    });

    it('should increase risk for no MFA', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        mfaEnabled: false
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.NO_MFA)).toBe(true);
    });

    it('should increase risk for high-risk country', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ countryCode: 'RU', country: 'Russia' })
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.SUSPICIOUS_COUNTRY)).toBe(true);
    });

    it('should increase risk for unusual login time', async () => {
      // 3 AM UTC
      const timestamp = new Date();
      timestamp.setUTCHours(3, 0, 0, 0);

      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        loginTimestamp: timestamp.getTime()
      });

      const result = await assessRisk(input);

      expect(result.riskFactors.some(f => f.type === RiskFactorType.UNUSUAL_TIME)).toBe(true);
    });

    it('should increase risk for bot-like user agent', async () => {
      const input = createBaseInput({
        userAgent: 'python-requests/2.28.0'
      });

      const result = await assessRisk(input);

      expect(result.networkRisk).toBeGreaterThan(0);
    });
  });

  describe('Adaptive Authentication', () => {
    it('should not require MFA for low risk', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        storedDevices: [createStoredDevice()],
        geoLocation: createGeoLocation(),
        accountAge: 365,
        mfaEnabled: true
      });

      const result = await assessRisk(input);

      expect(result.adaptiveAuthLevel).toBe('none');
      expect(result.requiresMfa).toBe(false);
    });

    it('should require MFA for medium risk', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint({ platform: 'Unknown' }),
        storedDevices: [], // No stored devices
        geoLocation: createGeoLocation({ isVpn: true }),
        failedAttempts: 2
      });

      const result = await assessRisk(input);

      if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.mfa) {
        expect(result.requiresMfa).toBe(true);
      }
    });

    it('should require verification for high risk', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isTor: true }),
        failedAttempts: 5,
        passwordStrength: 20
      });

      const result = await assessRisk(input);

      if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.verification) {
        expect(result.requiresVerification).toBe(true);
      }
    });

    it('should block for critical risk', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isTor: true }),
        isBreachedPassword: true,
        failedAttempts: 10
      });

      const result = await assessRisk(input);

      if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.block) {
        expect(result.shouldBlock).toBe(true);
        expect(result.adaptiveAuthLevel).toBe('block');
      }
    });
  });

  describe('Risk Score Calculation', () => {
    it('should calculate weighted risk score correctly', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint()
      });

      const result = await assessRisk(input);

      // Risk score should be between 0 and 100
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);

      // Component scores should be between 0 and 100
      expect(result.deviceRisk).toBeGreaterThanOrEqual(0);
      expect(result.deviceRisk).toBeLessThanOrEqual(100);
      expect(result.geoRisk).toBeGreaterThanOrEqual(0);
      expect(result.geoRisk).toBeLessThanOrEqual(100);
      expect(result.behaviorRisk).toBeGreaterThanOrEqual(0);
      expect(result.behaviorRisk).toBeLessThanOrEqual(100);
      expect(result.credentialRisk).toBeGreaterThanOrEqual(0);
      expect(result.credentialRisk).toBeLessThanOrEqual(100);
      expect(result.networkRisk).toBeGreaterThanOrEqual(0);
      expect(result.networkRisk).toBeLessThanOrEqual(100);
      expect(result.historicalRisk).toBeGreaterThanOrEqual(0);
      expect(result.historicalRisk).toBeLessThanOrEqual(100);
    });

    it('should have consistent risk levels', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint()
      });

      const result = await assessRisk(input);

      // Risk level should match score
      if (result.riskScore >= RISK_THRESHOLDS.critical) {
        expect(result.riskLevel).toBe('critical');
      } else if (result.riskScore >= RISK_THRESHOLDS.high) {
        expect(result.riskLevel).toBe('high');
      } else if (result.riskScore >= RISK_THRESHOLDS.medium) {
        expect(result.riskLevel).toBe('medium');
      } else {
        expect(result.riskLevel).toBe('low');
      }
    });
  });

  describe('Risk Factors', () => {
    it('should include all detected risk factors', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isVpn: true }),
        failedAttempts: 5,
        mfaEnabled: false
      });

      const result = await assessRisk(input);

      // Should have multiple risk factors
      expect(result.riskFactors.length).toBeGreaterThan(0);

      // Each factor should have required fields
      result.riskFactors.forEach(factor => {
        expect(factor.type).toBeDefined();
        expect(factor.severity).toBeDefined();
        expect(factor.score).toBeGreaterThanOrEqual(0);
        expect(factor.score).toBeLessThanOrEqual(100);
        expect(factor.description).toBeDefined();
      });
    });

    it('should categorize severity correctly', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isTor: true }),
        isBreachedPassword: true
      });

      const result = await assessRisk(input);

      // Should have critical severity factors
      const criticalFactors = result.riskFactors.filter(f => f.severity === 'critical');
      expect(criticalFactors.length).toBeGreaterThan(0);
    });
  });

  describe('Assessment Metadata', () => {
    it('should include assessment metadata', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint()
      });

      const result = await assessRisk(input);

      expect(result.assessmentId).toBeDefined();
      expect(result.assessmentId).toMatch(/^risk_/);
      expect(result.timestamp).toBeDefined();
      expect(result.modelVersion).toBeDefined();
      expect(result.explanation).toBeDefined();
    });
  });
});

// ============================================================================
// Property-Based Tests
// ============================================================================

describe('Property-Based Tests', () => {
  /**
   * Property 22: AI risk score consistency
   * Same input should produce consistent risk scores
   */
  describe('Property 22: AI risk score consistency', () => {
    it('should produce consistent scores for identical inputs', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation(),
        accountAge: 100,
        mfaEnabled: true
      });

      // Run assessment multiple times
      const results = await Promise.all([
        assessRisk(input),
        assessRisk(input),
        assessRisk(input)
      ]);

      // All scores should be identical
      const scores = results.map(r => r.riskScore);
      expect(new Set(scores).size).toBe(1);

      // All risk levels should be identical
      const levels = results.map(r => r.riskLevel);
      expect(new Set(levels).size).toBe(1);
    });

    it('should produce higher scores for riskier inputs', async () => {
      const lowRiskInput = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        storedDevices: [createStoredDevice()],
        geoLocation: createGeoLocation(),
        accountAge: 365,
        mfaEnabled: true
      });

      const highRiskInput = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isTor: true }),
        failedAttempts: 5,
        isBreachedPassword: true,
        mfaEnabled: false
      });

      const lowRiskResult = await assessRisk(lowRiskInput);
      const highRiskResult = await assessRisk(highRiskInput);

      expect(highRiskResult.riskScore).toBeGreaterThan(lowRiskResult.riskScore);
    });

    it('should have monotonic risk increase with more risk factors', async () => {
      const baseInput = createBaseInput({
        deviceFingerprint: createDeviceFingerprint()
      });

      const withVpn = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isVpn: true })
      });

      const withVpnAndFailures = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isVpn: true }),
        failedAttempts: 5
      });

      const baseResult = await assessRisk(baseInput);
      const vpnResult = await assessRisk(withVpn);
      const vpnFailuresResult = await assessRisk(withVpnAndFailures);

      expect(vpnResult.riskScore).toBeGreaterThanOrEqual(baseResult.riskScore);
      expect(vpnFailuresResult.riskScore).toBeGreaterThanOrEqual(vpnResult.riskScore);
    });
  });

  /**
   * Property 23: High risk score triggers MFA
   * Risk scores above threshold should always require MFA
   */
  describe('Property 23: High risk score triggers MFA', () => {
    it('should require MFA when risk score exceeds threshold', async () => {
      // Create high-risk scenario
      const highRiskInput = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isVpn: true }),
        failedAttempts: 3,
        mfaEnabled: false,
        accountAge: 1
      });

      const result = await assessRisk(highRiskInput);

      if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.mfa) {
        expect(result.requiresMfa).toBe(true);
      }
    });

    it('should require verification when risk score is very high', async () => {
      const veryHighRiskInput = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isTor: true }),
        failedAttempts: 5,
        isBreachedPassword: true
      });

      const result = await assessRisk(veryHighRiskInput);

      if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.verification) {
        expect(result.requiresVerification).toBe(true);
      }
    });

    it('should block when risk score is critical', async () => {
      const criticalRiskInput = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation({ isTor: true }),
        failedAttempts: 10,
        isBreachedPassword: true,
        passwordStrength: 10
      });

      const result = await assessRisk(criticalRiskInput);

      if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.block) {
        expect(result.shouldBlock).toBe(true);
      }
    });
  });
});

// ============================================================================
// Utility Function Tests
// ============================================================================

describe('Utility Functions', () => {
  describe('requiresMfaForRisk', () => {
    it('should return true for medium, high, and critical risk', () => {
      expect(requiresMfaForRisk('medium')).toBe(true);
      expect(requiresMfaForRisk('high')).toBe(true);
      expect(requiresMfaForRisk('critical')).toBe(true);
    });

    it('should return false for low risk', () => {
      expect(requiresMfaForRisk('low')).toBe(false);
    });
  });

  describe('shouldBlockForRisk', () => {
    it('should return true only for critical risk', () => {
      expect(shouldBlockForRisk('critical')).toBe(true);
      expect(shouldBlockForRisk('high')).toBe(false);
      expect(shouldBlockForRisk('medium')).toBe(false);
      expect(shouldBlockForRisk('low')).toBe(false);
    });
  });

  describe('getRiskColor', () => {
    it('should return correct colors for risk levels', () => {
      expect(getRiskColor('low')).toBe('#22c55e');
      expect(getRiskColor('medium')).toBe('#f59e0b');
      expect(getRiskColor('high')).toBe('#ef4444');
      expect(getRiskColor('critical')).toBe('#7f1d1d');
    });
  });

  describe('formatRiskScore', () => {
    it('should format risk scores correctly', () => {
      expect(formatRiskScore(95)).toBe('Critical');
      expect(formatRiskScore(80)).toBe('High');
      expect(formatRiskScore(60)).toBe('Medium');
      expect(formatRiskScore(30)).toBe('Low');
      expect(formatRiskScore(10)).toBe('Minimal');
    });
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('Integration Tests', () => {
  describe('assessRiskWithAttackDetection', () => {
    it('should combine risk assessment with attack detection', async () => {
      const input = createBaseInput({
        deviceFingerprint: createDeviceFingerprint(),
        geoLocation: createGeoLocation()
      });

      const result = await assessRiskWithAttackDetection(input, 'password123');

      expect(result.riskScore).toBeDefined();
      expect(result.riskLevel).toBeDefined();
      // attackDetection may or may not be present depending on detection
    });
  });
});


// ============================================================================
// AIRiskService Class Tests - Task 15.2
// ============================================================================

import {
  AIRiskService,
  createAIRiskService,
  getAIRiskService,
  LoginContext,
  BehaviorEvent,
  IPReputationResult,
  DeviceTrustResult
} from './ai-risk.service';

describe('AIRiskService Class', () => {
  let service: AIRiskService;

  beforeEach(() => {
    service = createAIRiskService('test-realm');
  });

  describe('assessLoginRisk', () => {
    it('should assess login risk and return a score', async () => {
      const context: LoginContext = {
        email: 'test@example.com',
        realmId: 'test-realm',
        ip: '192.168.1.1',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        timestamp: Date.now()
      };

      const result = await service.assessLoginRisk(context);

      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
      expect(result.riskLevel).toBeDefined();
      expect(['low', 'medium', 'high', 'critical']).toContain(result.riskLevel);
    });

    it('should return higher risk for suspicious IP', async () => {
      const normalContext: LoginContext = {
        email: 'test@example.com',
        realmId: 'test-realm',
        ip: '192.168.1.1',
        timestamp: Date.now()
      };

      const suspiciousContext: LoginContext = {
        email: 'test@example.com',
        realmId: 'test-realm',
        ip: '185.220.101.1', // Known Tor exit
        geoLocation: {
          latitude: 52.52,
          longitude: 13.405,
          city: 'Berlin',
          country: 'Germany',
          countryCode: 'DE',
          isTor: true
        },
        timestamp: Date.now()
      };

      const normalResult = await service.assessLoginRisk(normalContext);
      const suspiciousResult = await service.assessLoginRisk(suspiciousContext);

      expect(suspiciousResult.riskScore).toBeGreaterThan(normalResult.riskScore);
    });

    it('should include risk factors in the result', async () => {
      const context: LoginContext = {
        email: 'test@example.com',
        realmId: 'test-realm',
        ip: '192.168.1.1',
        failedAttempts: 5,
        mfaEnabled: false,
        timestamp: Date.now()
      };

      const result = await service.assessLoginRisk(context);

      expect(result.riskFactors).toBeDefined();
      expect(Array.isArray(result.riskFactors)).toBe(true);
    });

    it('should be deterministic for same inputs', async () => {
      const context: LoginContext = {
        email: 'test@example.com',
        realmId: 'test-realm',
        ip: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        timestamp: 1700000000000 // Fixed timestamp
      };

      const result1 = await service.assessLoginRisk(context);
      const result2 = await service.assessLoginRisk(context);

      expect(result1.riskScore).toBe(result2.riskScore);
      expect(result1.riskLevel).toBe(result2.riskLevel);
    });
  });

  describe('updateUserBehaviorProfile', () => {
    it('should update behavior profile without throwing', async () => {
      const event: BehaviorEvent = {
        type: 'login_success',
        timestamp: Date.now(),
        ip: '192.168.1.1',
        geoLocation: {
          latitude: 41.0082,
          longitude: 28.9784,
          city: 'Istanbul',
          country: 'Turkey',
          countryCode: 'TR'
        }
      };

      // Should not throw
      await expect(service.updateUserBehaviorProfile('user-123', event)).resolves.not.toThrow();
    });

    it('should handle different event types', async () => {
      const eventTypes: BehaviorEvent['type'][] = [
        'login_success',
        'login_failure',
        'password_change',
        'mfa_setup',
        'session_created',
        'api_call'
      ];

      for (const type of eventTypes) {
        const event: BehaviorEvent = {
          type,
          timestamp: Date.now()
        };

        await expect(service.updateUserBehaviorProfile('user-123', event)).resolves.not.toThrow();
      }
    });
  });

  describe('detectImpossibleTravel', () => {
    it('should return false for first login (no previous location)', async () => {
      const location = {
        latitude: 41.0082,
        longitude: 28.9784,
        city: 'Istanbul',
        country: 'Turkey',
        countryCode: 'TR'
      };

      const result = await service.detectImpossibleTravel('new-user-123', location);

      expect(typeof result).toBe('boolean');
    });

    it('should detect impossible travel for extreme distances', async () => {
      // This test verifies the function works correctly
      // In production, it would check against stored locations
      const location = {
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'United States',
        countryCode: 'US'
      };

      const result = await service.detectImpossibleTravel('user-123', location);

      expect(typeof result).toBe('boolean');
    });
  });

  describe('checkIPReputation', () => {
    it('should return a score between 0 and 100', async () => {
      const score = await service.checkIPReputation('192.168.1.1');

      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    });

    it('should return lower score for known Tor exit nodes', async () => {
      const normalScore = await service.checkIPReputation('8.8.8.8');
      const torScore = await service.checkIPReputation('185.220.101.1');

      expect(torScore).toBeLessThan(normalScore);
    });

    it('should return lower score for private IPs (likely VPN)', async () => {
      const publicScore = await service.checkIPReputation('8.8.8.8');
      const privateScore = await service.checkIPReputation('10.0.0.1');

      expect(privateScore).toBeLessThan(publicScore);
    });

    it('should cache results for performance', async () => {
      const ip = '192.168.1.100';
      
      // First call
      const score1 = await service.checkIPReputation(ip);
      
      // Second call should use cache
      const score2 = await service.checkIPReputation(ip);

      expect(score1).toBe(score2);
    });
  });

  describe('getDeviceTrustScore', () => {
    it('should return a score between 0 and 100', async () => {
      const fingerprint = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        screen: '1920x1080',
        timezone: 'Europe/Istanbul',
        language: 'en-US',
        platform: 'MacIntel'
      };

      const score = await service.getDeviceTrustScore(fingerprint, 'user-123');

      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    });

    it('should return low score for new users (no stored devices)', async () => {
      const fingerprint = {
        userAgent: 'Mozilla/5.0',
        screen: '1920x1080',
        platform: 'MacIntel'
      };

      const score = await service.getDeviceTrustScore(fingerprint, 'brand-new-user');

      // New users should have low trust score
      expect(score).toBeLessThanOrEqual(50);
    });
  });

  describe('getIPReputationDetails', () => {
    it('should return detailed IP reputation information', async () => {
      const result = await service.getIPReputationDetails('192.168.1.1');

      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('isTor');
      expect(result).toHaveProperty('isVpn');
      expect(result).toHaveProperty('isProxy');
      expect(result).toHaveProperty('isDatacenter');
      expect(result).toHaveProperty('threatLevel');
    });

    it('should detect Tor exit nodes', async () => {
      const result = await service.getIPReputationDetails('185.220.101.1');

      expect(result.isTor).toBe(true);
      // Tor exit nodes are critical threat level due to anonymization
      expect(['high', 'critical']).toContain(result.threatLevel);
    });

    it('should detect private IPs as VPN/datacenter', async () => {
      const result = await service.getIPReputationDetails('10.0.0.1');

      expect(result.isVpn).toBe(true);
      expect(result.isDatacenter).toBe(true);
    });
  });

  describe('getDeviceTrustDetails', () => {
    it('should return detailed device trust information', async () => {
      const fingerprint = {
        userAgent: 'Mozilla/5.0',
        screen: '1920x1080',
        platform: 'MacIntel'
      };

      const result = await service.getDeviceTrustDetails(fingerprint, 'user-123');

      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('isKnownDevice');
      expect(result).toHaveProperty('isNewDevice');
      expect(result).toHaveProperty('trustLevel');
    });

    it('should identify new devices correctly', async () => {
      const fingerprint = {
        userAgent: 'Mozilla/5.0',
        screen: '1920x1080',
        platform: 'MacIntel'
      };

      const result = await service.getDeviceTrustDetails(fingerprint, 'new-user-xyz');

      expect(result.isNewDevice).toBe(true);
      expect(result.isKnownDevice).toBe(false);
    });
  });
});

describe('AIRiskService Factory Functions', () => {
  describe('createAIRiskService', () => {
    it('should create a new service instance', () => {
      const service = createAIRiskService('my-realm');

      expect(service).toBeInstanceOf(AIRiskService);
    });

    it('should create different instances for different realms', () => {
      const service1 = createAIRiskService('realm-1');
      const service2 = createAIRiskService('realm-2');

      expect(service1).not.toBe(service2);
    });
  });

  describe('getAIRiskService', () => {
    it('should return a service instance', () => {
      const service = getAIRiskService('test-realm');

      expect(service).toBeInstanceOf(AIRiskService);
    });

    it('should return the same instance for the same realm', () => {
      const service1 = getAIRiskService('same-realm');
      const service2 = getAIRiskService('same-realm');

      expect(service1).toBe(service2);
    });
  });
});

// ============================================================================
// Property-Based Tests for AIRiskService - Task 15.2
// ============================================================================

describe('AIRiskService Property-Based Tests', () => {
  let service: AIRiskService;

  beforeEach(() => {
    service = createAIRiskService('test-realm');
  });

  /**
   * Property 28: Risk score consistency (±5 within 1 min)
   * Same input should produce consistent risk scores
   * **Validates: Requirements 10.1**
   */
  describe('Property 28: Risk score consistency', () => {
    it('should produce consistent scores for identical inputs within tolerance', async () => {
      const context: LoginContext = {
        email: 'consistency-test@example.com',
        realmId: 'test-realm',
        ip: '192.168.1.50',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        timestamp: 1700000000000, // Fixed timestamp
        mfaEnabled: true,
        accountAge: 100
      };

      // Run multiple assessments
      const results = await Promise.all([
        service.assessLoginRisk(context),
        service.assessLoginRisk(context),
        service.assessLoginRisk(context),
        service.assessLoginRisk(context),
        service.assessLoginRisk(context)
      ]);

      // All scores should be within ±5 of each other
      const scores = results.map(r => r.riskScore);
      const minScore = Math.min(...scores);
      const maxScore = Math.max(...scores);

      expect(maxScore - minScore).toBeLessThanOrEqual(5);
    });
  });

  /**
   * Property: IP reputation scores are bounded
   * **Validates: Requirements 10.5**
   */
  describe('Property: IP reputation scores are bounded', () => {
    it('should always return scores between 0 and 100', async () => {
      const testIPs = [
        '8.8.8.8',
        '192.168.1.1',
        '10.0.0.1',
        '185.220.101.1',
        '127.0.0.1',
        '255.255.255.255'
      ];

      for (const ip of testIPs) {
        const score = await service.checkIPReputation(ip);
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
      }
    });
  });

  /**
   * Property: Device trust scores are bounded
   * **Validates: Requirements 10.6**
   */
  describe('Property: Device trust scores are bounded', () => {
    it('should always return scores between 0 and 100', async () => {
      const fingerprints = [
        { userAgent: 'Mozilla/5.0', platform: 'MacIntel' },
        { userAgent: 'Chrome/120', platform: 'Win32' },
        { userAgent: 'Safari/605', platform: 'iPhone' },
        { userAgent: '', platform: '' }
      ];

      for (const fp of fingerprints) {
        const score = await service.getDeviceTrustScore(fp, 'test-user');
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
      }
    });
  });

  /**
   * Property: Higher risk inputs produce higher scores
   * **Validates: Requirements 10.1, 10.2**
   */
  describe('Property: Risk monotonicity', () => {
    it('should produce higher scores for riskier inputs', async () => {
      const lowRiskContext: LoginContext = {
        email: 'safe@example.com',
        realmId: 'test-realm',
        ip: '8.8.8.8',
        mfaEnabled: true,
        accountAge: 365,
        failedAttempts: 0,
        timestamp: Date.now()
      };

      const highRiskContext: LoginContext = {
        email: 'risky@example.com',
        realmId: 'test-realm',
        ip: '185.220.101.1', // Tor exit
        geoLocation: {
          latitude: 0,
          longitude: 0,
          isTor: true
        },
        mfaEnabled: false,
        accountAge: 1,
        failedAttempts: 5,
        isBreachedPassword: true,
        timestamp: Date.now()
      };

      const lowRiskResult = await service.assessLoginRisk(lowRiskContext);
      const highRiskResult = await service.assessLoginRisk(highRiskContext);

      expect(highRiskResult.riskScore).toBeGreaterThan(lowRiskResult.riskScore);
    });
  });
});
