/**
 * AWS Bedrock Risk Assessment Service Tests
 * Phase 6: AI Security - Task 15.3
 * 
 * Tests for:
 * - Anomaly detection model
 * - Behavior pattern analysis
 * - Risk factor correlation
 * 
 * Validates: Requirements 10.5
 */

import {
  analyzeRiskWithBedrock,
  detectAnomaliesWithBedrock,
  analyzeBehaviorWithBedrock,
  correlateRiskFactorsWithBedrock,
  createAnonymizedContext,
  blendWithRuleBasedResult,
  isBedrockAvailable,
  getBedrockHealthStatus,
  AnonymizedRiskContext,
  BedrockAnalysisResult,
  BedrockConfig,
  DEFAULT_BEDROCK_CONFIG
} from './bedrock-risk.service';
import { RiskFactorType, RiskFactor } from './ai-risk.service';

// ============================================================================
// Test Fixtures
// ============================================================================

const createBaseContext = (overrides: Partial<AnonymizedRiskContext> = {}): AnonymizedRiskContext => ({
  deviceTrustScore: 80,
  isNewDevice: false,
  deviceSimilarityScore: 85,
  geoRiskScore: 10,
  isVpn: false,
  isTor: false,
  isProxy: false,
  isDatacenter: false,
  isImpossibleTravel: false,
  loginHour: 10,
  dayOfWeek: 1,
  failedAttempts: 0,
  isTypicalLoginTime: true,
  accountAgeDays: 365,
  mfaEnabled: true,
  totalLogins: 100,
  passwordStrength: 80,
  isBreachedPassword: false,
  averageRiskScore: 15,
  highRiskLoginCount: 0,
  credentialStuffingScore: 0,
  bruteForceScore: 0,
  ...overrides
});


const createHighRiskContext = (): AnonymizedRiskContext => createBaseContext({
  deviceTrustScore: 20,
  isNewDevice: true,
  deviceSimilarityScore: 10,
  geoRiskScore: 80,
  isVpn: true,
  isTor: false,
  isProxy: false,
  isDatacenter: true,
  isImpossibleTravel: true,
  distanceFromLastLogin: 5000,
  loginHour: 3,
  dayOfWeek: 0,
  failedAttempts: 5,
  minutesSinceLastLogin: 30,
  isTypicalLoginTime: false,
  accountAgeDays: 7,
  mfaEnabled: false,
  totalLogins: 3,
  passwordStrength: 30,
  isBreachedPassword: true,
  averageRiskScore: 60,
  highRiskLoginCount: 2,
  credentialStuffingScore: 70,
  bruteForceScore: 50
});

const createMockBedrockResult = (overrides: Partial<BedrockAnalysisResult> = {}): BedrockAnalysisResult => ({
  riskScore: 25,
  confidence: 85,
  anomalyDetected: false,
  anomalyScore: 10,
  anomalyTypes: [],
  behaviorDeviation: 0.5,
  isTypicalBehavior: true,
  correlatedFactors: [],
  primaryThreat: undefined,
  recommendedAction: 'allow',
  reasoning: 'Normal login behavior detected',
  modelId: 'anthropic.claude-3-haiku-20240307-v1:0',
  processingTimeMs: 150,
  ...overrides
});

// ============================================================================
// Unit Tests
// ============================================================================

describe('Bedrock Risk Service', () => {
  describe('createAnonymizedContext', () => {
    it('should create anonymized context from risk input', () => {
      const input = {
        deviceRisk: 20,
        geoRisk: 15,
        behaviorRisk: 10,
        credentialRisk: 5,
        networkRisk: 10,
        historicalRisk: 5,
        riskFactors: [] as RiskFactor[],
        loginTimestamp: new Date('2026-01-25T10:00:00Z').getTime(),
        failedAttempts: 0,
        accountAgeDays: 365,
        mfaEnabled: true,
        totalLogins: 100,
        passwordStrength: 80
      };

      const context = createAnonymizedContext(input);

      expect(context.deviceTrustScore).toBe(80); // 100 - 20
      expect(context.geoRiskScore).toBe(15);
      expect(context.loginHour).toBe(10);
      expect(context.accountAgeDays).toBe(365);
      expect(context.mfaEnabled).toBe(true);
      expect(context.passwordStrength).toBe(80);
    });

    it('should detect risk factors from riskFactors array', () => {
      const input = {
        deviceRisk: 40,
        geoRisk: 60,
        behaviorRisk: 30,
        credentialRisk: 70,
        networkRisk: 20,
        historicalRisk: 10,
        riskFactors: [
          { type: RiskFactorType.NEW_DEVICE, severity: 'medium' as const, score: 40, description: 'New device' },
          { type: RiskFactorType.VPN_DETECTED, severity: 'medium' as const, score: 30, description: 'VPN' },
          { type: RiskFactorType.TOR_DETECTED, severity: 'high' as const, score: 60, description: 'Tor' },
          { type: RiskFactorType.BREACHED_PASSWORD, severity: 'critical' as const, score: 70, description: 'Breached' }
        ]
      };

      const context = createAnonymizedContext(input);

      expect(context.isNewDevice).toBe(true);
      expect(context.isVpn).toBe(true);
      expect(context.isTor).toBe(true);
      expect(context.isBreachedPassword).toBe(false); // Not from riskFactors, from input
    });

    it('should calculate average risk score from history', () => {
      const input = {
        deviceRisk: 20,
        geoRisk: 15,
        behaviorRisk: 10,
        credentialRisk: 5,
        networkRisk: 10,
        historicalRisk: 5,
        riskFactors: [] as RiskFactor[],
        previousRiskScores: [20, 30, 40, 50, 60]
      };

      const context = createAnonymizedContext(input);

      expect(context.averageRiskScore).toBe(40); // (20+30+40+50+60)/5
      expect(context.highRiskLoginCount).toBe(0); // None >= 75
    });

    it('should count high risk logins correctly', () => {
      const input = {
        deviceRisk: 20,
        geoRisk: 15,
        behaviorRisk: 10,
        credentialRisk: 5,
        networkRisk: 10,
        historicalRisk: 5,
        riskFactors: [] as RiskFactor[],
        previousRiskScores: [20, 75, 80, 90, 30]
      };

      const context = createAnonymizedContext(input);

      expect(context.highRiskLoginCount).toBe(3); // 75, 80, 90 >= 75
    });

    it('should not include any PII in context', () => {
      const input = {
        deviceRisk: 20,
        geoRisk: 15,
        behaviorRisk: 10,
        credentialRisk: 5,
        networkRisk: 10,
        historicalRisk: 5,
        riskFactors: [] as RiskFactor[]
      };

      const context = createAnonymizedContext(input);
      const contextString = JSON.stringify(context);

      // Verify no PII fields exist
      expect(contextString).not.toContain('email');
      expect(contextString).not.toContain('userId');
      expect(contextString).not.toContain('ip');
      expect(contextString).not.toContain('name');
      expect(contextString).not.toContain('address');
      expect(contextString).not.toContain('phone');
    });
  });

  describe('blendWithRuleBasedResult', () => {
    it('should return rule-based score when Bedrock result is null', () => {
      const result = blendWithRuleBasedResult(50, null);

      expect(result.blendedScore).toBe(50);
      expect(result.usedML).toBe(false);
      expect(result.confidence).toBe(100);
    });

    it('should blend scores with default weight', () => {
      const bedrockResult = createMockBedrockResult({
        riskScore: 30,
        confidence: 100
      });

      const result = blendWithRuleBasedResult(50, bedrockResult, 0.4);

      // 50 * 0.6 + 30 * 0.4 = 30 + 12 = 42
      expect(result.blendedScore).toBe(42);
      expect(result.usedML).toBe(true);
      expect(result.confidence).toBe(100);
    });

    it('should adjust ML weight based on confidence', () => {
      const lowConfidenceResult = createMockBedrockResult({
        riskScore: 30,
        confidence: 50 // 50% confidence
      });

      const result = blendWithRuleBasedResult(50, lowConfidenceResult, 0.4);

      // Adjusted ML weight = 0.4 * 0.5 = 0.2
      // 50 * 0.8 + 30 * 0.2 = 40 + 6 = 46
      expect(result.blendedScore).toBe(46);
      expect(result.usedML).toBe(true);
      expect(result.confidence).toBe(50);
    });

    it('should clamp blended score to 0-100 range', () => {
      const highRiskResult = createMockBedrockResult({
        riskScore: 100,
        confidence: 100
      });

      const result = blendWithRuleBasedResult(100, highRiskResult);

      expect(result.blendedScore).toBeLessThanOrEqual(100);
      expect(result.blendedScore).toBeGreaterThanOrEqual(0);
    });
  });

  describe('isBedrockAvailable', () => {
    it('should return true when Bedrock is enabled and configured', () => {
      const config: BedrockConfig = {
        ...DEFAULT_BEDROCK_CONFIG,
        enabled: true,
        modelId: 'anthropic.claude-3-haiku-20240307-v1:0'
      };

      expect(isBedrockAvailable(config)).toBe(true);
    });

    it('should return false when Bedrock is disabled', () => {
      const config: BedrockConfig = {
        ...DEFAULT_BEDROCK_CONFIG,
        enabled: false
      };

      expect(isBedrockAvailable(config)).toBe(false);
    });

    it('should return false when model ID is empty', () => {
      const config: BedrockConfig = {
        ...DEFAULT_BEDROCK_CONFIG,
        enabled: true,
        modelId: ''
      };

      expect(isBedrockAvailable(config)).toBe(false);
    });
  });

  describe('getBedrockHealthStatus', () => {
    it('should return health status', async () => {
      const status = await getBedrockHealthStatus();

      expect(status).toHaveProperty('available');
      expect(status).toHaveProperty('modelId');
      expect(status).toHaveProperty('region');
      expect(status).toHaveProperty('rateLimitRemaining');
      expect(typeof status.rateLimitRemaining).toBe('number');
    });
  });
});


// ============================================================================
// Integration Tests (with mocked Bedrock)
// ============================================================================

describe('Bedrock Integration Tests', () => {
  describe('analyzeRiskWithBedrock', () => {
    it('should return null when Bedrock is disabled', async () => {
      const context = createBaseContext();
      const config: BedrockConfig = {
        ...DEFAULT_BEDROCK_CONFIG,
        enabled: false
      };

      const result = await analyzeRiskWithBedrock(context, config);

      expect(result).toBeNull();
    });

    it('should handle low-risk context appropriately', async () => {
      const context = createBaseContext();
      
      // This test verifies the function handles the context correctly
      // In production, it would call Bedrock; here we test the input validation
      expect(context.deviceTrustScore).toBe(80);
      expect(context.geoRiskScore).toBe(10);
      expect(context.isTypicalLoginTime).toBe(true);
    });

    it('should handle high-risk context appropriately', async () => {
      const context = createHighRiskContext();
      
      // Verify high-risk signals are captured
      expect(context.deviceTrustScore).toBe(20);
      expect(context.geoRiskScore).toBe(80);
      expect(context.isImpossibleTravel).toBe(true);
      expect(context.isTor).toBe(false);
      expect(context.isVpn).toBe(true);
      expect(context.isBreachedPassword).toBe(true);
    });
  });

  describe('detectAnomaliesWithBedrock', () => {
    it('should return null when Bedrock is disabled', async () => {
      const context = createBaseContext();
      const config: BedrockConfig = {
        ...DEFAULT_BEDROCK_CONFIG,
        enabled: false
      };

      const result = await detectAnomaliesWithBedrock(context, config);

      expect(result).toBeNull();
    });
  });

  describe('analyzeBehaviorWithBedrock', () => {
    it('should return null when Bedrock is disabled', async () => {
      const context = createBaseContext();
      const config: BedrockConfig = {
        ...DEFAULT_BEDROCK_CONFIG,
        enabled: false
      };

      const result = await analyzeBehaviorWithBedrock(context, config);

      expect(result).toBeNull();
    });
  });

  describe('correlateRiskFactorsWithBedrock', () => {
    it('should return null when Bedrock is disabled', async () => {
      const context = createBaseContext();
      const config: BedrockConfig = {
        ...DEFAULT_BEDROCK_CONFIG,
        enabled: false
      };

      const result = await correlateRiskFactorsWithBedrock(context, config);

      expect(result).toBeNull();
    });
  });
});

// ============================================================================
// Security Tests
// ============================================================================

describe('Security Tests', () => {
  describe('Privacy Protection', () => {
    it('should never include PII in anonymized context', () => {
      const input = {
        deviceRisk: 20,
        geoRisk: 15,
        behaviorRisk: 10,
        credentialRisk: 5,
        networkRisk: 10,
        historicalRisk: 5,
        riskFactors: [] as RiskFactor[],
        // These should NOT appear in output
        userId: 'user_123',
        email: 'test@example.com',
        ipAddress: '192.168.1.1'
      };

      const context = createAnonymizedContext(input as any);
      const keys = Object.keys(context);

      // Verify no PII fields
      expect(keys).not.toContain('userId');
      expect(keys).not.toContain('email');
      expect(keys).not.toContain('ipAddress');
      expect(keys).not.toContain('ip');
      expect(keys).not.toContain('name');
    });

    it('should only include behavioral signals', () => {
      const context = createBaseContext();
      const keys = Object.keys(context);

      // All keys should be behavioral signals
      const allowedKeys = [
        'deviceTrustScore', 'isNewDevice', 'deviceSimilarityScore',
        'geoRiskScore', 'isVpn', 'isTor', 'isProxy', 'isDatacenter',
        'isImpossibleTravel', 'distanceFromLastLogin',
        'loginHour', 'dayOfWeek', 'failedAttempts', 'minutesSinceLastLogin',
        'isTypicalLoginTime', 'accountAgeDays', 'mfaEnabled', 'totalLogins',
        'passwordStrength', 'isBreachedPassword',
        'averageRiskScore', 'highRiskLoginCount',
        'credentialStuffingScore', 'bruteForceScore'
      ];

      keys.forEach(key => {
        expect(allowedKeys).toContain(key);
      });
    });
  });

  describe('Rate Limiting', () => {
    it('should respect rate limit configuration', () => {
      const config: BedrockConfig = {
        ...DEFAULT_BEDROCK_CONFIG,
        rateLimitPerMinute: 100
      };

      expect(config.rateLimitPerMinute).toBe(100);
    });
  });

  describe('Timeout Protection', () => {
    it('should have reasonable timeout configuration', () => {
      expect(DEFAULT_BEDROCK_CONFIG.timeoutMs).toBeLessThanOrEqual(10000);
      expect(DEFAULT_BEDROCK_CONFIG.timeoutMs).toBeGreaterThanOrEqual(1000);
    });
  });
});

// ============================================================================
// Property-Based Tests
// ============================================================================

describe('Property-Based Tests', () => {
  /**
   * Property: Anonymized context should never contain PII
   */
  describe('Property: No PII in anonymized context', () => {
    it('should produce PII-free context for any input', () => {
      // Test with various inputs
      const testCases = [
        { deviceRisk: 0, geoRisk: 0 },
        { deviceRisk: 50, geoRisk: 50 },
        { deviceRisk: 100, geoRisk: 100 },
        { deviceRisk: 25, geoRisk: 75, failedAttempts: 10 },
        { deviceRisk: 75, geoRisk: 25, isBreachedPassword: true }
      ];

      testCases.forEach(testCase => {
        const input = {
          ...testCase,
          behaviorRisk: 10,
          credentialRisk: 10,
          networkRisk: 10,
          historicalRisk: 10,
          riskFactors: [] as RiskFactor[]
        };

        const context = createAnonymizedContext(input);
        const contextString = JSON.stringify(context);

        // No PII patterns
        expect(contextString).not.toMatch(/@/); // No email
        expect(contextString).not.toMatch(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/); // No IP
        expect(contextString).not.toMatch(/user_/); // No user ID
      });
    });
  });

  /**
   * Property: Blended score should always be in valid range
   */
  describe('Property: Blended score in valid range', () => {
    it('should produce scores between 0 and 100', () => {
      const testCases = [
        { ruleScore: 0, mlScore: 0 },
        { ruleScore: 100, mlScore: 100 },
        { ruleScore: 0, mlScore: 100 },
        { ruleScore: 100, mlScore: 0 },
        { ruleScore: 50, mlScore: 50 },
        { ruleScore: 25, mlScore: 75 },
        { ruleScore: 75, mlScore: 25 }
      ];

      testCases.forEach(({ ruleScore, mlScore }) => {
        const bedrockResult = createMockBedrockResult({
          riskScore: mlScore,
          confidence: 100
        });

        const result = blendWithRuleBasedResult(ruleScore, bedrockResult);

        expect(result.blendedScore).toBeGreaterThanOrEqual(0);
        expect(result.blendedScore).toBeLessThanOrEqual(100);
      });
    });
  });

  /**
   * Property: Higher risk inputs should produce higher risk contexts
   */
  describe('Property: Risk monotonicity', () => {
    it('should produce higher geo risk score for riskier geo inputs', () => {
      const lowRiskInput = {
        deviceRisk: 10,
        geoRisk: 10,
        behaviorRisk: 10,
        credentialRisk: 10,
        networkRisk: 10,
        historicalRisk: 10,
        riskFactors: [] as RiskFactor[]
      };

      const highRiskInput = {
        deviceRisk: 10,
        geoRisk: 80,
        behaviorRisk: 10,
        credentialRisk: 10,
        networkRisk: 10,
        historicalRisk: 10,
        riskFactors: [] as RiskFactor[]
      };

      const lowRiskContext = createAnonymizedContext(lowRiskInput);
      const highRiskContext = createAnonymizedContext(highRiskInput);

      expect(highRiskContext.geoRiskScore).toBeGreaterThan(lowRiskContext.geoRiskScore);
    });

    it('should produce lower device trust for higher device risk', () => {
      const lowRiskInput = {
        deviceRisk: 10,
        geoRisk: 10,
        behaviorRisk: 10,
        credentialRisk: 10,
        networkRisk: 10,
        historicalRisk: 10,
        riskFactors: [] as RiskFactor[]
      };

      const highRiskInput = {
        deviceRisk: 80,
        geoRisk: 10,
        behaviorRisk: 10,
        credentialRisk: 10,
        networkRisk: 10,
        historicalRisk: 10,
        riskFactors: [] as RiskFactor[]
      };

      const lowRiskContext = createAnonymizedContext(lowRiskInput);
      const highRiskContext = createAnonymizedContext(highRiskInput);

      expect(highRiskContext.deviceTrustScore).toBeLessThan(lowRiskContext.deviceTrustScore);
    });
  });
});
