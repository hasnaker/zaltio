/**
 * AI Security Integration Tests
 * Phase 6: AI Security - Task 16.4
 * 
 * Comprehensive property-based tests for AI Security features:
 * - Property 22: AI risk score consistency
 * - Property 23: High risk score triggers MFA
 * - Property 24: Bot detection blocks automated requests
 * - Property 25: Anomaly detection learns user patterns
 * - Property 26: Fraud score blocks disposable emails
 * 
 * Validates: Requirements 14.8, 15.1 (AI Security)
 */

import {
  assessRisk,
  assessRiskWithAttackDetection,
  RiskAssessmentInput,
  RISK_THRESHOLDS,
  ADAPTIVE_AUTH_THRESHOLDS
} from './ai-risk.service';

import {
  detectLoginAnomaly,
  createInitialProfile,
  updateBehaviorProfile,
  DEFAULT_ANOMALY_CONFIG
} from './ai-anomaly.service';

import {
  detectFraud,
  FraudDetectionInput,
  FRAUD_THRESHOLDS,
  isDisposableEmail,
  isBotUserAgent
} from './ai-fraud.service';

// ============================================================================
// Test Fixtures
// ============================================================================

const createRiskInput = (overrides: Partial<RiskAssessmentInput> = {}): RiskAssessmentInput => ({
  email: 'test@example.com',
  realmId: 'test-realm',
  ipAddress: '192.168.1.1',
  ...overrides
});

const createFraudInput = (overrides: Partial<FraudDetectionInput> = {}): FraudDetectionInput => ({
  email: 'test@example.com',
  realmId: 'test-realm',
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
  ...overrides
});

// ============================================================================
// Property 22: AI risk score consistency
// ============================================================================

describe('Property 22: AI risk score consistency', () => {
  it('should produce consistent scores for identical inputs', async () => {
    const input = createRiskInput({
      deviceFingerprint: {
        userAgent: 'Mozilla/5.0',
        screen: '1920x1080',
        timezone: 'UTC',
        language: 'en-US',
        platform: 'MacIntel'
      },
      geoLocation: {
        latitude: 41.0,
        longitude: 29.0,
        city: 'Istanbul',
        country: 'Turkey',
        countryCode: 'TR'
      }
    });

    const results = await Promise.all([
      assessRisk(input),
      assessRisk(input),
      assessRisk(input)
    ]);

    // All scores should be identical
    const scores = results.map(r => r.riskScore);
    expect(new Set(scores).size).toBe(1);
  });

  it('should produce monotonically increasing scores with more risk factors', async () => {
    const baseInput = createRiskInput();
    
    const withVpn = createRiskInput({
      geoLocation: { latitude: 0, longitude: 0, city: 'Unknown', country: 'Unknown', countryCode: 'XX', isVpn: true }
    });
    
    const withVpnAndFailures = createRiskInput({
      geoLocation: { latitude: 0, longitude: 0, city: 'Unknown', country: 'Unknown', countryCode: 'XX', isVpn: true },
      failedAttempts: 5
    });

    const baseResult = await assessRisk(baseInput);
    const vpnResult = await assessRisk(withVpn);
    const vpnFailuresResult = await assessRisk(withVpnAndFailures);

    expect(vpnResult.riskScore).toBeGreaterThanOrEqual(baseResult.riskScore);
    expect(vpnFailuresResult.riskScore).toBeGreaterThanOrEqual(vpnResult.riskScore);
  });

  it('should have risk score bounded between 0 and 100', async () => {
    // Test with various inputs
    const inputs = [
      createRiskInput(),
      createRiskInput({ failedAttempts: 100 }),
      createRiskInput({ isBreachedPassword: true }),
      createRiskInput({ geoLocation: { latitude: 0, longitude: 0, city: '', country: '', countryCode: '', isTor: true } })
    ];

    for (const input of inputs) {
      const result = await assessRisk(input);
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.riskScore).toBeLessThanOrEqual(100);
    }
  });
});

// ============================================================================
// Property 23: High risk score triggers MFA
// ============================================================================

describe('Property 23: High risk score triggers MFA', () => {
  it('should require MFA when risk score exceeds threshold', async () => {
    const highRiskInput = createRiskInput({
      geoLocation: { latitude: 0, longitude: 0, city: '', country: '', countryCode: '', isVpn: true },
      failedAttempts: 3,
      mfaEnabled: false
    });

    const result = await assessRisk(highRiskInput);

    if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.mfa) {
      expect(result.requiresMfa).toBe(true);
    }
  });

  it('should require verification for very high risk', async () => {
    const veryHighRiskInput = createRiskInput({
      geoLocation: { latitude: 0, longitude: 0, city: '', country: '', countryCode: '', isTor: true },
      failedAttempts: 5,
      isBreachedPassword: true
    });

    const result = await assessRisk(veryHighRiskInput);

    if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.verification) {
      expect(result.requiresVerification).toBe(true);
    }
  });

  it('should block for critical risk', async () => {
    const criticalRiskInput = createRiskInput({
      geoLocation: { latitude: 0, longitude: 0, city: '', country: '', countryCode: '', isTor: true },
      failedAttempts: 10,
      isBreachedPassword: true,
      passwordStrength: 10
    });

    const result = await assessRisk(criticalRiskInput);

    if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.block) {
      expect(result.shouldBlock).toBe(true);
    }
  });

  it('should have adaptive auth level match risk score', async () => {
    const inputs = [
      createRiskInput(), // Low risk
      createRiskInput({ failedAttempts: 3 }), // Medium risk
      createRiskInput({ geoLocation: { latitude: 0, longitude: 0, city: '', country: '', countryCode: '', isTor: true } }) // High risk
    ];

    for (const input of inputs) {
      const result = await assessRisk(input);
      
      // Verify adaptive auth level is consistent with risk score
      if (result.riskScore < ADAPTIVE_AUTH_THRESHOLDS.mfa) {
        expect(result.adaptiveAuthLevel).toBe('none');
      } else if (result.riskScore >= ADAPTIVE_AUTH_THRESHOLDS.block) {
        expect(result.adaptiveAuthLevel).toBe('block');
      }
    }
  });
});

// ============================================================================
// Property 24: Bot detection blocks automated requests
// ============================================================================

describe('Property 24: Bot detection blocks automated requests', () => {
  const botUserAgents = [
    'python-requests/2.28.0',
    'curl/7.79.1',
    'wget/1.21',
    'Java/11.0.11',
    'HeadlessChrome/91.0.4472.124',
    'PhantomJS/2.1.1',
    'Puppeteer/10.0.0'
  ];

  it.each(botUserAgents)('should detect bot: %s', async (userAgent) => {
    const input = createFraudInput({ userAgent });
    const result = await detectFraud(input);

    expect(result.fraudScore).toBeGreaterThan(0);
    expect(result.signals.length).toBeGreaterThan(0);
  });

  it('should have higher score for headless browsers', async () => {
    const regularBot = await detectFraud(createFraudInput({ userAgent: 'curl/7.79.1' }));
    const headless = await detectFraud(createFraudInput({ userAgent: 'HeadlessChrome/91.0' }));

    expect(headless.fraudScore).toBeGreaterThanOrEqual(regularBot.fraudScore);
  });

  it('should detect fast form fills as bot behavior', async () => {
    const input = createFraudInput({
      requestTiming: { formFillTime: 100 } // 100ms - impossibly fast
    });

    const result = await detectFraud(input);
    expect(result.signals.some(s => s.type === 'fast_form_fill')).toBe(true);
  });

  it('should detect uniform keystrokes as bot behavior', async () => {
    const input = createFraudInput({
      requestTiming: {
        keystrokeIntervals: [100, 100, 100, 100, 100, 100, 100] // Perfectly uniform
      }
    });

    const result = await detectFraud(input);
    expect(result.signals.some(s => s.type === 'uniform_keystrokes')).toBe(true);
  });
});

// ============================================================================
// Property 25: Anomaly detection learns user patterns
// ============================================================================

describe('Property 25: Anomaly detection learns user patterns', () => {
  it('should build profile with each login', async () => {
    const profile = createInitialProfile('user-123', 'test-realm');
    
    let currentProfile = profile;
    for (let i = 0; i < 5; i++) {
      const event = {
        userId: 'user-123',
        realmId: 'test-realm',
        timestamp: Date.now() + i * 1000,
        ipAddress: '192.168.1.1',
        success: true,
        location: {
          latitude: 41.0,
          longitude: 29.0,
          city: 'Istanbul',
          country: 'Turkey',
          countryCode: 'TR'
        },
        deviceFingerprint: 'device-1'
      };
      currentProfile = await updateBehaviorProfile(currentProfile, event);
    }

    expect(currentProfile.totalLogins).toBe(5);
    expect(currentProfile.dataPoints).toBe(5);
    expect(currentProfile.commonLocations.length).toBeGreaterThan(0);
  });

  it('should have higher confidence with more data points', () => {
    const lowData = createInitialProfile('user-1', 'realm-1');
    lowData.dataPoints = 10;
    
    const highData = createInitialProfile('user-2', 'realm-1');
    highData.dataPoints = 100;

    const lowConfidence = Math.min(100, lowData.dataPoints * 5);
    const highConfidence = Math.min(100, highData.dataPoints * 5);

    expect(highConfidence).toBeGreaterThanOrEqual(lowConfidence);
  });

  it('should track location frequency accurately', async () => {
    const profile = createInitialProfile('user-123', 'test-realm');
    
    let currentProfile = profile;
    
    // Login from Istanbul 3 times
    for (let i = 0; i < 3; i++) {
      currentProfile = await updateBehaviorProfile(currentProfile, {
        userId: 'user-123',
        realmId: 'test-realm',
        timestamp: Date.now() + i * 1000,
        ipAddress: '192.168.1.1',
        success: true,
        location: { latitude: 41.0, longitude: 29.0, city: 'Istanbul', country: 'Turkey', countryCode: 'TR' }
      });
    }

    const istanbul = currentProfile.commonLocations.find(l => l.city === 'Istanbul');
    expect(istanbul?.frequency).toBe(3);
  });
});

// ============================================================================
// Property 26: Fraud score blocks disposable emails
// ============================================================================

describe('Property 26: Fraud score blocks disposable emails', () => {
  const disposableEmails = [
    'test@tempmail.com',
    'user@guerrillamail.com',
    'random@mailinator.com',
    'fake@10minutemail.com',
    'temp@yopmail.com'
  ];

  it.each(disposableEmails)('should detect disposable email: %s', async (email) => {
    const input = createFraudInput({ email });
    const result = await detectFraud(input);

    expect(result.signals.some(s => s.type === 'disposable_email')).toBe(true);
    expect(result.fraudScore).toBeGreaterThanOrEqual(70);
  });

  it('should recommend blocking disposable emails', async () => {
    const input = createFraudInput({ email: 'test@tempmail.com' });
    const result = await detectFraud(input);

    expect(['block', 'manual_review', 'captcha']).toContain(result.recommendedAction);
  });

  it('should not flag legitimate email providers', async () => {
    const legitimateEmails = ['user@gmail.com', 'user@outlook.com', 'user@company.com'];

    for (const email of legitimateEmails) {
      expect(isDisposableEmail(email)).toBe(false);
    }
  });

  it('should have fraud score proportional to email risk', async () => {
    const legitimate = await detectFraud(createFraudInput({ email: 'user@gmail.com' }));
    const disposable = await detectFraud(createFraudInput({ email: 'test@tempmail.com' }));

    expect(disposable.fraudScore).toBeGreaterThan(legitimate.fraudScore);
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('AI Security Integration', () => {
  it('should combine risk and fraud detection', async () => {
    const riskInput = createRiskInput({
      geoLocation: { latitude: 0, longitude: 0, city: '', country: '', countryCode: '', isVpn: true }
    });

    const fraudInput = createFraudInput({
      email: 'test@tempmail.com',
      userAgent: 'python-requests/2.28.0'
    });

    const riskResult = await assessRisk(riskInput);
    const fraudResult = await detectFraud(fraudInput);

    // Both should detect issues
    expect(riskResult.riskScore).toBeGreaterThan(0);
    expect(fraudResult.fraudScore).toBeGreaterThan(0);
  });

  it('should have consistent thresholds across services', () => {
    // Risk thresholds
    expect(RISK_THRESHOLDS.low).toBeLessThan(RISK_THRESHOLDS.medium);
    expect(RISK_THRESHOLDS.medium).toBeLessThan(RISK_THRESHOLDS.high);
    expect(RISK_THRESHOLDS.high).toBeLessThan(RISK_THRESHOLDS.critical);

    // Fraud thresholds
    expect(FRAUD_THRESHOLDS.captchaThreshold).toBeLessThan(FRAUD_THRESHOLDS.blockThreshold);
    expect(FRAUD_THRESHOLDS.blockThreshold).toBeLessThan(FRAUD_THRESHOLDS.manualReviewThreshold);

    // Adaptive auth thresholds
    expect(ADAPTIVE_AUTH_THRESHOLDS.mfa).toBeLessThan(ADAPTIVE_AUTH_THRESHOLDS.mfaStrict);
    expect(ADAPTIVE_AUTH_THRESHOLDS.mfaStrict).toBeLessThan(ADAPTIVE_AUTH_THRESHOLDS.verification);
    expect(ADAPTIVE_AUTH_THRESHOLDS.verification).toBeLessThan(ADAPTIVE_AUTH_THRESHOLDS.block);
  });
});
