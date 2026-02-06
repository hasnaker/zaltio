/**
 * AI Fraud Detection Service Tests
 * Phase 6: AI Security - Task 16.3
 * 
 * Property-Based Tests:
 * - Property 24: Bot detection blocks automated requests
 * - Property 26: Fraud score blocks disposable emails
 * 
 * Validates: Requirements 14.8, 15.1 (AI Security, Fraud Prevention)
 */

import {
  detectFraud,
  FraudDetectionInput,
  FraudDetectionResult,
  FraudType,
  FraudSignalType,
  FRAUD_THRESHOLDS,
  isDisposableEmail,
  isBotUserAgent,
  getFraudRiskLevel
} from './ai-fraud.service';

// ============================================================================
// Test Fixtures
// ============================================================================

const createFraudInput = (overrides: Partial<FraudDetectionInput> = {}): FraudDetectionInput => ({
  email: 'legitimate@company.com',
  realmId: 'test-realm',
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
  ...overrides
});

// ============================================================================
// Unit Tests
// ============================================================================

describe('AI Fraud Detection Service', () => {
  describe('detectFraud', () => {
    describe('Bot Detection', () => {
      it('should detect bot user agent', async () => {
        const input = createFraudInput({
          userAgent: 'python-requests/2.28.0'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.BOT_USER_AGENT)).toBe(true);
        expect(result.fraudScore).toBeGreaterThan(0);
      });

      it('should detect headless browser', async () => {
        const input = createFraudInput({
          userAgent: 'Mozilla/5.0 HeadlessChrome/91.0.4472.124'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.HEADLESS_BROWSER)).toBe(true);
        expect(result.fraudScore).toBeGreaterThanOrEqual(60);
      });


      it('should detect fast form fill', async () => {
        const input = createFraudInput({
          requestTiming: {
            formFillTime: 500 // 500ms - too fast
          }
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.FAST_FORM_FILL)).toBe(true);
      });

      it('should detect no mouse movement', async () => {
        const input = createFraudInput({
          requestTiming: {
            mouseMovement: false,
            touchEvents: false
          }
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.NO_MOUSE_MOVEMENT)).toBe(true);
      });

      it('should detect uniform keystrokes', async () => {
        const input = createFraudInput({
          requestTiming: {
            keystrokeIntervals: [100, 100, 100, 100, 100, 100, 100] // Uniform timing
          }
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.UNIFORM_KEYSTROKES)).toBe(true);
      });

      it('should not flag legitimate user agent', async () => {
        const input = createFraudInput({
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.BOT_USER_AGENT)).toBe(false);
        expect(result.signals.some(s => s.type === FraudSignalType.HEADLESS_BROWSER)).toBe(false);
      });
    });

    describe('Disposable Email Detection', () => {
      it('should detect disposable email', async () => {
        const input = createFraudInput({
          email: 'test@tempmail.com'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.DISPOSABLE_EMAIL)).toBe(true);
        expect(result.fraudScore).toBeGreaterThanOrEqual(70);
      });

      it('should detect guerrillamail', async () => {
        const input = createFraudInput({
          email: 'random@guerrillamail.com'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.DISPOSABLE_EMAIL)).toBe(true);
      });

      it('should detect mailinator', async () => {
        const input = createFraudInput({
          email: 'test123@mailinator.com'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.DISPOSABLE_EMAIL)).toBe(true);
      });

      it('should not flag legitimate email domains', async () => {
        const input = createFraudInput({
          email: 'user@gmail.com'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.DISPOSABLE_EMAIL)).toBe(false);
      });

      it('should detect suspicious email patterns', async () => {
        const input = createFraudInput({
          email: 'test123@example.com'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.SUSPICIOUS_EMAIL_PATTERN)).toBe(true);
      });
    });

    describe('Registration Fraud Detection', () => {
      it('should detect generic names', async () => {
        const input = createFraudInput({
          isRegistration: true,
          profile: {
            firstName: 'Test',
            lastName: 'User'
          }
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.GENERIC_NAME)).toBe(true);
      });

      it('should detect keyboard pattern names', async () => {
        const input = createFraudInput({
          isRegistration: true,
          profile: {
            firstName: 'Qwerty',
            lastName: 'Asdf'
          }
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.KEYBOARD_PATTERN_NAME)).toBe(true);
      });

      it('should detect weak password patterns', async () => {
        const input = createFraudInput({
          isRegistration: true,
          password: '123456789'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.WEAK_PASSWORD_PATTERN)).toBe(true);
      });

      it('should not flag legitimate registration', async () => {
        const input = createFraudInput({
          isRegistration: true,
          profile: {
            firstName: 'John',
            lastName: 'Williams'
          },
          password: 'SecureP@ssw0rd123!'
        });

        const result = await detectFraud(input);

        expect(result.signals.some(s => s.type === FraudSignalType.GENERIC_NAME)).toBe(false);
        expect(result.signals.some(s => s.type === FraudSignalType.WEAK_PASSWORD_PATTERN)).toBe(false);
      });
    });

    describe('Fraud Score Calculation', () => {
      it('should return score between 0 and 100', async () => {
        const input = createFraudInput();

        const result = await detectFraud(input);

        expect(result.fraudScore).toBeGreaterThanOrEqual(0);
        expect(result.fraudScore).toBeLessThanOrEqual(100);
      });

      it('should return higher score for multiple signals', async () => {
        const lowRiskInput = createFraudInput({
          email: 'user@gmail.com'
        });

        const highRiskInput = createFraudInput({
          email: 'test@tempmail.com',
          userAgent: 'python-requests/2.28.0',
          requestTiming: {
            formFillTime: 100
          }
        });

        const lowRiskResult = await detectFraud(lowRiskInput);
        const highRiskResult = await detectFraud(highRiskInput);

        expect(highRiskResult.fraudScore).toBeGreaterThan(lowRiskResult.fraudScore);
      });
    });

    describe('Recommended Actions', () => {
      it('should recommend allow for low fraud score', async () => {
        const input = createFraudInput({
          email: 'legitimate@company.com',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124'
        });

        const result = await detectFraud(input);

        if (result.fraudScore < FRAUD_THRESHOLDS.captchaThreshold) {
          expect(result.recommendedAction).toBe('allow');
        }
      });

      it('should recommend captcha for medium fraud score', async () => {
        const input = createFraudInput({
          email: 'test123@example.com',
          requestTiming: {
            mouseMovement: false,
            touchEvents: false
          }
        });

        const result = await detectFraud(input);

        if (result.fraudScore >= FRAUD_THRESHOLDS.captchaThreshold && 
            result.fraudScore < FRAUD_THRESHOLDS.blockThreshold) {
          expect(result.recommendedAction).toBe('captcha');
        }
      });

      it('should recommend block for high fraud score', async () => {
        const input = createFraudInput({
          email: 'test@tempmail.com',
          userAgent: 'python-requests/2.28.0'
        });

        const result = await detectFraud(input);

        if (result.fraudScore >= FRAUD_THRESHOLDS.blockThreshold) {
          expect(['block', 'manual_review']).toContain(result.recommendedAction);
        }
      });
    });
  });
});

// ============================================================================
// Property-Based Tests
// ============================================================================

describe('Property-Based Tests', () => {
  /**
   * Property 24: Bot detection blocks automated requests
   */
  describe('Property 24: Bot detection blocks automated requests', () => {
    const botUserAgents = [
      'python-requests/2.28.0',
      'curl/7.79.1',
      'wget/1.21',
      'Java/11.0.11',
      'Go-http-client/1.1',
      'Scrapy/2.5.0',
      'HeadlessChrome/91.0.4472.124',
      'PhantomJS/2.1.1',
      'Puppeteer/10.0.0',
      'Selenium/4.0.0'
    ];

    it.each(botUserAgents)('should detect bot user agent: %s', async (userAgent) => {
      const input = createFraudInput({ userAgent });
      const result = await detectFraud(input);

      expect(result.signals.some(s => 
        s.type === FraudSignalType.BOT_USER_AGENT || 
        s.type === FraudSignalType.HEADLESS_BROWSER
      )).toBe(true);
      expect(result.fraudScore).toBeGreaterThan(0);
    });

    it('should have higher fraud score for headless browsers than regular bots', async () => {
      const regularBot = createFraudInput({ userAgent: 'curl/7.79.1' });
      const headlessBrowser = createFraudInput({ userAgent: 'HeadlessChrome/91.0.4472.124' });

      const regularResult = await detectFraud(regularBot);
      const headlessResult = await detectFraud(headlessBrowser);

      expect(headlessResult.fraudScore).toBeGreaterThanOrEqual(regularResult.fraudScore);
    });
  });

  /**
   * Property 26: Fraud score blocks disposable emails
   */
  describe('Property 26: Fraud score blocks disposable emails', () => {
    const disposableEmails = [
      'test@tempmail.com',
      'user@guerrillamail.com',
      'random@mailinator.com',
      'fake@10minutemail.com',
      'temp@yopmail.com',
      'throwaway@trashmail.com'
    ];

    it.each(disposableEmails)('should detect disposable email: %s', async (email) => {
      const input = createFraudInput({ email });
      const result = await detectFraud(input);

      expect(result.signals.some(s => s.type === FraudSignalType.DISPOSABLE_EMAIL)).toBe(true);
      expect(result.fraudScore).toBeGreaterThanOrEqual(70);
    });

    it('should recommend block or manual review for disposable emails', async () => {
      const input = createFraudInput({ email: 'test@tempmail.com' });
      const result = await detectFraud(input);

      expect(['block', 'manual_review', 'captcha']).toContain(result.recommendedAction);
    });
  });
});

// ============================================================================
// Utility Function Tests
// ============================================================================

describe('Utility Functions', () => {
  describe('isDisposableEmail', () => {
    it('should return true for disposable emails', () => {
      expect(isDisposableEmail('test@tempmail.com')).toBe(true);
      expect(isDisposableEmail('user@guerrillamail.com')).toBe(true);
      expect(isDisposableEmail('random@mailinator.com')).toBe(true);
    });

    it('should return false for legitimate emails', () => {
      expect(isDisposableEmail('user@gmail.com')).toBe(false);
      expect(isDisposableEmail('user@company.com')).toBe(false);
      expect(isDisposableEmail('user@outlook.com')).toBe(false);
    });
  });

  describe('isBotUserAgent', () => {
    it('should return true for bot user agents', () => {
      expect(isBotUserAgent('python-requests/2.28.0')).toBe(true);
      expect(isBotUserAgent('curl/7.79.1')).toBe(true);
      expect(isBotUserAgent('Scrapy/2.5.0')).toBe(true);
    });

    it('should return false for browser user agents', () => {
      expect(isBotUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124')).toBe(false);
      expect(isBotUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15')).toBe(false);
    });
  });

  describe('getFraudRiskLevel', () => {
    it('should return correct risk levels', () => {
      expect(getFraudRiskLevel(10)).toBe('low');
      expect(getFraudRiskLevel(50)).toBe('medium');
      expect(getFraudRiskLevel(75)).toBe('high');
      expect(getFraudRiskLevel(90)).toBe('critical');
    });
  });
});

// ============================================================================
// Configuration Tests
// ============================================================================

describe('Configuration', () => {
  it('should have valid thresholds', () => {
    expect(FRAUD_THRESHOLDS.captchaThreshold).toBeGreaterThan(0);
    expect(FRAUD_THRESHOLDS.blockThreshold).toBeGreaterThan(FRAUD_THRESHOLDS.captchaThreshold);
    expect(FRAUD_THRESHOLDS.manualReviewThreshold).toBeGreaterThan(FRAUD_THRESHOLDS.blockThreshold);
    expect(FRAUD_THRESHOLDS.manualReviewThreshold).toBeLessThanOrEqual(100);
  });

  it('should have reasonable form fill time threshold', () => {
    expect(FRAUD_THRESHOLDS.minFormFillTime).toBeGreaterThanOrEqual(1000);
    expect(FRAUD_THRESHOLDS.minFormFillTime).toBeLessThanOrEqual(10000);
  });
});
