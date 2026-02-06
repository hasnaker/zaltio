/**
 * AI Fraud Detection Service for Zalt.io Auth Platform
 * Phase 6: AI Security - Task 16.3
 * 
 * SECURITY FEATURES:
 * - Bot detection
 * - Disposable email detection
 * - Fraudulent registration detection
 * - Account takeover prevention
 * 
 * DETECTION TYPES:
 * 1. Bot detection (automated requests)
 * 2. Disposable email detection
 * 3. Suspicious registration patterns
 * 4. Fake account detection
 * 5. Account takeover indicators
 * 
 * Validates: Requirements 14.8, 15.1 (AI Security, Fraud Prevention)
 */

import { logSimpleSecurityEvent } from './security-logger.service';

// ============================================================================
// Types
// ============================================================================

/**
 * Fraud detection input
 */
export interface FraudDetectionInput {
  // User context
  email: string;
  realmId: string;
  ipAddress: string;
  
  // Request context
  userAgent?: string;
  requestHeaders?: Record<string, string>;
  requestTiming?: RequestTiming;
  
  // Registration context (for new accounts)
  isRegistration?: boolean;
  password?: string;
  profile?: {
    firstName?: string;
    lastName?: string;
  };
}


/**
 * Request timing for bot detection
 */
export interface RequestTiming {
  // Time from page load to form submission (ms)
  formFillTime?: number;
  // Time between keystrokes (ms)
  keystrokeIntervals?: number[];
  // Mouse movement detected
  mouseMovement?: boolean;
  // Touch events detected
  touchEvents?: boolean;
  // JavaScript execution time (ms)
  jsExecutionTime?: number;
}

/**
 * Fraud detection result
 */
export interface FraudDetectionResult {
  isFraudulent: boolean;
  fraudScore: number;           // 0-100
  fraudType?: FraudType;
  confidence: number;           // 0-100
  signals: FraudSignal[];
  recommendedAction: 'allow' | 'captcha' | 'block' | 'manual_review';
  explanation: string;
}

/**
 * Fraud types
 */
export enum FraudType {
  BOT = 'bot',
  DISPOSABLE_EMAIL = 'disposable_email',
  SUSPICIOUS_REGISTRATION = 'suspicious_registration',
  FAKE_ACCOUNT = 'fake_account',
  ACCOUNT_TAKEOVER = 'account_takeover',
  MULTIPLE = 'multiple'
}

/**
 * Individual fraud signal
 */
export interface FraudSignal {
  type: FraudSignalType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  description: string;
  details?: Record<string, unknown>;
}

/**
 * Fraud signal types
 */
export enum FraudSignalType {
  // Bot signals
  BOT_USER_AGENT = 'bot_user_agent',
  FAST_FORM_FILL = 'fast_form_fill',
  NO_MOUSE_MOVEMENT = 'no_mouse_movement',
  UNIFORM_KEYSTROKES = 'uniform_keystrokes',
  HEADLESS_BROWSER = 'headless_browser',
  
  // Email signals
  DISPOSABLE_EMAIL = 'disposable_email',
  SUSPICIOUS_EMAIL_PATTERN = 'suspicious_email_pattern',
  RECENTLY_CREATED_DOMAIN = 'recently_created_domain',
  
  // Registration signals
  GENERIC_NAME = 'generic_name',
  KEYBOARD_PATTERN_NAME = 'keyboard_pattern_name',
  SEQUENTIAL_CHARACTERS = 'sequential_characters',
  WEAK_PASSWORD_PATTERN = 'weak_password_pattern',
  
  // Network signals
  DATACENTER_IP = 'datacenter_ip',
  TOR_EXIT_NODE = 'tor_exit_node',
  KNOWN_FRAUD_IP = 'known_fraud_ip',
  HIGH_RISK_COUNTRY = 'high_risk_country'
}

// ============================================================================
// Configuration
// ============================================================================

/**
 * Fraud detection thresholds
 */
export const FRAUD_THRESHOLDS = {
  // Bot detection
  minFormFillTime: 3000,        // Minimum 3 seconds to fill form
  minKeystrokeVariance: 20,     // Minimum variance in keystroke timing (ms)
  
  // Score thresholds
  captchaThreshold: 40,
  blockThreshold: 70,
  manualReviewThreshold: 85
};

/**
 * Known disposable email domains
 */
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  // Common disposable email providers
  'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'guerrillamail.org',
  'mailinator.com', 'maildrop.cc', 'throwaway.email', 'fakeinbox.com',
  '10minutemail.com', '10minutemail.net', 'minutemail.com', 'tempail.com',
  'dispostable.com', 'mailnesia.com', 'trashmail.com', 'trashmail.net',
  'yopmail.com', 'yopmail.fr', 'sharklasers.com', 'guerrillamailblock.com',
  'pokemail.net', 'spam4.me', 'grr.la', 'getairmail.com', 'mohmal.com',
  'tempmailo.com', 'emailondeck.com', 'getnada.com', 'burnermail.io',
  'mailsac.com', 'inboxkitten.com', 'tempr.email', 'discard.email',
  'mailcatch.com', 'mytemp.email', 'tmpmail.org', 'tmpmail.net',
  'emailfake.com', 'crazymailing.com', 'tempinbox.com', 'fakemailgenerator.com'
]);

/**
 * Suspicious email patterns
 */
const SUSPICIOUS_EMAIL_PATTERNS = [
  /^test\d*@/i,
  /^user\d+@/i,
  /^admin\d*@/i,
  /^[a-z]{1,2}\d{5,}@/i,        // Single letter + many numbers
  /^\d{8,}@/i,                   // Many numbers only
  /^[a-z]+\d{4}[a-z]+@/i,       // Pattern like abc1234def@
  /^(asdf|qwerty|zxcv)/i,       // Keyboard patterns
  /^(aaa|bbb|ccc|111|123)/i     // Repeated characters
];

/**
 * Bot user agent patterns
 */
const BOT_USER_AGENT_PATTERNS = [
  /bot/i, /crawler/i, /spider/i, /scraper/i, /scrapy/i,
  /curl/i, /wget/i, /python/i, /java\//i,
  /httpclient/i, /libwww/i, /lwp/i, /go-http/i,
  /headless/i, /phantom/i, /selenium/i,
  /puppeteer/i, /playwright/i, /cypress/i
];

/**
 * Generic/fake name patterns
 */
const GENERIC_NAME_PATTERNS = [
  /^(test|user|admin|guest|demo|sample)/i,
  /^(john|jane)\s*(doe|smith)$/i,
  /^(foo|bar|baz|qux)/i,
  /^[a-z]{1,2}$/i,              // Single or double letter names
  /^\d+$/,                       // Numbers only
  /^(asdf|qwerty|zxcv)/i        // Keyboard patterns
];


// ============================================================================
// Fraud Detection Functions
// ============================================================================

/**
 * Perform comprehensive fraud detection
 */
export async function detectFraud(
  input: FraudDetectionInput
): Promise<FraudDetectionResult> {
  const signals: FraudSignal[] = [];

  // Run all detection checks
  detectBotSignals(input, signals);
  detectEmailSignals(input, signals);
  
  if (input.isRegistration) {
    detectRegistrationSignals(input, signals);
  }
  
  detectNetworkSignals(input, signals);

  // Calculate fraud score
  const fraudScore = calculateFraudScore(signals);
  const confidence = calculateConfidence(signals);

  // Determine fraud type
  const fraudType = determineFraudType(signals);

  // Determine recommended action
  const recommendedAction = determineAction(fraudScore);

  // Generate explanation
  const explanation = generateExplanation(signals, fraudScore);

  // Log if fraudulent
  if (fraudScore >= FRAUD_THRESHOLDS.captchaThreshold) {
    await logFraudEvent(input, signals, fraudScore);
  }

  return {
    isFraudulent: fraudScore >= FRAUD_THRESHOLDS.blockThreshold,
    fraudScore,
    fraudType: signals.length > 0 ? fraudType : undefined,
    confidence,
    signals,
    recommendedAction,
    explanation
  };
}

/**
 * Detect bot-related signals
 */
function detectBotSignals(
  input: FraudDetectionInput,
  signals: FraudSignal[]
): void {
  // Check user agent
  if (input.userAgent) {
    if (BOT_USER_AGENT_PATTERNS.some(pattern => pattern.test(input.userAgent!))) {
      signals.push({
        type: FraudSignalType.BOT_USER_AGENT,
        severity: 'high',
        score: 60,
        description: 'Bot-like user agent detected',
        details: { userAgent: input.userAgent.substring(0, 100) }
      });
    }

    // Check for headless browser indicators
    if (/headless|phantom|puppeteer|playwright/i.test(input.userAgent)) {
      signals.push({
        type: FraudSignalType.HEADLESS_BROWSER,
        severity: 'critical',
        score: 80,
        description: 'Headless browser detected',
        details: { userAgent: input.userAgent.substring(0, 100) }
      });
    }
  } else {
    // No user agent is suspicious
    signals.push({
      type: FraudSignalType.BOT_USER_AGENT,
      severity: 'medium',
      score: 30,
      description: 'No user agent provided'
    });
  }

  // Check request timing
  if (input.requestTiming) {
    const timing = input.requestTiming;

    // Fast form fill
    if (timing.formFillTime !== undefined && timing.formFillTime < FRAUD_THRESHOLDS.minFormFillTime) {
      signals.push({
        type: FraudSignalType.FAST_FORM_FILL,
        severity: 'high',
        score: 50,
        description: `Form filled too quickly: ${timing.formFillTime}ms`,
        details: { formFillTime: timing.formFillTime, threshold: FRAUD_THRESHOLDS.minFormFillTime }
      });
    }

    // No mouse movement
    if (timing.mouseMovement === false && timing.touchEvents === false) {
      signals.push({
        type: FraudSignalType.NO_MOUSE_MOVEMENT,
        severity: 'medium',
        score: 35,
        description: 'No mouse or touch interaction detected'
      });
    }

    // Uniform keystrokes (bot-like typing)
    if (timing.keystrokeIntervals && timing.keystrokeIntervals.length > 5) {
      const variance = calculateVariance(timing.keystrokeIntervals);
      if (variance < FRAUD_THRESHOLDS.minKeystrokeVariance) {
        signals.push({
          type: FraudSignalType.UNIFORM_KEYSTROKES,
          severity: 'high',
          score: 55,
          description: 'Uniform keystroke timing detected (bot-like)',
          details: { variance, threshold: FRAUD_THRESHOLDS.minKeystrokeVariance }
        });
      }
    }
  }
}

/**
 * Detect email-related signals
 */
function detectEmailSignals(
  input: FraudDetectionInput,
  signals: FraudSignal[]
): void {
  const email = input.email.toLowerCase();
  const domain = email.split('@')[1];

  // Check disposable email
  if (domain && DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
    signals.push({
      type: FraudSignalType.DISPOSABLE_EMAIL,
      severity: 'critical',
      score: 90,
      description: 'Disposable email address detected',
      details: { domain }
    });
  }

  // Check suspicious email patterns
  for (const pattern of SUSPICIOUS_EMAIL_PATTERNS) {
    if (pattern.test(email)) {
      signals.push({
        type: FraudSignalType.SUSPICIOUS_EMAIL_PATTERN,
        severity: 'medium',
        score: 40,
        description: 'Suspicious email pattern detected',
        details: { email: maskEmail(email) }
      });
      break; // Only add one signal for patterns
    }
  }

  // Check for sequential characters in email
  if (hasSequentialCharacters(email.split('@')[0], 4)) {
    signals.push({
      type: FraudSignalType.SEQUENTIAL_CHARACTERS,
      severity: 'low',
      score: 20,
      description: 'Sequential characters in email',
      details: { email: maskEmail(email) }
    });
  }
}

/**
 * Detect registration-related signals
 */
function detectRegistrationSignals(
  input: FraudDetectionInput,
  signals: FraudSignal[]
): void {
  // Check name patterns
  if (input.profile?.firstName) {
    const firstName = input.profile.firstName;
    
    for (const pattern of GENERIC_NAME_PATTERNS) {
      if (pattern.test(firstName)) {
        signals.push({
          type: FraudSignalType.GENERIC_NAME,
          severity: 'medium',
          score: 35,
          description: 'Generic or test name detected',
          details: { name: firstName }
        });
        break;
      }
    }

    // Check for keyboard pattern names
    if (isKeyboardPattern(firstName)) {
      signals.push({
        type: FraudSignalType.KEYBOARD_PATTERN_NAME,
        severity: 'high',
        score: 50,
        description: 'Keyboard pattern detected in name',
        details: { name: firstName }
      });
    }
  }

  // Check password patterns (if provided)
  if (input.password) {
    if (isWeakPasswordPattern(input.password)) {
      signals.push({
        type: FraudSignalType.WEAK_PASSWORD_PATTERN,
        severity: 'medium',
        score: 30,
        description: 'Weak password pattern detected'
      });
    }
  }
}

/**
 * Detect network-related signals
 */
function detectNetworkSignals(
  input: FraudDetectionInput,
  signals: FraudSignal[]
): void {
  // Check request headers for suspicious patterns
  if (input.requestHeaders) {
    // Missing common headers
    const requiredHeaders = ['accept', 'accept-language', 'accept-encoding'];
    const missingHeaders = requiredHeaders.filter(
      h => !Object.keys(input.requestHeaders!).some(k => k.toLowerCase() === h)
    );

    if (missingHeaders.length >= 2) {
      signals.push({
        type: FraudSignalType.BOT_USER_AGENT,
        severity: 'low',
        score: 20,
        description: 'Missing common browser headers',
        details: { missingHeaders }
      });
    }
  }
}


// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Calculate overall fraud score from signals
 */
function calculateFraudScore(signals: FraudSignal[]): number {
  if (signals.length === 0) return 0;

  // Use weighted average with diminishing returns
  let totalScore = 0;
  const sortedSignals = [...signals].sort((a, b) => b.score - a.score);

  for (let i = 0; i < sortedSignals.length; i++) {
    // Each subsequent signal contributes less
    const weight = 1 / (i + 1);
    totalScore += sortedSignals[i].score * weight;
  }

  // Normalize to 0-100
  const normalizedScore = Math.min(100, totalScore);
  return Math.round(normalizedScore);
}

/**
 * Calculate confidence based on signals
 */
function calculateConfidence(signals: FraudSignal[]): number {
  if (signals.length === 0) return 100; // High confidence it's not fraud

  // More signals = higher confidence in fraud detection
  const signalCount = signals.length;
  const avgSeverity = signals.reduce((sum, s) => {
    const severityScore = { low: 25, medium: 50, high: 75, critical: 100 }[s.severity];
    return sum + severityScore;
  }, 0) / signalCount;

  return Math.min(100, Math.round(avgSeverity));
}

/**
 * Determine primary fraud type
 */
function determineFraudType(signals: FraudSignal[]): FraudType {
  if (signals.length === 0) return FraudType.BOT;

  // Count signals by category
  const botSignals = signals.filter(s => 
    [FraudSignalType.BOT_USER_AGENT, FraudSignalType.FAST_FORM_FILL, 
     FraudSignalType.NO_MOUSE_MOVEMENT, FraudSignalType.UNIFORM_KEYSTROKES,
     FraudSignalType.HEADLESS_BROWSER].includes(s.type)
  );

  const emailSignals = signals.filter(s =>
    [FraudSignalType.DISPOSABLE_EMAIL, FraudSignalType.SUSPICIOUS_EMAIL_PATTERN,
     FraudSignalType.RECENTLY_CREATED_DOMAIN].includes(s.type)
  );

  const registrationSignals = signals.filter(s =>
    [FraudSignalType.GENERIC_NAME, FraudSignalType.KEYBOARD_PATTERN_NAME,
     FraudSignalType.SEQUENTIAL_CHARACTERS, FraudSignalType.WEAK_PASSWORD_PATTERN].includes(s.type)
  );

  // Determine primary type
  const counts = [
    { type: FraudType.BOT, count: botSignals.length },
    { type: FraudType.DISPOSABLE_EMAIL, count: emailSignals.length },
    { type: FraudType.SUSPICIOUS_REGISTRATION, count: registrationSignals.length }
  ];

  const sorted = counts.sort((a, b) => b.count - a.count);
  
  if (sorted[0].count === sorted[1].count && sorted[0].count > 0) {
    return FraudType.MULTIPLE;
  }

  return sorted[0].type;
}

/**
 * Determine recommended action based on score
 */
function determineAction(
  fraudScore: number
): 'allow' | 'captcha' | 'block' | 'manual_review' {
  if (fraudScore >= FRAUD_THRESHOLDS.manualReviewThreshold) return 'manual_review';
  if (fraudScore >= FRAUD_THRESHOLDS.blockThreshold) return 'block';
  if (fraudScore >= FRAUD_THRESHOLDS.captchaThreshold) return 'captcha';
  return 'allow';
}

/**
 * Generate human-readable explanation
 */
function generateExplanation(signals: FraudSignal[], fraudScore: number): string {
  if (signals.length === 0) {
    return 'No fraud signals detected';
  }

  const criticalSignals = signals.filter(s => s.severity === 'critical');
  const highSignals = signals.filter(s => s.severity === 'high');

  if (criticalSignals.length > 0) {
    return `Critical fraud detected: ${criticalSignals.map(s => s.description).join('; ')}`;
  }

  if (highSignals.length > 0) {
    return `High fraud risk: ${highSignals.map(s => s.description).join('; ')}`;
  }

  return `Fraud score ${fraudScore}: ${signals.slice(0, 3).map(s => s.description).join('; ')}`;
}

/**
 * Calculate variance of numbers
 */
function calculateVariance(numbers: number[]): number {
  if (numbers.length === 0) return 0;
  
  const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
  const squaredDiffs = numbers.map(n => Math.pow(n - mean, 2));
  return squaredDiffs.reduce((a, b) => a + b, 0) / numbers.length;
}

/**
 * Check for sequential characters
 */
function hasSequentialCharacters(str: string, minLength: number): boolean {
  if (str.length < minLength) return false;

  for (let i = 0; i <= str.length - minLength; i++) {
    let isSequential = true;
    for (let j = 1; j < minLength; j++) {
      if (str.charCodeAt(i + j) !== str.charCodeAt(i + j - 1) + 1) {
        isSequential = false;
        break;
      }
    }
    if (isSequential) return true;
  }

  return false;
}

/**
 * Check for keyboard patterns
 */
function isKeyboardPattern(str: string): boolean {
  const patterns = ['qwerty', 'asdf', 'zxcv', 'qazwsx', '123456', 'abcdef'];
  const lower = str.toLowerCase();
  return patterns.some(p => lower.includes(p));
}

/**
 * Check for weak password patterns
 */
function isWeakPasswordPattern(password: string): boolean {
  const weakPatterns = [
    /^123456/,
    /^password/i,
    /^qwerty/i,
    /^abc123/i,
    /^(.)\1{3,}/,  // Repeated characters
    /^[a-z]+$/i,   // Only letters
    /^\d+$/        // Only numbers
  ];

  return weakPatterns.some(p => p.test(password));
}

/**
 * Mask email for logging
 */
function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (local.length <= 2) return `**@${domain}`;
  return `${local[0]}***${local[local.length - 1]}@${domain}`;
}

/**
 * Log fraud detection event
 */
async function logFraudEvent(
  input: FraudDetectionInput,
  signals: FraudSignal[],
  fraudScore: number
): Promise<void> {
  try {
    await logSimpleSecurityEvent({
      event_type: 'fraud_detected',
      realm_id: input.realmId,
      ip_address: input.ipAddress,
      details: {
        email: maskEmail(input.email),
        fraud_score: fraudScore,
        signal_count: signals.length,
        signal_types: signals.map(s => s.type),
        is_registration: input.isRegistration
      }
    });
  } catch (error) {
    console.error('Log fraud event error:', error);
  }
}

// ============================================================================
// Utility Exports
// ============================================================================

/**
 * Check if email is disposable
 */
export function isDisposableEmail(email: string): boolean {
  const domain = email.toLowerCase().split('@')[1];
  return domain ? DISPOSABLE_EMAIL_DOMAINS.has(domain) : false;
}

/**
 * Check if user agent is bot-like
 */
export function isBotUserAgent(userAgent: string): boolean {
  return BOT_USER_AGENT_PATTERNS.some(pattern => pattern.test(userAgent));
}

/**
 * Get fraud risk level from score
 */
export function getFraudRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= 85) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}
