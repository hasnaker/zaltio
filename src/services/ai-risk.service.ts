/**
 * AI Risk Assessment Service for Zalt.io Auth Platform
 * Phase 6: AI Security - Task 16.1
 * 
 * SECURITY FEATURES:
 * - Risk-based authentication using ML models
 * - Login context analysis (device, location, behavior)
 * - Risk score calculation (0-100)
 * - Adaptive auth requirements based on risk
 * 
 * INTEGRATION:
 * - AWS Bedrock for ML inference
 * - Combines multiple risk signals
 * - Real-time risk scoring
 * 
 * RISK FACTORS:
 * 1. Device trust (new device, fingerprint mismatch)
 * 2. Geographic anomaly (impossible travel, VPN/Tor)
 * 3. Behavioral anomaly (unusual time, frequency)
 * 4. Credential risk (breached password, weak password)
 * 5. Network risk (suspicious IP, datacenter)
 * 6. Historical risk (past suspicious activity)
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { logSimpleSecurityEvent } from './security-logger.service';
import { 
  DeviceFingerprintInput, 
  matchDevice, 
  StoredDevice,
  calculateTrustScore,
  getTrustLevel
} from './device.service';
import { 
  GeoLocation, 
  checkGeoVelocity, 
  isAnonymizedLocation,
  VelocityCheckResult,
  lookupIpLocation,
  getRealmVelocityConfig
} from './geo-velocity.service';
import { detectAttack, DetectionResult, AttackType } from './credential-stuffing.service';

// ============================================================================
// Types
// ============================================================================

/**
 * Risk assessment input
 */
export interface RiskAssessmentInput {
  // User context
  userId?: string;
  email: string;
  realmId: string;
  
  // Device context
  deviceFingerprint?: DeviceFingerprintInput;
  storedDevices?: StoredDevice[];
  
  // Network context
  ipAddress: string;
  geoLocation?: GeoLocation;
  userAgent?: string;
  
  // Behavioral context
  loginTimestamp?: number;
  previousLoginTimestamp?: number;
  failedAttempts?: number;
  
  // Credential context
  passwordStrength?: number; // 0-100
  isBreachedPassword?: boolean;
  
  // Historical context
  accountAge?: number; // days
  mfaEnabled?: boolean;
  previousRiskScores?: number[];
}

/**
 * Risk assessment result
 */
export interface RiskAssessmentResult {
  // Overall risk
  riskScore: number; // 0-100
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  // Component scores
  deviceRisk: number;
  geoRisk: number;
  behaviorRisk: number;
  credentialRisk: number;
  networkRisk: number;
  historicalRisk: number;
  
  // Risk factors detected
  riskFactors: RiskFactor[];
  
  // Recommended actions
  requiresMfa: boolean;
  requiresVerification: boolean;
  shouldBlock: boolean;
  shouldAlert: boolean;
  
  // Adaptive auth
  adaptiveAuthLevel: 'none' | 'mfa' | 'mfa_strict' | 'verification' | 'block';
  
  // Explanation
  explanation: string;
  
  // Metadata
  assessmentId: string;
  timestamp: string;
  modelVersion: string;
}

/**
 * Individual risk factor
 */
export interface RiskFactor {
  type: RiskFactorType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number; // 0-100
  description: string;
  details?: Record<string, unknown>;
}

/**
 * Risk factor types
 */
export enum RiskFactorType {
  NEW_DEVICE = 'new_device',
  DEVICE_MISMATCH = 'device_mismatch',
  IMPOSSIBLE_TRAVEL = 'impossible_travel',
  VPN_DETECTED = 'vpn_detected',
  TOR_DETECTED = 'tor_detected',
  PROXY_DETECTED = 'proxy_detected',
  DATACENTER_IP = 'datacenter_ip',
  UNUSUAL_TIME = 'unusual_time',
  HIGH_FREQUENCY = 'high_frequency',
  FAILED_ATTEMPTS = 'failed_attempts',
  WEAK_PASSWORD = 'weak_password',
  BREACHED_PASSWORD = 'breached_password',
  CREDENTIAL_STUFFING = 'credential_stuffing',
  BRUTE_FORCE = 'brute_force',
  DISTRIBUTED_ATTACK = 'distributed_attack',
  NEW_ACCOUNT = 'new_account',
  NO_MFA = 'no_mfa',
  SUSPICIOUS_COUNTRY = 'suspicious_country',
  PREVIOUS_HIGH_RISK = 'previous_high_risk'
}

// ============================================================================
// Configuration
// ============================================================================

/**
 * Risk scoring weights
 */
export const RISK_WEIGHTS = {
  device: 25,
  geo: 20,
  behavior: 15,
  credential: 20,
  network: 10,
  historical: 10
} as const;

/**
 * Risk thresholds
 */
export const RISK_THRESHOLDS = {
  low: 25,
  medium: 50,
  high: 75,
  critical: 90
} as const;

/**
 * Adaptive auth thresholds
 */
export const ADAPTIVE_AUTH_THRESHOLDS = {
  mfa: 30,           // Require MFA
  mfaStrict: 50,     // Require MFA + device verification
  verification: 70,  // Require email/phone verification
  block: 90          // Block login
} as const;

/**
 * High-risk countries (for additional scrutiny, not blocking)
 */
const HIGH_RISK_COUNTRIES = new Set([
  'RU', 'CN', 'KP', 'IR', 'NG', 'RO', 'UA', 'BY'
]);

// ============================================================================
// Bedrock Client
// ============================================================================

let bedrockClient: BedrockRuntimeClient | null = null;

function getBedrockClient(): BedrockRuntimeClient {
  if (!bedrockClient) {
    bedrockClient = new BedrockRuntimeClient({
      region: process.env.AWS_REGION || 'us-east-1'
    });
  }
  return bedrockClient;
}

// ============================================================================
// Risk Assessment Functions
// ============================================================================

/**
 * Perform comprehensive risk assessment
 */
export async function assessRisk(
  input: RiskAssessmentInput
): Promise<RiskAssessmentResult> {
  const assessmentId = generateAssessmentId();
  const timestamp = new Date().toISOString();
  const riskFactors: RiskFactor[] = [];

  // Calculate component risks
  const deviceRisk = await assessDeviceRisk(input, riskFactors);
  const geoRisk = await assessGeoRisk(input, riskFactors);
  const behaviorRisk = assessBehaviorRisk(input, riskFactors);
  const credentialRisk = assessCredentialRisk(input, riskFactors);
  const networkRisk = assessNetworkRisk(input, riskFactors);
  const historicalRisk = assessHistoricalRisk(input, riskFactors);

  // Calculate weighted overall risk score
  const riskScore = calculateOverallRisk({
    deviceRisk,
    geoRisk,
    behaviorRisk,
    credentialRisk,
    networkRisk,
    historicalRisk
  });

  // Determine risk level
  const riskLevel = determineRiskLevel(riskScore);

  // Determine adaptive auth requirements
  const adaptiveAuth = determineAdaptiveAuth(riskScore, riskFactors, input);

  // Generate explanation
  const explanation = generateExplanation(riskFactors, riskScore);

  // Log security event for high risk
  if (riskScore >= RISK_THRESHOLDS.high) {
    await logSecurityEvent(input, riskScore, riskLevel, riskFactors);
  }

  return {
    riskScore,
    riskLevel,
    deviceRisk,
    geoRisk,
    behaviorRisk,
    credentialRisk,
    networkRisk,
    historicalRisk,
    riskFactors,
    requiresMfa: adaptiveAuth.requiresMfa,
    requiresVerification: adaptiveAuth.requiresVerification,
    shouldBlock: adaptiveAuth.shouldBlock,
    shouldAlert: riskScore >= RISK_THRESHOLDS.high,
    adaptiveAuthLevel: adaptiveAuth.level,
    explanation,
    assessmentId,
    timestamp,
    modelVersion: '1.0.0'
  };
}

/**
 * Assess device-related risk
 */
async function assessDeviceRisk(
  input: RiskAssessmentInput,
  riskFactors: RiskFactor[]
): Promise<number> {
  let risk = 0;

  // No device fingerprint = higher risk
  if (!input.deviceFingerprint) {
    risk += 30;
    riskFactors.push({
      type: RiskFactorType.NEW_DEVICE,
      severity: 'medium',
      score: 30,
      description: 'No device fingerprint provided'
    });
    return Math.min(100, risk);
  }

  // Check against stored devices
  if (input.storedDevices && input.storedDevices.length > 0) {
    const match = matchDevice(input.deviceFingerprint, input.storedDevices);
    
    if (!match.matched) {
      risk += 40;
      riskFactors.push({
        type: RiskFactorType.NEW_DEVICE,
        severity: 'medium',
        score: 40,
        description: 'Login from new/unrecognized device',
        details: { similarityScore: match.similarityScore }
      });
    } else if (match.trustLevel === 'suspicious') {
      risk += 25;
      riskFactors.push({
        type: RiskFactorType.DEVICE_MISMATCH,
        severity: 'low',
        score: 25,
        description: 'Device fingerprint partially matches',
        details: { 
          similarityScore: match.similarityScore,
          componentScores: match.componentScores
        }
      });
    }
  } else {
    // First login, no stored devices
    risk += 20;
    riskFactors.push({
      type: RiskFactorType.NEW_DEVICE,
      severity: 'low',
      score: 20,
      description: 'First login - no device history'
    });
  }

  return Math.min(100, risk);
}

/**
 * Assess geographic risk
 */
async function assessGeoRisk(
  input: RiskAssessmentInput,
  riskFactors: RiskFactor[]
): Promise<number> {
  let risk = 0;

  if (!input.geoLocation) {
    return 20; // Unknown location = moderate risk
  }

  // Check for VPN/Proxy/Tor
  if (isAnonymizedLocation(input.geoLocation)) {
    if (input.geoLocation.isTor) {
      risk += 60;
      riskFactors.push({
        type: RiskFactorType.TOR_DETECTED,
        severity: 'high',
        score: 60,
        description: 'Tor exit node detected'
      });
    } else if (input.geoLocation.isVpn) {
      risk += 30;
      riskFactors.push({
        type: RiskFactorType.VPN_DETECTED,
        severity: 'medium',
        score: 30,
        description: 'VPN connection detected'
      });
    } else if (input.geoLocation.isProxy) {
      risk += 40;
      riskFactors.push({
        type: RiskFactorType.PROXY_DETECTED,
        severity: 'medium',
        score: 40,
        description: 'Proxy server detected'
      });
    } else if (input.geoLocation.isDatacenter) {
      risk += 35;
      riskFactors.push({
        type: RiskFactorType.DATACENTER_IP,
        severity: 'medium',
        score: 35,
        description: 'Datacenter IP detected'
      });
    }
  }

  // Check for high-risk country
  if (input.geoLocation.countryCode && HIGH_RISK_COUNTRIES.has(input.geoLocation.countryCode)) {
    risk += 20;
    riskFactors.push({
      type: RiskFactorType.SUSPICIOUS_COUNTRY,
      severity: 'low',
      score: 20,
      description: `Login from high-risk country: ${input.geoLocation.country}`,
      details: { countryCode: input.geoLocation.countryCode }
    });
  }

  // Check for impossible travel (if user exists)
  if (input.userId) {
    try {
      const velocityCheck = await checkGeoVelocity(
        input.userId,
        input.realmId,
        input.ipAddress,
        input.geoLocation
      );

      if (velocityCheck.isImpossibleTravel) {
        risk += 80;
        riskFactors.push({
          type: RiskFactorType.IMPOSSIBLE_TRAVEL,
          severity: 'critical',
          score: 80,
          description: velocityCheck.reason || 'Impossible travel detected',
          details: {
            distanceKm: velocityCheck.distanceKm,
            speedKmh: velocityCheck.speedKmh,
            timeElapsedHours: velocityCheck.timeElapsedHours
          }
        });
      } else if (velocityCheck.isSuspicious) {
        risk += 40;
        riskFactors.push({
          type: RiskFactorType.IMPOSSIBLE_TRAVEL,
          severity: 'medium',
          score: 40,
          description: velocityCheck.reason || 'Suspicious travel pattern',
          details: {
            distanceKm: velocityCheck.distanceKm,
            speedKmh: velocityCheck.speedKmh
          }
        });
      }
    } catch (error) {
      console.error('Geo velocity check error:', error);
    }
  }

  return Math.min(100, risk);
}

/**
 * Assess behavioral risk
 */
function assessBehaviorRisk(
  input: RiskAssessmentInput,
  riskFactors: RiskFactor[]
): number {
  let risk = 0;

  // Check login time (unusual hours)
  if (input.loginTimestamp) {
    const hour = new Date(input.loginTimestamp).getUTCHours();
    // Unusual hours: 2 AM - 5 AM local time (approximate)
    if (hour >= 2 && hour <= 5) {
      risk += 15;
      riskFactors.push({
        type: RiskFactorType.UNUSUAL_TIME,
        severity: 'low',
        score: 15,
        description: 'Login at unusual hour',
        details: { hour }
      });
    }
  }

  // Check login frequency
  if (input.previousLoginTimestamp && input.loginTimestamp) {
    const timeDiff = input.loginTimestamp - input.previousLoginTimestamp;
    const minutesDiff = timeDiff / (1000 * 60);
    
    // Very frequent logins (< 1 minute apart)
    if (minutesDiff < 1) {
      risk += 30;
      riskFactors.push({
        type: RiskFactorType.HIGH_FREQUENCY,
        severity: 'medium',
        score: 30,
        description: 'Very frequent login attempts',
        details: { minutesSinceLastLogin: minutesDiff }
      });
    }
  }

  // Check failed attempts
  if (input.failedAttempts && input.failedAttempts > 0) {
    const failedRisk = Math.min(50, input.failedAttempts * 10);
    risk += failedRisk;
    
    if (input.failedAttempts >= 3) {
      riskFactors.push({
        type: RiskFactorType.FAILED_ATTEMPTS,
        severity: input.failedAttempts >= 5 ? 'high' : 'medium',
        score: failedRisk,
        description: `${input.failedAttempts} failed login attempts`,
        details: { failedAttempts: input.failedAttempts }
      });
    }
  }

  return Math.min(100, risk);
}

/**
 * Assess credential risk
 */
function assessCredentialRisk(
  input: RiskAssessmentInput,
  riskFactors: RiskFactor[]
): number {
  let risk = 0;

  // Check password strength
  if (input.passwordStrength !== undefined) {
    if (input.passwordStrength < 30) {
      risk += 40;
      riskFactors.push({
        type: RiskFactorType.WEAK_PASSWORD,
        severity: 'high',
        score: 40,
        description: 'Very weak password detected',
        details: { strength: input.passwordStrength }
      });
    } else if (input.passwordStrength < 50) {
      risk += 20;
      riskFactors.push({
        type: RiskFactorType.WEAK_PASSWORD,
        severity: 'medium',
        score: 20,
        description: 'Weak password detected',
        details: { strength: input.passwordStrength }
      });
    }
  }

  // Check breached password
  if (input.isBreachedPassword) {
    risk += 70;
    riskFactors.push({
      type: RiskFactorType.BREACHED_PASSWORD,
      severity: 'critical',
      score: 70,
      description: 'Password found in known data breaches'
    });
  }

  return Math.min(100, risk);
}

/**
 * Assess network risk
 */
function assessNetworkRisk(
  input: RiskAssessmentInput,
  riskFactors: RiskFactor[]
): number {
  let risk = 0;

  // IP-based risks are mostly covered in geo risk
  // This handles additional network signals

  // Check user agent anomalies
  if (input.userAgent) {
    // Bot-like user agents
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java\//i
    ];
    
    if (botPatterns.some(pattern => pattern.test(input.userAgent!))) {
      risk += 50;
      riskFactors.push({
        type: RiskFactorType.DATACENTER_IP,
        severity: 'high',
        score: 50,
        description: 'Bot-like user agent detected',
        details: { userAgent: input.userAgent }
      });
    }

    // Empty or very short user agent
    if (input.userAgent.length < 20) {
      risk += 20;
    }
  } else {
    // No user agent
    risk += 25;
  }

  return Math.min(100, risk);
}

/**
 * Assess historical risk
 */
function assessHistoricalRisk(
  input: RiskAssessmentInput,
  riskFactors: RiskFactor[]
): number {
  let risk = 0;

  // New account risk
  if (input.accountAge !== undefined && input.accountAge < 7) {
    risk += 20;
    riskFactors.push({
      type: RiskFactorType.NEW_ACCOUNT,
      severity: 'low',
      score: 20,
      description: 'Recently created account',
      details: { accountAgeDays: input.accountAge }
    });
  }

  // No MFA enabled
  if (input.mfaEnabled === false) {
    risk += 15;
    riskFactors.push({
      type: RiskFactorType.NO_MFA,
      severity: 'low',
      score: 15,
      description: 'MFA not enabled on account'
    });
  }

  // Previous high risk scores
  if (input.previousRiskScores && input.previousRiskScores.length > 0) {
    const recentHighRisk = input.previousRiskScores.filter(s => s >= RISK_THRESHOLDS.high);
    if (recentHighRisk.length > 0) {
      const avgHighRisk = recentHighRisk.reduce((a, b) => a + b, 0) / recentHighRisk.length;
      risk += Math.min(30, avgHighRisk * 0.3);
      riskFactors.push({
        type: RiskFactorType.PREVIOUS_HIGH_RISK,
        severity: 'medium',
        score: Math.min(30, avgHighRisk * 0.3),
        description: 'Previous high-risk login attempts',
        details: { 
          highRiskCount: recentHighRisk.length,
          averageRisk: avgHighRisk
        }
      });
    }
  }

  return Math.min(100, risk);
}

/**
 * Calculate overall weighted risk score
 */
function calculateOverallRisk(scores: {
  deviceRisk: number;
  geoRisk: number;
  behaviorRisk: number;
  credentialRisk: number;
  networkRisk: number;
  historicalRisk: number;
}): number {
  const weighted = 
    (scores.deviceRisk * RISK_WEIGHTS.device / 100) +
    (scores.geoRisk * RISK_WEIGHTS.geo / 100) +
    (scores.behaviorRisk * RISK_WEIGHTS.behavior / 100) +
    (scores.credentialRisk * RISK_WEIGHTS.credential / 100) +
    (scores.networkRisk * RISK_WEIGHTS.network / 100) +
    (scores.historicalRisk * RISK_WEIGHTS.historical / 100);

  return Math.round(Math.min(100, weighted));
}

/**
 * Determine risk level from score
 */
function determineRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score >= RISK_THRESHOLDS.critical) return 'critical';
  if (score >= RISK_THRESHOLDS.high) return 'high';
  if (score >= RISK_THRESHOLDS.medium) return 'medium';
  return 'low';
}

/**
 * Determine adaptive authentication requirements
 */
function determineAdaptiveAuth(
  riskScore: number,
  riskFactors: RiskFactor[],
  input: RiskAssessmentInput
): {
  level: 'none' | 'mfa' | 'mfa_strict' | 'verification' | 'block';
  requiresMfa: boolean;
  requiresVerification: boolean;
  shouldBlock: boolean;
} {
  // Critical risk factors that always require action
  const hasCriticalFactor = riskFactors.some(f => f.severity === 'critical');
  const hasImpossibleTravel = riskFactors.some(f => f.type === RiskFactorType.IMPOSSIBLE_TRAVEL);
  const hasBreachedPassword = riskFactors.some(f => f.type === RiskFactorType.BREACHED_PASSWORD);

  // Block on critical risk
  if (riskScore >= ADAPTIVE_AUTH_THRESHOLDS.block || (hasCriticalFactor && hasImpossibleTravel)) {
    return {
      level: 'block',
      requiresMfa: true,
      requiresVerification: true,
      shouldBlock: true
    };
  }

  // Require verification on high risk
  if (riskScore >= ADAPTIVE_AUTH_THRESHOLDS.verification || hasBreachedPassword) {
    return {
      level: 'verification',
      requiresMfa: true,
      requiresVerification: true,
      shouldBlock: false
    };
  }

  // Require strict MFA on medium-high risk
  if (riskScore >= ADAPTIVE_AUTH_THRESHOLDS.mfaStrict || hasCriticalFactor) {
    return {
      level: 'mfa_strict',
      requiresMfa: true,
      requiresVerification: false,
      shouldBlock: false
    };
  }

  // Require MFA on medium risk
  if (riskScore >= ADAPTIVE_AUTH_THRESHOLDS.mfa) {
    return {
      level: 'mfa',
      requiresMfa: true,
      requiresVerification: false,
      shouldBlock: false
    };
  }

  // Low risk - no additional auth required
  return {
    level: 'none',
    requiresMfa: false,
    requiresVerification: false,
    shouldBlock: false
  };
}

/**
 * Generate human-readable explanation
 */
function generateExplanation(riskFactors: RiskFactor[], riskScore: number): string {
  if (riskFactors.length === 0) {
    return 'No risk factors detected. Login appears normal.';
  }

  const criticalFactors = riskFactors.filter(f => f.severity === 'critical');
  const highFactors = riskFactors.filter(f => f.severity === 'high');

  if (criticalFactors.length > 0) {
    return `Critical risk detected: ${criticalFactors.map(f => f.description).join('; ')}`;
  }

  if (highFactors.length > 0) {
    return `High risk detected: ${highFactors.map(f => f.description).join('; ')}`;
  }

  return `Risk score ${riskScore}: ${riskFactors.slice(0, 3).map(f => f.description).join('; ')}`;
}

/**
 * Log security event for risk assessment
 */
async function logSecurityEvent(
  input: RiskAssessmentInput,
  riskScore: number,
  riskLevel: string,
  riskFactors: RiskFactor[]
): Promise<void> {
  try {
    await logSimpleSecurityEvent({
      event_type: 'high_risk_login_attempt',
      realm_id: input.realmId,
      user_id: input.userId,
      ip_address: input.ipAddress,
      details: {
        email: input.email,
        risk_score: riskScore,
        risk_level: riskLevel,
        risk_factors: riskFactors.map(f => ({
          type: f.type,
          severity: f.severity,
          score: f.score
        })),
        location: input.geoLocation ? {
          city: input.geoLocation.city,
          country: input.geoLocation.country
        } : undefined
      }
    });
  } catch (error) {
    console.error('Failed to log security event:', error);
  }
}

/**
 * Generate unique assessment ID
 */
function generateAssessmentId(): string {
  return `risk_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}


// ============================================================================
// Bedrock ML Integration
// ============================================================================

/**
 * ML model input for risk prediction
 */
interface MLRiskInput {
  features: {
    device_trust_score: number;
    geo_risk_score: number;
    behavior_risk_score: number;
    credential_risk_score: number;
    network_risk_score: number;
    historical_risk_score: number;
    is_new_device: boolean;
    is_vpn: boolean;
    is_tor: boolean;
    is_impossible_travel: boolean;
    failed_attempts: number;
    account_age_days: number;
    mfa_enabled: boolean;
    hour_of_day: number;
    day_of_week: number;
  };
}

/**
 * ML model output
 */
interface MLRiskOutput {
  risk_score: number;
  confidence: number;
  anomaly_detected: boolean;
  recommended_action: string;
}

/**
 * Use Bedrock ML model for enhanced risk scoring
 * Falls back to rule-based scoring if Bedrock is unavailable
 * 
 * Enhanced in Task 15.3 with:
 * - Anomaly detection model
 * - Behavior pattern analysis
 * - Risk factor correlation
 */
export async function assessRiskWithML(
  input: RiskAssessmentInput
): Promise<RiskAssessmentResult> {
  // First, get rule-based assessment
  const ruleBasedResult = await assessRisk(input);

  // Try enhanced Bedrock ML analysis
  try {
    // Import the enhanced Bedrock service dynamically to avoid circular deps
    const { 
      analyzeRiskWithBedrock, 
      createAnonymizedContext, 
      blendWithRuleBasedResult,
      isBedrockAvailable 
    } = await import('./bedrock-risk.service');
    
    // Check if Bedrock is available
    if (!isBedrockAvailable()) {
      // Fall back to legacy ML if available
      const mlInput = prepareMLInput(input, ruleBasedResult);
      const mlOutput = await invokeBedrockModel(mlInput);
      
      if (mlOutput) {
        const blendedScore = Math.round(
          (ruleBasedResult.riskScore * 0.6) + (mlOutput.risk_score * 0.4)
        );
        
        return {
          ...ruleBasedResult,
          riskScore: blendedScore,
          riskLevel: determineRiskLevel(blendedScore),
          modelVersion: '1.0.0-ml-legacy',
          explanation: mlOutput.anomaly_detected
            ? `ML anomaly detected: ${ruleBasedResult.explanation}`
            : ruleBasedResult.explanation
        };
      }
      
      return ruleBasedResult;
    }
    
    // Create anonymized context for Bedrock (NO PII)
    const anonymizedContext = createAnonymizedContext({
      deviceRisk: ruleBasedResult.deviceRisk,
      geoRisk: ruleBasedResult.geoRisk,
      behaviorRisk: ruleBasedResult.behaviorRisk,
      credentialRisk: ruleBasedResult.credentialRisk,
      networkRisk: ruleBasedResult.networkRisk,
      historicalRisk: ruleBasedResult.historicalRisk,
      riskFactors: ruleBasedResult.riskFactors,
      isVpn: input.geoLocation?.isVpn,
      isTor: input.geoLocation?.isTor,
      isProxy: input.geoLocation?.isProxy,
      isDatacenter: input.geoLocation?.isDatacenter,
      loginTimestamp: input.loginTimestamp,
      failedAttempts: input.failedAttempts,
      accountAgeDays: input.accountAge,
      mfaEnabled: input.mfaEnabled,
      passwordStrength: input.passwordStrength,
      isBreachedPassword: input.isBreachedPassword,
      previousRiskScores: input.previousRiskScores
    });
    
    // Analyze with enhanced Bedrock service
    const bedrockResult = await analyzeRiskWithBedrock(anonymizedContext);
    
    if (bedrockResult) {
      // Blend ML and rule-based scores
      const { blendedScore, usedML, confidence } = blendWithRuleBasedResult(
        ruleBasedResult.riskScore,
        bedrockResult,
        0.4 // 40% ML weight
      );
      
      // Determine new risk level
      const newRiskLevel = determineRiskLevel(blendedScore);
      
      // Update adaptive auth based on ML recommendation
      const adaptiveAuth = determineAdaptiveAuth(blendedScore, ruleBasedResult.riskFactors, input);
      
      // Build enhanced explanation
      let explanation = ruleBasedResult.explanation;
      if (bedrockResult.anomalyDetected) {
        explanation = `ML anomaly detected (${bedrockResult.anomalyTypes.join(', ')}): ${explanation}`;
      }
      if (bedrockResult.primaryThreat) {
        explanation = `Primary threat: ${bedrockResult.primaryThreat}. ${explanation}`;
      }
      
      return {
        ...ruleBasedResult,
        riskScore: blendedScore,
        riskLevel: newRiskLevel,
        requiresMfa: adaptiveAuth.requiresMfa || bedrockResult.recommendedAction !== 'allow',
        requiresVerification: adaptiveAuth.requiresVerification || bedrockResult.recommendedAction === 'verify',
        shouldBlock: adaptiveAuth.shouldBlock || bedrockResult.recommendedAction === 'block',
        shouldAlert: blendedScore >= RISK_THRESHOLDS.high || bedrockResult.anomalyDetected,
        adaptiveAuthLevel: adaptiveAuth.level,
        explanation,
        modelVersion: usedML ? `2.0.0-bedrock-enhanced (confidence: ${confidence}%)` : '1.0.0'
      };
    }
  } catch (error) {
    console.error('Enhanced ML risk assessment failed, using rule-based:', error);
  }

  return ruleBasedResult;
}

/**
 * Prepare input for ML model
 */
function prepareMLInput(
  input: RiskAssessmentInput,
  ruleBasedResult: RiskAssessmentResult
): MLRiskInput {
  const now = new Date(input.loginTimestamp || Date.now());

  return {
    features: {
      device_trust_score: 100 - ruleBasedResult.deviceRisk,
      geo_risk_score: ruleBasedResult.geoRisk,
      behavior_risk_score: ruleBasedResult.behaviorRisk,
      credential_risk_score: ruleBasedResult.credentialRisk,
      network_risk_score: ruleBasedResult.networkRisk,
      historical_risk_score: ruleBasedResult.historicalRisk,
      is_new_device: ruleBasedResult.riskFactors.some(f => f.type === RiskFactorType.NEW_DEVICE),
      is_vpn: input.geoLocation?.isVpn || false,
      is_tor: input.geoLocation?.isTor || false,
      is_impossible_travel: ruleBasedResult.riskFactors.some(f => f.type === RiskFactorType.IMPOSSIBLE_TRAVEL),
      failed_attempts: input.failedAttempts || 0,
      account_age_days: input.accountAge || 0,
      mfa_enabled: input.mfaEnabled || false,
      hour_of_day: now.getUTCHours(),
      day_of_week: now.getUTCDay()
    }
  };
}

/**
 * Invoke Bedrock model for risk prediction
 */
async function invokeBedrockModel(input: MLRiskInput): Promise<MLRiskOutput | null> {
  // Skip if Bedrock is not configured
  if (!process.env.BEDROCK_MODEL_ID) {
    return null;
  }

  try {
    const client = getBedrockClient();
    
    // Use Claude for risk analysis
    const prompt = buildRiskAnalysisPrompt(input);
    
    const command = new InvokeModelCommand({
      modelId: process.env.BEDROCK_MODEL_ID || 'anthropic.claude-3-haiku-20240307-v1:0',
      contentType: 'application/json',
      accept: 'application/json',
      body: JSON.stringify({
        anthropic_version: 'bedrock-2023-05-31',
        max_tokens: 500,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      })
    });

    const response = await client.send(command);
    const responseBody = JSON.parse(new TextDecoder().decode(response.body));
    
    // Parse Claude's response
    return parseMLResponse(responseBody);
  } catch (error) {
    console.error('Bedrock invocation error:', error);
    return null;
  }
}

/**
 * Build prompt for risk analysis
 */
function buildRiskAnalysisPrompt(input: MLRiskInput): string {
  return `Analyze this login attempt for security risk. Return ONLY a JSON object with risk_score (0-100), confidence (0-100), anomaly_detected (boolean), and recommended_action (string).

Login Features:
- Device Trust Score: ${input.features.device_trust_score}
- Geo Risk Score: ${input.features.geo_risk_score}
- Behavior Risk Score: ${input.features.behavior_risk_score}
- Credential Risk Score: ${input.features.credential_risk_score}
- Network Risk Score: ${input.features.network_risk_score}
- Historical Risk Score: ${input.features.historical_risk_score}
- New Device: ${input.features.is_new_device}
- VPN: ${input.features.is_vpn}
- Tor: ${input.features.is_tor}
- Impossible Travel: ${input.features.is_impossible_travel}
- Failed Attempts: ${input.features.failed_attempts}
- Account Age (days): ${input.features.account_age_days}
- MFA Enabled: ${input.features.mfa_enabled}
- Hour of Day (UTC): ${input.features.hour_of_day}
- Day of Week: ${input.features.day_of_week}

Respond with JSON only:`;
}

/**
 * Parse ML model response
 */
function parseMLResponse(responseBody: Record<string, unknown>): MLRiskOutput | null {
  try {
    const content = responseBody.content as Array<{ text?: string }>;
    if (!content || !content[0]?.text) return null;

    const text = content[0].text;
    // Extract JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]);
    return {
      risk_score: Math.min(100, Math.max(0, parsed.risk_score || 50)),
      confidence: Math.min(100, Math.max(0, parsed.confidence || 50)),
      anomaly_detected: parsed.anomaly_detected || false,
      recommended_action: parsed.recommended_action || 'allow'
    };
  } catch (error) {
    console.error('Failed to parse ML response:', error);
    return null;
  }
}

// ============================================================================
// Attack Detection Integration
// ============================================================================

/**
 * Comprehensive risk assessment with attack detection
 */
export async function assessRiskWithAttackDetection(
  input: RiskAssessmentInput,
  password?: string
): Promise<RiskAssessmentResult & { attackDetection?: DetectionResult }> {
  // Get base risk assessment
  const riskResult = await assessRisk(input);

  // Run attack detection if password provided
  if (password) {
    try {
      const attackResult = await detectAttack(
        input.realmId,
        input.email,
        input.ipAddress,
        password
      );

      if (attackResult.detected) {
        // Add attack-related risk factors
        const attackFactor: RiskFactor = {
          type: mapAttackTypeToRiskFactor(attackResult.attackType!),
          severity: attackResult.confidence >= 80 ? 'critical' : 'high',
          score: attackResult.confidence,
          description: `${attackResult.attackType} attack detected`,
          details: attackResult.details
        };

        riskResult.riskFactors.push(attackFactor);

        // Recalculate risk score
        const attackRisk = attackResult.confidence;
        const newRiskScore = Math.min(100, Math.round(
          (riskResult.riskScore * 0.7) + (attackRisk * 0.3)
        ));

        return {
          ...riskResult,
          riskScore: newRiskScore,
          riskLevel: determineRiskLevel(newRiskScore),
          shouldBlock: attackResult.shouldBlock || riskResult.shouldBlock,
          requiresMfa: attackResult.requiresCaptcha || riskResult.requiresMfa,
          attackDetection: attackResult
        };
      }
    } catch (error) {
      console.error('Attack detection error:', error);
    }
  }

  return riskResult;
}

/**
 * Map attack type to risk factor type
 */
function mapAttackTypeToRiskFactor(attackType: AttackType): RiskFactorType {
  switch (attackType) {
    case AttackType.CREDENTIAL_STUFFING:
      return RiskFactorType.CREDENTIAL_STUFFING;
    case AttackType.BRUTE_FORCE:
      return RiskFactorType.BRUTE_FORCE;
    case AttackType.DISTRIBUTED_ATTACK:
      return RiskFactorType.DISTRIBUTED_ATTACK;
    case AttackType.HIGH_VELOCITY:
      return RiskFactorType.HIGH_FREQUENCY;
    default:
      return RiskFactorType.BRUTE_FORCE;
  }
}

// ============================================================================
// Risk Score History
// ============================================================================

/**
 * Store risk assessment result for historical analysis
 */
export async function storeRiskAssessment(
  userId: string,
  realmId: string,
  result: RiskAssessmentResult
): Promise<void> {
  // This would store to DynamoDB for historical tracking
  // Implementation depends on your data model
  console.log(`Storing risk assessment for user ${userId}: score=${result.riskScore}`);
}

/**
 * Get recent risk scores for a user
 */
export async function getRecentRiskScores(
  userId: string,
  realmId: string,
  limit: number = 10
): Promise<number[]> {
  // This would query DynamoDB for recent assessments
  // Implementation depends on your data model
  return [];
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Check if risk level requires MFA
 */
export function requiresMfaForRisk(riskLevel: string): boolean {
  return riskLevel === 'medium' || riskLevel === 'high' || riskLevel === 'critical';
}

/**
 * Check if risk level should block login
 */
export function shouldBlockForRisk(riskLevel: string): boolean {
  return riskLevel === 'critical';
}

/**
 * Get risk color for UI display
 */
export function getRiskColor(riskLevel: string): string {
  switch (riskLevel) {
    case 'low': return '#22c55e';      // green
    case 'medium': return '#f59e0b';   // amber
    case 'high': return '#ef4444';     // red
    case 'critical': return '#7f1d1d'; // dark red
    default: return '#6b7280';         // gray
  }
}

/**
 * Format risk score for display
 */
export function formatRiskScore(score: number): string {
  if (score >= 90) return 'Critical';
  if (score >= 75) return 'High';
  if (score >= 50) return 'Medium';
  if (score >= 25) return 'Low';
  return 'Minimal';
}

// ============================================================================
// AIRiskService Class - Task 15.2
// ============================================================================

/**
 * Login context for risk assessment
 * Used by assessLoginRisk method
 */
export interface LoginContext {
  userId?: string;
  email: string;
  realmId: string;
  ip: string;
  userAgent?: string;
  deviceFingerprint?: DeviceFingerprintInput;
  geoLocation?: GeoLocation;
  timestamp?: number;
  previousAttempts?: number;
  failedAttempts?: number;
  passwordStrength?: number;
  isBreachedPassword?: boolean;
  accountAge?: number;
  mfaEnabled?: boolean;
}

/**
 * Behavior event for user profile updates
 */
export interface BehaviorEvent {
  type: 'login_success' | 'login_failure' | 'password_change' | 'mfa_setup' | 'session_created' | 'api_call';
  timestamp: number;
  ip?: string;
  userAgent?: string;
  geoLocation?: GeoLocation;
  deviceFingerprint?: string;
  metadata?: Record<string, unknown>;
}

/**
 * User behavior profile
 */
export interface UserBehaviorProfile {
  userId: string;
  realmId: string;
  typicalLoginHours: number[];  // Hours of day (0-23) when user typically logs in
  typicalCountries: string[];   // Country codes where user typically logs in
  typicalDevices: string[];     // Device fingerprint hashes
  averageSessionDuration: number; // Average session duration in minutes
  loginFrequency: number;       // Average logins per week
  lastUpdated: string;
  eventCount: number;
}

/**
 * IP reputation result
 */
export interface IPReputationResult {
  score: number;              // 0-100 (0 = bad, 100 = good)
  isTor: boolean;
  isVpn: boolean;
  isProxy: boolean;
  isDatacenter: boolean;
  isKnownAttacker: boolean;
  threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  country?: string;
  asn?: string;
  isp?: string;
}

/**
 * Device trust result
 */
export interface DeviceTrustResult {
  score: number;              // 0-100 (0 = untrusted, 100 = fully trusted)
  isKnownDevice: boolean;
  isNewDevice: boolean;
  trustLevel: 'untrusted' | 'suspicious' | 'partial' | 'trusted';
  lastSeen?: string;
  loginCount?: number;
  matchedDeviceId?: string;
}

/**
 * AIRiskService - AI-Powered Risk Assessment Service
 * 
 * Provides comprehensive risk assessment for login attempts and user behavior.
 * Uses multiple signals including IP reputation, device trust, geo-velocity,
 * and behavior patterns to calculate risk scores.
 * 
 * Security Requirements:
 * - Risk scores must be deterministic for same inputs
 * - No information leakage in error messages
 * - All assessments are audit logged
 * 
 * Validates: Requirements 10.1, 10.2, 10.5, 10.6
 */
export class AIRiskService {
  private realmId: string;
  
  // In-memory cache for IP reputation (in production, use Redis/DynamoDB)
  private ipReputationCache: Map<string, { result: IPReputationResult; timestamp: number }> = new Map();
  private readonly IP_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
  
  // Known malicious IP ranges (simplified - in production use threat intelligence feeds)
  private readonly KNOWN_MALICIOUS_ASNS = new Set([
    'AS14061', // DigitalOcean (often abused)
    'AS16276', // OVH (often abused)
    'AS45102', // Alibaba Cloud
  ]);
  
  // Known Tor exit node IPs (simplified - in production use Tor exit list)
  private readonly KNOWN_TOR_EXITS = new Set([
    '185.220.101.1',
    '185.220.101.2',
    '185.220.102.1',
  ]);
  
  constructor(realmId: string) {
    this.realmId = realmId;
  }

  /**
   * Assess login risk based on context
   * 
   * Calculates a risk score (0-100) based on multiple factors:
   * - IP reputation
   * - Device trust
   * - Geographic velocity (impossible travel)
   * - Behavior patterns
   * - Credential risk
   * 
   * @param context - Login context with all available signals
   * @returns Risk assessment result with score and recommendation
   * 
   * Validates: Requirements 10.1, 10.2
   */
  async assessLoginRisk(context: LoginContext): Promise<RiskAssessmentResult> {
    const startTime = Date.now();
    
    // Convert LoginContext to RiskAssessmentInput
    const input: RiskAssessmentInput = {
      userId: context.userId,
      email: context.email,
      realmId: context.realmId || this.realmId,
      ipAddress: context.ip,
      userAgent: context.userAgent,
      deviceFingerprint: context.deviceFingerprint,
      geoLocation: context.geoLocation,
      loginTimestamp: context.timestamp || Date.now(),
      failedAttempts: context.failedAttempts ?? context.previousAttempts,
      passwordStrength: context.passwordStrength,
      isBreachedPassword: context.isBreachedPassword,
      accountAge: context.accountAge,
      mfaEnabled: context.mfaEnabled
    };

    // Get stored devices for the user if userId is provided
    if (context.userId && context.deviceFingerprint) {
      const storedDevices = await this.getStoredDevicesForUser(context.userId);
      input.storedDevices = storedDevices;
    }

    // Get previous risk scores for historical context
    if (context.userId) {
      const previousScores = await getRecentRiskScores(context.userId, this.realmId, 5);
      input.previousRiskScores = previousScores;
    }

    // Perform the risk assessment
    const result = await assessRisk(input);

    // Log the assessment for audit
    const processingTime = Date.now() - startTime;
    await this.logRiskAssessment(context, result, processingTime);

    return result;
  }

  /**
   * Update user behavior profile based on an event
   * 
   * Learns user patterns over time to improve risk assessment accuracy.
   * Tracks typical login hours, locations, devices, and session patterns.
   * 
   * @param userId - User ID
   * @param event - Behavior event to record
   * 
   * Validates: Requirement 10.6
   */
  async updateUserBehaviorProfile(userId: string, event: BehaviorEvent): Promise<void> {
    try {
      // Get existing profile or create new one
      let profile = await this.getUserBehaviorProfile(userId);
      
      if (!profile) {
        profile = {
          userId,
          realmId: this.realmId,
          typicalLoginHours: [],
          typicalCountries: [],
          typicalDevices: [],
          averageSessionDuration: 0,
          loginFrequency: 0,
          lastUpdated: new Date().toISOString(),
          eventCount: 0
        };
      }

      // Update profile based on event type
      if (event.type === 'login_success') {
        // Update typical login hours
        const hour = new Date(event.timestamp).getUTCHours();
        if (!profile.typicalLoginHours.includes(hour)) {
          profile.typicalLoginHours.push(hour);
          // Keep only last 24 unique hours
          if (profile.typicalLoginHours.length > 24) {
            profile.typicalLoginHours = profile.typicalLoginHours.slice(-24);
          }
        }

        // Update typical countries
        if (event.geoLocation?.countryCode) {
          if (!profile.typicalCountries.includes(event.geoLocation.countryCode)) {
            profile.typicalCountries.push(event.geoLocation.countryCode);
            // Keep only last 10 countries
            if (profile.typicalCountries.length > 10) {
              profile.typicalCountries = profile.typicalCountries.slice(-10);
            }
          }
        }

        // Update typical devices
        if (event.deviceFingerprint) {
          if (!profile.typicalDevices.includes(event.deviceFingerprint)) {
            profile.typicalDevices.push(event.deviceFingerprint);
            // Keep only last 10 devices
            if (profile.typicalDevices.length > 10) {
              profile.typicalDevices = profile.typicalDevices.slice(-10);
            }
          }
        }

        // Update login frequency (simplified calculation)
        profile.loginFrequency = Math.min(profile.loginFrequency + 0.1, 50);
      }

      // Update metadata
      profile.eventCount++;
      profile.lastUpdated = new Date().toISOString();

      // Store updated profile
      await this.storeUserBehaviorProfile(profile);

      // Log the update
      await logSimpleSecurityEvent({
        event_type: 'behavior_profile_updated',
        realm_id: this.realmId,
        user_id: userId,
        details: {
          event_type: event.type,
          event_count: profile.eventCount
        }
      });
    } catch (error) {
      console.error('Failed to update user behavior profile:', error);
      // Don't throw - behavior profile updates should not block login
    }
  }

  /**
   * Detect impossible travel for a user
   * 
   * Checks if the user could have physically traveled from their last
   * known location to the current location. Uses geo-velocity calculation
   * with a threshold of 1000 km/h (faster than commercial aircraft).
   * 
   * @param userId - User ID
   * @param currentLocation - Current geo-location
   * @returns True if impossible travel is detected
   * 
   * Validates: Requirement 10.2
   */
  async detectImpossibleTravel(userId: string, currentLocation: GeoLocation): Promise<boolean> {
    try {
      // Get the velocity check result
      const velocityResult = await checkGeoVelocity(
        userId,
        this.realmId,
        '0.0.0.0', // IP not needed for this check
        currentLocation,
        getRealmVelocityConfig(this.realmId)
      );

      // Log if impossible travel detected
      if (velocityResult.isImpossibleTravel) {
        await logSimpleSecurityEvent({
          event_type: 'impossible_travel_detected',
          realm_id: this.realmId,
          user_id: userId,
          details: {
            previous_location: velocityResult.previousLocation 
              ? `${velocityResult.previousLocation.city}, ${velocityResult.previousLocation.country}`
              : 'unknown',
            current_location: `${currentLocation.city}, ${currentLocation.country}`,
            distance_km: Math.round(velocityResult.distanceKm),
            speed_kmh: Math.round(velocityResult.speedKmh),
            time_elapsed_hours: velocityResult.timeElapsedHours.toFixed(2)
          }
        });
      }

      return velocityResult.isImpossibleTravel;
    } catch (error) {
      console.error('Failed to detect impossible travel:', error);
      return false; // Fail open - don't block on errors
    }
  }

  /**
   * Check IP reputation
   * 
   * Evaluates the reputation of an IP address based on:
   * - Known malicious IP databases
   * - Tor exit node detection
   * - VPN/Proxy detection
   * - Datacenter IP detection
   * - Geographic risk factors
   * 
   * @param ip - IP address to check
   * @returns IP reputation score (0-100, higher is better)
   * 
   * Validates: Requirement 10.5
   */
  async checkIPReputation(ip: string): Promise<number> {
    try {
      const result = await this.getIPReputationDetails(ip);
      return result.score;
    } catch (error) {
      console.error('Failed to check IP reputation:', error);
      return 50; // Return neutral score on error
    }
  }

  /**
   * Get detailed IP reputation information
   * 
   * @param ip - IP address to check
   * @returns Detailed IP reputation result
   */
  async getIPReputationDetails(ip: string): Promise<IPReputationResult> {
    // Check cache first
    const cached = this.ipReputationCache.get(ip);
    if (cached && (Date.now() - cached.timestamp) < this.IP_CACHE_TTL_MS) {
      return cached.result;
    }

    // Initialize result
    const result: IPReputationResult = {
      score: 100, // Start with perfect score
      isTor: false,
      isVpn: false,
      isProxy: false,
      isDatacenter: false,
      isKnownAttacker: false,
      threatLevel: 'none'
    };

    // Check for Tor exit nodes
    if (this.KNOWN_TOR_EXITS.has(ip)) {
      result.isTor = true;
      result.score -= 60;
      result.threatLevel = 'high';
    }

    // Check for private/reserved IPs (likely VPN/Proxy)
    if (this.isPrivateIP(ip)) {
      result.isVpn = true;
      result.isDatacenter = true;
      result.score -= 30;
      if (result.threatLevel === 'none') result.threatLevel = 'medium';
    }

    // Check for datacenter IPs (simplified check)
    if (this.isDatacenterIP(ip)) {
      result.isDatacenter = true;
      result.score -= 20;
      if (result.threatLevel === 'none') result.threatLevel = 'low';
    }

    // Lookup geo information
    const geoInfo = await lookupIpLocation(ip);
    if (geoInfo) {
      result.country = geoInfo.countryCode;
      
      if (geoInfo.isVpn) {
        result.isVpn = true;
        result.score -= 30;
        if (result.threatLevel === 'none') result.threatLevel = 'medium';
      }
      
      if (geoInfo.isProxy) {
        result.isProxy = true;
        result.score -= 25;
        if (result.threatLevel === 'none') result.threatLevel = 'medium';
      }
      
      if (geoInfo.isTor) {
        result.isTor = true;
        result.score -= 60;
        result.threatLevel = 'high';
      }
      
      if (geoInfo.isDatacenter) {
        result.isDatacenter = true;
        result.score -= 20;
        if (result.threatLevel === 'none') result.threatLevel = 'low';
      }
    }

    // Ensure score is within bounds
    result.score = Math.max(0, Math.min(100, result.score));

    // Determine final threat level based on score
    if (result.score < 20) result.threatLevel = 'critical';
    else if (result.score < 40) result.threatLevel = 'high';
    else if (result.score < 60) result.threatLevel = 'medium';
    else if (result.score < 80) result.threatLevel = 'low';
    else result.threatLevel = 'none';

    // Cache the result
    this.ipReputationCache.set(ip, { result, timestamp: Date.now() });

    return result;
  }

  /**
   * Get device trust score
   * 
   * Evaluates how trustworthy a device is based on:
   * - Whether it's a known device for this user
   * - Device fingerprint similarity to known devices
   * - Login history from this device
   * - Device age (how long it's been trusted)
   * 
   * @param fingerprint - Device fingerprint
   * @param userId - User ID
   * @returns Device trust score (0-100, higher is more trusted)
   * 
   * Validates: Requirement 10.6
   */
  async getDeviceTrustScore(fingerprint: DeviceFingerprintInput, userId: string): Promise<number> {
    try {
      const result = await this.getDeviceTrustDetails(fingerprint, userId);
      return result.score;
    } catch (error) {
      console.error('Failed to get device trust score:', error);
      return 30; // Return low trust score on error
    }
  }

  /**
   * Get detailed device trust information
   * 
   * @param fingerprint - Device fingerprint
   * @param userId - User ID
   * @returns Detailed device trust result
   */
  async getDeviceTrustDetails(fingerprint: DeviceFingerprintInput, userId: string): Promise<DeviceTrustResult> {
    // Get stored devices for the user
    const storedDevices = await this.getStoredDevicesForUser(userId);

    if (storedDevices.length === 0) {
      // No stored devices - this is a new device
      return {
        score: 30,
        isKnownDevice: false,
        isNewDevice: true,
        trustLevel: 'suspicious'
      };
    }

    // Match against stored devices
    const matchResult = matchDevice(fingerprint, storedDevices);

    if (!matchResult.matched) {
      // Device doesn't match any known devices
      return {
        score: 20,
        isKnownDevice: false,
        isNewDevice: true,
        trustLevel: 'untrusted'
      };
    }

    // Device matched - calculate trust score
    const matchedDevice = matchResult.device!;
    const similarityScore = matchResult.similarityScore;

    // Calculate trust score based on multiple factors
    let score = 0;

    // Similarity score contribution (0-40 points)
    score += Math.round(similarityScore * 0.4);

    // Login count contribution (0-30 points)
    const loginCountScore = Math.min(30, matchedDevice.loginCount * 3);
    score += loginCountScore;

    // Device age contribution (0-20 points)
    const deviceAgeMs = Date.now() - new Date(matchedDevice.firstSeenAt).getTime();
    const deviceAgeDays = deviceAgeMs / (1000 * 60 * 60 * 24);
    const ageScore = Math.min(20, deviceAgeDays * 0.5);
    score += Math.round(ageScore);

    // Trusted flag contribution (0-10 points)
    if (matchedDevice.trusted) {
      score += 10;
    }

    // Ensure score is within bounds
    score = Math.max(0, Math.min(100, score));

    // Determine trust level
    let trustLevel: 'untrusted' | 'suspicious' | 'partial' | 'trusted';
    if (score >= 80) trustLevel = 'trusted';
    else if (score >= 60) trustLevel = 'partial';
    else if (score >= 40) trustLevel = 'suspicious';
    else trustLevel = 'untrusted';

    return {
      score,
      isKnownDevice: true,
      isNewDevice: false,
      trustLevel,
      lastSeen: matchedDevice.lastSeenAt,
      loginCount: matchedDevice.loginCount,
      matchedDeviceId: matchedDevice.id
    };
  }

  // ==========================================================================
  // Private Helper Methods
  // ==========================================================================

  /**
   * Get stored devices for a user
   */
  private async getStoredDevicesForUser(userId: string): Promise<StoredDevice[]> {
    try {
      // In production, this would query DynamoDB
      // For now, return empty array (devices will be stored separately)
      return [];
    } catch (error) {
      console.error('Failed to get stored devices:', error);
      return [];
    }
  }

  /**
   * Get user behavior profile
   */
  private async getUserBehaviorProfile(userId: string): Promise<UserBehaviorProfile | null> {
    try {
      // In production, this would query DynamoDB
      // For now, return null (profile will be created on first event)
      return null;
    } catch (error) {
      console.error('Failed to get user behavior profile:', error);
      return null;
    }
  }

  /**
   * Store user behavior profile
   */
  private async storeUserBehaviorProfile(profile: UserBehaviorProfile): Promise<void> {
    try {
      // In production, this would store to DynamoDB
      console.log(`Storing behavior profile for user ${profile.userId}`);
    } catch (error) {
      console.error('Failed to store user behavior profile:', error);
    }
  }

  /**
   * Log risk assessment for audit
   */
  private async logRiskAssessment(
    context: LoginContext,
    result: RiskAssessmentResult,
    processingTimeMs: number
  ): Promise<void> {
    try {
      await logSimpleSecurityEvent({
        event_type: 'risk_assessment',
        realm_id: this.realmId,
        user_id: context.userId,
        ip_address: context.ip,
        details: {
          email: context.email,
          risk_score: result.riskScore,
          risk_level: result.riskLevel,
          recommendation: result.adaptiveAuthLevel,
          requires_mfa: result.requiresMfa,
          should_block: result.shouldBlock,
          risk_factors: result.riskFactors.map(f => ({
            type: f.type,
            severity: f.severity,
            score: f.score
          })),
          processing_time_ms: processingTimeMs
        }
      });
    } catch (error) {
      console.error('Failed to log risk assessment:', error);
    }
  }

  /**
   * Check if IP is a private/reserved address
   */
  private isPrivateIP(ip: string): boolean {
    // Check for private IP ranges
    const privateRanges = [
      /^10\./,                    // 10.0.0.0/8
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
      /^192\.168\./,              // 192.168.0.0/16
      /^127\./,                   // 127.0.0.0/8 (loopback)
      /^169\.254\./,              // 169.254.0.0/16 (link-local)
    ];

    return privateRanges.some(range => range.test(ip));
  }

  /**
   * Check if IP is likely a datacenter IP
   */
  private isDatacenterIP(ip: string): boolean {
    // Simplified check - in production, use IP intelligence service
    const datacenterRanges = [
      /^35\./,   // Google Cloud
      /^34\./,   // Google Cloud
      /^52\./,   // AWS
      /^54\./,   // AWS
      /^13\./,   // AWS
      /^104\./,  // Google/Cloudflare
      /^157\./,  // Microsoft Azure
      /^40\./,   // Microsoft Azure
    ];

    return datacenterRanges.some(range => range.test(ip));
  }
}

// ============================================================================
// Singleton Instance Factory
// ============================================================================

/**
 * Create an AIRiskService instance for a realm
 */
export function createAIRiskService(realmId: string): AIRiskService {
  return new AIRiskService(realmId);
}

/**
 * Default AIRiskService instance (for backward compatibility)
 */
let defaultAIRiskService: AIRiskService | null = null;

/**
 * Get or create the default AIRiskService instance
 */
export function getAIRiskService(realmId: string = 'default'): AIRiskService {
  if (!defaultAIRiskService || defaultAIRiskService['realmId'] !== realmId) {
    defaultAIRiskService = new AIRiskService(realmId);
  }
  return defaultAIRiskService;
}
