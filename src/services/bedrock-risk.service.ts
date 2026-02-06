/**
 * AWS Bedrock Risk Assessment Service for Zalt.io Auth Platform
 * Phase 6: AI Security - Task 15.3
 * 
 * SECURITY FEATURES:
 * - ML-powered anomaly detection using AWS Bedrock
 * - Behavior pattern analysis with Claude models
 * - Risk factor correlation for accurate threat detection
 * - Privacy-preserving: No PII sent to Bedrock
 * 
 * INTEGRATION:
 * - AWS Bedrock Runtime for ML inference
 * - Claude 3 Haiku for fast, cost-effective analysis
 * - Fallback to rule-based scoring when Bedrock unavailable
 * 
 * COMPLIANCE:
 * - HIPAA: All data anonymized before ML processing
 * - GDPR: No personal data stored in Bedrock
 * - Audit logging for all Bedrock calls
 * 
 * Validates: Requirements 10.5
 */

import { BedrockRuntimeClient, InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';
import { logSimpleSecurityEvent } from './security-logger.service';
import { RiskFactorType, RiskFactor, RISK_THRESHOLDS } from './ai-risk.service';

// ============================================================================
// Types
// ============================================================================

/**
 * Anonymized risk context for Bedrock analysis
 * NO PII - only behavioral signals
 */
export interface AnonymizedRiskContext {
  // Device signals (anonymized)
  deviceTrustScore: number;           // 0-100
  isNewDevice: boolean;
  deviceSimilarityScore: number;      // 0-100
  
  // Geographic signals (anonymized)
  geoRiskScore: number;               // 0-100
  isVpn: boolean;
  isTor: boolean;
  isProxy: boolean;
  isDatacenter: boolean;
  isImpossibleTravel: boolean;
  distanceFromLastLogin?: number;     // km (no actual location)
  
  // Behavioral signals
  loginHour: number;                  // 0-23 UTC
  dayOfWeek: number;                  // 0-6
  failedAttempts: number;
  minutesSinceLastLogin?: number;
  isTypicalLoginTime: boolean;
  
  // Account signals
  accountAgeDays: number;
  mfaEnabled: boolean;
  totalLogins: number;
  
  // Credential signals
  passwordStrength: number;           // 0-100
  isBreachedPassword: boolean;
  
  // Historical signals
  averageRiskScore: number;           // 0-100
  highRiskLoginCount: number;
  
  // Attack detection signals
  credentialStuffingScore: number;    // 0-100
  bruteForceScore: number;            // 0-100
}

/**
 * Bedrock ML analysis result
 */
export interface BedrockAnalysisResult {
  // Risk assessment
  riskScore: number;                  // 0-100
  confidence: number;                 // 0-100
  
  // Anomaly detection
  anomalyDetected: boolean;
  anomalyScore: number;               // 0-100
  anomalyTypes: string[];
  
  // Behavior analysis
  behaviorDeviation: number;          // Standard deviations from normal
  isTypicalBehavior: boolean;
  
  // Risk factor correlation
  correlatedFactors: CorrelatedRiskFactor[];
  primaryThreat?: string;
  
  // Recommendation
  recommendedAction: 'allow' | 'mfa' | 'verify' | 'block';
  reasoning: string;
  
  // Metadata
  modelId: string;
  processingTimeMs: number;
}

/**
 * Correlated risk factor from ML analysis
 */
export interface CorrelatedRiskFactor {
  factor: string;
  contribution: number;               // 0-100 (% contribution to risk)
  correlation: string;                // Description of correlation
}

/**
 * Bedrock service configuration
 */
export interface BedrockConfig {
  modelId: string;
  region: string;
  maxTokens: number;
  temperature: number;
  enabled: boolean;
  fallbackOnError: boolean;
  timeoutMs: number;
  rateLimitPerMinute: number;
}

// ============================================================================
// Configuration
// ============================================================================

/**
 * Default Bedrock configuration
 */
export const DEFAULT_BEDROCK_CONFIG: BedrockConfig = {
  modelId: process.env.BEDROCK_MODEL_ID || 'anthropic.claude-3-haiku-20240307-v1:0',
  region: process.env.AWS_REGION || 'us-east-1',
  maxTokens: 1000,
  temperature: 0.1,                   // Low temperature for consistent results
  enabled: process.env.BEDROCK_ENABLED !== 'false',
  fallbackOnError: true,
  timeoutMs: 5000,                    // 5 second timeout
  rateLimitPerMinute: 100             // Rate limit Bedrock calls
};

/**
 * Healthcare-specific configuration (stricter)
 */
export const HEALTHCARE_BEDROCK_CONFIG: BedrockConfig = {
  ...DEFAULT_BEDROCK_CONFIG,
  temperature: 0.05,                  // Even lower for healthcare
  timeoutMs: 3000,                    // Faster timeout for healthcare
  rateLimitPerMinute: 200             // Higher limit for healthcare
};

// ============================================================================
// Bedrock Client Management
// ============================================================================

let bedrockClient: BedrockRuntimeClient | null = null;
let lastCallTimestamp = 0;
let callsInCurrentMinute = 0;

/**
 * Get or create Bedrock client
 */
function getBedrockClient(config: BedrockConfig = DEFAULT_BEDROCK_CONFIG): BedrockRuntimeClient {
  if (!bedrockClient) {
    bedrockClient = new BedrockRuntimeClient({
      region: config.region,
      maxAttempts: 2
    });
  }
  return bedrockClient;
}

/**
 * Check rate limit for Bedrock calls
 */
function checkRateLimit(config: BedrockConfig): boolean {
  const now = Date.now();
  const minuteStart = Math.floor(now / 60000) * 60000;
  
  if (lastCallTimestamp < minuteStart) {
    // New minute, reset counter
    callsInCurrentMinute = 0;
  }
  
  if (callsInCurrentMinute >= config.rateLimitPerMinute) {
    return false;
  }
  
  callsInCurrentMinute++;
  lastCallTimestamp = now;
  return true;
}

// ============================================================================
// Main Analysis Functions
// ============================================================================

/**
 * Analyze risk using AWS Bedrock ML
 * 
 * This function sends anonymized risk context to Bedrock for ML analysis.
 * NO PII is ever sent to Bedrock - only behavioral signals.
 * 
 * @param context - Anonymized risk context
 * @param config - Bedrock configuration
 * @returns ML analysis result or null if unavailable
 */
export async function analyzeRiskWithBedrock(
  context: AnonymizedRiskContext,
  config: BedrockConfig = DEFAULT_BEDROCK_CONFIG
): Promise<BedrockAnalysisResult | null> {
  const startTime = Date.now();
  
  // Check if Bedrock is enabled
  if (!config.enabled) {
    return null;
  }
  
  // Check rate limit
  if (!checkRateLimit(config)) {
    console.warn('Bedrock rate limit exceeded, falling back to rule-based');
    return null;
  }
  
  try {
    const client = getBedrockClient(config);
    const prompt = buildAnalysisPrompt(context);
    
    const command = new InvokeModelCommand({
      modelId: config.modelId,
      contentType: 'application/json',
      accept: 'application/json',
      body: JSON.stringify({
        anthropic_version: 'bedrock-2023-05-31',
        max_tokens: config.maxTokens,
        temperature: config.temperature,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      })
    });
    
    // Set timeout
    const timeoutPromise = new Promise<null>((_, reject) => {
      setTimeout(() => reject(new Error('Bedrock timeout')), config.timeoutMs);
    });
    
    const responsePromise = client.send(command);
    const response = await Promise.race([responsePromise, timeoutPromise]);
    
    if (!response) {
      return null;
    }
    
    const responseBody = JSON.parse(new TextDecoder().decode(response.body));
    const result = parseAnalysisResponse(responseBody, config.modelId, Date.now() - startTime);
    
    // Audit log the Bedrock call (no PII)
    await logBedrockCall(context, result);
    
    return result;
  } catch (error) {
    console.error('Bedrock analysis error:', error);
    
    // Log the error for monitoring
    await logBedrockError(error as Error);
    
    if (config.fallbackOnError) {
      return null; // Caller will use rule-based fallback
    }
    
    throw error;
  }
}

/**
 * Detect anomalies using Bedrock ML
 * 
 * Specialized function for anomaly detection that focuses on
 * identifying deviations from normal behavior patterns.
 */
export async function detectAnomaliesWithBedrock(
  context: AnonymizedRiskContext,
  config: BedrockConfig = DEFAULT_BEDROCK_CONFIG
): Promise<{
  anomalyDetected: boolean;
  anomalyScore: number;
  anomalyTypes: string[];
  confidence: number;
} | null> {
  const result = await analyzeRiskWithBedrock(context, config);
  
  if (!result) {
    return null;
  }
  
  return {
    anomalyDetected: result.anomalyDetected,
    anomalyScore: result.anomalyScore,
    anomalyTypes: result.anomalyTypes,
    confidence: result.confidence
  };
}

/**
 * Analyze behavior patterns using Bedrock ML
 * 
 * Specialized function for behavior pattern analysis that focuses on
 * understanding user behavior and detecting deviations.
 */
export async function analyzeBehaviorWithBedrock(
  context: AnonymizedRiskContext,
  config: BedrockConfig = DEFAULT_BEDROCK_CONFIG
): Promise<{
  isTypicalBehavior: boolean;
  behaviorDeviation: number;
  reasoning: string;
} | null> {
  const result = await analyzeRiskWithBedrock(context, config);
  
  if (!result) {
    return null;
  }
  
  return {
    isTypicalBehavior: result.isTypicalBehavior,
    behaviorDeviation: result.behaviorDeviation,
    reasoning: result.reasoning
  };
}

/**
 * Correlate risk factors using Bedrock ML
 * 
 * Specialized function for risk factor correlation that identifies
 * relationships between different risk signals.
 */
export async function correlateRiskFactorsWithBedrock(
  context: AnonymizedRiskContext,
  config: BedrockConfig = DEFAULT_BEDROCK_CONFIG
): Promise<{
  correlatedFactors: CorrelatedRiskFactor[];
  primaryThreat?: string;
  riskScore: number;
} | null> {
  const result = await analyzeRiskWithBedrock(context, config);
  
  if (!result) {
    return null;
  }
  
  return {
    correlatedFactors: result.correlatedFactors,
    primaryThreat: result.primaryThreat,
    riskScore: result.riskScore
  };
}

// ============================================================================
// Prompt Building
// ============================================================================

/**
 * Build analysis prompt for Bedrock
 * 
 * The prompt is carefully crafted to:
 * 1. Never include PII
 * 2. Focus on behavioral signals
 * 3. Request structured JSON output
 * 4. Include security context
 */
function buildAnalysisPrompt(context: AnonymizedRiskContext): string {
  return `You are a security AI analyzing a login attempt for an enterprise authentication system. 
Analyze the following ANONYMIZED behavioral signals and provide a risk assessment.

IMPORTANT: This data contains NO personally identifiable information (PII). 
All values are anonymized behavioral signals only.

=== DEVICE SIGNALS ===
- Device Trust Score: ${context.deviceTrustScore}/100
- Is New Device: ${context.isNewDevice}
- Device Similarity Score: ${context.deviceSimilarityScore}/100

=== GEOGRAPHIC SIGNALS ===
- Geo Risk Score: ${context.geoRiskScore}/100
- VPN Detected: ${context.isVpn}
- Tor Detected: ${context.isTor}
- Proxy Detected: ${context.isProxy}
- Datacenter IP: ${context.isDatacenter}
- Impossible Travel: ${context.isImpossibleTravel}
${context.distanceFromLastLogin !== undefined ? `- Distance from Last Login: ${context.distanceFromLastLogin} km` : ''}

=== BEHAVIORAL SIGNALS ===
- Login Hour (UTC): ${context.loginHour}
- Day of Week: ${context.dayOfWeek}
- Failed Attempts: ${context.failedAttempts}
${context.minutesSinceLastLogin !== undefined ? `- Minutes Since Last Login: ${context.minutesSinceLastLogin}` : ''}
- Is Typical Login Time: ${context.isTypicalLoginTime}

=== ACCOUNT SIGNALS ===
- Account Age (Days): ${context.accountAgeDays}
- MFA Enabled: ${context.mfaEnabled}
- Total Logins: ${context.totalLogins}

=== CREDENTIAL SIGNALS ===
- Password Strength: ${context.passwordStrength}/100
- Breached Password: ${context.isBreachedPassword}

=== HISTORICAL SIGNALS ===
- Average Risk Score: ${context.averageRiskScore}/100
- High Risk Login Count: ${context.highRiskLoginCount}

=== ATTACK DETECTION SIGNALS ===
- Credential Stuffing Score: ${context.credentialStuffingScore}/100
- Brute Force Score: ${context.bruteForceScore}/100

Analyze these signals and respond with ONLY a JSON object (no markdown, no explanation outside JSON):

{
  "risk_score": <0-100>,
  "confidence": <0-100>,
  "anomaly_detected": <true/false>,
  "anomaly_score": <0-100>,
  "anomaly_types": [<list of anomaly types detected>],
  "behavior_deviation": <standard deviations from normal, 0-5>,
  "is_typical_behavior": <true/false>,
  "correlated_factors": [
    {"factor": "<factor name>", "contribution": <0-100>, "correlation": "<description>"}
  ],
  "primary_threat": "<main threat type or null>",
  "recommended_action": "<allow|mfa|verify|block>",
  "reasoning": "<brief explanation>"
}

Risk Score Guidelines:
- 0-25: Low risk, normal behavior
- 26-50: Medium risk, some suspicious signals
- 51-70: High risk, multiple suspicious signals
- 71-90: Very high risk, likely attack
- 91-100: Critical risk, definite attack

Anomaly Types to consider:
- time_anomaly: Unusual login time
- location_anomaly: Unusual location/network
- device_anomaly: Unusual device
- frequency_anomaly: Unusual login frequency
- credential_anomaly: Credential-related issues
- attack_pattern: Attack pattern detected`;
}

// ============================================================================
// Response Parsing
// ============================================================================

/**
 * Parse Bedrock response into structured result
 */
function parseAnalysisResponse(
  responseBody: Record<string, unknown>,
  modelId: string,
  processingTimeMs: number
): BedrockAnalysisResult {
  try {
    const content = responseBody.content as Array<{ text?: string }>;
    if (!content || !content[0]?.text) {
      throw new Error('Empty response from Bedrock');
    }
    
    const text = content[0].text;
    
    // Extract JSON from response (handle potential markdown wrapping)
    let jsonText = text;
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      jsonText = jsonMatch[0];
    }
    
    const parsed = JSON.parse(jsonText);
    
    // Validate and normalize the response
    return {
      riskScore: clamp(parsed.risk_score ?? 50, 0, 100),
      confidence: clamp(parsed.confidence ?? 50, 0, 100),
      anomalyDetected: Boolean(parsed.anomaly_detected),
      anomalyScore: clamp(parsed.anomaly_score ?? 0, 0, 100),
      anomalyTypes: Array.isArray(parsed.anomaly_types) ? parsed.anomaly_types : [],
      behaviorDeviation: clamp(parsed.behavior_deviation ?? 0, 0, 5),
      isTypicalBehavior: Boolean(parsed.is_typical_behavior),
      correlatedFactors: parseCorrelatedFactors(parsed.correlated_factors),
      primaryThreat: parsed.primary_threat || undefined,
      recommendedAction: parseRecommendedAction(parsed.recommended_action),
      reasoning: parsed.reasoning || 'No reasoning provided',
      modelId,
      processingTimeMs
    };
  } catch (error) {
    console.error('Failed to parse Bedrock response:', error);
    
    // Return a safe default on parse error
    return {
      riskScore: 50,
      confidence: 0,
      anomalyDetected: false,
      anomalyScore: 0,
      anomalyTypes: [],
      behaviorDeviation: 0,
      isTypicalBehavior: true,
      correlatedFactors: [],
      primaryThreat: undefined,
      recommendedAction: 'mfa',
      reasoning: 'Failed to parse ML response, defaulting to MFA requirement',
      modelId,
      processingTimeMs
    };
  }
}

/**
 * Parse correlated factors from response
 */
function parseCorrelatedFactors(factors: unknown): CorrelatedRiskFactor[] {
  if (!Array.isArray(factors)) {
    return [];
  }
  
  return factors
    .filter((f): f is Record<string, unknown> => typeof f === 'object' && f !== null)
    .map(f => ({
      factor: String(f.factor || 'unknown'),
      contribution: clamp(Number(f.contribution) || 0, 0, 100),
      correlation: String(f.correlation || '')
    }))
    .slice(0, 10); // Limit to 10 factors
}

/**
 * Parse recommended action from response
 */
function parseRecommendedAction(action: unknown): 'allow' | 'mfa' | 'verify' | 'block' {
  const validActions = ['allow', 'mfa', 'verify', 'block'];
  const actionStr = String(action).toLowerCase();
  
  if (validActions.includes(actionStr)) {
    return actionStr as 'allow' | 'mfa' | 'verify' | 'block';
  }
  
  return 'mfa'; // Default to MFA on unknown action
}

/**
 * Clamp a number to a range
 */
function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, Math.round(value)));
}

// ============================================================================
// Audit Logging
// ============================================================================

/**
 * Log Bedrock call for audit (no PII)
 */
async function logBedrockCall(
  context: AnonymizedRiskContext,
  result: BedrockAnalysisResult
): Promise<void> {
  try {
    await logSimpleSecurityEvent({
      event_type: 'bedrock_risk_analysis',
      details: {
        // Only log anonymized metrics, no PII
        input_device_trust: context.deviceTrustScore,
        input_geo_risk: context.geoRiskScore,
        input_is_tor: context.isTor,
        input_is_vpn: context.isVpn,
        input_failed_attempts: context.failedAttempts,
        output_risk_score: result.riskScore,
        output_confidence: result.confidence,
        output_anomaly_detected: result.anomalyDetected,
        output_recommended_action: result.recommendedAction,
        model_id: result.modelId,
        processing_time_ms: result.processingTimeMs
      }
    });
  } catch (error) {
    console.error('Failed to log Bedrock call:', error);
  }
}

/**
 * Log Bedrock error for monitoring
 */
async function logBedrockError(error: Error): Promise<void> {
  try {
    await logSimpleSecurityEvent({
      event_type: 'bedrock_error',
      details: {
        error_message: error.message,
        error_name: error.name
      }
    });
  } catch (logError) {
    console.error('Failed to log Bedrock error:', logError);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create anonymized risk context from risk assessment input
 * 
 * This function ensures NO PII is included in the context sent to Bedrock.
 */
export function createAnonymizedContext(input: {
  deviceRisk: number;
  geoRisk: number;
  behaviorRisk: number;
  credentialRisk: number;
  networkRisk: number;
  historicalRisk: number;
  riskFactors: RiskFactor[];
  isNewDevice?: boolean;
  isVpn?: boolean;
  isTor?: boolean;
  isProxy?: boolean;
  isDatacenter?: boolean;
  isImpossibleTravel?: boolean;
  distanceKm?: number;
  loginTimestamp?: number;
  failedAttempts?: number;
  minutesSinceLastLogin?: number;
  accountAgeDays?: number;
  mfaEnabled?: boolean;
  totalLogins?: number;
  passwordStrength?: number;
  isBreachedPassword?: boolean;
  previousRiskScores?: number[];
  credentialStuffingScore?: number;
  bruteForceScore?: number;
}): AnonymizedRiskContext {
  const now = new Date(input.loginTimestamp || Date.now());
  
  // Calculate average risk score from history
  const avgRiskScore = input.previousRiskScores && input.previousRiskScores.length > 0
    ? input.previousRiskScores.reduce((a, b) => a + b, 0) / input.previousRiskScores.length
    : 0;
  
  // Count high risk logins
  const highRiskCount = input.previousRiskScores
    ? input.previousRiskScores.filter(s => s >= RISK_THRESHOLDS.high).length
    : 0;
  
  // Check if login time is typical (9 AM - 6 PM local time approximation)
  const hour = now.getUTCHours();
  const isTypicalTime = hour >= 9 && hour <= 18;
  
  return {
    deviceTrustScore: 100 - input.deviceRisk,
    isNewDevice: input.isNewDevice ?? input.riskFactors.some(f => f.type === RiskFactorType.NEW_DEVICE),
    deviceSimilarityScore: 100 - input.deviceRisk,
    
    geoRiskScore: input.geoRisk,
    isVpn: input.isVpn ?? input.riskFactors.some(f => f.type === RiskFactorType.VPN_DETECTED),
    isTor: input.isTor ?? input.riskFactors.some(f => f.type === RiskFactorType.TOR_DETECTED),
    isProxy: input.isProxy ?? input.riskFactors.some(f => f.type === RiskFactorType.PROXY_DETECTED),
    isDatacenter: input.isDatacenter ?? input.riskFactors.some(f => f.type === RiskFactorType.DATACENTER_IP),
    isImpossibleTravel: input.isImpossibleTravel ?? input.riskFactors.some(f => f.type === RiskFactorType.IMPOSSIBLE_TRAVEL),
    distanceFromLastLogin: input.distanceKm,
    
    loginHour: hour,
    dayOfWeek: now.getUTCDay(),
    failedAttempts: input.failedAttempts ?? 0,
    minutesSinceLastLogin: input.minutesSinceLastLogin,
    isTypicalLoginTime: isTypicalTime,
    
    accountAgeDays: input.accountAgeDays ?? 0,
    mfaEnabled: input.mfaEnabled ?? false,
    totalLogins: input.totalLogins ?? 0,
    
    passwordStrength: input.passwordStrength ?? 50,
    isBreachedPassword: input.isBreachedPassword ?? false,
    
    averageRiskScore: avgRiskScore,
    highRiskLoginCount: highRiskCount,
    
    credentialStuffingScore: input.credentialStuffingScore ?? 0,
    bruteForceScore: input.bruteForceScore ?? 0
  };
}

/**
 * Blend Bedrock ML result with rule-based result
 * 
 * Uses weighted average to combine ML and rule-based scores.
 * ML weight increases with confidence.
 */
export function blendWithRuleBasedResult(
  ruleBasedScore: number,
  bedrockResult: BedrockAnalysisResult | null,
  mlWeight: number = 0.4
): {
  blendedScore: number;
  usedML: boolean;
  confidence: number;
} {
  if (!bedrockResult) {
    return {
      blendedScore: ruleBasedScore,
      usedML: false,
      confidence: 100 // Full confidence in rule-based
    };
  }
  
  // Adjust ML weight based on confidence
  const adjustedMLWeight = mlWeight * (bedrockResult.confidence / 100);
  const ruleWeight = 1 - adjustedMLWeight;
  
  const blendedScore = Math.round(
    (ruleBasedScore * ruleWeight) + (bedrockResult.riskScore * adjustedMLWeight)
  );
  
  return {
    blendedScore: clamp(blendedScore, 0, 100),
    usedML: true,
    confidence: bedrockResult.confidence
  };
}

/**
 * Check if Bedrock is available and configured
 */
export function isBedrockAvailable(config: BedrockConfig = DEFAULT_BEDROCK_CONFIG): boolean {
  return config.enabled && Boolean(config.modelId);
}

/**
 * Get Bedrock health status
 */
export async function getBedrockHealthStatus(): Promise<{
  available: boolean;
  modelId: string;
  region: string;
  rateLimitRemaining: number;
}> {
  const config = DEFAULT_BEDROCK_CONFIG;
  const minuteStart = Math.floor(Date.now() / 60000) * 60000;
  const currentCalls = lastCallTimestamp >= minuteStart ? callsInCurrentMinute : 0;
  
  return {
    available: isBedrockAvailable(config),
    modelId: config.modelId,
    region: config.region,
    rateLimitRemaining: config.rateLimitPerMinute - currentCalls
  };
}
