/**
 * RiskAssessment Model - AI-Powered Risk Assessment for Zalt.io
 * 
 * Risk assessments evaluate login attempts and user behavior to detect
 * suspicious activity. Each assessment produces a score (0-100) and
 * a recommendation for how to proceed.
 * 
 * Security Requirements:
 * - Risk scores must be deterministic for same inputs
 * - No information leakage in error messages
 * - All assessments are audit logged
 * 
 * Validates: Requirements 10.1, 10.2
 */

/**
 * Risk factor types that contribute to the overall risk score
 */
export type RiskFactorType = 
  | 'ip_reputation'      // IP address reputation from threat intelligence
  | 'geo_velocity'       // Impossible travel detection
  | 'device_trust'       // Device fingerprint trust score
  | 'behavior_anomaly'   // Unusual behavior patterns
  | 'credential_stuffing' // Credential stuffing attack detection
  | 'brute_force'        // Brute force attack detection
  | 'tor_exit_node'      // Tor exit node detection
  | 'vpn_proxy'          // VPN/Proxy detection
  | 'bot_detection'      // Bot/automation detection
  | 'time_anomaly';      // Unusual login time for user

/**
 * Risk recommendation based on the overall score
 */
export type RiskRecommendation = 'allow' | 'mfa_required' | 'block';

/**
 * Individual risk factor with score and details
 */
export interface RiskFactor {
  type: RiskFactorType;           // Type of risk factor
  score: number;                  // Individual factor score (0-100)
  details: string;                // Human-readable explanation
  weight?: number;                // Weight in overall calculation (0-1)
  metadata?: Record<string, unknown>; // Additional context data
}

/**
 * Complete risk assessment result
 */
export interface RiskAssessment {
  score: number;                  // Overall risk score (0-100)
  factors: RiskFactor[];          // Contributing risk factors
  recommendation: RiskRecommendation; // Action recommendation
  assessedAt: string;             // ISO 8601 timestamp
  userId?: string;                // User being assessed (if known)
  sessionId?: string;             // Session ID (if applicable)
  requestId?: string;             // Request ID for tracing
  metadata?: RiskAssessmentMetadata; // Additional assessment context
}

/**
 * Risk assessment metadata for additional context
 */
export interface RiskAssessmentMetadata {
  ip?: string;                    // IP address (masked for privacy)
  userAgent?: string;             // User agent string
  country?: string;               // Geo-located country
  city?: string;                  // Geo-located city
  deviceFingerprint?: string;     // Device fingerprint hash
  previousAssessmentId?: string;  // Previous assessment for comparison
  modelVersion?: string;          // AI model version used
  processingTimeMs?: number;      // Time taken to assess
}

/**
 * Input context for risk assessment
 */
export interface RiskAssessmentContext {
  userId?: string;                // User ID (if known)
  email?: string;                 // Email being used
  ip: string;                     // Client IP address
  userAgent?: string;             // User agent string
  deviceFingerprint?: string;     // Device fingerprint
  geoLocation?: GeoLocation;      // Geo-location data
  timestamp?: string;             // Request timestamp
  requestType: RiskRequestType;   // Type of request being assessed
  previousAttempts?: number;      // Number of recent failed attempts
  metadata?: Record<string, unknown>; // Additional context
}

/**
 * Geo-location data for risk assessment
 */
export interface GeoLocation {
  country?: string;               // Country code (ISO 3166-1 alpha-2)
  region?: string;                // Region/state
  city?: string;                  // City name
  latitude?: number;              // Latitude coordinate
  longitude?: number;             // Longitude coordinate
  timezone?: string;              // Timezone
  isp?: string;                   // Internet Service Provider
  asn?: string;                   // Autonomous System Number
}

/**
 * Types of requests that can be risk-assessed
 */
export type RiskRequestType = 
  | 'login'                       // Login attempt
  | 'registration'                // New user registration
  | 'password_reset'              // Password reset request
  | 'mfa_setup'                   // MFA setup
  | 'api_key_creation'            // API key creation
  | 'sensitive_operation';        // Other sensitive operations

/**
 * Risk assessment response for API
 */
export interface RiskAssessmentResponse {
  score: number;
  recommendation: RiskRecommendation;
  factors: RiskFactorSummary[];
  assessedAt: string;
  requiresMfa: boolean;
  blocked: boolean;
}

/**
 * Summarized risk factor for API response (no sensitive details)
 */
export interface RiskFactorSummary {
  type: RiskFactorType;
  score: number;
  description: string;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Minimum risk score
 */
export const MIN_RISK_SCORE = 0;

/**
 * Maximum risk score
 */
export const MAX_RISK_SCORE = 100;

/**
 * Threshold for requiring MFA (score > this value)
 */
export const MFA_REQUIRED_THRESHOLD = 70;

/**
 * Threshold for blocking login (score > this value)
 */
export const BLOCK_THRESHOLD = 90;

/**
 * Valid risk factor types
 */
export const RISK_FACTOR_TYPES: RiskFactorType[] = [
  'ip_reputation',
  'geo_velocity',
  'device_trust',
  'behavior_anomaly',
  'credential_stuffing',
  'brute_force',
  'tor_exit_node',
  'vpn_proxy',
  'bot_detection',
  'time_anomaly'
];

/**
 * Valid risk recommendations
 */
export const RISK_RECOMMENDATIONS: RiskRecommendation[] = [
  'allow',
  'mfa_required',
  'block'
];

/**
 * Valid request types for risk assessment
 */
export const RISK_REQUEST_TYPES: RiskRequestType[] = [
  'login',
  'registration',
  'password_reset',
  'mfa_setup',
  'api_key_creation',
  'sensitive_operation'
];

/**
 * Default weights for risk factors
 */
export const DEFAULT_FACTOR_WEIGHTS: Record<RiskFactorType, number> = {
  ip_reputation: 0.20,
  geo_velocity: 0.25,
  device_trust: 0.15,
  behavior_anomaly: 0.15,
  credential_stuffing: 0.20,
  brute_force: 0.20,
  tor_exit_node: 0.10,
  vpn_proxy: 0.05,
  bot_detection: 0.15,
  time_anomaly: 0.05
};

/**
 * Risk level descriptions
 */
export const RISK_LEVEL_DESCRIPTIONS: Record<string, string> = {
  low: 'Low risk - Normal activity',
  medium: 'Medium risk - Some suspicious indicators',
  high: 'High risk - Multiple suspicious indicators',
  critical: 'Critical risk - Strong indicators of malicious activity'
};

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate risk score is within valid range
 */
export function isValidRiskScore(score: number): boolean {
  return typeof score === 'number' && 
         !isNaN(score) && 
         score >= MIN_RISK_SCORE && 
         score <= MAX_RISK_SCORE;
}

/**
 * Validate risk factor type
 */
export function isValidRiskFactorType(type: string): type is RiskFactorType {
  return RISK_FACTOR_TYPES.includes(type as RiskFactorType);
}

/**
 * Validate risk recommendation
 */
export function isValidRiskRecommendation(recommendation: string): recommendation is RiskRecommendation {
  return RISK_RECOMMENDATIONS.includes(recommendation as RiskRecommendation);
}

/**
 * Validate risk request type
 */
export function isValidRiskRequestType(type: string): type is RiskRequestType {
  return RISK_REQUEST_TYPES.includes(type as RiskRequestType);
}

/**
 * Validate a complete risk factor
 */
export function isValidRiskFactor(factor: unknown): factor is RiskFactor {
  if (typeof factor !== 'object' || factor === null) return false;
  
  const f = factor as Record<string, unknown>;
  
  if (!isValidRiskFactorType(f.type as string)) return false;
  if (!isValidRiskScore(f.score as number)) return false;
  if (typeof f.details !== 'string' || f.details.trim().length === 0) return false;
  
  // Optional weight validation
  if (f.weight !== undefined) {
    if (typeof f.weight !== 'number' || f.weight < 0 || f.weight > 1) return false;
  }
  
  return true;
}

/**
 * Validate a complete risk assessment
 */
export function isValidRiskAssessment(assessment: unknown): assessment is RiskAssessment {
  if (typeof assessment !== 'object' || assessment === null) return false;
  
  const a = assessment as Record<string, unknown>;
  
  if (!isValidRiskScore(a.score as number)) return false;
  if (!isValidRiskRecommendation(a.recommendation as string)) return false;
  
  if (!Array.isArray(a.factors)) return false;
  if (!a.factors.every(isValidRiskFactor)) return false;
  
  if (typeof a.assessedAt !== 'string') return false;
  // Validate ISO 8601 format
  const date = new Date(a.assessedAt);
  if (isNaN(date.getTime())) return false;
  
  return true;
}

/**
 * Validate risk assessment context
 */
export function isValidRiskAssessmentContext(context: unknown): context is RiskAssessmentContext {
  if (typeof context !== 'object' || context === null) return false;
  
  const c = context as Record<string, unknown>;
  
  // IP is required
  if (typeof c.ip !== 'string' || c.ip.trim().length === 0) return false;
  
  // Request type is required
  if (!isValidRiskRequestType(c.requestType as string)) return false;
  
  return true;
}

/**
 * Validate IP address format (IPv4 or IPv6)
 */
export function isValidIPAddress(ip: string): boolean {
  if (typeof ip !== 'string') return false;
  
  // IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(ip)) {
    const parts = ip.split('.').map(Number);
    return parts.every(part => part >= 0 && part <= 255);
  }
  
  // IPv6 pattern (simplified)
  const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:)*:([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
  return ipv6Pattern.test(ip);
}

/**
 * Validate geo-location data
 */
export function isValidGeoLocation(location: unknown): location is GeoLocation {
  if (typeof location !== 'object' || location === null) return false;
  
  const loc = location as Record<string, unknown>;
  
  // All fields are optional, but if present must be valid
  if (loc.country !== undefined && (typeof loc.country !== 'string' || loc.country.length !== 2)) {
    return false;
  }
  
  if (loc.latitude !== undefined) {
    if (typeof loc.latitude !== 'number' || loc.latitude < -90 || loc.latitude > 90) {
      return false;
    }
  }
  
  if (loc.longitude !== undefined) {
    if (typeof loc.longitude !== 'number' || loc.longitude < -180 || loc.longitude > 180) {
      return false;
    }
  }
  
  return true;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get risk level from score
 */
export function getRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score <= 30) return 'low';
  if (score <= 60) return 'medium';
  if (score <= 85) return 'high';
  return 'critical';
}

/**
 * Get risk level description
 */
export function getRiskLevelDescription(score: number): string {
  const level = getRiskLevel(score);
  return RISK_LEVEL_DESCRIPTIONS[level];
}

/**
 * Determine recommendation based on score
 */
export function getRecommendationFromScore(score: number): RiskRecommendation {
  if (score > BLOCK_THRESHOLD) return 'block';
  if (score > MFA_REQUIRED_THRESHOLD) return 'mfa_required';
  return 'allow';
}

/**
 * Check if MFA is required based on score
 */
export function requiresMfa(score: number): boolean {
  return score > MFA_REQUIRED_THRESHOLD && score <= BLOCK_THRESHOLD;
}

/**
 * Check if login should be blocked based on score
 */
export function shouldBlock(score: number): boolean {
  return score > BLOCK_THRESHOLD;
}

/**
 * Calculate weighted risk score from factors
 */
export function calculateWeightedScore(factors: RiskFactor[]): number {
  if (factors.length === 0) return 0;
  
  let totalWeight = 0;
  let weightedSum = 0;
  
  for (const factor of factors) {
    const weight = factor.weight ?? DEFAULT_FACTOR_WEIGHTS[factor.type] ?? 0.1;
    weightedSum += factor.score * weight;
    totalWeight += weight;
  }
  
  if (totalWeight === 0) return 0;
  
  // Normalize to 0-100 range
  const score = Math.round(weightedSum / totalWeight);
  return Math.max(MIN_RISK_SCORE, Math.min(MAX_RISK_SCORE, score));
}

/**
 * Create a risk assessment from factors
 */
export function createRiskAssessment(
  factors: RiskFactor[],
  options?: {
    userId?: string;
    sessionId?: string;
    requestId?: string;
    metadata?: RiskAssessmentMetadata;
  }
): RiskAssessment {
  const score = calculateWeightedScore(factors);
  const recommendation = getRecommendationFromScore(score);
  
  return {
    score,
    factors,
    recommendation,
    assessedAt: new Date().toISOString(),
    userId: options?.userId,
    sessionId: options?.sessionId,
    requestId: options?.requestId,
    metadata: options?.metadata
  };
}

/**
 * Create a risk factor
 */
export function createRiskFactor(
  type: RiskFactorType,
  score: number,
  details: string,
  options?: {
    weight?: number;
    metadata?: Record<string, unknown>;
  }
): RiskFactor {
  // Clamp score to valid range
  const clampedScore = Math.max(MIN_RISK_SCORE, Math.min(MAX_RISK_SCORE, Math.round(score)));
  
  return {
    type,
    score: clampedScore,
    details,
    weight: options?.weight,
    metadata: options?.metadata
  };
}

/**
 * Convert RiskAssessment to API response format (no sensitive data)
 */
export function toRiskAssessmentResponse(assessment: RiskAssessment): RiskAssessmentResponse {
  return {
    score: assessment.score,
    recommendation: assessment.recommendation,
    factors: assessment.factors.map(f => ({
      type: f.type,
      score: f.score,
      description: getFactorDescription(f.type)
    })),
    assessedAt: assessment.assessedAt,
    requiresMfa: requiresMfa(assessment.score),
    blocked: shouldBlock(assessment.score)
  };
}

/**
 * Get human-readable description for a risk factor type
 */
export function getFactorDescription(type: RiskFactorType): string {
  const descriptions: Record<RiskFactorType, string> = {
    ip_reputation: 'IP address reputation check',
    geo_velocity: 'Geographic velocity analysis',
    device_trust: 'Device trust verification',
    behavior_anomaly: 'Behavior pattern analysis',
    credential_stuffing: 'Credential stuffing detection',
    brute_force: 'Brute force attack detection',
    tor_exit_node: 'Tor network detection',
    vpn_proxy: 'VPN/Proxy detection',
    bot_detection: 'Bot activity detection',
    time_anomaly: 'Login time analysis'
  };
  
  return descriptions[type] || 'Unknown risk factor';
}

/**
 * Get the highest scoring factor from an assessment
 */
export function getHighestRiskFactor(assessment: RiskAssessment): RiskFactor | undefined {
  if (assessment.factors.length === 0) return undefined;
  
  return assessment.factors.reduce((highest, current) => 
    current.score > highest.score ? current : highest
  );
}

/**
 * Get factors above a certain threshold
 */
export function getHighRiskFactors(assessment: RiskAssessment, threshold: number = 70): RiskFactor[] {
  return assessment.factors.filter(f => f.score > threshold);
}

/**
 * Calculate distance between two geo-locations in kilometers
 */
export function calculateGeoDistance(loc1: GeoLocation, loc2: GeoLocation): number | null {
  if (loc1.latitude === undefined || loc1.longitude === undefined ||
      loc2.latitude === undefined || loc2.longitude === undefined) {
    return null;
  }
  
  const R = 6371; // Earth's radius in kilometers
  const dLat = toRadians(loc2.latitude - loc1.latitude);
  const dLon = toRadians(loc2.longitude - loc1.longitude);
  
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(toRadians(loc1.latitude)) * Math.cos(toRadians(loc2.latitude)) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  
  return R * c;
}

/**
 * Convert degrees to radians
 */
function toRadians(degrees: number): number {
  return degrees * (Math.PI / 180);
}

/**
 * Check for impossible travel (velocity > 1000 km/h)
 */
export function detectImpossibleTravel(
  loc1: GeoLocation,
  loc2: GeoLocation,
  timeDifferenceMs: number
): { impossible: boolean; velocity: number | null } {
  const distance = calculateGeoDistance(loc1, loc2);
  
  if (distance === null || timeDifferenceMs <= 0) {
    return { impossible: false, velocity: null };
  }
  
  const hours = timeDifferenceMs / (1000 * 60 * 60);
  const velocity = distance / hours; // km/h
  
  // Commercial aircraft max speed is ~900 km/h
  // We use 1000 km/h as threshold to account for some margin
  const impossible = velocity > 1000;
  
  return { impossible, velocity: Math.round(velocity) };
}

/**
 * Mask IP address for privacy (show only first two octets for IPv4)
 */
export function maskIPAddress(ip: string): string {
  if (!ip) return 'unknown';
  
  // IPv4
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.*.*`;
    }
  }
  
  // IPv6 - mask last 4 groups
  if (ip.includes(':')) {
    const parts = ip.split(':');
    if (parts.length >= 4) {
      return parts.slice(0, 4).join(':') + ':****:****:****:****';
    }
  }
  
  return 'masked';
}

/**
 * Compare two risk assessments for consistency (within tolerance)
 */
export function areAssessmentsConsistent(
  assessment1: RiskAssessment,
  assessment2: RiskAssessment,
  tolerance: number = 5
): boolean {
  return Math.abs(assessment1.score - assessment2.score) <= tolerance;
}

/**
 * Merge multiple risk factors of the same type (take highest score)
 */
export function mergeRiskFactors(factors: RiskFactor[]): RiskFactor[] {
  const factorMap = new Map<RiskFactorType, RiskFactor>();
  
  for (const factor of factors) {
    const existing = factorMap.get(factor.type);
    if (!existing || factor.score > existing.score) {
      factorMap.set(factor.type, factor);
    }
  }
  
  return Array.from(factorMap.values());
}

/**
 * Sort factors by score (highest first)
 */
export function sortFactorsByScore(factors: RiskFactor[]): RiskFactor[] {
  return [...factors].sort((a, b) => b.score - a.score);
}

/**
 * Create a low-risk assessment (for trusted scenarios)
 */
export function createLowRiskAssessment(options?: {
  userId?: string;
  sessionId?: string;
  requestId?: string;
}): RiskAssessment {
  return createRiskAssessment(
    [createRiskFactor('device_trust', 10, 'Trusted device recognized')],
    options
  );
}

/**
 * Create a high-risk assessment (for suspicious scenarios)
 */
export function createHighRiskAssessment(
  factors: RiskFactor[],
  options?: {
    userId?: string;
    sessionId?: string;
    requestId?: string;
  }
): RiskAssessment {
  // Ensure at least one high-risk factor
  const highRiskFactors = factors.length > 0 ? factors : [
    createRiskFactor('behavior_anomaly', 85, 'Suspicious activity detected')
  ];
  
  return createRiskAssessment(highRiskFactors, options);
}
