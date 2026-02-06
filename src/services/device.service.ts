/**
 * Device Fingerprinting & Trust Service
 * Validates: Requirements 3.1, 3.2 (Device Trust)
 * 
 * SECURITY: Device fingerprinting for:
 * - Detecting new/unknown devices
 * - Fuzzy matching for returning devices
 * - Trust scoring for MFA decisions
 * 
 * Threshold: 70% similarity = same device (Siberci approved)
 */

import crypto from 'crypto';

/**
 * Device fingerprint components with weights
 * Total weight = 100%
 */
export const FINGERPRINT_WEIGHTS = {
  userAgent: 30,      // Browser/OS info
  screenResolution: 20, // Screen size
  timezone: 20,       // Timezone offset
  language: 15,       // Browser language
  platform: 15        // OS platform
} as const;

/**
 * Trust score thresholds
 */
export const TRUST_THRESHOLDS = {
  TRUSTED: 80,      // >= 80: Skip MFA for trusted device
  FAMILIAR: 50,     // 50-79: Require MFA
  SUSPICIOUS: 0     // < 50: MFA + email verification
} as const;

/**
 * Device fingerprint input from client
 */
export interface DeviceFingerprintInput {
  userAgent?: string;
  screen?: string;        // "1920x1080" format
  timezone?: string;      // "Europe/Istanbul" or offset "-180"
  language?: string;      // "en-US", "tr-TR"
  platform?: string;      // "MacIntel", "Win32", "Linux x86_64"
  colorDepth?: number;
  hardwareConcurrency?: number;
  deviceMemory?: number;
  touchSupport?: boolean;
  webglVendor?: string;
  webglRenderer?: string;
}

/**
 * Stored device record
 */
export interface StoredDevice {
  id: string;
  userId: string;
  realmId: string;
  fingerprintHash: string;
  components: DeviceFingerprintInput;
  name?: string;
  trusted: boolean;
  trustExpiresAt?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  lastIpAddress?: string;
  loginCount: number;
}

/**
 * Device match result
 */
export interface DeviceMatchResult {
  matched: boolean;
  device?: StoredDevice;
  similarityScore: number;
  componentScores: Record<string, number>;
  trustLevel: 'trusted' | 'familiar' | 'suspicious' | 'new';
}

/**
 * Generate a stable hash for device fingerprint
 */
export function generateFingerprintHash(fingerprint: DeviceFingerprintInput): string {
  const normalized = normalizeFingerprint(fingerprint);
  const data = JSON.stringify(normalized);
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Normalize fingerprint for consistent comparison
 */
export function normalizeFingerprint(fingerprint: DeviceFingerprintInput): DeviceFingerprintInput {
  return {
    userAgent: normalizeUserAgent(fingerprint.userAgent),
    screen: fingerprint.screen?.toLowerCase().trim(),
    timezone: fingerprint.timezone?.trim(),
    language: fingerprint.language?.toLowerCase().split(',')[0].trim(),
    platform: fingerprint.platform?.toLowerCase().trim()
  };
}

/**
 * Normalize user agent (remove version numbers for fuzzy matching)
 */
function normalizeUserAgent(userAgent?: string): string | undefined {
  if (!userAgent) return undefined;
  
  // Remove specific version numbers but keep browser/OS identity
  return userAgent
    .replace(/\d+\.\d+(\.\d+)?/g, 'X.X')  // Replace version numbers
    .toLowerCase()
    .trim();
}

/**
 * Calculate similarity between two fingerprints
 * Returns score 0-100
 */
export function calculateFingerprintSimilarity(
  current: DeviceFingerprintInput,
  stored: DeviceFingerprintInput
): { totalScore: number; componentScores: Record<string, number> } {
  const normalizedCurrent = normalizeFingerprint(current);
  const normalizedStored = normalizeFingerprint(stored);
  
  const componentScores: Record<string, number> = {};
  let totalScore = 0;

  // User Agent (30%)
  componentScores.userAgent = compareStrings(
    normalizedCurrent.userAgent,
    normalizedStored.userAgent
  );
  totalScore += componentScores.userAgent * (FINGERPRINT_WEIGHTS.userAgent / 100);

  // Screen Resolution (20%)
  componentScores.screenResolution = compareStrings(
    normalizedCurrent.screen,
    normalizedStored.screen
  );
  totalScore += componentScores.screenResolution * (FINGERPRINT_WEIGHTS.screenResolution / 100);

  // Timezone (20%)
  componentScores.timezone = compareStrings(
    normalizedCurrent.timezone,
    normalizedStored.timezone
  );
  totalScore += componentScores.timezone * (FINGERPRINT_WEIGHTS.timezone / 100);

  // Language (15%)
  componentScores.language = compareStrings(
    normalizedCurrent.language,
    normalizedStored.language
  );
  totalScore += componentScores.language * (FINGERPRINT_WEIGHTS.language / 100);

  // Platform (15%)
  componentScores.platform = compareStrings(
    normalizedCurrent.platform,
    normalizedStored.platform
  );
  totalScore += componentScores.platform * (FINGERPRINT_WEIGHTS.platform / 100);

  return {
    totalScore: Math.round(totalScore),
    componentScores
  };
}

/**
 * Compare two strings with fuzzy matching
 * Returns 0-100 similarity score
 */
function compareStrings(a?: string, b?: string): number {
  if (!a && !b) return 100;  // Both empty = match
  if (!a || !b) return 0;    // One empty = no match
  if (a === b) return 100;   // Exact match
  
  // Levenshtein-based similarity for fuzzy matching
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 100;
  
  const distance = levenshteinDistance(a, b);
  const similarity = ((maxLen - distance) / maxLen) * 100;
  
  return Math.round(similarity);
}

/**
 * Levenshtein distance for string comparison
 */
function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Match current fingerprint against stored devices
 * Uses 70% threshold for fuzzy matching
 */
export function matchDevice(
  currentFingerprint: DeviceFingerprintInput,
  storedDevices: StoredDevice[]
): DeviceMatchResult {
  if (storedDevices.length === 0) {
    return {
      matched: false,
      similarityScore: 0,
      componentScores: {},
      trustLevel: 'new'
    };
  }

  let bestMatch: StoredDevice | undefined;
  let bestScore = 0;
  let bestComponentScores: Record<string, number> = {};

  for (const device of storedDevices) {
    const { totalScore, componentScores } = calculateFingerprintSimilarity(
      currentFingerprint,
      device.components
    );

    if (totalScore > bestScore) {
      bestScore = totalScore;
      bestMatch = device;
      bestComponentScores = componentScores;
    }
  }

  // 70% threshold for device match
  const matched = bestScore >= 70;

  // Determine trust level
  let trustLevel: 'trusted' | 'familiar' | 'suspicious' | 'new';
  if (!matched) {
    trustLevel = 'new';
  } else if (bestMatch?.trusted && bestScore >= TRUST_THRESHOLDS.TRUSTED) {
    trustLevel = 'trusted';
  } else if (bestScore >= TRUST_THRESHOLDS.FAMILIAR) {
    trustLevel = 'familiar';
  } else {
    trustLevel = 'suspicious';
  }

  return {
    matched,
    device: matched ? bestMatch : undefined,
    similarityScore: bestScore,
    componentScores: bestComponentScores,
    trustLevel
  };
}

/**
 * Create a new device record
 */
export function createDeviceRecord(
  userId: string,
  realmId: string,
  fingerprint: DeviceFingerprintInput,
  ipAddress?: string,
  deviceName?: string
): StoredDevice {
  const now = new Date().toISOString();
  
  return {
    id: crypto.randomUUID(),
    userId,
    realmId,
    fingerprintHash: generateFingerprintHash(fingerprint),
    components: normalizeFingerprint(fingerprint),
    name: deviceName || generateDeviceName(fingerprint),
    trusted: false,
    firstSeenAt: now,
    lastSeenAt: now,
    lastIpAddress: ipAddress,
    loginCount: 1
  };
}

/**
 * Generate a human-readable device name from fingerprint
 */
export function generateDeviceName(fingerprint: DeviceFingerprintInput): string {
  const ua = fingerprint.userAgent || '';
  
  // Detect browser
  let browser = 'Unknown Browser';
  if (ua.includes('Chrome') && !ua.includes('Edg')) browser = 'Chrome';
  else if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Safari') && !ua.includes('Chrome')) browser = 'Safari';
  else if (ua.includes('Edg')) browser = 'Edge';
  
  // Detect OS
  let os = 'Unknown OS';
  const platform = fingerprint.platform?.toLowerCase() || ua.toLowerCase();
  if (platform.includes('mac')) os = 'macOS';
  else if (platform.includes('win')) os = 'Windows';
  else if (platform.includes('linux')) os = 'Linux';
  else if (platform.includes('android')) os = 'Android';
  else if (platform.includes('iphone') || platform.includes('ipad')) os = 'iOS';
  
  return `${browser} on ${os}`;
}

/**
 * Calculate trust score based on multiple factors
 */
export interface TrustScoreInput {
  fingerprintSimilarity: number;  // 0-100
  ipProximity?: number;           // 0-100 (same country = 100, same city = 80, etc.)
  userAgentConsistency?: number;  // 0-100
  loginTimePattern?: number;      // 0-100 (normal hours = 100)
}

export function calculateTrustScore(input: TrustScoreInput): number {
  // Weights for trust score components
  const weights = {
    fingerprintSimilarity: 50,
    ipProximity: 20,
    userAgentConsistency: 15,
    loginTimePattern: 15
  };

  let score = 0;
  let totalWeight = 0;

  // Fingerprint similarity (always available)
  score += input.fingerprintSimilarity * (weights.fingerprintSimilarity / 100);
  totalWeight += weights.fingerprintSimilarity;

  // IP proximity (optional)
  if (input.ipProximity !== undefined) {
    score += input.ipProximity * (weights.ipProximity / 100);
    totalWeight += weights.ipProximity;
  }

  // User agent consistency (optional)
  if (input.userAgentConsistency !== undefined) {
    score += input.userAgentConsistency * (weights.userAgentConsistency / 100);
    totalWeight += weights.userAgentConsistency;
  }

  // Login time pattern (optional)
  if (input.loginTimePattern !== undefined) {
    score += input.loginTimePattern * (weights.loginTimePattern / 100);
    totalWeight += weights.loginTimePattern;
  }

  // Normalize to 0-100 based on available components
  const normalizedScore = (score / totalWeight) * 100;
  
  return Math.round(normalizedScore);
}

/**
 * Determine trust level from score
 */
export function getTrustLevel(score: number): 'trusted' | 'familiar' | 'suspicious' {
  if (score >= TRUST_THRESHOLDS.TRUSTED) return 'trusted';
  if (score >= TRUST_THRESHOLDS.FAMILIAR) return 'familiar';
  return 'suspicious';
}

/**
 * Check if device trust has expired
 */
export function isDeviceTrustExpired(device: StoredDevice): boolean {
  if (!device.trusted || !device.trustExpiresAt) return true;
  return new Date(device.trustExpiresAt) < new Date();
}

/**
 * Update device on successful login
 */
export function updateDeviceOnLogin(
  device: StoredDevice,
  ipAddress?: string
): StoredDevice {
  return {
    ...device,
    lastSeenAt: new Date().toISOString(),
    lastIpAddress: ipAddress || device.lastIpAddress,
    loginCount: device.loginCount + 1
  };
}
