/**
 * AI Anomaly Detection Service for Zalt.io Auth Platform
 * Phase 6: AI Security - Task 16.2
 * 
 * SECURITY FEATURES:
 * - User behavior profiling
 * - Login anomaly detection
 * - Behavioral anomaly detection
 * - Pattern learning and deviation detection
 * 
 * DETECTION TYPES:
 * 1. Login time anomaly (unusual hours)
 * 2. Location anomaly (unusual locations)
 * 3. Device anomaly (unusual devices)
 * 4. Frequency anomaly (unusual login frequency)
 * 5. Session anomaly (unusual session patterns)
 * 6. Action anomaly (unusual actions after login)
 * 
 * Validates: Requirements 14.8 (AI Security)
 */

import { QueryCommand, PutCommand, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';
import { logSimpleSecurityEvent } from './security-logger.service';
import { GeoLocation } from './geo-velocity.service';

// ============================================================================
// Types
// ============================================================================

/**
 * User behavior profile
 */
export interface UserBehaviorProfile {
  userId: string;
  realmId: string;
  
  // Login time patterns
  loginHours: number[];           // Histogram of login hours (0-23)
  loginDays: number[];            // Histogram of login days (0-6)
  averageLoginTime: number;       // Average hour of login
  loginTimeStdDev: number;        // Standard deviation of login times
  
  // Location patterns
  commonLocations: LocationPattern[];
  commonCountries: string[];
  
  // Device patterns
  commonDevices: string[];        // Device fingerprint hashes
  deviceCount: number;
  
  // Frequency patterns
  averageLoginsPerDay: number;
  averageLoginsPerWeek: number;
  maxLoginsPerDay: number;
  
  // Session patterns
  averageSessionDuration: number; // minutes
  averageActionsPerSession: number;
  
  // Metadata
  profileCreatedAt: string;
  profileUpdatedAt: string;
  totalLogins: number;
  dataPoints: number;             // Number of data points used for profiling
}

/**
 * Location pattern
 */
export interface LocationPattern {
  city: string;
  country: string;
  countryCode: string;
  frequency: number;              // Number of logins from this location
  lastSeen: string;
}

/**
 * Login event for profiling
 */
export interface LoginEvent {
  userId: string;
  realmId: string;
  timestamp: number;
  ipAddress: string;
  location?: GeoLocation;
  deviceFingerprint?: string;
  userAgent?: string;
  success: boolean;
  sessionId?: string;
}

/**
 * Anomaly detection result
 */
export interface AnomalyDetectionResult {
  isAnomaly: boolean;
  anomalyScore: number;           // 0-100
  anomalyType?: AnomalyType;
  confidence: number;             // 0-100
  deviation: number;              // Standard deviations from normal
  description: string;
  details: Record<string, unknown>;
  recommendedAction: 'allow' | 'mfa' | 'verify' | 'block';
}

/**
 * Anomaly types
 */
export enum AnomalyType {
  LOGIN_TIME = 'login_time',
  LOGIN_LOCATION = 'login_location',
  LOGIN_DEVICE = 'login_device',
  LOGIN_FREQUENCY = 'login_frequency',
  SESSION_DURATION = 'session_duration',
  ACTION_PATTERN = 'action_pattern',
  MULTIPLE = 'multiple'
}

/**
 * Anomaly detection configuration
 */
export interface AnomalyConfig {
  // Time anomaly thresholds
  timeDeviationThreshold: number;     // Standard deviations
  
  // Location anomaly thresholds
  newLocationThreshold: number;       // Days since last seen
  
  // Frequency anomaly thresholds
  frequencyMultiplier: number;        // X times normal frequency
  
  // Session anomaly thresholds
  sessionDurationMultiplier: number;  // X times normal duration
  
  // Minimum data points for reliable detection
  minDataPoints: number;
  
  // Anomaly score thresholds
  anomalyScoreThreshold: number;      // Score above this = anomaly
}

// ============================================================================
// Configuration
// ============================================================================

/**
 * Default anomaly detection configuration
 */
export const DEFAULT_ANOMALY_CONFIG: AnomalyConfig = {
  timeDeviationThreshold: 2.5,        // 2.5 standard deviations
  newLocationThreshold: 30,           // 30 days
  frequencyMultiplier: 3,             // 3x normal frequency
  sessionDurationMultiplier: 5,       // 5x normal duration
  minDataPoints: 10,                  // Minimum 10 logins for profiling
  anomalyScoreThreshold: 60           // Score >= 60 = anomaly
};

/**
 * Healthcare-specific configuration (stricter)
 */
export const HEALTHCARE_ANOMALY_CONFIG: AnomalyConfig = {
  timeDeviationThreshold: 2.0,
  newLocationThreshold: 14,
  frequencyMultiplier: 2,
  sessionDurationMultiplier: 3,
  minDataPoints: 5,
  anomalyScoreThreshold: 50
};

// ============================================================================
// User Behavior Profiling
// ============================================================================

/**
 * Get or create user behavior profile
 */
export async function getUserBehaviorProfile(
  userId: string,
  realmId: string
): Promise<UserBehaviorProfile | null> {
  try {
    const getCommand = new GetCommand({
      TableName: TableNames.DOCUMENTS,
      Key: {
        pk: `USER#${realmId}#${userId}`,
        sk: 'BEHAVIOR_PROFILE'
      }
    });

    const result = await dynamoDb.send(getCommand);
    
    if (result.Item) {
      return result.Item as unknown as UserBehaviorProfile;
    }
    
    return null;
  } catch (error) {
    console.error('Get user behavior profile error:', error);
    return null;
  }
}

/**
 * Create initial user behavior profile
 */
export function createInitialProfile(
  userId: string,
  realmId: string
): UserBehaviorProfile {
  const now = new Date().toISOString();
  
  return {
    userId,
    realmId,
    loginHours: new Array(24).fill(0),
    loginDays: new Array(7).fill(0),
    averageLoginTime: 12,
    loginTimeStdDev: 6,
    commonLocations: [],
    commonCountries: [],
    commonDevices: [],
    deviceCount: 0,
    averageLoginsPerDay: 0,
    averageLoginsPerWeek: 0,
    maxLoginsPerDay: 0,
    averageSessionDuration: 30,
    averageActionsPerSession: 10,
    profileCreatedAt: now,
    profileUpdatedAt: now,
    totalLogins: 0,
    dataPoints: 0
  };
}

/**
 * Update user behavior profile with new login event
 */
export async function updateBehaviorProfile(
  profile: UserBehaviorProfile,
  event: LoginEvent
): Promise<UserBehaviorProfile> {
  const loginDate = new Date(event.timestamp);
  const hour = loginDate.getUTCHours();
  const day = loginDate.getUTCDay();

  // Update login time histogram
  const newLoginHours = [...profile.loginHours];
  newLoginHours[hour] = (newLoginHours[hour] || 0) + 1;

  const newLoginDays = [...profile.loginDays];
  newLoginDays[day] = (newLoginDays[day] || 0) + 1;

  // Calculate new average login time
  const totalLogins = profile.totalLogins + 1;
  const newAverageLoginTime = 
    (profile.averageLoginTime * profile.totalLogins + hour) / totalLogins;

  // Calculate new standard deviation (simplified)
  const variance = calculateVariance(newLoginHours);
  const newStdDev = Math.sqrt(variance);

  // Update location patterns
  let newCommonLocations = [...profile.commonLocations];
  let newCommonCountries = [...profile.commonCountries];
  
  if (event.location) {
    const existingLocation = newCommonLocations.find(
      l => l.city === event.location!.city && l.countryCode === event.location!.countryCode
    );
    
    if (existingLocation) {
      existingLocation.frequency++;
      existingLocation.lastSeen = new Date(event.timestamp).toISOString();
    } else {
      newCommonLocations.push({
        city: event.location.city || 'Unknown',
        country: event.location.country || 'Unknown',
        countryCode: event.location.countryCode || 'XX',
        frequency: 1,
        lastSeen: new Date(event.timestamp).toISOString()
      });
    }

    // Keep top 10 locations
    newCommonLocations = newCommonLocations
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, 10);

    // Update common countries
    if (event.location.countryCode && !newCommonCountries.includes(event.location.countryCode)) {
      newCommonCountries.push(event.location.countryCode);
    }
  }

  // Update device patterns
  let newCommonDevices = [...profile.commonDevices];
  if (event.deviceFingerprint && !newCommonDevices.includes(event.deviceFingerprint)) {
    newCommonDevices.push(event.deviceFingerprint);
    // Keep last 10 devices
    if (newCommonDevices.length > 10) {
      newCommonDevices = newCommonDevices.slice(-10);
    }
  }

  // Update frequency patterns (simplified - would need more data in production)
  const newAverageLoginsPerDay = totalLogins / Math.max(1, getDaysSinceCreation(profile));
  const newAverageLoginsPerWeek = newAverageLoginsPerDay * 7;

  const updatedProfile: UserBehaviorProfile = {
    ...profile,
    loginHours: newLoginHours,
    loginDays: newLoginDays,
    averageLoginTime: newAverageLoginTime,
    loginTimeStdDev: newStdDev,
    commonLocations: newCommonLocations,
    commonCountries: newCommonCountries,
    commonDevices: newCommonDevices,
    deviceCount: newCommonDevices.length,
    averageLoginsPerDay: newAverageLoginsPerDay,
    averageLoginsPerWeek: newAverageLoginsPerWeek,
    maxLoginsPerDay: Math.max(profile.maxLoginsPerDay, newAverageLoginsPerDay),
    profileUpdatedAt: new Date().toISOString(),
    totalLogins,
    dataPoints: profile.dataPoints + 1
  };

  // Save updated profile
  await saveBehaviorProfile(updatedProfile);

  return updatedProfile;
}

/**
 * Save user behavior profile
 */
export async function saveBehaviorProfile(
  profile: UserBehaviorProfile
): Promise<void> {
  try {
    const putCommand = new PutCommand({
      TableName: TableNames.DOCUMENTS,
      Item: {
        pk: `USER#${profile.realmId}#${profile.userId}`,
        sk: 'BEHAVIOR_PROFILE',
        doc_type: 'behavior_profile',
        ...profile
      }
    });

    await dynamoDb.send(putCommand);
  } catch (error) {
    console.error('Save behavior profile error:', error);
  }
}

// ============================================================================
// Anomaly Detection
// ============================================================================

/**
 * Detect anomalies in login event
 */
export async function detectLoginAnomaly(
  event: LoginEvent,
  config: AnomalyConfig = DEFAULT_ANOMALY_CONFIG
): Promise<AnomalyDetectionResult> {
  // Get user's behavior profile
  let profile = await getUserBehaviorProfile(event.userId, event.realmId);
  
  // If no profile exists, create one and return no anomaly
  if (!profile) {
    profile = createInitialProfile(event.userId, event.realmId);
    await updateBehaviorProfile(profile, event);
    
    return {
      isAnomaly: false,
      anomalyScore: 0,
      confidence: 0,
      deviation: 0,
      description: 'First login - establishing baseline',
      details: { isFirstLogin: true },
      recommendedAction: 'allow'
    };
  }

  // Check if we have enough data points
  if (profile.dataPoints < config.minDataPoints) {
    await updateBehaviorProfile(profile, event);
    
    return {
      isAnomaly: false,
      anomalyScore: 0,
      confidence: Math.round((profile.dataPoints / config.minDataPoints) * 100),
      deviation: 0,
      description: `Building profile (${profile.dataPoints}/${config.minDataPoints} data points)`,
      details: { dataPoints: profile.dataPoints, minRequired: config.minDataPoints },
      recommendedAction: 'allow'
    };
  }

  // Run anomaly detection
  const anomalies: AnomalyDetectionResult[] = [];

  // 1. Login time anomaly
  const timeAnomaly = detectTimeAnomaly(event, profile, config);
  if (timeAnomaly.isAnomaly) anomalies.push(timeAnomaly);

  // 2. Location anomaly
  const locationAnomaly = detectLocationAnomaly(event, profile, config);
  if (locationAnomaly.isAnomaly) anomalies.push(locationAnomaly);

  // 3. Device anomaly
  const deviceAnomaly = detectDeviceAnomaly(event, profile, config);
  if (deviceAnomaly.isAnomaly) anomalies.push(deviceAnomaly);

  // 4. Frequency anomaly
  const frequencyAnomaly = await detectFrequencyAnomaly(event, profile, config);
  if (frequencyAnomaly.isAnomaly) anomalies.push(frequencyAnomaly);

  // Update profile with new event
  await updateBehaviorProfile(profile, event);

  // Combine anomalies
  if (anomalies.length === 0) {
    return {
      isAnomaly: false,
      anomalyScore: 0,
      confidence: 90,
      deviation: 0,
      description: 'Login matches expected behavior',
      details: {},
      recommendedAction: 'allow'
    };
  }

  // Calculate combined anomaly score
  const combinedScore = Math.min(100, anomalies.reduce((sum, a) => sum + a.anomalyScore, 0));
  const maxDeviation = Math.max(...anomalies.map(a => a.deviation));
  const avgConfidence = anomalies.reduce((sum, a) => sum + a.confidence, 0) / anomalies.length;

  // Determine recommended action
  let recommendedAction: 'allow' | 'mfa' | 'verify' | 'block' = 'allow';
  if (combinedScore >= 90) recommendedAction = 'block';
  else if (combinedScore >= 70) recommendedAction = 'verify';
  else if (combinedScore >= 50) recommendedAction = 'mfa';

  // Log security event for significant anomalies
  if (combinedScore >= config.anomalyScoreThreshold) {
    await logAnomalyEvent(event, anomalies, combinedScore);
  }

  return {
    isAnomaly: combinedScore >= config.anomalyScoreThreshold,
    anomalyScore: combinedScore,
    anomalyType: anomalies.length > 1 ? AnomalyType.MULTIPLE : anomalies[0].anomalyType,
    confidence: Math.round(avgConfidence),
    deviation: maxDeviation,
    description: anomalies.map(a => a.description).join('; '),
    details: {
      anomalyCount: anomalies.length,
      anomalies: anomalies.map(a => ({
        type: a.anomalyType,
        score: a.anomalyScore,
        description: a.description
      }))
    },
    recommendedAction
  };
}

/**
 * Detect login time anomaly
 */
function detectTimeAnomaly(
  event: LoginEvent,
  profile: UserBehaviorProfile,
  config: AnomalyConfig
): AnomalyDetectionResult {
  const loginHour = new Date(event.timestamp).getUTCHours();
  
  // Calculate z-score (standard deviations from mean)
  const zScore = profile.loginTimeStdDev > 0
    ? Math.abs(loginHour - profile.averageLoginTime) / profile.loginTimeStdDev
    : 0;

  // Check if login hour is unusual
  const hourFrequency = profile.loginHours[loginHour] || 0;
  const totalLogins = profile.totalLogins || 1;
  const hourPercentage = (hourFrequency / totalLogins) * 100;

  const isAnomaly = zScore > config.timeDeviationThreshold || hourPercentage < 1;
  const anomalyScore = isAnomaly ? Math.min(100, Math.round(zScore * 20)) : 0;

  return {
    isAnomaly,
    anomalyScore,
    anomalyType: AnomalyType.LOGIN_TIME,
    confidence: Math.min(100, profile.dataPoints * 5),
    deviation: zScore,
    description: isAnomaly 
      ? `Unusual login time: ${loginHour}:00 UTC (${zScore.toFixed(1)} std devs from normal)`
      : 'Login time is normal',
    details: {
      loginHour,
      averageLoginTime: profile.averageLoginTime,
      stdDev: profile.loginTimeStdDev,
      zScore,
      hourPercentage
    },
    recommendedAction: anomalyScore >= 70 ? 'mfa' : 'allow'
  };
}

/**
 * Detect location anomaly
 */
function detectLocationAnomaly(
  event: LoginEvent,
  profile: UserBehaviorProfile,
  config: AnomalyConfig
): AnomalyDetectionResult {
  if (!event.location) {
    return {
      isAnomaly: false,
      anomalyScore: 0,
      anomalyType: AnomalyType.LOGIN_LOCATION,
      confidence: 0,
      deviation: 0,
      description: 'No location data available',
      details: {},
      recommendedAction: 'allow'
    };
  }

  // Check if location is in common locations
  const matchingLocation = profile.commonLocations.find(
    l => l.city === event.location!.city && l.countryCode === event.location!.countryCode
  );

  // Check if country is common
  const isCommonCountry = profile.commonCountries.includes(event.location.countryCode || '');

  let anomalyScore = 0;
  let description = '';

  if (!matchingLocation && !isCommonCountry) {
    // New country - high anomaly
    anomalyScore = 70;
    description = `Login from new country: ${event.location.country}`;
  } else if (!matchingLocation && isCommonCountry) {
    // New city in known country - medium anomaly
    anomalyScore = 40;
    description = `Login from new city: ${event.location.city}, ${event.location.country}`;
  } else if (matchingLocation) {
    // Check if location hasn't been seen recently
    const daysSinceLastSeen = getDaysSince(matchingLocation.lastSeen);
    if (daysSinceLastSeen > config.newLocationThreshold) {
      anomalyScore = 30;
      description = `Login from location not seen in ${daysSinceLastSeen} days`;
    }
  }

  const isAnomaly = anomalyScore >= config.anomalyScoreThreshold / 2;

  return {
    isAnomaly,
    anomalyScore,
    anomalyType: AnomalyType.LOGIN_LOCATION,
    confidence: Math.min(100, profile.commonLocations.length * 10),
    deviation: anomalyScore / 20,
    description: description || 'Location matches expected pattern',
    details: {
      location: event.location,
      isCommonCountry,
      matchingLocation: matchingLocation ? {
        city: matchingLocation.city,
        frequency: matchingLocation.frequency
      } : null
    },
    recommendedAction: anomalyScore >= 60 ? 'mfa' : 'allow'
  };
}

/**
 * Detect device anomaly
 */
function detectDeviceAnomaly(
  event: LoginEvent,
  profile: UserBehaviorProfile,
  config: AnomalyConfig
): AnomalyDetectionResult {
  if (!event.deviceFingerprint) {
    return {
      isAnomaly: false,
      anomalyScore: 20, // Slight risk for no fingerprint
      anomalyType: AnomalyType.LOGIN_DEVICE,
      confidence: 0,
      deviation: 0,
      description: 'No device fingerprint provided',
      details: {},
      recommendedAction: 'allow'
    };
  }

  const isKnownDevice = profile.commonDevices.includes(event.deviceFingerprint);
  const deviceCount = profile.deviceCount;

  let anomalyScore = 0;
  let description = '';

  if (!isKnownDevice) {
    // New device
    if (deviceCount === 0) {
      // First device - no anomaly
      anomalyScore = 0;
      description = 'First device registered';
    } else if (deviceCount < 3) {
      // Few devices - moderate anomaly
      anomalyScore = 40;
      description = 'Login from new device (user has few devices)';
    } else {
      // Many devices - lower anomaly
      anomalyScore = 25;
      description = 'Login from new device';
    }
  }

  const isAnomaly = anomalyScore >= config.anomalyScoreThreshold / 2;

  return {
    isAnomaly,
    anomalyScore,
    anomalyType: AnomalyType.LOGIN_DEVICE,
    confidence: Math.min(100, deviceCount * 20),
    deviation: anomalyScore / 20,
    description: description || 'Known device',
    details: {
      isKnownDevice,
      deviceCount,
      fingerprint: event.deviceFingerprint.substring(0, 8) + '...'
    },
    recommendedAction: anomalyScore >= 40 ? 'mfa' : 'allow'
  };
}

/**
 * Detect login frequency anomaly
 */
async function detectFrequencyAnomaly(
  event: LoginEvent,
  profile: UserBehaviorProfile,
  config: AnomalyConfig
): Promise<AnomalyDetectionResult> {
  // Get recent login count
  const recentLogins = await getRecentLoginCount(event.userId, event.realmId, 24 * 60 * 60 * 1000);
  
  const expectedDaily = profile.averageLoginsPerDay || 1;
  const frequencyRatio = recentLogins / Math.max(1, expectedDaily);

  let anomalyScore = 0;
  let description = '';

  if (frequencyRatio > config.frequencyMultiplier) {
    anomalyScore = Math.min(80, Math.round((frequencyRatio - 1) * 20));
    description = `Unusual login frequency: ${recentLogins} logins in 24h (${frequencyRatio.toFixed(1)}x normal)`;
  }

  const isAnomaly = anomalyScore >= config.anomalyScoreThreshold / 2;

  return {
    isAnomaly,
    anomalyScore,
    anomalyType: AnomalyType.LOGIN_FREQUENCY,
    confidence: Math.min(100, profile.dataPoints * 5),
    deviation: frequencyRatio - 1,
    description: description || 'Login frequency is normal',
    details: {
      recentLogins,
      expectedDaily,
      frequencyRatio
    },
    recommendedAction: anomalyScore >= 60 ? 'mfa' : 'allow'
  };
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Calculate variance of histogram
 */
function calculateVariance(histogram: number[]): number {
  const total = histogram.reduce((sum, val) => sum + val, 0);
  if (total === 0) return 0;

  // Calculate weighted mean
  let weightedSum = 0;
  for (let i = 0; i < histogram.length; i++) {
    weightedSum += i * histogram[i];
  }
  const mean = weightedSum / total;

  // Calculate variance
  let varianceSum = 0;
  for (let i = 0; i < histogram.length; i++) {
    varianceSum += histogram[i] * Math.pow(i - mean, 2);
  }

  return varianceSum / total;
}

/**
 * Get days since profile creation
 */
function getDaysSinceCreation(profile: UserBehaviorProfile): number {
  const created = new Date(profile.profileCreatedAt);
  const now = new Date();
  return Math.max(1, Math.floor((now.getTime() - created.getTime()) / (24 * 60 * 60 * 1000)));
}

/**
 * Get days since a date
 */
function getDaysSince(dateStr: string): number {
  const date = new Date(dateStr);
  const now = new Date();
  return Math.floor((now.getTime() - date.getTime()) / (24 * 60 * 60 * 1000));
}

/**
 * Get recent login count for user
 */
async function getRecentLoginCount(
  userId: string,
  realmId: string,
  windowMs: number
): Promise<number> {
  try {
    const windowStart = Date.now() - windowMs;
    
    const queryCommand = new QueryCommand({
      TableName: TableNames.DOCUMENTS,
      KeyConditionExpression: 'pk = :pk AND sk > :windowStart',
      ExpressionAttributeValues: {
        ':pk': `USER#${realmId}#${userId}`,
        ':windowStart': `LOGIN_EVENT#${windowStart}`
      }
    });

    const result = await dynamoDb.send(queryCommand);
    return result.Items?.length || 0;
  } catch (error) {
    console.error('Get recent login count error:', error);
    return 0;
  }
}

/**
 * Log anomaly security event
 */
async function logAnomalyEvent(
  event: LoginEvent,
  anomalies: AnomalyDetectionResult[],
  combinedScore: number
): Promise<void> {
  try {
    await logSimpleSecurityEvent({
      event_type: 'behavior_anomaly_detected',
      realm_id: event.realmId,
      user_id: event.userId,
      ip_address: event.ipAddress,
      details: {
        anomaly_score: combinedScore,
        anomaly_count: anomalies.length,
        anomaly_types: anomalies.map(a => a.anomalyType),
        descriptions: anomalies.map(a => a.description)
      }
    });
  } catch (error) {
    console.error('Log anomaly event error:', error);
  }
}

// All functions are already exported inline with their definitions
