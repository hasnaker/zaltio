/**
 * Geographic Velocity Check Service for Zalt.io Auth Platform
 * Task 6.8: Impossible Travel Detection
 * 
 * SECURITY CRITICAL:
 * - Detects physically impossible travel between logins
 * - Prevents account takeover from different geographic locations
 * - Integrates with VPN/Proxy detection
 * 
 * Algorithm:
 * 1. Get last login IP → Geolocation (lat, lon)
 * 2. Get new login IP → Geolocation (lat, lon)
 * 3. Calculate distance (Haversine formula)
 * 4. Calculate time elapsed (last login - now)
 * 5. Speed = Distance / Time
 * 6. Speed > 1000 km/h → SUSPICIOUS
 */

import { GetCommand, PutCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';
import { logSimpleSecurityEvent } from './security-logger.service';

/**
 * Geographic location
 */
export interface GeoLocation {
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  timezone?: string;
  isVpn?: boolean;
  isProxy?: boolean;
  isTor?: boolean;
  isDatacenter?: boolean;
}

/**
 * Login location record
 */
export interface LoginLocationRecord {
  userId: string;
  realmId: string;
  ipAddress: string;
  location: GeoLocation;
  timestamp: number;
  deviceFingerprint?: string;
  userAgent?: string;
}

/**
 * Velocity check result
 */
export interface VelocityCheckResult {
  isImpossibleTravel: boolean;
  isSuspicious: boolean;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  distanceKm: number;
  timeElapsedHours: number;
  speedKmh: number;
  previousLocation?: GeoLocation;
  currentLocation: GeoLocation;
  reason?: string;
  requiresMfa: boolean;
  requiresVerification: boolean;
  blocked: boolean;
}

/**
 * Velocity check configuration
 */
export interface VelocityConfig {
  // Maximum speed in km/h (commercial flight ~900 km/h)
  maxSpeedKmh: number;
  
  // Suspicious speed threshold
  suspiciousSpeedKmh: number;
  
  // Minimum time between logins to check (seconds)
  minTimeBetweenChecks: number;
  
  // Maximum distance for same-city tolerance (km)
  sameCityToleranceKm: number;
  
  // Block on impossible travel
  blockOnImpossibleTravel: boolean;
  
  // Require MFA on suspicious travel
  requireMfaOnSuspicious: boolean;
  
  // Send alert on detection
  sendAlertOnDetection: boolean;
}

/**
 * Default velocity configuration
 */
export const DEFAULT_VELOCITY_CONFIG: VelocityConfig = {
  maxSpeedKmh: 1000, // Slightly above commercial flight speed
  suspiciousSpeedKmh: 500, // Half of max
  minTimeBetweenChecks: 60, // 1 minute minimum
  sameCityToleranceKm: 50, // Same city tolerance
  blockOnImpossibleTravel: false, // Don't block, but flag
  requireMfaOnSuspicious: true,
  sendAlertOnDetection: true
};

/**
 * Healthcare-specific velocity configuration (stricter)
 */
export const HEALTHCARE_VELOCITY_CONFIG: VelocityConfig = {
  maxSpeedKmh: 800, // More conservative
  suspiciousSpeedKmh: 300,
  minTimeBetweenChecks: 60,
  sameCityToleranceKm: 30,
  blockOnImpossibleTravel: true, // Block for healthcare
  requireMfaOnSuspicious: true,
  sendAlertOnDetection: true
};

/**
 * Earth's radius in kilometers
 */
const EARTH_RADIUS_KM = 6371;

/**
 * Calculate distance between two points using Haversine formula
 * 
 * @param lat1 - Latitude of point 1
 * @param lon1 - Longitude of point 1
 * @param lat2 - Latitude of point 2
 * @param lon2 - Longitude of point 2
 * @returns Distance in kilometers
 */
export function calculateHaversineDistance(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number {
  // Convert to radians
  const toRad = (deg: number) => deg * (Math.PI / 180);
  
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  
  const a = 
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  
  return EARTH_RADIUS_KM * c;
}

/**
 * Calculate travel speed
 * 
 * @param distanceKm - Distance in kilometers
 * @param timeSeconds - Time in seconds
 * @returns Speed in km/h
 */
export function calculateSpeed(distanceKm: number, timeSeconds: number): number {
  if (timeSeconds <= 0) return Infinity;
  return (distanceKm / timeSeconds) * 3600; // Convert to km/h
}

/**
 * Determine risk level based on speed
 */
export function determineRiskLevel(
  speedKmh: number,
  config: VelocityConfig
): 'low' | 'medium' | 'high' | 'critical' {
  if (speedKmh > config.maxSpeedKmh) return 'critical';
  if (speedKmh > config.suspiciousSpeedKmh) return 'high';
  if (speedKmh > config.suspiciousSpeedKmh / 2) return 'medium';
  return 'low';
}

/**
 * Check if location is from VPN/Proxy/Tor
 */
export function isAnonymizedLocation(location: GeoLocation): boolean {
  return !!(location.isVpn || location.isProxy || location.isTor || location.isDatacenter);
}

/**
 * Get last login location for user
 */
export async function getLastLoginLocation(
  userId: string,
  realmId: string
): Promise<LoginLocationRecord | null> {
  try {
    const queryCommand = new QueryCommand({
      TableName: TableNames.DOCUMENTS,
      KeyConditionExpression: 'pk = :pk AND begins_with(sk, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk': `USER#${realmId}#${userId}`,
        ':skPrefix': 'LOGIN_LOCATION#'
      },
      ScanIndexForward: false, // Most recent first
      Limit: 1
    });

    const result = await dynamoDb.send(queryCommand);
    
    if (result.Items && result.Items.length > 0) {
      const item = result.Items[0];
      return {
        userId: item.user_id,
        realmId: item.realm_id,
        ipAddress: item.ip_address,
        location: item.location,
        timestamp: item.timestamp,
        deviceFingerprint: item.device_fingerprint,
        userAgent: item.user_agent
      };
    }
    
    return null;
  } catch (error) {
    console.error('Get last login location error:', error);
    return null;
  }
}

/**
 * Record login location
 */
export async function recordLoginLocation(
  record: LoginLocationRecord
): Promise<void> {
  try {
    const now = Math.floor(Date.now() / 1000);
    
    const putCommand = new PutCommand({
      TableName: TableNames.DOCUMENTS,
      Item: {
        pk: `USER#${record.realmId}#${record.userId}`,
        sk: `LOGIN_LOCATION#${now}`,
        doc_type: 'login_location',
        user_id: record.userId,
        realm_id: record.realmId,
        ip_address: record.ipAddress,
        location: record.location,
        timestamp: record.timestamp,
        device_fingerprint: record.deviceFingerprint,
        user_agent: record.userAgent,
        ttl: now + (90 * 24 * 60 * 60) // Keep for 90 days
      }
    });

    await dynamoDb.send(putCommand);
  } catch (error) {
    console.error('Record login location error:', error);
  }
}

/**
 * Check geographic velocity for login attempt
 */
export async function checkGeoVelocity(
  userId: string,
  realmId: string,
  currentIp: string,
  currentLocation: GeoLocation,
  config: VelocityConfig = DEFAULT_VELOCITY_CONFIG
): Promise<VelocityCheckResult> {
  const now = Math.floor(Date.now() / 1000);

  // Default result for first login or no previous location
  const defaultResult: VelocityCheckResult = {
    isImpossibleTravel: false,
    isSuspicious: false,
    riskLevel: 'low',
    distanceKm: 0,
    timeElapsedHours: 0,
    speedKmh: 0,
    currentLocation,
    requiresMfa: false,
    requiresVerification: false,
    blocked: false
  };

  try {
    // Check for VPN/Proxy first
    if (isAnonymizedLocation(currentLocation)) {
      return {
        ...defaultResult,
        isSuspicious: true,
        riskLevel: 'medium',
        reason: 'VPN/Proxy/Tor detected',
        requiresMfa: true
      };
    }

    // Get last login location
    const lastLogin = await getLastLoginLocation(userId, realmId);
    
    if (!lastLogin) {
      // First login, record and allow
      await recordLoginLocation({
        userId,
        realmId,
        ipAddress: currentIp,
        location: currentLocation,
        timestamp: now
      });
      return defaultResult;
    }

    // Calculate time elapsed
    const timeElapsedSeconds = now - lastLogin.timestamp;
    const timeElapsedHours = timeElapsedSeconds / 3600;

    // Skip check if too little time has passed
    if (timeElapsedSeconds < config.minTimeBetweenChecks) {
      return {
        ...defaultResult,
        previousLocation: lastLogin.location,
        timeElapsedHours
      };
    }

    // Calculate distance
    const distanceKm = calculateHaversineDistance(
      lastLogin.location.latitude,
      lastLogin.location.longitude,
      currentLocation.latitude,
      currentLocation.longitude
    );

    // Same city tolerance
    if (distanceKm < config.sameCityToleranceKm) {
      await recordLoginLocation({
        userId,
        realmId,
        ipAddress: currentIp,
        location: currentLocation,
        timestamp: now
      });
      return {
        ...defaultResult,
        previousLocation: lastLogin.location,
        distanceKm,
        timeElapsedHours
      };
    }

    // Calculate speed
    const speedKmh = calculateSpeed(distanceKm, timeElapsedSeconds);
    const riskLevel = determineRiskLevel(speedKmh, config);
    const isImpossibleTravel = speedKmh > config.maxSpeedKmh;
    const isSuspicious = speedKmh > config.suspiciousSpeedKmh;

    // Determine actions
    const blocked = isImpossibleTravel && config.blockOnImpossibleTravel;
    const requiresMfa = isSuspicious && config.requireMfaOnSuspicious;
    const requiresVerification = isImpossibleTravel;

    // Build reason
    let reason: string | undefined;
    if (isImpossibleTravel) {
      reason = `Impossible travel detected: ${Math.round(distanceKm)}km in ${timeElapsedHours.toFixed(2)}h (${Math.round(speedKmh)}km/h)`;
    } else if (isSuspicious) {
      reason = `Suspicious travel speed: ${Math.round(speedKmh)}km/h`;
    }

    // Log security event
    if (isSuspicious && config.sendAlertOnDetection) {
      await logSimpleSecurityEvent({
        event_type: isImpossibleTravel ? 'impossible_travel_detected' : 'suspicious_travel_detected',
        realm_id: realmId,
        user_id: userId,
        details: {
          previous_location: `${lastLogin.location.city}, ${lastLogin.location.country}`,
          current_location: `${currentLocation.city}, ${currentLocation.country}`,
          distance_km: Math.round(distanceKm),
          time_elapsed_hours: timeElapsedHours.toFixed(2),
          speed_kmh: Math.round(speedKmh),
          risk_level: riskLevel,
          blocked
        }
      });
    }

    // Record current location (unless blocked)
    if (!blocked) {
      await recordLoginLocation({
        userId,
        realmId,
        ipAddress: currentIp,
        location: currentLocation,
        timestamp: now
      });
    }

    return {
      isImpossibleTravel,
      isSuspicious,
      riskLevel,
      distanceKm,
      timeElapsedHours,
      speedKmh,
      previousLocation: lastLogin.location,
      currentLocation,
      reason,
      requiresMfa,
      requiresVerification,
      blocked
    };
  } catch (error) {
    console.error('Check geo velocity error:', error);
    return defaultResult;
  }
}

/**
 * Get velocity config for realm
 */
export function getRealmVelocityConfig(realmId: string): VelocityConfig {
  // Healthcare realms get stricter config
  if (realmId.startsWith('clinisyn')) {
    return HEALTHCARE_VELOCITY_CONFIG;
  }
  return DEFAULT_VELOCITY_CONFIG;
}

/**
 * Mock IP geolocation lookup (in production, use MaxMind or similar)
 * This is a placeholder that should be replaced with actual geolocation service
 */
export async function lookupIpLocation(ipAddress: string): Promise<GeoLocation | null> {
  // Known test IPs for development
  const testLocations: Record<string, GeoLocation> = {
    // Istanbul
    '85.105.1.1': {
      latitude: 41.0082,
      longitude: 28.9784,
      city: 'Istanbul',
      country: 'Turkey',
      countryCode: 'TR',
      region: 'Istanbul',
      timezone: 'Europe/Istanbul'
    },
    // Ankara
    '78.180.1.1': {
      latitude: 39.9334,
      longitude: 32.8597,
      city: 'Ankara',
      country: 'Turkey',
      countryCode: 'TR',
      region: 'Ankara',
      timezone: 'Europe/Istanbul'
    },
    // New York
    '74.125.1.1': {
      latitude: 40.7128,
      longitude: -74.0060,
      city: 'New York',
      country: 'United States',
      countryCode: 'US',
      region: 'New York',
      timezone: 'America/New_York'
    },
    // London
    '51.140.1.1': {
      latitude: 51.5074,
      longitude: -0.1278,
      city: 'London',
      country: 'United Kingdom',
      countryCode: 'GB',
      region: 'England',
      timezone: 'Europe/London'
    },
    // VPN/Datacenter
    '10.0.0.1': {
      latitude: 0,
      longitude: 0,
      city: 'Unknown',
      country: 'Unknown',
      countryCode: 'XX',
      isVpn: true,
      isDatacenter: true
    },
    // Tor exit node
    '185.220.101.1': {
      latitude: 52.5200,
      longitude: 13.4050,
      city: 'Berlin',
      country: 'Germany',
      countryCode: 'DE',
      isTor: true
    }
  };

  return testLocations[ipAddress] || null;
}

/**
 * Get user's login history with locations
 */
export async function getUserLoginHistory(
  userId: string,
  realmId: string,
  limit: number = 10
): Promise<LoginLocationRecord[]> {
  try {
    const queryCommand = new QueryCommand({
      TableName: TableNames.DOCUMENTS,
      KeyConditionExpression: 'pk = :pk AND begins_with(sk, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk': `USER#${realmId}#${userId}`,
        ':skPrefix': 'LOGIN_LOCATION#'
      },
      ScanIndexForward: false,
      Limit: limit
    });

    const result = await dynamoDb.send(queryCommand);
    
    return (result.Items || []).map(item => ({
      userId: item.user_id,
      realmId: item.realm_id,
      ipAddress: item.ip_address,
      location: item.location,
      timestamp: item.timestamp,
      deviceFingerprint: item.device_fingerprint,
      userAgent: item.user_agent
    }));
  } catch (error) {
    console.error('Get user login history error:', error);
    return [];
  }
}

/**
 * Check if two locations are in the same country
 */
export function isSameCountry(loc1: GeoLocation, loc2: GeoLocation): boolean {
  return loc1.countryCode === loc2.countryCode;
}

/**
 * Check if two locations are in the same city
 */
export function isSameCity(loc1: GeoLocation, loc2: GeoLocation): boolean {
  return loc1.city === loc2.city && loc1.countryCode === loc2.countryCode;
}

/**
 * Estimate travel time between two locations (hours)
 * Based on typical commercial flight speeds
 */
export function estimateTravelTime(distanceKm: number): number {
  if (distanceKm < 100) return 0.5; // Local travel
  if (distanceKm < 500) return 1; // Short flight
  if (distanceKm < 2000) return 3; // Medium flight
  if (distanceKm < 5000) return 8; // Long flight
  return 15; // Very long flight with connections
}
