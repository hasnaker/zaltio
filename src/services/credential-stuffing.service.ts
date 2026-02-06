/**
 * Credential Stuffing Detection Service for Zalt.io Auth Platform
 * Task 6.2: Credential Stuffing Detection
 * 
 * SECURITY FEATURES:
 * - Pattern detection for automated attacks
 * - Same password across different emails detection
 * - High-velocity request detection
 * - Distributed attack detection (multiple IPs, same target)
 * - CAPTCHA triggering
 * - IP blocking
 * - Security alerting
 * 
 * DETECTION PATTERNS:
 * 1. Same password hash used with multiple emails (credential stuffing)
 * 2. Same IP with many failed logins (brute force)
 * 3. Multiple IPs targeting same email (distributed attack)
 * 4. Request velocity > 1 req/second (automated attack)
 */

import { GetCommand, PutCommand, UpdateCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';
import { logSimpleSecurityEvent } from './security-logger.service';
import crypto from 'crypto';

/**
 * Attack types detected by the service
 */
export enum AttackType {
  CREDENTIAL_STUFFING = 'credential_stuffing',
  BRUTE_FORCE = 'brute_force',
  DISTRIBUTED_ATTACK = 'distributed_attack',
  HIGH_VELOCITY = 'high_velocity',
  PASSWORD_SPRAY = 'password_spray'
}

/**
 * Detection result
 */
export interface DetectionResult {
  detected: boolean;
  attackType?: AttackType;
  confidence: number; // 0-100
  requiresCaptcha: boolean;
  shouldBlock: boolean;
  blockDuration?: number; // seconds
  alertSent: boolean;
  details: Record<string, unknown>;
}

/**
 * Attack pattern record stored in DynamoDB
 */
interface AttackPatternRecord {
  pk: string;
  sk: string;
  pattern_type: AttackType;
  count: number;
  first_seen: number;
  last_seen: number;
  identifiers: string[]; // emails, IPs, etc.
  blocked_until?: number;
  ttl: number;
}

/**
 * Login attempt record for pattern analysis
 */
interface LoginAttemptRecord {
  pk: string;
  sk: string;
  realm_id: string;
  email: string;
  ip_address: string;
  password_hash: string; // SHA-256 of password for pattern detection (NOT stored password)
  success: boolean;
  timestamp: number;
  user_agent?: string;
  ttl: number;
}

/**
 * Detection thresholds
 */
export const DETECTION_THRESHOLDS = {
  // Same password used with X different emails = credential stuffing
  samePasswordDifferentEmails: 3,
  // Same IP with X failed logins = brute force
  sameIpFailedLogins: 10,
  // X different IPs targeting same email = distributed attack
  differentIpsTargetingSameEmail: 5,
  // More than X requests per second = high velocity
  requestsPerSecond: 1,
  // Time window for pattern detection (seconds)
  detectionWindow: 300, // 5 minutes
  // Confidence threshold for blocking
  blockingConfidenceThreshold: 70,
  // Confidence threshold for CAPTCHA
  captchaConfidenceThreshold: 50,
  // Block duration (seconds)
  defaultBlockDuration: 900, // 15 minutes
  extendedBlockDuration: 3600 // 1 hour for severe attacks
};

/**
 * Generate a hash of the password for pattern detection
 * This is NOT the stored password hash - just for detecting same password across attempts
 */
export function hashPasswordForDetection(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex').substring(0, 16);
}

/**
 * Record a login attempt for pattern analysis
 */
export async function recordLoginAttempt(
  realmId: string,
  email: string,
  ipAddress: string,
  password: string,
  success: boolean,
  userAgent?: string
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const passwordHash = hashPasswordForDetection(password);
  
  const record: LoginAttemptRecord = {
    pk: `LOGINATTEMPT#${realmId}`,
    sk: `${now}#${crypto.randomBytes(8).toString('hex')}`,
    realm_id: realmId,
    email: email.toLowerCase(),
    ip_address: ipAddress,
    password_hash: passwordHash,
    success,
    timestamp: now,
    user_agent: userAgent,
    ttl: now + DETECTION_THRESHOLDS.detectionWindow + 3600 // Keep for 1 hour after window
  };

  try {
    const putCommand = new PutCommand({
      TableName: TableNames.SESSIONS,
      Item: record
    });

    await dynamoDb.send(putCommand);
  } catch (error) {
    console.error('Failed to record login attempt:', error);
  }
}

/**
 * Detect credential stuffing attack
 * Pattern: Same password hash used with multiple different emails
 */
export async function detectCredentialStuffing(
  realmId: string,
  passwordHash: string,
  currentEmail: string
): Promise<DetectionResult> {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - DETECTION_THRESHOLDS.detectionWindow;

  try {
    // Query recent login attempts with this password hash
    const queryCommand = new QueryCommand({
      TableName: TableNames.SESSIONS,
      KeyConditionExpression: 'pk = :pk AND sk > :windowStart',
      FilterExpression: 'password_hash = :passwordHash',
      ExpressionAttributeValues: {
        ':pk': `LOGINATTEMPT#${realmId}`,
        ':windowStart': `${windowStart}`,
        ':passwordHash': passwordHash
      }
    });

    const result = await dynamoDb.send(queryCommand);
    const attempts = (result.Items || []) as LoginAttemptRecord[];

    // Get unique emails using this password
    const uniqueEmails = new Set(attempts.map(a => a.email));
    uniqueEmails.add(currentEmail.toLowerCase());

    const emailCount = uniqueEmails.size;

    if (emailCount >= DETECTION_THRESHOLDS.samePasswordDifferentEmails) {
      const confidence = Math.min(100, 50 + (emailCount - DETECTION_THRESHOLDS.samePasswordDifferentEmails) * 15);
      
      return {
        detected: true,
        attackType: AttackType.CREDENTIAL_STUFFING,
        confidence,
        requiresCaptcha: confidence >= DETECTION_THRESHOLDS.captchaConfidenceThreshold,
        shouldBlock: confidence >= DETECTION_THRESHOLDS.blockingConfidenceThreshold,
        blockDuration: confidence >= 80 ? DETECTION_THRESHOLDS.extendedBlockDuration : DETECTION_THRESHOLDS.defaultBlockDuration,
        alertSent: false,
        details: {
          uniqueEmails: emailCount,
          threshold: DETECTION_THRESHOLDS.samePasswordDifferentEmails,
          windowSeconds: DETECTION_THRESHOLDS.detectionWindow
        }
      };
    }

    return createNegativeResult();
  } catch (error) {
    console.error('Credential stuffing detection error:', error);
    return createNegativeResult();
  }
}

/**
 * Detect brute force attack from single IP
 * Pattern: Same IP with many failed login attempts
 */
export async function detectBruteForce(
  realmId: string,
  ipAddress: string
): Promise<DetectionResult> {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - DETECTION_THRESHOLDS.detectionWindow;

  try {
    const queryCommand = new QueryCommand({
      TableName: TableNames.SESSIONS,
      KeyConditionExpression: 'pk = :pk AND sk > :windowStart',
      FilterExpression: 'ip_address = :ip AND success = :success',
      ExpressionAttributeValues: {
        ':pk': `LOGINATTEMPT#${realmId}`,
        ':windowStart': `${windowStart}`,
        ':ip': ipAddress,
        ':success': false
      }
    });

    const result = await dynamoDb.send(queryCommand);
    const failedAttempts = (result.Items || []).length;

    if (failedAttempts >= DETECTION_THRESHOLDS.sameIpFailedLogins) {
      const confidence = Math.min(100, 60 + (failedAttempts - DETECTION_THRESHOLDS.sameIpFailedLogins) * 5);
      
      return {
        detected: true,
        attackType: AttackType.BRUTE_FORCE,
        confidence,
        requiresCaptcha: confidence >= DETECTION_THRESHOLDS.captchaConfidenceThreshold,
        shouldBlock: confidence >= DETECTION_THRESHOLDS.blockingConfidenceThreshold,
        blockDuration: DETECTION_THRESHOLDS.defaultBlockDuration,
        alertSent: false,
        details: {
          failedAttempts,
          threshold: DETECTION_THRESHOLDS.sameIpFailedLogins,
          ipAddress,
          windowSeconds: DETECTION_THRESHOLDS.detectionWindow
        }
      };
    }

    return createNegativeResult();
  } catch (error) {
    console.error('Brute force detection error:', error);
    return createNegativeResult();
  }
}

/**
 * Detect distributed attack
 * Pattern: Multiple different IPs targeting the same email
 */
export async function detectDistributedAttack(
  realmId: string,
  email: string
): Promise<DetectionResult> {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - DETECTION_THRESHOLDS.detectionWindow;

  try {
    const queryCommand = new QueryCommand({
      TableName: TableNames.SESSIONS,
      KeyConditionExpression: 'pk = :pk AND sk > :windowStart',
      FilterExpression: 'email = :email AND success = :success',
      ExpressionAttributeValues: {
        ':pk': `LOGINATTEMPT#${realmId}`,
        ':windowStart': `${windowStart}`,
        ':email': email.toLowerCase(),
        ':success': false
      }
    });

    const result = await dynamoDb.send(queryCommand);
    const attempts = (result.Items || []) as LoginAttemptRecord[];

    // Get unique IPs targeting this email
    const uniqueIps = new Set(attempts.map(a => a.ip_address));

    if (uniqueIps.size >= DETECTION_THRESHOLDS.differentIpsTargetingSameEmail) {
      const confidence = Math.min(100, 55 + (uniqueIps.size - DETECTION_THRESHOLDS.differentIpsTargetingSameEmail) * 10);
      
      return {
        detected: true,
        attackType: AttackType.DISTRIBUTED_ATTACK,
        confidence,
        requiresCaptcha: confidence >= DETECTION_THRESHOLDS.captchaConfidenceThreshold,
        shouldBlock: false, // Don't block the user, just require CAPTCHA
        alertSent: false,
        details: {
          uniqueIps: uniqueIps.size,
          threshold: DETECTION_THRESHOLDS.differentIpsTargetingSameEmail,
          targetEmail: email,
          windowSeconds: DETECTION_THRESHOLDS.detectionWindow
        }
      };
    }

    return createNegativeResult();
  } catch (error) {
    console.error('Distributed attack detection error:', error);
    return createNegativeResult();
  }
}

/**
 * Detect high velocity attack
 * Pattern: More than X requests per second from same IP
 */
export async function detectHighVelocity(
  realmId: string,
  ipAddress: string
): Promise<DetectionResult> {
  const now = Math.floor(Date.now() / 1000);
  const oneSecondAgo = now - 1;

  try {
    const queryCommand = new QueryCommand({
      TableName: TableNames.SESSIONS,
      KeyConditionExpression: 'pk = :pk AND sk > :windowStart',
      FilterExpression: 'ip_address = :ip',
      ExpressionAttributeValues: {
        ':pk': `LOGINATTEMPT#${realmId}`,
        ':windowStart': `${oneSecondAgo}`,
        ':ip': ipAddress
      }
    });

    const result = await dynamoDb.send(queryCommand);
    const recentAttempts = (result.Items || []).length;

    if (recentAttempts > DETECTION_THRESHOLDS.requestsPerSecond) {
      const confidence = Math.min(100, 70 + recentAttempts * 5);
      
      return {
        detected: true,
        attackType: AttackType.HIGH_VELOCITY,
        confidence,
        requiresCaptcha: true,
        shouldBlock: confidence >= DETECTION_THRESHOLDS.blockingConfidenceThreshold,
        blockDuration: DETECTION_THRESHOLDS.defaultBlockDuration,
        alertSent: false,
        details: {
          requestsPerSecond: recentAttempts,
          threshold: DETECTION_THRESHOLDS.requestsPerSecond,
          ipAddress
        }
      };
    }

    return createNegativeResult();
  } catch (error) {
    console.error('High velocity detection error:', error);
    return createNegativeResult();
  }
}

/**
 * Comprehensive attack detection
 * Runs all detection algorithms and returns the most severe result
 */
export async function detectAttack(
  realmId: string,
  email: string,
  ipAddress: string,
  password: string
): Promise<DetectionResult> {
  const passwordHash = hashPasswordForDetection(password);

  // Run all detections in parallel
  const [credentialStuffing, bruteForce, distributed, highVelocity] = await Promise.all([
    detectCredentialStuffing(realmId, passwordHash, email),
    detectBruteForce(realmId, ipAddress),
    detectDistributedAttack(realmId, email),
    detectHighVelocity(realmId, ipAddress)
  ]);

  // Find the most severe detection
  const detections = [credentialStuffing, bruteForce, distributed, highVelocity]
    .filter(d => d.detected)
    .sort((a, b) => b.confidence - a.confidence);

  if (detections.length === 0) {
    return createNegativeResult();
  }

  const mostSevere = detections[0];

  // If multiple attack types detected, increase confidence
  if (detections.length > 1) {
    mostSevere.confidence = Math.min(100, mostSevere.confidence + detections.length * 5);
    mostSevere.details = {
      ...mostSevere.details,
      multipleAttackTypes: detections.map(d => d.attackType),
      combinedDetections: detections.length
    };
  }

  // Send security alert if high confidence
  if (mostSevere.confidence >= DETECTION_THRESHOLDS.blockingConfidenceThreshold) {
    await sendSecurityAlert(realmId, mostSevere, email, ipAddress);
    mostSevere.alertSent = true;
  }

  return mostSevere;
}

/**
 * Send security alert for detected attack
 */
async function sendSecurityAlert(
  realmId: string,
  detection: DetectionResult,
  email: string,
  ipAddress: string
): Promise<void> {
  try {
    await logSimpleSecurityEvent({
      event_type: 'attack_detected',
      realm_id: realmId,
      ip_address: ipAddress,
      details: {
        attack_type: detection.attackType,
        confidence: detection.confidence,
        target_email: email,
        requires_captcha: detection.requiresCaptcha,
        should_block: detection.shouldBlock,
        ...detection.details
      }
    });
  } catch (error) {
    console.error('Failed to send security alert:', error);
  }
}

/**
 * Block an IP address
 */
export async function blockIP(
  realmId: string,
  ipAddress: string,
  duration: number,
  reason: AttackType
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const blockedUntil = now + duration;

  try {
    const record: AttackPatternRecord = {
      pk: `BLOCKED#${realmId}`,
      sk: `IP#${ipAddress}`,
      pattern_type: reason,
      count: 1,
      first_seen: now,
      last_seen: now,
      identifiers: [ipAddress],
      blocked_until: blockedUntil,
      ttl: blockedUntil + 3600
    };

    const putCommand = new PutCommand({
      TableName: TableNames.SESSIONS,
      Item: record
    });

    await dynamoDb.send(putCommand);

    await logSimpleSecurityEvent({
      event_type: 'ip_blocked',
      realm_id: realmId,
      ip_address: ipAddress,
      details: {
        reason,
        duration,
        blocked_until: new Date(blockedUntil * 1000).toISOString()
      }
    });
  } catch (error) {
    console.error('Failed to block IP:', error);
  }
}

/**
 * Check if an IP is blocked
 */
export async function isIPBlocked(
  realmId: string,
  ipAddress: string
): Promise<{ blocked: boolean; blockedUntil?: number; reason?: AttackType }> {
  const now = Math.floor(Date.now() / 1000);

  try {
    const getCommand = new GetCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `BLOCKED#${realmId}`,
        sk: `IP#${ipAddress}`
      }
    });

    const result = await dynamoDb.send(getCommand);
    const record = result.Item as AttackPatternRecord | undefined;

    if (record && record.blocked_until && record.blocked_until > now) {
      return {
        blocked: true,
        blockedUntil: record.blocked_until,
        reason: record.pattern_type
      };
    }

    return { blocked: false };
  } catch (error) {
    console.error('Failed to check IP block status:', error);
    return { blocked: false };
  }
}

/**
 * Unblock an IP address
 */
export async function unblockIP(realmId: string, ipAddress: string): Promise<void> {
  try {
    const updateCommand = new UpdateCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `BLOCKED#${realmId}`,
        sk: `IP#${ipAddress}`
      },
      UpdateExpression: 'SET blocked_until = :null',
      ExpressionAttributeValues: {
        ':null': null
      }
    });

    await dynamoDb.send(updateCommand);
  } catch (error) {
    console.error('Failed to unblock IP:', error);
  }
}

/**
 * Get attack statistics for a realm
 */
export async function getAttackStatistics(
  realmId: string,
  windowSeconds: number = 3600
): Promise<{
  totalAttempts: number;
  failedAttempts: number;
  uniqueIPs: number;
  uniqueEmails: number;
  blockedIPs: number;
}> {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - windowSeconds;

  try {
    const queryCommand = new QueryCommand({
      TableName: TableNames.SESSIONS,
      KeyConditionExpression: 'pk = :pk AND sk > :windowStart',
      ExpressionAttributeValues: {
        ':pk': `LOGINATTEMPT#${realmId}`,
        ':windowStart': `${windowStart}`
      }
    });

    const result = await dynamoDb.send(queryCommand);
    const attempts = (result.Items || []) as LoginAttemptRecord[];

    const uniqueIPs = new Set(attempts.map(a => a.ip_address));
    const uniqueEmails = new Set(attempts.map(a => a.email));
    const failedAttempts = attempts.filter(a => !a.success).length;

    // Count blocked IPs
    const blockedQuery = new QueryCommand({
      TableName: TableNames.SESSIONS,
      KeyConditionExpression: 'pk = :pk',
      FilterExpression: 'blocked_until > :now',
      ExpressionAttributeValues: {
        ':pk': `BLOCKED#${realmId}`,
        ':now': now
      }
    });

    const blockedResult = await dynamoDb.send(blockedQuery);
    const blockedIPs = (blockedResult.Items || []).length;

    return {
      totalAttempts: attempts.length,
      failedAttempts,
      uniqueIPs: uniqueIPs.size,
      uniqueEmails: uniqueEmails.size,
      blockedIPs
    };
  } catch (error) {
    console.error('Failed to get attack statistics:', error);
    return {
      totalAttempts: 0,
      failedAttempts: 0,
      uniqueIPs: 0,
      uniqueEmails: 0,
      blockedIPs: 0
    };
  }
}

/**
 * Create a negative detection result
 */
function createNegativeResult(): DetectionResult {
  return {
    detected: false,
    confidence: 0,
    requiresCaptcha: false,
    shouldBlock: false,
    alertSent: false,
    details: {}
  };
}

/**
 * Check if CAPTCHA is required based on detection result
 */
export function isCaptchaRequired(detection: DetectionResult): boolean {
  return detection.requiresCaptcha || detection.confidence >= DETECTION_THRESHOLDS.captchaConfidenceThreshold;
}

/**
 * Get recommended action based on detection result
 */
export function getRecommendedAction(detection: DetectionResult): {
  action: 'allow' | 'captcha' | 'block';
  message: string;
} {
  if (detection.shouldBlock) {
    return {
      action: 'block',
      message: `Suspicious activity detected (${detection.attackType}). Access temporarily blocked.`
    };
  }

  if (detection.requiresCaptcha) {
    return {
      action: 'captcha',
      message: 'Please complete the security verification to continue.'
    };
  }

  return {
    action: 'allow',
    message: ''
  };
}
