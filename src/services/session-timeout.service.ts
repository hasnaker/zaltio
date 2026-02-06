/**
 * Session Timeout Service for Zalt.io Auth Platform
 * Task 6.6: Session Timeout Policies
 * 
 * HEALTHCARE CRITICAL:
 * - Idle timeout: 30 minutes inactivity → logout
 * - Absolute timeout: 8-12 hours → forced logout
 * - Activity tracking: Every API call updates last_activity
 * - Realm-based configuration
 * 
 * COMPLIANCE:
 * - HIPAA requires automatic session termination
 * - Patient data protection
 * - Audit logging for all timeout events
 */

import { GetCommand, UpdateCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';
import { logSimpleSecurityEvent } from './security-logger.service';

/**
 * Session timeout configuration
 */
export interface SessionTimeoutConfig {
  // Idle timeout (seconds) - logout after inactivity
  idleTimeoutSeconds: number;
  
  // Absolute timeout (seconds) - forced logout regardless of activity
  absoluteTimeoutSeconds: number;
  
  // Warning before timeout (seconds)
  warningBeforeTimeoutSeconds: number;
  
  // Activity tracking enabled
  activityTrackingEnabled: boolean;
  
  // Extend session on activity
  extendOnActivity: boolean;
}

/**
 * Session status
 */
export interface SessionStatus {
  isValid: boolean;
  isExpired: boolean;
  expiredReason?: 'idle' | 'absolute' | 'revoked';
  lastActivity?: string;
  sessionStart?: string;
  idleTimeRemaining?: number;
  absoluteTimeRemaining?: number;
  warningActive: boolean;
}

/**
 * Default timeout configurations by realm type
 */
export const TIMEOUT_CONFIGS: Record<string, SessionTimeoutConfig> = {
  // Healthcare realms - strict timeouts
  healthcare: {
    idleTimeoutSeconds: 1800, // 30 minutes
    absoluteTimeoutSeconds: 28800, // 8 hours
    warningBeforeTimeoutSeconds: 300, // 5 minutes warning
    activityTrackingEnabled: true,
    extendOnActivity: true
  },
  
  // Standard realms - moderate timeouts
  standard: {
    idleTimeoutSeconds: 3600, // 1 hour
    absoluteTimeoutSeconds: 43200, // 12 hours
    warningBeforeTimeoutSeconds: 300,
    activityTrackingEnabled: true,
    extendOnActivity: true
  },
  
  // Extended realms - longer timeouts
  extended: {
    idleTimeoutSeconds: 7200, // 2 hours
    absoluteTimeoutSeconds: 86400, // 24 hours
    warningBeforeTimeoutSeconds: 600,
    activityTrackingEnabled: true,
    extendOnActivity: true
  }
};

/**
 * Default healthcare timeout (for Clinisyn)
 */
export const DEFAULT_HEALTHCARE_TIMEOUT = TIMEOUT_CONFIGS.healthcare;

/**
 * Session record in DynamoDB
 */
interface SessionRecord {
  pk: string;
  sk: string;
  user_id: string;
  realm_id: string;
  session_start: number;
  last_activity: number;
  absolute_expiry: number;
  idle_expiry: number;
  is_active: boolean;
  revoked: boolean;
  revoked_reason?: string;
  device_info?: string;
  ip_address?: string;
  ttl: number;
}

/**
 * Check if session is valid based on timeout policies
 */
export async function checkSessionTimeout(
  sessionId: string,
  realmId: string,
  config: SessionTimeoutConfig = DEFAULT_HEALTHCARE_TIMEOUT
): Promise<SessionStatus> {
  const now = Math.floor(Date.now() / 1000);

  try {
    const getCommand = new GetCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `SESSION#${realmId}`,
        sk: `ID#${sessionId}`
      }
    });

    const result = await dynamoDb.send(getCommand);
    const session = result.Item as SessionRecord | undefined;

    if (!session) {
      return {
        isValid: false,
        isExpired: true,
        expiredReason: 'revoked',
        warningActive: false
      };
    }

    // Check if revoked
    if (session.revoked) {
      return {
        isValid: false,
        isExpired: true,
        expiredReason: 'revoked',
        lastActivity: new Date(session.last_activity * 1000).toISOString(),
        sessionStart: new Date(session.session_start * 1000).toISOString(),
        warningActive: false
      };
    }

    // Check absolute timeout
    if (now >= session.absolute_expiry) {
      await expireSession(sessionId, realmId, 'absolute');
      return {
        isValid: false,
        isExpired: true,
        expiredReason: 'absolute',
        lastActivity: new Date(session.last_activity * 1000).toISOString(),
        sessionStart: new Date(session.session_start * 1000).toISOString(),
        warningActive: false
      };
    }

    // Check idle timeout
    const idleExpiry = session.last_activity + config.idleTimeoutSeconds;
    if (now >= idleExpiry) {
      await expireSession(sessionId, realmId, 'idle');
      return {
        isValid: false,
        isExpired: true,
        expiredReason: 'idle',
        lastActivity: new Date(session.last_activity * 1000).toISOString(),
        sessionStart: new Date(session.session_start * 1000).toISOString(),
        warningActive: false
      };
    }

    // Calculate remaining times
    const idleTimeRemaining = idleExpiry - now;
    const absoluteTimeRemaining = session.absolute_expiry - now;
    const warningActive = idleTimeRemaining <= config.warningBeforeTimeoutSeconds ||
                          absoluteTimeRemaining <= config.warningBeforeTimeoutSeconds;

    return {
      isValid: true,
      isExpired: false,
      lastActivity: new Date(session.last_activity * 1000).toISOString(),
      sessionStart: new Date(session.session_start * 1000).toISOString(),
      idleTimeRemaining,
      absoluteTimeRemaining,
      warningActive
    };
  } catch (error) {
    console.error('Check session timeout error:', error);
    return {
      isValid: false,
      isExpired: true,
      expiredReason: 'revoked',
      warningActive: false
    };
  }
}

/**
 * Update session activity (called on each API request)
 */
export async function updateSessionActivity(
  sessionId: string,
  realmId: string,
  config: SessionTimeoutConfig = DEFAULT_HEALTHCARE_TIMEOUT
): Promise<boolean> {
  if (!config.activityTrackingEnabled) {
    return true;
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    // First check if session is still valid
    const status = await checkSessionTimeout(sessionId, realmId, config);
    if (!status.isValid) {
      return false;
    }

    // Update last activity
    const updateCommand = new UpdateCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `SESSION#${realmId}`,
        sk: `ID#${sessionId}`
      },
      UpdateExpression: 'SET last_activity = :now',
      ConditionExpression: 'attribute_exists(pk) AND revoked <> :true',
      ExpressionAttributeValues: {
        ':now': now,
        ':true': true
      }
    });

    await dynamoDb.send(updateCommand);
    return true;
  } catch (error) {
    console.error('Update session activity error:', error);
    return false;
  }
}

/**
 * Create a new session with timeout tracking
 */
export async function createSessionWithTimeout(
  sessionId: string,
  userId: string,
  realmId: string,
  config: SessionTimeoutConfig = DEFAULT_HEALTHCARE_TIMEOUT,
  metadata?: {
    deviceInfo?: string;
    ipAddress?: string;
  }
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const absoluteExpiry = now + config.absoluteTimeoutSeconds;

  const session: SessionRecord = {
    pk: `SESSION#${realmId}`,
    sk: `ID#${sessionId}`,
    user_id: userId,
    realm_id: realmId,
    session_start: now,
    last_activity: now,
    absolute_expiry: absoluteExpiry,
    idle_expiry: now + config.idleTimeoutSeconds,
    is_active: true,
    revoked: false,
    device_info: metadata?.deviceInfo,
    ip_address: metadata?.ipAddress,
    ttl: absoluteExpiry + 86400 // Keep for 1 day after expiry
  };

  try {
    const putCommand = {
      TableName: TableNames.SESSIONS,
      Item: session
    };

    await dynamoDb.send(new (require('@aws-sdk/lib-dynamodb').PutCommand)(putCommand));

    await logSimpleSecurityEvent({
      event_type: 'session_created',
      realm_id: realmId,
      user_id: userId,
      details: {
        session_id: sessionId.substring(0, 8) + '...',
        absolute_expiry: new Date(absoluteExpiry * 1000).toISOString(),
        idle_timeout_seconds: config.idleTimeoutSeconds
      }
    });
  } catch (error) {
    console.error('Create session with timeout error:', error);
    throw error;
  }
}

/**
 * Expire a session
 */
export async function expireSession(
  sessionId: string,
  realmId: string,
  reason: 'idle' | 'absolute' | 'manual' | 'logout'
): Promise<void> {
  try {
    const updateCommand = new UpdateCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `SESSION#${realmId}`,
        sk: `ID#${sessionId}`
      },
      UpdateExpression: 'SET revoked = :true, revoked_reason = :reason, is_active = :false',
      ExpressionAttributeValues: {
        ':true': true,
        ':reason': reason,
        ':false': false
      }
    });

    await dynamoDb.send(updateCommand);

    await logSimpleSecurityEvent({
      event_type: 'session_expired',
      realm_id: realmId,
      details: {
        session_id: sessionId.substring(0, 8) + '...',
        reason
      }
    });
  } catch (error) {
    console.error('Expire session error:', error);
  }
}

/**
 * Get timeout configuration for a realm
 */
export function getRealmTimeoutConfig(
  realmId: string,
  realmSettings?: { 
    session_timeout_type?: 'healthcare' | 'standard' | 'extended';
    custom_idle_timeout?: number;
    custom_absolute_timeout?: number;
  }
): SessionTimeoutConfig {
  // Default to healthcare for Clinisyn realms
  if (realmId.startsWith('clinisyn')) {
    return TIMEOUT_CONFIGS.healthcare;
  }

  // Use realm-specific settings if provided
  if (realmSettings?.session_timeout_type) {
    const baseConfig = TIMEOUT_CONFIGS[realmSettings.session_timeout_type] || TIMEOUT_CONFIGS.standard;
    
    return {
      ...baseConfig,
      idleTimeoutSeconds: realmSettings.custom_idle_timeout || baseConfig.idleTimeoutSeconds,
      absoluteTimeoutSeconds: realmSettings.custom_absolute_timeout || baseConfig.absoluteTimeoutSeconds
    };
  }

  return TIMEOUT_CONFIGS.standard;
}

/**
 * Get all active sessions for a user
 */
export async function getUserActiveSessions(
  userId: string,
  realmId: string
): Promise<Array<{
  sessionId: string;
  sessionStart: string;
  lastActivity: string;
  deviceInfo?: string;
  ipAddress?: string;
}>> {
  const now = Math.floor(Date.now() / 1000);

  try {
    const queryCommand = new QueryCommand({
      TableName: TableNames.SESSIONS,
      KeyConditionExpression: 'pk = :pk',
      FilterExpression: 'user_id = :userId AND revoked <> :true AND absolute_expiry > :now',
      ExpressionAttributeValues: {
        ':pk': `SESSION#${realmId}`,
        ':userId': userId,
        ':true': true,
        ':now': now
      }
    });

    const result = await dynamoDb.send(queryCommand);
    const sessions = (result.Items || []) as SessionRecord[];

    return sessions.map(s => ({
      sessionId: s.sk.replace('ID#', ''),
      sessionStart: new Date(s.session_start * 1000).toISOString(),
      lastActivity: new Date(s.last_activity * 1000).toISOString(),
      deviceInfo: s.device_info,
      ipAddress: s.ip_address
    }));
  } catch (error) {
    console.error('Get user active sessions error:', error);
    return [];
  }
}

/**
 * Terminate all sessions for a user
 */
export async function terminateAllUserSessions(
  userId: string,
  realmId: string,
  reason: string = 'manual'
): Promise<number> {
  try {
    const sessions = await getUserActiveSessions(userId, realmId);
    
    for (const session of sessions) {
      await expireSession(session.sessionId, realmId, 'manual');
    }

    await logSimpleSecurityEvent({
      event_type: 'all_sessions_terminated',
      realm_id: realmId,
      user_id: userId,
      details: {
        terminated_count: sessions.length,
        reason
      }
    });

    return sessions.length;
  } catch (error) {
    console.error('Terminate all user sessions error:', error);
    return 0;
  }
}

/**
 * Extend session (for "keep me logged in" scenarios)
 */
export async function extendSession(
  sessionId: string,
  realmId: string,
  additionalSeconds: number,
  config: SessionTimeoutConfig = DEFAULT_HEALTHCARE_TIMEOUT
): Promise<boolean> {
  // Healthcare realms cannot extend beyond absolute timeout
  if (realmId.startsWith('clinisyn')) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    const status = await checkSessionTimeout(sessionId, realmId, config);
    if (!status.isValid) {
      return false;
    }

    const newAbsoluteExpiry = now + additionalSeconds;
    
    const updateCommand = new UpdateCommand({
      TableName: TableNames.SESSIONS,
      Key: {
        pk: `SESSION#${realmId}`,
        sk: `ID#${sessionId}`
      },
      UpdateExpression: 'SET absolute_expiry = :expiry, last_activity = :now',
      ExpressionAttributeValues: {
        ':expiry': newAbsoluteExpiry,
        ':now': now
      }
    });

    await dynamoDb.send(updateCommand);
    return true;
  } catch (error) {
    console.error('Extend session error:', error);
    return false;
  }
}

/**
 * Check if session needs warning
 */
export function needsTimeoutWarning(status: SessionStatus, config: SessionTimeoutConfig): boolean {
  if (!status.isValid || status.isExpired) {
    return false;
  }

  const idleWarning = status.idleTimeRemaining !== undefined && 
                      status.idleTimeRemaining <= config.warningBeforeTimeoutSeconds;
  const absoluteWarning = status.absoluteTimeRemaining !== undefined && 
                          status.absoluteTimeRemaining <= config.warningBeforeTimeoutSeconds;

  return idleWarning || absoluteWarning;
}

/**
 * Get session timeout info for client
 */
export function getTimeoutInfo(
  status: SessionStatus,
  config: SessionTimeoutConfig
): {
  timeoutType: 'idle' | 'absolute' | null;
  secondsRemaining: number | null;
  warningActive: boolean;
} {
  if (!status.isValid || status.isExpired) {
    return {
      timeoutType: null,
      secondsRemaining: null,
      warningActive: false
    };
  }

  const idleRemaining = status.idleTimeRemaining || Infinity;
  const absoluteRemaining = status.absoluteTimeRemaining || Infinity;

  if (idleRemaining <= absoluteRemaining) {
    return {
      timeoutType: 'idle',
      secondsRemaining: idleRemaining,
      warningActive: idleRemaining <= config.warningBeforeTimeoutSeconds
    };
  }

  return {
    timeoutType: 'absolute',
    secondsRemaining: absoluteRemaining,
    warningActive: absoluteRemaining <= config.warningBeforeTimeoutSeconds
  };
}
