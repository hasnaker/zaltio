/**
 * Password History Service for Zalt.io Auth Platform
 * Task 6.10: Password History
 * 
 * SECURITY CRITICAL:
 * - Prevents reuse of last 5 passwords
 * - All passwords stored as Argon2id hashes
 * - Protects against credential cycling attacks
 * 
 * COMPLIANCE:
 * - HIPAA requires password history enforcement
 * - NIST 800-63B recommends checking against previous passwords
 */

import { GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';
import { hashPassword, verifyPassword } from '../utils/password';
import { logSimpleSecurityEvent } from './security-logger.service';

/**
 * Password history configuration
 */
export interface PasswordHistoryConfig {
  // Number of previous passwords to remember
  historySize: number;
  
  // Minimum time between password changes (seconds)
  minPasswordAge: number;
  
  // Maximum password age before forced change (seconds)
  maxPasswordAge: number;
  
  // Require different from current password
  requireDifferentFromCurrent: boolean;
}

/**
 * Default password history configuration
 */
export const DEFAULT_PASSWORD_HISTORY_CONFIG: PasswordHistoryConfig = {
  historySize: 5,
  minPasswordAge: 86400, // 1 day minimum
  maxPasswordAge: 90 * 86400, // 90 days maximum
  requireDifferentFromCurrent: true
};

/**
 * Healthcare password history configuration (stricter)
 */
export const HEALTHCARE_PASSWORD_HISTORY_CONFIG: PasswordHistoryConfig = {
  historySize: 12, // Remember more passwords for healthcare
  minPasswordAge: 86400, // 1 day minimum
  maxPasswordAge: 60 * 86400, // 60 days maximum for healthcare
  requireDifferentFromCurrent: true
};

/**
 * Password history record
 */
export interface PasswordHistoryRecord {
  hash: string;
  changedAt: number;
}

/**
 * Password change result
 */
export interface PasswordChangeResult {
  success: boolean;
  error?: string;
  errorCode?: 'SAME_AS_CURRENT' | 'IN_HISTORY' | 'TOO_SOON' | 'WEAK_PASSWORD' | 'INVALID_CURRENT';
  historyPosition?: number; // Which historical password it matched (1-5)
}

/**
 * Get password history for user
 */
export async function getPasswordHistory(
  userId: string,
  realmId: string
): Promise<PasswordHistoryRecord[]> {
  try {
    const getCommand = new GetCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `REALM#${realmId}`,
        sk: `USER#${userId}`
      },
      ProjectionExpression: 'password_history'
    });

    const result = await dynamoDb.send(getCommand);
    return result.Item?.password_history || [];
  } catch (error) {
    console.error('Get password history error:', error);
    return [];
  }
}

/**
 * Check if password is in history
 */
export async function isPasswordInHistory(
  password: string,
  userId: string,
  realmId: string,
  config: PasswordHistoryConfig = DEFAULT_PASSWORD_HISTORY_CONFIG
): Promise<{ inHistory: boolean; position?: number }> {
  try {
    const history = await getPasswordHistory(userId, realmId);
    
    // Check against each historical password
    for (let i = 0; i < Math.min(history.length, config.historySize); i++) {
      const isMatch = await verifyPassword(password, history[i].hash);
      if (isMatch) {
        return { inHistory: true, position: i + 1 };
      }
    }
    
    return { inHistory: false };
  } catch (error) {
    console.error('Check password history error:', error);
    return { inHistory: false };
  }
}

/**
 * Check if password matches current password
 */
export async function isCurrentPassword(
  password: string,
  userId: string,
  realmId: string
): Promise<boolean> {
  try {
    const getCommand = new GetCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `REALM#${realmId}`,
        sk: `USER#${userId}`
      },
      ProjectionExpression: 'password_hash'
    });

    const result = await dynamoDb.send(getCommand);
    if (!result.Item?.password_hash) {
      return false;
    }

    return await verifyPassword(password, result.Item.password_hash);
  } catch (error) {
    console.error('Check current password error:', error);
    return false;
  }
}

/**
 * Check if password change is allowed (minimum age)
 */
export async function canChangePassword(
  userId: string,
  realmId: string,
  config: PasswordHistoryConfig = DEFAULT_PASSWORD_HISTORY_CONFIG
): Promise<{ allowed: boolean; waitSeconds?: number }> {
  try {
    const getCommand = new GetCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `REALM#${realmId}`,
        sk: `USER#${userId}`
      },
      ProjectionExpression: 'password_changed_at'
    });

    const result = await dynamoDb.send(getCommand);
    const lastChange = result.Item?.password_changed_at;
    
    if (!lastChange) {
      return { allowed: true };
    }

    const now = Math.floor(Date.now() / 1000);
    const timeSinceChange = now - lastChange;
    
    if (timeSinceChange < config.minPasswordAge) {
      return {
        allowed: false,
        waitSeconds: config.minPasswordAge - timeSinceChange
      };
    }

    return { allowed: true };
  } catch (error) {
    console.error('Check can change password error:', error);
    return { allowed: true };
  }
}

/**
 * Check if password has expired
 */
export async function isPasswordExpired(
  userId: string,
  realmId: string,
  config: PasswordHistoryConfig = DEFAULT_PASSWORD_HISTORY_CONFIG
): Promise<{ expired: boolean; daysOverdue?: number }> {
  try {
    const getCommand = new GetCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `REALM#${realmId}`,
        sk: `USER#${userId}`
      },
      ProjectionExpression: 'password_changed_at'
    });

    const result = await dynamoDb.send(getCommand);
    const lastChange = result.Item?.password_changed_at;
    
    if (!lastChange) {
      return { expired: false };
    }

    const now = Math.floor(Date.now() / 1000);
    const timeSinceChange = now - lastChange;
    
    if (timeSinceChange > config.maxPasswordAge) {
      const daysOverdue = Math.floor((timeSinceChange - config.maxPasswordAge) / 86400);
      return { expired: true, daysOverdue };
    }

    return { expired: false };
  } catch (error) {
    console.error('Check password expired error:', error);
    return { expired: false };
  }
}

/**
 * Validate new password against history
 */
export async function validateNewPassword(
  newPassword: string,
  currentPassword: string | null,
  userId: string,
  realmId: string,
  config: PasswordHistoryConfig = DEFAULT_PASSWORD_HISTORY_CONFIG
): Promise<PasswordChangeResult> {
  // Check if same as current password
  if (config.requireDifferentFromCurrent && currentPassword) {
    if (newPassword === currentPassword) {
      return {
        success: false,
        error: 'New password must be different from current password',
        errorCode: 'SAME_AS_CURRENT'
      };
    }
  }

  // Check if in history
  const historyCheck = await isPasswordInHistory(newPassword, userId, realmId, config);
  if (historyCheck.inHistory) {
    return {
      success: false,
      error: `Password was used recently. Please choose a different password.`,
      errorCode: 'IN_HISTORY',
      historyPosition: historyCheck.position
    };
  }

  // Check minimum password age
  const canChange = await canChangePassword(userId, realmId, config);
  if (!canChange.allowed) {
    const hours = Math.ceil((canChange.waitSeconds || 0) / 3600);
    return {
      success: false,
      error: `Password was changed recently. Please wait ${hours} hour(s) before changing again.`,
      errorCode: 'TOO_SOON'
    };
  }

  return { success: true };
}

/**
 * Add password to history
 */
export async function addPasswordToHistory(
  userId: string,
  realmId: string,
  passwordHash: string,
  config: PasswordHistoryConfig = DEFAULT_PASSWORD_HISTORY_CONFIG
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);

  try {
    // Get current history
    const history = await getPasswordHistory(userId, realmId);
    
    // Add new password to beginning
    const newHistory: PasswordHistoryRecord[] = [
      { hash: passwordHash, changedAt: now },
      ...history
    ].slice(0, config.historySize); // Keep only historySize entries

    // Update user record
    const updateCommand = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `REALM#${realmId}`,
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET password_history = :history, password_changed_at = :now',
      ExpressionAttributeValues: {
        ':history': newHistory,
        ':now': now
      }
    });

    await dynamoDb.send(updateCommand);

    await logSimpleSecurityEvent({
      event_type: 'password_history_updated',
      realm_id: realmId,
      user_id: userId,
      details: {
        history_size: newHistory.length
      }
    });
  } catch (error) {
    console.error('Add password to history error:', error);
    throw error;
  }
}

/**
 * Clear password history (admin action)
 */
export async function clearPasswordHistory(
  userId: string,
  realmId: string,
  adminUserId: string
): Promise<void> {
  try {
    const updateCommand = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `REALM#${realmId}`,
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET password_history = :empty',
      ExpressionAttributeValues: {
        ':empty': []
      }
    });

    await dynamoDb.send(updateCommand);

    await logSimpleSecurityEvent({
      event_type: 'password_history_cleared',
      realm_id: realmId,
      user_id: userId,
      details: {
        cleared_by: adminUserId,
        reason: 'admin_action'
      }
    });
  } catch (error) {
    console.error('Clear password history error:', error);
    throw error;
  }
}

/**
 * Get password history configuration for realm
 */
export function getRealmPasswordHistoryConfig(realmId: string): PasswordHistoryConfig {
  // Healthcare realms get stricter config
  if (realmId.startsWith('clinisyn')) {
    return HEALTHCARE_PASSWORD_HISTORY_CONFIG;
  }
  return DEFAULT_PASSWORD_HISTORY_CONFIG;
}

/**
 * Get password age info
 */
export async function getPasswordAgeInfo(
  userId: string,
  realmId: string,
  config: PasswordHistoryConfig = DEFAULT_PASSWORD_HISTORY_CONFIG
): Promise<{
  lastChanged: string | null;
  daysSinceChange: number;
  daysUntilExpiry: number;
  isExpired: boolean;
  mustChangeImmediately: boolean;
}> {
  try {
    const getCommand = new GetCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `REALM#${realmId}`,
        sk: `USER#${userId}`
      },
      ProjectionExpression: 'password_changed_at'
    });

    const result = await dynamoDb.send(getCommand);
    const lastChange = result.Item?.password_changed_at;
    
    if (!lastChange) {
      return {
        lastChanged: null,
        daysSinceChange: 0,
        daysUntilExpiry: Math.floor(config.maxPasswordAge / 86400),
        isExpired: false,
        mustChangeImmediately: false
      };
    }

    const now = Math.floor(Date.now() / 1000);
    const timeSinceChange = now - lastChange;
    const daysSinceChange = Math.floor(timeSinceChange / 86400);
    const maxAgeDays = Math.floor(config.maxPasswordAge / 86400);
    const daysUntilExpiry = Math.max(0, maxAgeDays - daysSinceChange);
    const isExpired = timeSinceChange > config.maxPasswordAge;

    return {
      lastChanged: new Date(lastChange * 1000).toISOString(),
      daysSinceChange,
      daysUntilExpiry,
      isExpired,
      mustChangeImmediately: isExpired
    };
  } catch (error) {
    console.error('Get password age info error:', error);
    return {
      lastChanged: null,
      daysSinceChange: 0,
      daysUntilExpiry: Math.floor(config.maxPasswordAge / 86400),
      isExpired: false,
      mustChangeImmediately: false
    };
  }
}
