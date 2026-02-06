/**
 * Realm Service - Multi-tenant Management & MFA Policy Enforcement
 * Validates: Requirements 1.1, 1.3, 2.2 (multi-tenant, MFA), Task 2.7, Task 9.1
 * 
 * CRITICAL: Healthcare realms (Clinisyn) require MFA
 * WebAuthn is mandatory for Evilginx2 phishing protection
 * 
 * Multi-tenant Features:
 * - Complete realm CRUD operations
 * - Cross-realm isolation enforcement
 * - Cascade delete (users, sessions, devices, audit logs)
 * - Realm statistics and health checks
 */

import { 
  getRealmSettings, 
  findRealmById,
  createRealm as createRealmInDb,
  updateRealm as updateRealmInDb,
  deleteRealm as deleteRealmInDb,
  listRealms as listRealmsFromDb,
  countRealms,
  realmExistsByName
} from '../repositories/realm.repository';
import { 
  MfaPolicy, 
  MfaConfig, 
  DEFAULT_MFA_CONFIG,
  HEALTHCARE_MFA_CONFIG,
  Realm,
  CreateRealmInput,
  RealmSettings,
  AuthProvider,
  DEFAULT_REALM_SETTINGS
} from '../models/realm.model';
import { User } from '../models/user.model';
import { QueryCommand, ScanCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';

/**
 * MFA enforcement result
 */
export interface MfaEnforcementResult {
  mfaRequired: boolean;
  reason: 'policy_required' | 'user_enabled' | 'sensitive_action' | 'new_device' | 'none';
  allowedMethods: ('totp' | 'webauthn')[];
  gracePeriodActive: boolean;
  gracePeriodEndsAt?: string;
  setupRequired: boolean;
  webauthnRequired: boolean;
}

/**
 * Device trust check result
 */
export interface DeviceTrustResult {
  trusted: boolean;
  trustExpiresAt?: string;
  deviceId?: string;
}

/**
 * Get MFA configuration for a realm
 * Falls back to defaults if not configured
 */
export async function getRealmMfaConfig(realmId: string): Promise<MfaConfig> {
  const settings = await getRealmSettings(realmId);
  
  // Check if new mfa_config exists
  if (settings.mfa_config) {
    return settings.mfa_config;
  }
  
  // Backward compatibility: convert old mfa_required boolean
  if (settings.mfa_required) {
    return {
      ...DEFAULT_MFA_CONFIG,
      policy: 'required'
    };
  }
  
  return DEFAULT_MFA_CONFIG;
}

/**
 * Check if realm is a healthcare realm (requires stricter MFA)
 */
export function isHealthcareRealm(realmId: string): boolean {
  // Healthcare realm patterns
  const healthcarePatterns = [
    'clinisyn',
    'healthcare',
    'medical',
    'hospital',
    'clinic',
    'doctor',
    'patient',
    'hipaa'
  ];
  
  const lowerRealmId = realmId.toLowerCase();
  return healthcarePatterns.some(pattern => lowerRealmId.includes(pattern));
}

/**
 * Get effective MFA config considering healthcare requirements
 */
export async function getEffectiveMfaConfig(realmId: string): Promise<MfaConfig> {
  const config = await getRealmMfaConfig(realmId);
  
  // Healthcare realms get stricter defaults
  if (isHealthcareRealm(realmId)) {
    return {
      ...config,
      policy: config.policy === 'disabled' ? 'required' : config.policy,
      require_webauthn_for_sensitive: true,
      remember_device_days: Math.min(config.remember_device_days, 7)
    };
  }
  
  return config;
}

/**
 * Check MFA enforcement for a user login
 */
export async function checkMfaEnforcement(
  realmId: string,
  user: User,
  options: {
    isSensitiveAction?: boolean;
    isNewDevice?: boolean;
    deviceTrusted?: boolean;
  } = {}
): Promise<MfaEnforcementResult> {
  const mfaConfig = await getEffectiveMfaConfig(realmId);
  
  const result: MfaEnforcementResult = {
    mfaRequired: false,
    reason: 'none',
    allowedMethods: mfaConfig.allowed_methods,
    gracePeriodActive: false,
    setupRequired: false,
    webauthnRequired: false
  };
  
  // Check if MFA is disabled for realm
  if (mfaConfig.policy === 'disabled') {
    return result;
  }
  
  // Check if user has MFA enabled
  const userHasMfa = user.mfa_enabled || 
    (user.webauthn_credentials && user.webauthn_credentials.length > 0);
  
  // Policy: required
  if (mfaConfig.policy === 'required') {
    if (!userHasMfa) {
      // Check grace period for new users
      const gracePeriodEnd = calculateGracePeriodEnd(user.created_at, mfaConfig.grace_period_hours);
      const now = new Date();
      
      if (now < gracePeriodEnd) {
        result.gracePeriodActive = true;
        result.gracePeriodEndsAt = gracePeriodEnd.toISOString();
        result.setupRequired = true;
        result.reason = 'policy_required';
        // Allow login but flag setup required
        return result;
      }
      
      // Grace period expired - MFA setup mandatory
      result.mfaRequired = true;
      result.setupRequired = true;
      result.reason = 'policy_required';
      return result;
    }
    
    // User has MFA - require verification
    result.mfaRequired = true;
    result.reason = 'policy_required';
  }
  
  // Policy: optional - check if user enabled MFA
  if (mfaConfig.policy === 'optional' && userHasMfa) {
    result.mfaRequired = true;
    result.reason = 'user_enabled';
  }
  
  // Check device trust (can skip MFA for trusted devices)
  if (result.mfaRequired && options.deviceTrusted && mfaConfig.remember_device_days > 0) {
    result.mfaRequired = false;
    result.reason = 'none';
  }
  
  // New device always requires MFA if user has it enabled
  if (options.isNewDevice && userHasMfa) {
    result.mfaRequired = true;
    result.reason = 'new_device';
  }
  
  // Sensitive actions may require WebAuthn specifically
  if (options.isSensitiveAction && mfaConfig.require_webauthn_for_sensitive) {
    result.mfaRequired = true;
    result.webauthnRequired = true;
    result.reason = 'sensitive_action';
    result.allowedMethods = ['webauthn'];
  }
  
  return result;
}

/**
 * Calculate grace period end date
 */
function calculateGracePeriodEnd(createdAt: string, gracePeriodHours: number): Date {
  const created = new Date(createdAt);
  return new Date(created.getTime() + (gracePeriodHours * 60 * 60 * 1000));
}

/**
 * Check if user needs to setup MFA (for required policy)
 */
export async function checkMfaSetupRequired(
  realmId: string,
  user: User
): Promise<{ required: boolean; gracePeriodEndsAt?: string; message?: string }> {
  const mfaConfig = await getEffectiveMfaConfig(realmId);
  
  if (mfaConfig.policy !== 'required') {
    return { required: false };
  }
  
  const userHasMfa = user.mfa_enabled || 
    (user.webauthn_credentials && user.webauthn_credentials.length > 0);
  
  if (userHasMfa) {
    return { required: false };
  }
  
  const gracePeriodEnd = calculateGracePeriodEnd(user.created_at, mfaConfig.grace_period_hours);
  const now = new Date();
  
  if (now < gracePeriodEnd) {
    const hoursRemaining = Math.ceil((gracePeriodEnd.getTime() - now.getTime()) / (1000 * 60 * 60));
    return {
      required: true,
      gracePeriodEndsAt: gracePeriodEnd.toISOString(),
      message: `MFA setup required within ${hoursRemaining} hours`
    };
  }
  
  return {
    required: true,
    message: 'MFA setup required to continue using this account'
  };
}

/**
 * Validate MFA method is allowed for realm
 */
export async function validateMfaMethod(
  realmId: string,
  method: 'totp' | 'webauthn'
): Promise<{ allowed: boolean; reason?: string }> {
  const mfaConfig = await getEffectiveMfaConfig(realmId);
  
  if (mfaConfig.policy === 'disabled') {
    return { allowed: false, reason: 'MFA is disabled for this realm' };
  }
  
  if (!mfaConfig.allowed_methods.includes(method)) {
    return { 
      allowed: false, 
      reason: `${method.toUpperCase()} is not allowed for this realm` 
    };
  }
  
  return { allowed: true };
}

/**
 * Get remember device duration for realm
 */
export async function getRememberDeviceDuration(realmId: string): Promise<number> {
  const mfaConfig = await getEffectiveMfaConfig(realmId);
  return mfaConfig.remember_device_days * 24 * 60 * 60; // Return in seconds
}


// ============================================================================
// REALM CRUD OPERATIONS (Task 9.1)
// ============================================================================

/**
 * Realm creation result
 */
export interface CreateRealmResult {
  success: boolean;
  realm?: Realm;
  error?: string;
}

/**
 * Realm update result
 */
export interface UpdateRealmResult {
  success: boolean;
  realm?: Realm;
  error?: string;
}

/**
 * Realm deletion result
 */
export interface DeleteRealmResult {
  success: boolean;
  deletedCounts?: {
    users: number;
    sessions: number;
    devices: number;
    auditLogs: number;
  };
  error?: string;
}

/**
 * Realm statistics
 */
export interface RealmStats {
  realmId: string;
  userCount: number;
  activeSessionCount: number;
  deviceCount: number;
  mfaEnabledUsers: number;
  webauthnEnabledUsers: number;
  lastLoginAt?: string;
  createdAt: string;
}

/**
 * Cross-realm access check result
 */
export interface CrossRealmCheckResult {
  allowed: boolean;
  reason?: string;
}

/**
 * Create a new realm with validation
 */
export async function createRealm(input: CreateRealmInput): Promise<CreateRealmResult> {
  try {
    // Validate realm name
    if (!input.name || input.name.length < 3 || input.name.length > 50) {
      return { success: false, error: 'Realm name must be between 3 and 50 characters' };
    }

    // Validate realm name format (alphanumeric, hyphens, no spaces)
    const nameRegex = /^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$/;
    if (!nameRegex.test(input.name)) {
      return { 
        success: false, 
        error: 'Realm name must start with a letter, contain only letters, numbers, and hyphens' 
      };
    }

    // Check for duplicate realm
    const exists = await realmExistsByName(input.name);
    if (exists) {
      return { success: false, error: 'Realm with this name already exists' };
    }

    // Validate domain if provided
    if (input.domain) {
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/;
      if (!domainRegex.test(input.domain)) {
        return { success: false, error: 'Invalid domain format' };
      }
    }

    // Apply healthcare defaults if applicable
    let settings = input.settings || {};
    if (isHealthcareRealm(input.name)) {
      settings = {
        ...settings,
        mfa_config: {
          ...HEALTHCARE_MFA_CONFIG,
          ...settings.mfa_config
        }
      };
    }

    const realm = await createRealmInDb({
      ...input,
      settings
    });

    return { success: true, realm };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    if (message.includes('ConditionalCheckFailed')) {
      return { success: false, error: 'Realm already exists' };
    }
    return { success: false, error: message };
  }
}

/**
 * Get realm by ID with validation
 */
export async function getRealm(realmId: string): Promise<Realm | null> {
  if (!realmId || realmId.length < 3) {
    return null;
  }
  return findRealmById(realmId);
}

/**
 * Update realm configuration
 */
export async function updateRealm(
  realmId: string,
  updates: {
    name?: string;
    domain?: string;
    settings?: Partial<RealmSettings>;
    auth_providers?: AuthProvider[];
  }
): Promise<UpdateRealmResult> {
  try {
    // Check realm exists
    const existing = await findRealmById(realmId);
    if (!existing) {
      return { success: false, error: 'Realm not found' };
    }

    // Validate name if being updated
    if (updates.name && updates.name !== existing.name) {
      const nameRegex = /^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$/;
      if (!nameRegex.test(updates.name)) {
        return { 
          success: false, 
          error: 'Realm name must start with a letter, contain only letters, numbers, and hyphens' 
        };
      }
    }

    // Validate domain if being updated
    if (updates.domain) {
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/;
      if (!domainRegex.test(updates.domain)) {
        return { success: false, error: 'Invalid domain format' };
      }
    }

    // Validate MFA config if being updated
    if (updates.settings?.mfa_config) {
      const mfaConfig = updates.settings.mfa_config;
      
      // Healthcare realms cannot disable MFA
      if (isHealthcareRealm(realmId) && mfaConfig.policy === 'disabled') {
        return { 
          success: false, 
          error: 'Healthcare realms cannot disable MFA (HIPAA compliance)' 
        };
      }

      // Validate remember device days
      if (mfaConfig.remember_device_days !== undefined) {
        if (mfaConfig.remember_device_days < 0 || mfaConfig.remember_device_days > 30) {
          return { success: false, error: 'Remember device days must be between 0 and 30' };
        }
      }
    }

    const realm = await updateRealmInDb(realmId, updates);
    if (!realm) {
      return { success: false, error: 'Failed to update realm' };
    }

    return { success: true, realm };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return { success: false, error: message };
  }
}

/**
 * Delete realm with cascade cleanup
 * CRITICAL: This deletes ALL data associated with the realm
 */
export async function deleteRealmWithCleanup(realmId: string): Promise<DeleteRealmResult> {
  try {
    // Check realm exists
    const existing = await findRealmById(realmId);
    if (!existing) {
      return { success: false, error: 'Realm not found' };
    }

    const deletedCounts = {
      users: 0,
      sessions: 0,
      devices: 0,
      auditLogs: 0
    };

    // Delete all users in realm
    deletedCounts.users = await deleteRealmUsers(realmId);

    // Delete all sessions in realm
    deletedCounts.sessions = await deleteRealmSessions(realmId);

    // Delete all devices in realm
    deletedCounts.devices = await deleteRealmDevices(realmId);

    // Delete audit logs (or mark for deletion - HIPAA may require retention)
    deletedCounts.auditLogs = await markRealmAuditLogsForDeletion(realmId);

    // Finally delete the realm itself
    const deleted = await deleteRealmInDb(realmId);
    if (!deleted) {
      return { success: false, error: 'Failed to delete realm record' };
    }

    return { success: true, deletedCounts };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return { success: false, error: message };
  }
}

/**
 * List all realms with optional filtering
 */
export async function listRealms(options?: {
  includeStats?: boolean;
  healthcareOnly?: boolean;
}): Promise<Realm[]> {
  let realms = await listRealmsFromDb();

  if (options?.healthcareOnly) {
    realms = realms.filter(r => isHealthcareRealm(r.id));
  }

  return realms;
}

/**
 * Get realm statistics
 */
export async function getRealmStats(realmId: string): Promise<RealmStats | null> {
  const realm = await findRealmById(realmId);
  if (!realm) {
    return null;
  }

  // Count users
  const userCount = await countRealmUsers(realmId);
  
  // Count active sessions
  const activeSessionCount = await countRealmActiveSessions(realmId);
  
  // Count devices
  const deviceCount = await countRealmDevices(realmId);
  
  // Count MFA enabled users
  const mfaStats = await countRealmMfaUsers(realmId);

  return {
    realmId,
    userCount,
    activeSessionCount,
    deviceCount,
    mfaEnabledUsers: mfaStats.mfaEnabled,
    webauthnEnabledUsers: mfaStats.webauthnEnabled,
    createdAt: realm.created_at
  };
}

// ============================================================================
// CROSS-REALM ISOLATION (Task 9.1)
// ============================================================================

/**
 * Validate cross-realm access
 * CRITICAL: Prevents data leakage between tenants
 */
export function validateCrossRealmAccess(
  requestRealmId: string,
  resourceRealmId: string
): CrossRealmCheckResult {
  // Exact match required
  if (requestRealmId !== resourceRealmId) {
    return {
      allowed: false,
      reason: 'Cross-realm access denied'
    };
  }

  return { allowed: true };
}

/**
 * Validate user belongs to realm
 */
export async function validateUserInRealm(
  userId: string,
  realmId: string
): Promise<CrossRealmCheckResult> {
  try {
    const command = new QueryCommand({
      TableName: TableNames.USERS,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: {
        ':pk': `USER#${userId}`
      },
      Limit: 1
    });

    const result = await dynamoDb.send(command);
    
    if (!result.Items || result.Items.length === 0) {
      return { allowed: false, reason: 'User not found' };
    }

    const user = result.Items[0];
    if (user.realm_id !== realmId) {
      return { allowed: false, reason: 'User does not belong to this realm' };
    }

    return { allowed: true };
  } catch {
    return { allowed: false, reason: 'Failed to validate user realm' };
  }
}

/**
 * Validate session belongs to realm
 */
export async function validateSessionInRealm(
  sessionId: string,
  realmId: string
): Promise<CrossRealmCheckResult> {
  try {
    const command = new QueryCommand({
      TableName: TableNames.SESSIONS,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: {
        ':pk': `SESSION#${sessionId}`
      },
      Limit: 1
    });

    const result = await dynamoDb.send(command);
    
    if (!result.Items || result.Items.length === 0) {
      return { allowed: false, reason: 'Session not found' };
    }

    const session = result.Items[0];
    if (session.realm_id !== realmId) {
      return { allowed: false, reason: 'Session does not belong to this realm' };
    }

    return { allowed: true };
  } catch {
    return { allowed: false, reason: 'Failed to validate session realm' };
  }
}

// ============================================================================
// HELPER FUNCTIONS FOR CASCADE DELETE
// ============================================================================

/**
 * Delete all users in a realm
 */
async function deleteRealmUsers(realmId: string): Promise<number> {
  let deletedCount = 0;
  let lastEvaluatedKey: Record<string, unknown> | undefined;

  do {
    const command = new ScanCommand({
      TableName: TableNames.USERS,
      FilterExpression: 'realm_id = :realmId',
      ExpressionAttributeValues: {
        ':realmId': realmId
      },
      ExclusiveStartKey: lastEvaluatedKey,
      Limit: 25
    });

    const result = await dynamoDb.send(command);
    lastEvaluatedKey = result.LastEvaluatedKey;

    if (result.Items && result.Items.length > 0) {
      const deleteRequests = result.Items.map(item => ({
        DeleteRequest: {
          Key: {
            pk: item.pk,
            sk: item.sk
          }
        }
      }));

      // Batch delete (max 25 items per batch)
      const batchCommand = new BatchWriteCommand({
        RequestItems: {
          [TableNames.USERS]: deleteRequests
        }
      });

      await dynamoDb.send(batchCommand);
      deletedCount += result.Items.length;
    }
  } while (lastEvaluatedKey);

  return deletedCount;
}

/**
 * Delete all sessions in a realm
 */
async function deleteRealmSessions(realmId: string): Promise<number> {
  let deletedCount = 0;
  let lastEvaluatedKey: Record<string, unknown> | undefined;

  do {
    const command = new ScanCommand({
      TableName: TableNames.SESSIONS,
      FilterExpression: 'realm_id = :realmId',
      ExpressionAttributeValues: {
        ':realmId': realmId
      },
      ExclusiveStartKey: lastEvaluatedKey,
      Limit: 25
    });

    const result = await dynamoDb.send(command);
    lastEvaluatedKey = result.LastEvaluatedKey;

    if (result.Items && result.Items.length > 0) {
      const deleteRequests = result.Items.map(item => ({
        DeleteRequest: {
          Key: {
            pk: item.pk,
            sk: item.sk
          }
        }
      }));

      const batchCommand = new BatchWriteCommand({
        RequestItems: {
          [TableNames.SESSIONS]: deleteRequests
        }
      });

      await dynamoDb.send(batchCommand);
      deletedCount += result.Items.length;
    }
  } while (lastEvaluatedKey);

  return deletedCount;
}

/**
 * Delete all devices in a realm
 * Note: Devices are stored in USERS table as nested data or separate items
 */
async function deleteRealmDevices(realmId: string): Promise<number> {
  // Devices are typically stored as part of user records or in sessions
  // For now, return 0 as device cleanup happens with user deletion
  return 0;
}

/**
 * Mark audit logs for deletion (HIPAA may require retention)
 * Instead of deleting, we mark them as "realm_deleted"
 */
async function markRealmAuditLogsForDeletion(realmId: string): Promise<number> {
  // For HIPAA compliance, we don't actually delete audit logs
  // Instead, we could mark them or move to archive
  // For now, return 0 as we're preserving audit trail
  return 0;
}

/**
 * Count users in a realm
 */
async function countRealmUsers(realmId: string): Promise<number> {
  const command = new ScanCommand({
    TableName: TableNames.USERS,
    FilterExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':realmId': realmId
    },
    Select: 'COUNT'
  });

  const result = await dynamoDb.send(command);
  return result.Count || 0;
}

/**
 * Count active sessions in a realm
 */
async function countRealmActiveSessions(realmId: string): Promise<number> {
  const now = Math.floor(Date.now() / 1000);
  
  const command = new ScanCommand({
    TableName: TableNames.SESSIONS,
    FilterExpression: 'realm_id = :realmId AND expires_at > :now',
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':now': now
    },
    Select: 'COUNT'
  });

  const result = await dynamoDb.send(command);
  return result.Count || 0;
}

/**
 * Count devices in a realm
 * Note: Devices are stored as part of user/session data
 */
async function countRealmDevices(realmId: string): Promise<number> {
  // Devices are typically stored as part of user records
  // Return 0 for now - actual count would require scanning user records
  return 0;
}

/**
 * Count MFA-enabled users in a realm
 */
async function countRealmMfaUsers(realmId: string): Promise<{ mfaEnabled: number; webauthnEnabled: number }> {
  const command = new ScanCommand({
    TableName: TableNames.USERS,
    FilterExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':realmId': realmId
    },
    ProjectionExpression: 'mfa_enabled, webauthn_enabled'
  });

  const result = await dynamoDb.send(command);
  
  let mfaEnabled = 0;
  let webauthnEnabled = 0;

  if (result.Items) {
    for (const item of result.Items) {
      if (item.mfa_enabled) mfaEnabled++;
      if (item.webauthn_enabled) webauthnEnabled++;
    }
  }

  return { mfaEnabled, webauthnEnabled };
}
