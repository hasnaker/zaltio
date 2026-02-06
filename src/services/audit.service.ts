/**
 * Audit Logging Service for Zalt.io Auth Platform
 * Task 7.1: Audit Logging Service
 * 
 * HIPAA/GDPR COMPLIANCE:
 * - All security events are logged
 * - Logs retained for 6 years (HIPAA requirement)
 * - User-queryable via GSI
 * - Immutable audit trail
 * - PII is hashed/masked where appropriate
 */

import { PutCommand, QueryCommand, BatchWriteCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';
import * as crypto from 'crypto';

/**
 * Generate UUID v4
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Audit event types
 */
export enum AuditEventType {
  // Authentication events
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
  LOGOUT = 'logout',
  REGISTER = 'register',
  
  // Password events
  PASSWORD_CHANGE = 'password_change',
  PASSWORD_RESET_REQUEST = 'password_reset_request',
  PASSWORD_RESET_COMPLETE = 'password_reset_complete',
  
  // MFA events
  MFA_ENABLE = 'mfa_enable',
  MFA_DISABLE = 'mfa_disable',
  MFA_VERIFY_SUCCESS = 'mfa_verify_success',
  MFA_VERIFY_FAILURE = 'mfa_verify_failure',
  BACKUP_CODE_USED = 'backup_code_used',
  BACKUP_CODES_REGENERATED = 'backup_codes_regenerated',
  
  // WebAuthn events
  WEBAUTHN_REGISTER = 'webauthn_register',
  WEBAUTHN_REMOVE = 'webauthn_remove',
  WEBAUTHN_AUTH_SUCCESS = 'webauthn_auth_success',
  WEBAUTHN_AUTH_FAILURE = 'webauthn_auth_failure',
  
  // Device events
  DEVICE_TRUST = 'device_trust',
  DEVICE_REVOKE = 'device_revoke',
  NEW_DEVICE_LOGIN = 'new_device_login',
  
  // Account events
  ACCOUNT_LOCK = 'account_lock',
  ACCOUNT_UNLOCK = 'account_unlock',
  EMAIL_VERIFY = 'email_verify',
  EMAIL_CHANGE = 'email_change',
  PROFILE_UPDATE = 'profile_update',
  ACCOUNT_DELETE = 'account_delete',
  
  // Security events
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  IMPOSSIBLE_TRAVEL = 'impossible_travel',
  CREDENTIAL_STUFFING = 'credential_stuffing',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  SESSION_TIMEOUT = 'session_timeout',
  
  // Token events
  TOKEN_REFRESH = 'token_refresh',
  TOKEN_REVOKE = 'token_revoke',
  JWT_KEY_ROTATION = 'jwt_key_rotation',
  
  // Admin events
  ADMIN_ACTION = 'admin_action',
  CONFIG_CHANGE = 'config_change',
  REALM_CREATE = 'realm_create',
  REALM_UPDATE = 'realm_update',
  USER_IMPERSONATE = 'user_impersonate',
  
  // OAuth events
  OAUTH_LINK = 'oauth_link',
  OAUTH_UNLINK = 'oauth_unlink',
  OAUTH_LOGIN = 'oauth_login'
}

/**
 * Audit event result
 */
export enum AuditResult {
  SUCCESS = 'success',
  FAILURE = 'failure',
  BLOCKED = 'blocked',
  PENDING = 'pending'
}

/**
 * Audit event severity
 */
export enum AuditSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  result: AuditResult;
  severity: AuditSeverity;
  
  // Actor information
  userId?: string;
  userEmail?: string;  // Hashed for privacy
  realmId: string;
  sessionId?: string;
  
  // Request context
  ipAddress: string;
  ipAddressHash: string;  // For querying without exposing IP
  userAgent?: string;
  requestId?: string;
  
  // Geolocation (if available)
  geoCountry?: string;
  geoCity?: string;
  
  // Event details
  action: string;
  resource?: string;
  details?: Record<string, unknown>;
  
  // Error information (if applicable)
  errorCode?: string;
  errorMessage?: string;
  
  // Compliance
  ttl?: number;  // DynamoDB TTL (default: 6 years for HIPAA)
  
  // Indexes
  pk: string;  // Partition key: REALM#<realm_id>
  sk: string;  // Sort key: TIMESTAMP#<timestamp>#<id>
  gsi1pk?: string;  // GSI1: USER#<user_id>
  gsi1sk?: string;  // GSI1: TIMESTAMP#<timestamp>
  gsi2pk?: string;  // GSI2: EVENT#<event_type>
  gsi2sk?: string;  // GSI2: TIMESTAMP#<timestamp>
}

/**
 * Audit log input (what callers provide)
 */
export interface AuditLogInput {
  eventType: AuditEventType;
  result: AuditResult;
  realmId: string;
  userId?: string;
  userEmail?: string;
  sessionId?: string;
  ipAddress: string;
  userAgent?: string;
  requestId?: string;
  geoCountry?: string;
  geoCity?: string;
  action: string;
  resource?: string;
  details?: Record<string, unknown>;
  errorCode?: string;
  errorMessage?: string;
  severity?: AuditSeverity;
}

/**
 * Query options for audit logs
 */
export interface AuditQueryOptions {
  realmId?: string;
  userId?: string;
  eventType?: AuditEventType;
  startTime?: Date;
  endTime?: Date;
  limit?: number;
  lastEvaluatedKey?: Record<string, unknown>;
}

/**
 * Query result
 */
export interface AuditQueryResult {
  logs: AuditLogEntry[];
  lastEvaluatedKey?: Record<string, unknown>;
  count: number;
}

/**
 * Audit service configuration
 */
export interface AuditConfig {
  // TTL in seconds (default: 6 years for HIPAA)
  defaultTTL: number;
  // Healthcare realm TTL (stricter)
  healthcareTTL: number;
  // Standard realm TTL
  standardTTL: number;
  // Enable async logging (non-blocking)
  asyncLogging: boolean;
  // Batch size for bulk operations
  batchSize: number;
}

/**
 * Default audit configuration
 */
export const DEFAULT_AUDIT_CONFIG: AuditConfig = {
  defaultTTL: 6 * 365 * 24 * 60 * 60,  // 6 years in seconds (HIPAA)
  healthcareTTL: 6 * 365 * 24 * 60 * 60,  // 6 years
  standardTTL: 90 * 24 * 60 * 60,  // 90 days for non-healthcare
  asyncLogging: true,
  batchSize: 25
};

/**
 * Hash sensitive data for privacy
 */
export function hashSensitiveData(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

/**
 * Mask email for display
 */
export function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!domain) return '***@***';
  
  const maskedLocal = local.length > 2 
    ? local[0] + '*'.repeat(local.length - 2) + local[local.length - 1]
    : '*'.repeat(local.length);
  
  return `${maskedLocal}@${domain}`;
}

/**
 * Mask IP address for display
 */
export function maskIP(ip: string): string {
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.*.*`;
  }
  // IPv6 or other format
  return ip.substring(0, ip.length / 2) + '***';
}

/**
 * Determine severity based on event type and result
 */
export function determineSeverity(eventType: AuditEventType, result: AuditResult): AuditSeverity {
  // Critical events
  const criticalEvents = [
    AuditEventType.CREDENTIAL_STUFFING,
    AuditEventType.IMPOSSIBLE_TRAVEL,
    AuditEventType.USER_IMPERSONATE,
    AuditEventType.ACCOUNT_DELETE
  ];
  
  if (criticalEvents.includes(eventType)) {
    return AuditSeverity.CRITICAL;
  }
  
  // Error events
  const errorEvents = [
    AuditEventType.ACCOUNT_LOCK,
    AuditEventType.SUSPICIOUS_ACTIVITY
  ];
  
  if (errorEvents.includes(eventType) || result === AuditResult.BLOCKED) {
    return AuditSeverity.ERROR;
  }
  
  // Warning events
  const warningEvents = [
    AuditEventType.LOGIN_FAILURE,
    AuditEventType.MFA_VERIFY_FAILURE,
    AuditEventType.WEBAUTHN_AUTH_FAILURE,
    AuditEventType.RATE_LIMIT_EXCEEDED,
    AuditEventType.NEW_DEVICE_LOGIN
  ];
  
  if (warningEvents.includes(eventType) || result === AuditResult.FAILURE) {
    return AuditSeverity.WARNING;
  }
  
  return AuditSeverity.INFO;
}

/**
 * Calculate TTL based on realm type
 */
export function calculateTTL(
  realmId: string, 
  config: AuditConfig = DEFAULT_AUDIT_CONFIG
): number {
  const now = Math.floor(Date.now() / 1000);
  
  // Healthcare realms get longer retention
  if (realmId.includes('clinisyn') || realmId.includes('healthcare') || realmId.includes('medical')) {
    return now + config.healthcareTTL;
  }
  
  return now + config.standardTTL;
}

/**
 * Create audit log entry from input
 */
export function createAuditLogEntry(
  input: AuditLogInput,
  config: AuditConfig = DEFAULT_AUDIT_CONFIG
): AuditLogEntry {
  const id = generateUUID();
  const timestamp = new Date().toISOString();
  const severity = input.severity || determineSeverity(input.eventType, input.result);
  
  const entry: AuditLogEntry = {
    id,
    timestamp,
    eventType: input.eventType,
    result: input.result,
    severity,
    
    userId: input.userId,
    userEmail: input.userEmail ? hashSensitiveData(input.userEmail) : undefined,
    realmId: input.realmId,
    sessionId: input.sessionId,
    
    ipAddress: maskIP(input.ipAddress),
    ipAddressHash: hashSensitiveData(input.ipAddress),
    userAgent: input.userAgent,
    requestId: input.requestId,
    
    geoCountry: input.geoCountry,
    geoCity: input.geoCity,
    
    action: input.action,
    resource: input.resource,
    details: sanitizeDetails(input.details),
    
    errorCode: input.errorCode,
    errorMessage: input.errorMessage,
    
    ttl: calculateTTL(input.realmId, config),
    
    // DynamoDB keys
    pk: `REALM#${input.realmId}`,
    sk: `TIMESTAMP#${timestamp}#${id}`,
    gsi1pk: input.userId ? `USER#${input.userId}` : undefined,
    gsi1sk: input.userId ? `TIMESTAMP#${timestamp}` : undefined,
    gsi2pk: `EVENT#${input.eventType}`,
    gsi2sk: `TIMESTAMP#${timestamp}`
  };
  
  return entry;
}

/**
 * Sanitize details to remove sensitive data
 */
export function sanitizeDetails(details?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!details) return undefined;
  
  const sensitiveKeys = ['password', 'token', 'secret', 'key', 'credential', 'authorization'];
  const sanitized: Record<string, unknown> = {};
  
  for (const [key, value] of Object.entries(details)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeDetails(value as Record<string, unknown>);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

/**
 * Log audit event to DynamoDB
 */
export async function logAuditEvent(
  input: AuditLogInput,
  config: AuditConfig = DEFAULT_AUDIT_CONFIG
): Promise<AuditLogEntry> {
  const entry = createAuditLogEntry(input, config);
  
  const command = new PutCommand({
    TableName: TableNames.AUDIT,
    Item: entry
  });
  
  if (config.asyncLogging) {
    // Fire and forget for non-blocking
    dynamoDb.send(command).catch(err => {
      console.error('Audit log write failed:', err);
    });
  } else {
    await dynamoDb.send(command);
  }
  
  return entry;
}

/**
 * Log audit event synchronously (for critical events)
 */
export async function logAuditEventSync(input: AuditLogInput): Promise<AuditLogEntry> {
  return logAuditEvent(input, { ...DEFAULT_AUDIT_CONFIG, asyncLogging: false });
}

/**
 * Batch log multiple audit events
 */
export async function batchLogAuditEvents(
  inputs: AuditLogInput[],
  config: AuditConfig = DEFAULT_AUDIT_CONFIG
): Promise<AuditLogEntry[]> {
  const entries = inputs.map(input => createAuditLogEntry(input, config));
  
  // DynamoDB batch write limit is 25 items
  const batches: AuditLogEntry[][] = [];
  for (let i = 0; i < entries.length; i += config.batchSize) {
    batches.push(entries.slice(i, i + config.batchSize));
  }
  
  for (const batch of batches) {
    const command = new BatchWriteCommand({
      RequestItems: {
        [TableNames.AUDIT]: batch.map(entry => ({
          PutRequest: { Item: entry }
        }))
      }
    });
    
    await dynamoDb.send(command);
  }
  
  return entries;
}

/**
 * Query audit logs by realm
 */
export async function queryAuditLogsByRealm(
  realmId: string,
  options: Omit<AuditQueryOptions, 'realmId'> = {}
): Promise<AuditQueryResult> {
  const { startTime, endTime, limit = 100, lastEvaluatedKey } = options;
  
  let keyConditionExpression = 'pk = :pk';
  const expressionAttributeValues: Record<string, unknown> = {
    ':pk': `REALM#${realmId}`
  };
  
  if (startTime && endTime) {
    keyConditionExpression += ' AND sk BETWEEN :start AND :end';
    expressionAttributeValues[':start'] = `TIMESTAMP#${startTime.toISOString()}`;
    expressionAttributeValues[':end'] = `TIMESTAMP#${endTime.toISOString()}#~`;
  } else if (startTime) {
    keyConditionExpression += ' AND sk >= :start';
    expressionAttributeValues[':start'] = `TIMESTAMP#${startTime.toISOString()}`;
  } else if (endTime) {
    keyConditionExpression += ' AND sk <= :end';
    expressionAttributeValues[':end'] = `TIMESTAMP#${endTime.toISOString()}#~`;
  }
  
  const command = new QueryCommand({
    TableName: TableNames.AUDIT,
    KeyConditionExpression: keyConditionExpression,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit,
    ScanIndexForward: false,  // Most recent first
    ExclusiveStartKey: lastEvaluatedKey as Record<string, unknown> | undefined
  });
  
  const result = await dynamoDb.send(command);
  
  return {
    logs: (result.Items || []) as AuditLogEntry[],
    lastEvaluatedKey: result.LastEvaluatedKey,
    count: result.Count || 0
  };
}

/**
 * Query audit logs by user
 */
export async function queryAuditLogsByUser(
  userId: string,
  options: Omit<AuditQueryOptions, 'userId'> = {}
): Promise<AuditQueryResult> {
  const { startTime, endTime, limit = 100, lastEvaluatedKey } = options;
  
  let keyConditionExpression = 'gsi1pk = :pk';
  const expressionAttributeValues: Record<string, unknown> = {
    ':pk': `USER#${userId}`
  };
  
  if (startTime && endTime) {
    keyConditionExpression += ' AND gsi1sk BETWEEN :start AND :end';
    expressionAttributeValues[':start'] = `TIMESTAMP#${startTime.toISOString()}`;
    expressionAttributeValues[':end'] = `TIMESTAMP#${endTime.toISOString()}`;
  } else if (startTime) {
    keyConditionExpression += ' AND gsi1sk >= :start';
    expressionAttributeValues[':start'] = `TIMESTAMP#${startTime.toISOString()}`;
  }
  
  const command = new QueryCommand({
    TableName: TableNames.AUDIT,
    IndexName: 'gsi1',
    KeyConditionExpression: keyConditionExpression,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit,
    ScanIndexForward: false,
    ExclusiveStartKey: lastEvaluatedKey as Record<string, unknown> | undefined
  });
  
  const result = await dynamoDb.send(command);
  
  return {
    logs: (result.Items || []) as AuditLogEntry[],
    lastEvaluatedKey: result.LastEvaluatedKey,
    count: result.Count || 0
  };
}

/**
 * Query audit logs by event type
 */
export async function queryAuditLogsByEventType(
  eventType: AuditEventType,
  options: Omit<AuditQueryOptions, 'eventType'> = {}
): Promise<AuditQueryResult> {
  const { startTime, endTime, limit = 100, lastEvaluatedKey } = options;
  
  let keyConditionExpression = 'gsi2pk = :pk';
  const expressionAttributeValues: Record<string, unknown> = {
    ':pk': `EVENT#${eventType}`
  };
  
  if (startTime && endTime) {
    keyConditionExpression += ' AND gsi2sk BETWEEN :start AND :end';
    expressionAttributeValues[':start'] = `TIMESTAMP#${startTime.toISOString()}`;
    expressionAttributeValues[':end'] = `TIMESTAMP#${endTime.toISOString()}`;
  } else if (startTime) {
    keyConditionExpression += ' AND gsi2sk >= :start';
    expressionAttributeValues[':start'] = `TIMESTAMP#${startTime.toISOString()}`;
  }
  
  const command = new QueryCommand({
    TableName: TableNames.AUDIT,
    IndexName: 'gsi2',
    KeyConditionExpression: keyConditionExpression,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit,
    ScanIndexForward: false,
    ExclusiveStartKey: lastEvaluatedKey as Record<string, unknown> | undefined
  });
  
  const result = await dynamoDb.send(command);
  
  return {
    logs: (result.Items || []) as AuditLogEntry[],
    lastEvaluatedKey: result.LastEvaluatedKey,
    count: result.Count || 0
  };
}

/**
 * Get audit statistics for a realm
 */
export async function getAuditStatistics(
  realmId: string,
  startTime: Date,
  endTime: Date
): Promise<{
  totalEvents: number;
  eventsByType: Record<string, number>;
  eventsByResult: Record<string, number>;
  eventsBySeverity: Record<string, number>;
}> {
  const result = await queryAuditLogsByRealm(realmId, {
    startTime,
    endTime,
    limit: 10000  // Get all events in range
  });
  
  const stats = {
    totalEvents: result.count,
    eventsByType: {} as Record<string, number>,
    eventsByResult: {} as Record<string, number>,
    eventsBySeverity: {} as Record<string, number>
  };
  
  for (const log of result.logs) {
    stats.eventsByType[log.eventType] = (stats.eventsByType[log.eventType] || 0) + 1;
    stats.eventsByResult[log.result] = (stats.eventsByResult[log.result] || 0) + 1;
    stats.eventsBySeverity[log.severity] = (stats.eventsBySeverity[log.severity] || 0) + 1;
  }
  
  return stats;
}

/**
 * Helper function to log common events
 */
export const AuditHelpers = {
  logLoginSuccess: (params: {
    realmId: string;
    userId: string;
    userEmail: string;
    ipAddress: string;
    userAgent?: string;
    sessionId?: string;
    geoCountry?: string;
    geoCity?: string;
  }) => logAuditEvent({
    eventType: AuditEventType.LOGIN_SUCCESS,
    result: AuditResult.SUCCESS,
    action: 'User logged in successfully',
    ...params
  }),
  
  logLoginFailure: (params: {
    realmId: string;
    userEmail?: string;
    ipAddress: string;
    userAgent?: string;
    errorCode?: string;
    errorMessage?: string;
    details?: Record<string, unknown>;
  }) => logAuditEvent({
    eventType: AuditEventType.LOGIN_FAILURE,
    result: AuditResult.FAILURE,
    action: 'Login attempt failed',
    ...params
  }),
  
  logLogout: (params: {
    realmId: string;
    userId: string;
    ipAddress: string;
    sessionId?: string;
    allDevices?: boolean;
  }) => logAuditEvent({
    eventType: AuditEventType.LOGOUT,
    result: AuditResult.SUCCESS,
    action: params.allDevices ? 'User logged out from all devices' : 'User logged out',
    details: { allDevices: params.allDevices },
    ...params
  }),
  
  logRegister: (params: {
    realmId: string;
    userId: string;
    userEmail: string;
    ipAddress: string;
    userAgent?: string;
  }) => logAuditEvent({
    eventType: AuditEventType.REGISTER,
    result: AuditResult.SUCCESS,
    action: 'New user registered',
    ...params
  }),
  
  logPasswordChange: (params: {
    realmId: string;
    userId: string;
    ipAddress: string;
  }) => logAuditEvent({
    eventType: AuditEventType.PASSWORD_CHANGE,
    result: AuditResult.SUCCESS,
    action: 'User changed password',
    ...params
  }),
  
  logMFAEnable: (params: {
    realmId: string;
    userId: string;
    ipAddress: string;
    mfaType: 'totp' | 'webauthn';
  }) => logAuditEvent({
    eventType: AuditEventType.MFA_ENABLE,
    result: AuditResult.SUCCESS,
    action: `User enabled ${params.mfaType.toUpperCase()} MFA`,
    details: { mfaType: params.mfaType },
    ...params
  }),
  
  logAccountLock: (params: {
    realmId: string;
    userId: string;
    ipAddress: string;
    reason: string;
    lockDuration?: number;
  }) => logAuditEventSync({
    eventType: AuditEventType.ACCOUNT_LOCK,
    result: AuditResult.BLOCKED,
    severity: AuditSeverity.ERROR,
    action: 'Account locked',
    details: { reason: params.reason, lockDuration: params.lockDuration },
    ...params
  }),
  
  logSuspiciousActivity: (params: {
    realmId: string;
    userId?: string;
    ipAddress: string;
    activityType: string;
    details?: Record<string, unknown>;
  }) => logAuditEventSync({
    eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
    result: AuditResult.BLOCKED,
    severity: AuditSeverity.CRITICAL,
    action: `Suspicious activity detected: ${params.activityType}`,
    ...params
  }),
  
  logImpossibleTravel: (params: {
    realmId: string;
    userId: string;
    ipAddress: string;
    fromLocation: string;
    toLocation: string;
    distanceKm: number;
    timeHours: number;
  }) => logAuditEventSync({
    eventType: AuditEventType.IMPOSSIBLE_TRAVEL,
    result: AuditResult.BLOCKED,
    severity: AuditSeverity.CRITICAL,
    action: 'Impossible travel detected',
    details: {
      fromLocation: params.fromLocation,
      toLocation: params.toLocation,
      distanceKm: params.distanceKm,
      timeHours: params.timeHours
    },
    ...params
  })
};
