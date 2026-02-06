/**
 * Security Event Logging Service for HSD Auth Platform
 * Validates: Requirements 9.4
 * 
 * Logs all authentication attempts and administrative actions
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

/**
 * Security event types
 */
export const SecurityEventTypes = {
  // Authentication events
  LOGIN_ATTEMPT: 'LOGIN_ATTEMPT',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  LOGOUT_ALL: 'LOGOUT_ALL',
  
  // Registration events
  REGISTRATION_ATTEMPT: 'REGISTRATION_ATTEMPT',
  REGISTRATION_SUCCESS: 'REGISTRATION_SUCCESS',
  REGISTRATION_FAILURE: 'REGISTRATION_FAILURE',
  
  // Token events
  TOKEN_REFRESH: 'TOKEN_REFRESH',
  TOKEN_REFRESH_FAILURE: 'TOKEN_REFRESH_FAILURE',
  TOKEN_INVALID: 'TOKEN_INVALID',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  
  // Session events
  SESSION_CREATED: 'SESSION_CREATED',
  SESSION_TERMINATED: 'SESSION_TERMINATED',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  
  // Account events
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  ACCOUNT_SUSPENDED: 'ACCOUNT_SUSPENDED',
  PASSWORD_CHANGED: 'PASSWORD_CHANGED',
  
  // Administrative events
  REALM_CREATED: 'REALM_CREATED',
  REALM_UPDATED: 'REALM_UPDATED',
  REALM_DELETED: 'REALM_DELETED',
  USER_DELETED: 'USER_DELETED',
  
  // Security events
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS',
  INVALID_REQUEST: 'INVALID_REQUEST',
  SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY'
} as const;

export type SecurityEventType = typeof SecurityEventTypes[keyof typeof SecurityEventTypes];

/**
 * Security event severity levels
 */
export const SecurityEventSeverity = {
  INFO: 'INFO',
  WARNING: 'WARNING',
  ERROR: 'ERROR',
  CRITICAL: 'CRITICAL'
} as const;

export type SecuritySeverity = typeof SecurityEventSeverity[keyof typeof SecurityEventSeverity];

/**
 * Security event structure
 */
export interface SecurityEvent {
  event_type: SecurityEventType;
  severity: SecuritySeverity;
  timestamp: string;
  request_id?: string;
  realm_id?: string;
  user_id?: string;
  email?: string;
  source_ip: string;
  user_agent: string;
  action: string;
  outcome: 'SUCCESS' | 'FAILURE';
  details?: Record<string, unknown>;
  error_code?: string;
  error_message?: string;
}

/**
 * Get severity for event type
 */
function getSeverityForEventType(eventType: SecurityEventType): SecuritySeverity {
  switch (eventType) {
    case SecurityEventTypes.LOGIN_SUCCESS:
    case SecurityEventTypes.REGISTRATION_SUCCESS:
    case SecurityEventTypes.TOKEN_REFRESH:
    case SecurityEventTypes.SESSION_CREATED:
    case SecurityEventTypes.LOGOUT:
      return SecurityEventSeverity.INFO;
      
    case SecurityEventTypes.LOGIN_FAILURE:
    case SecurityEventTypes.REGISTRATION_FAILURE:
    case SecurityEventTypes.TOKEN_REFRESH_FAILURE:
    case SecurityEventTypes.TOKEN_INVALID:
    case SecurityEventTypes.TOKEN_EXPIRED:
    case SecurityEventTypes.INVALID_REQUEST:
      return SecurityEventSeverity.WARNING;
      
    case SecurityEventTypes.RATE_LIMIT_EXCEEDED:
    case SecurityEventTypes.UNAUTHORIZED_ACCESS:
    case SecurityEventTypes.ACCOUNT_LOCKED:
    case SecurityEventTypes.ACCOUNT_SUSPENDED:
      return SecurityEventSeverity.ERROR;
      
    case SecurityEventTypes.SUSPICIOUS_ACTIVITY:
    case SecurityEventTypes.REALM_DELETED:
    case SecurityEventTypes.USER_DELETED:
      return SecurityEventSeverity.CRITICAL;
      
    default:
      return SecurityEventSeverity.INFO;
  }
}

/**
 * Extract request metadata from API Gateway event
 */
function extractRequestMetadata(event: APIGatewayProxyEvent): {
  requestId: string | undefined;
  sourceIp: string;
  userAgent: string;
} {
  return {
    requestId: event.requestContext?.requestId,
    sourceIp: event.requestContext?.identity?.sourceIp || 'unknown',
    userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown'
  };
}

/**
 * Simple security event input for async logging
 */
export interface SimpleSecurityEventInput {
  event_type: string;
  ip_address: string;
  realm_id?: string;
  user_id?: string;
  email?: string;
  details?: Record<string, unknown>;
}

/**
 * Log a security event (async version with simple object input)
 * Used by handlers for simplified logging
 */
export async function logSecurityEvent(input: SimpleSecurityEventInput): Promise<void>;

/**
 * Log a security event (sync version with full parameters)
 */
export function logSecurityEvent(
  event: APIGatewayProxyEvent,
  eventType: SecurityEventType,
  action: string,
  outcome: 'SUCCESS' | 'FAILURE',
  options?: {
    realmId?: string;
    userId?: string;
    email?: string;
    details?: Record<string, unknown>;
    errorCode?: string;
    errorMessage?: string;
    severity?: SecuritySeverity;
  }
): SecurityEvent;

/**
 * Log a security event - implementation
 */
export function logSecurityEvent(
  eventOrInput: APIGatewayProxyEvent | SimpleSecurityEventInput,
  eventType?: SecurityEventType,
  action?: string,
  outcome?: 'SUCCESS' | 'FAILURE',
  options?: {
    realmId?: string;
    userId?: string;
    email?: string;
    details?: Record<string, unknown>;
    errorCode?: string;
    errorMessage?: string;
    severity?: SecuritySeverity;
  }
): SecurityEvent | Promise<void> {
  // Check if called with simple object input (async pattern)
  if ('event_type' in eventOrInput && 'ip_address' in eventOrInput) {
    const input = eventOrInput as SimpleSecurityEventInput;
    const severity = SecurityEventSeverity.INFO;
    
    const securityEvent: SecurityEvent = {
      event_type: input.event_type as SecurityEventType,
      severity,
      timestamp: new Date().toISOString(),
      request_id: undefined,
      realm_id: input.realm_id,
      user_id: input.user_id,
      email: input.email,
      source_ip: input.ip_address,
      user_agent: 'unknown',
      action: input.event_type,
      outcome: 'SUCCESS',
      details: input.details
    };
    
    // Log to CloudWatch
    console.info(JSON.stringify({
      level: 'info',
      message: `[SECURITY] ${input.event_type}`,
      ...securityEvent
    }));
    
    return Promise.resolve();
  }
  
  // Original implementation with full parameters
  const event = eventOrInput as APIGatewayProxyEvent;
  const metadata = extractRequestMetadata(event);
  const severity = options?.severity || getSeverityForEventType(eventType!);
  
  const securityEvent: SecurityEvent = {
    event_type: eventType!,
    severity,
    timestamp: new Date().toISOString(),
    request_id: metadata.requestId,
    realm_id: options?.realmId,
    user_id: options?.userId,
    email: options?.email,
    source_ip: metadata.sourceIp,
    user_agent: metadata.userAgent,
    action: action!,
    outcome: outcome!,
    details: options?.details,
    error_code: options?.errorCode,
    error_message: options?.errorMessage
  };
  
  // Log to CloudWatch (structured JSON logging)
  const logLevel = severity === SecurityEventSeverity.CRITICAL || severity === SecurityEventSeverity.ERROR
    ? 'error'
    : severity === SecurityEventSeverity.WARNING
    ? 'warn'
    : 'info';
  
  const logMessage = JSON.stringify({
    level: logLevel,
    message: `[SECURITY] ${eventType}: ${action} - ${outcome}`,
    ...securityEvent
  });
  
  switch (logLevel) {
    case 'error':
      console.error(logMessage);
      break;
    case 'warn':
      console.warn(logMessage);
      break;
    default:
      console.info(logMessage);
  }
  
  return securityEvent;
}

/**
 * Log authentication attempt
 */
export function logAuthAttempt(
  event: APIGatewayProxyEvent,
  realmId: string,
  email: string,
  success: boolean,
  errorCode?: string,
  errorMessage?: string
): SecurityEvent {
  return logSecurityEvent(
    event,
    success ? SecurityEventTypes.LOGIN_SUCCESS : SecurityEventTypes.LOGIN_FAILURE,
    'User authentication',
    success ? 'SUCCESS' : 'FAILURE',
    {
      realmId,
      email,
      errorCode,
      errorMessage
    }
  );
}

/**
 * Log registration attempt
 */
export function logRegistrationAttempt(
  event: APIGatewayProxyEvent,
  realmId: string,
  email: string,
  success: boolean,
  errorCode?: string,
  errorMessage?: string
): SecurityEvent {
  return logSecurityEvent(
    event,
    success ? SecurityEventTypes.REGISTRATION_SUCCESS : SecurityEventTypes.REGISTRATION_FAILURE,
    'User registration',
    success ? 'SUCCESS' : 'FAILURE',
    {
      realmId,
      email,
      errorCode,
      errorMessage
    }
  );
}

/**
 * Log token refresh attempt
 */
export function logTokenRefresh(
  event: APIGatewayProxyEvent,
  realmId: string,
  userId: string,
  success: boolean,
  errorCode?: string,
  errorMessage?: string
): SecurityEvent {
  return logSecurityEvent(
    event,
    success ? SecurityEventTypes.TOKEN_REFRESH : SecurityEventTypes.TOKEN_REFRESH_FAILURE,
    'Token refresh',
    success ? 'SUCCESS' : 'FAILURE',
    {
      realmId,
      userId,
      errorCode,
      errorMessage
    }
  );
}

/**
 * Log logout event
 */
export function logLogout(
  event: APIGatewayProxyEvent,
  realmId: string,
  userId: string,
  logoutAll: boolean
): SecurityEvent {
  return logSecurityEvent(
    event,
    logoutAll ? SecurityEventTypes.LOGOUT_ALL : SecurityEventTypes.LOGOUT,
    logoutAll ? 'Logout all sessions' : 'Logout single session',
    'SUCCESS',
    {
      realmId,
      userId
    }
  );
}

/**
 * Log rate limit exceeded
 */
export function logRateLimitExceeded(
  event: APIGatewayProxyEvent,
  realmId: string,
  retryAfter: number
): SecurityEvent {
  return logSecurityEvent(
    event,
    SecurityEventTypes.RATE_LIMIT_EXCEEDED,
    'Rate limit exceeded',
    'FAILURE',
    {
      realmId,
      details: { retry_after: retryAfter }
    }
  );
}

/**
 * Log administrative action
 */
export function logAdminAction(
  event: APIGatewayProxyEvent,
  eventType: SecurityEventType,
  action: string,
  realmId: string,
  success: boolean,
  details?: Record<string, unknown>
): SecurityEvent {
  return logSecurityEvent(
    event,
    eventType,
    action,
    success ? 'SUCCESS' : 'FAILURE',
    {
      realmId,
      details
    }
  );
}

/**
 * Log unauthorized access attempt
 */
export function logUnauthorizedAccess(
  event: APIGatewayProxyEvent,
  action: string,
  errorCode?: string,
  errorMessage?: string
): SecurityEvent {
  return logSecurityEvent(
    event,
    SecurityEventTypes.UNAUTHORIZED_ACCESS,
    action,
    'FAILURE',
    {
      errorCode,
      errorMessage,
      severity: SecurityEventSeverity.ERROR
    }
  );
}


/**
 * Simple security event logging (without API Gateway event)
 * Used for internal logging where full request context is not available
 */
export interface SimpleSecurityEvent {
  event_type: string;
  ip_address?: string;
  realm_id?: string;
  user_id?: string;
  details?: Record<string, unknown>;
}

export async function logSimpleSecurityEvent(event: SimpleSecurityEvent): Promise<void> {
  const logEntry = {
    level: 'info',
    message: `[SECURITY] ${event.event_type}`,
    timestamp: new Date().toISOString(),
    event_type: event.event_type,
    ip_address: event.ip_address || 'unknown',
    realm_id: event.realm_id,
    user_id: event.user_id,
    details: event.details
  };

  // Log to CloudWatch
  console.info(JSON.stringify(logEntry));
}

// Alias for backward compatibility
export { logSimpleSecurityEvent as logSecurityEventSimple };
