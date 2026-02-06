/**
 * Security Alerting Service for Zalt.io Auth Platform
 * Task 7.2: Security Alerting
 * 
 * SECURITY CRITICAL:
 * - Real-time alerts for security events
 * - Email notifications to users and admins
 * - Webhook integration for external systems
 * - Alert throttling to prevent spam
 * - Realm-specific alert configuration
 */

import * as crypto from 'crypto';
import { AuditEventType, AuditSeverity } from './audit.service';

/**
 * Alert types
 */
export enum AlertType {
  // User alerts
  NEW_DEVICE_LOGIN = 'new_device_login',
  PASSWORD_CHANGED = 'password_changed',
  MFA_DISABLED = 'mfa_disabled',
  MFA_ENABLED = 'mfa_enabled',
  ACCOUNT_LOCKED = 'account_locked',
  SUSPICIOUS_LOGIN = 'suspicious_login',
  
  // Admin alerts
  FAILED_LOGIN_SPIKE = 'failed_login_spike',
  CREDENTIAL_STUFFING = 'credential_stuffing',
  IMPOSSIBLE_TRAVEL = 'impossible_travel',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  BRUTE_FORCE_DETECTED = 'brute_force_detected',
  
  // System alerts
  HIGH_ERROR_RATE = 'high_error_rate',
  SERVICE_DEGRADATION = 'service_degradation'
}

/**
 * Alert priority
 */
export enum AlertPriority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Alert channel
 */
export enum AlertChannel {
  EMAIL = 'email',
  WEBHOOK = 'webhook',
  SMS = 'sms',  // Not implemented - SS7 vulnerability
  SLACK = 'slack',
  PAGERDUTY = 'pagerduty'
}

/**
 * Alert recipient type
 */
export enum RecipientType {
  USER = 'user',
  ADMIN = 'admin',
  SECURITY_TEAM = 'security_team',
  WEBHOOK = 'webhook'
}

/**
 * Alert configuration
 */
export interface AlertConfig {
  // Enable/disable alerts
  enabled: boolean;
  
  // Channels to use
  channels: AlertChannel[];
  
  // Throttle settings (prevent spam)
  throttle: {
    enabled: boolean;
    windowMs: number;  // Time window in ms
    maxAlerts: number;  // Max alerts per window
  };
  
  // Alert priorities to send
  minPriority: AlertPriority;
  
  // Webhook URL (if webhook channel enabled)
  webhookUrl?: string;
  webhookSecret?: string;
  
  // Email settings
  adminEmails?: string[];
  securityTeamEmails?: string[];
}

/**
 * Default alert configuration
 */
export const DEFAULT_ALERT_CONFIG: AlertConfig = {
  enabled: true,
  channels: [AlertChannel.EMAIL],
  throttle: {
    enabled: true,
    windowMs: 5 * 60 * 1000,  // 5 minutes
    maxAlerts: 10
  },
  minPriority: AlertPriority.MEDIUM
};

/**
 * Healthcare realm alert configuration (stricter)
 */
export const HEALTHCARE_ALERT_CONFIG: AlertConfig = {
  enabled: true,
  channels: [AlertChannel.EMAIL, AlertChannel.WEBHOOK],
  throttle: {
    enabled: true,
    windowMs: 5 * 60 * 1000,
    maxAlerts: 20  // Higher limit for healthcare
  },
  minPriority: AlertPriority.LOW  // All alerts for healthcare
};

/**
 * Alert data
 */
export interface AlertData {
  id: string;
  type: AlertType;
  priority: AlertPriority;
  timestamp: string;
  
  // Context
  realmId: string;
  userId?: string;
  userEmail?: string;
  ipAddress?: string;
  
  // Alert details
  title: string;
  message: string;
  details?: Record<string, unknown>;
  
  // Delivery
  recipients: AlertRecipient[];
  channels: AlertChannel[];
  
  // Status
  sent: boolean;
  sentAt?: string;
  throttled: boolean;
  error?: string;
}

/**
 * Alert recipient
 */
export interface AlertRecipient {
  type: RecipientType;
  email?: string;
  webhookUrl?: string;
}

/**
 * Alert input
 */
export interface AlertInput {
  type: AlertType;
  realmId: string;
  userId?: string;
  userEmail?: string;
  ipAddress?: string;
  details?: Record<string, unknown>;
  customMessage?: string;
}

/**
 * Throttle state (in-memory for Lambda, should use DynamoDB for production)
 */
const throttleState: Map<string, { count: number; windowStart: number }> = new Map();

/**
 * Generate alert ID
 */
function generateAlertId(): string {
  return crypto.randomUUID();
}

/**
 * Get alert priority based on type
 */
export function getAlertPriority(type: AlertType): AlertPriority {
  const criticalAlerts = [
    AlertType.CREDENTIAL_STUFFING,
    AlertType.IMPOSSIBLE_TRAVEL,
    AlertType.BRUTE_FORCE_DETECTED
  ];
  
  const highAlerts = [
    AlertType.ACCOUNT_LOCKED,
    AlertType.SUSPICIOUS_LOGIN,
    AlertType.FAILED_LOGIN_SPIKE,
    AlertType.HIGH_ERROR_RATE
  ];
  
  const mediumAlerts = [
    AlertType.NEW_DEVICE_LOGIN,
    AlertType.PASSWORD_CHANGED,
    AlertType.MFA_DISABLED,
    AlertType.RATE_LIMIT_EXCEEDED
  ];
  
  if (criticalAlerts.includes(type)) return AlertPriority.CRITICAL;
  if (highAlerts.includes(type)) return AlertPriority.HIGH;
  if (mediumAlerts.includes(type)) return AlertPriority.MEDIUM;
  return AlertPriority.LOW;
}

/**
 * Get alert title based on type
 */
export function getAlertTitle(type: AlertType): string {
  const titles: Record<AlertType, string> = {
    [AlertType.NEW_DEVICE_LOGIN]: 'New Device Login Detected',
    [AlertType.PASSWORD_CHANGED]: 'Password Changed',
    [AlertType.MFA_DISABLED]: 'MFA Disabled - Security Alert',
    [AlertType.MFA_ENABLED]: 'MFA Enabled',
    [AlertType.ACCOUNT_LOCKED]: 'Account Locked',
    [AlertType.SUSPICIOUS_LOGIN]: 'Suspicious Login Activity',
    [AlertType.FAILED_LOGIN_SPIKE]: 'Failed Login Spike Detected',
    [AlertType.CREDENTIAL_STUFFING]: 'Credential Stuffing Attack Detected',
    [AlertType.IMPOSSIBLE_TRAVEL]: 'Impossible Travel Detected',
    [AlertType.RATE_LIMIT_EXCEEDED]: 'Rate Limit Exceeded',
    [AlertType.BRUTE_FORCE_DETECTED]: 'Brute Force Attack Detected',
    [AlertType.HIGH_ERROR_RATE]: 'High Error Rate Alert',
    [AlertType.SERVICE_DEGRADATION]: 'Service Degradation Detected'
  };
  
  return titles[type] || 'Security Alert';
}

/**
 * Get alert message based on type and details
 */
export function getAlertMessage(type: AlertType, details?: Record<string, unknown>): string {
  switch (type) {
    case AlertType.NEW_DEVICE_LOGIN:
      return `A new device was used to access your account from ${details?.location || 'unknown location'}.`;
    
    case AlertType.PASSWORD_CHANGED:
      return 'Your password was successfully changed. If you did not make this change, please contact support immediately.';
    
    case AlertType.MFA_DISABLED:
      return 'Multi-factor authentication has been disabled on your account. If you did not make this change, please re-enable MFA immediately.';
    
    case AlertType.MFA_ENABLED:
      return 'Multi-factor authentication has been enabled on your account.';
    
    case AlertType.ACCOUNT_LOCKED:
      return `Your account has been locked due to ${details?.reason || 'security reasons'}. ${details?.lockDuration ? `It will be unlocked in ${Math.round((details.lockDuration as number) / 60)} minutes.` : ''}`;
    
    case AlertType.SUSPICIOUS_LOGIN:
      return `Suspicious login activity detected from ${details?.location || 'unknown location'}. Please verify this was you.`;
    
    case AlertType.FAILED_LOGIN_SPIKE:
      return `Detected ${details?.count || 'multiple'} failed login attempts in the last ${details?.windowMinutes || 5} minutes.`;
    
    case AlertType.CREDENTIAL_STUFFING:
      return `Credential stuffing attack detected. ${details?.blockedAttempts || 'Multiple'} attempts blocked.`;
    
    case AlertType.IMPOSSIBLE_TRAVEL:
      return `Login detected from ${details?.toLocation || 'new location'} which is ${details?.distanceKm || 'far'} km from previous login in ${details?.fromLocation || 'previous location'}. This travel is physically impossible in ${details?.timeHours || 'the given'} hours.`;
    
    case AlertType.RATE_LIMIT_EXCEEDED:
      return `Rate limit exceeded for ${details?.endpoint || 'API endpoint'}. ${details?.blockedRequests || 'Multiple'} requests blocked.`;
    
    case AlertType.BRUTE_FORCE_DETECTED:
      return `Brute force attack detected targeting ${details?.targetType || 'account'}. Attack has been blocked.`;
    
    case AlertType.HIGH_ERROR_RATE:
      return `Error rate has exceeded ${details?.threshold || 'threshold'}%. Current rate: ${details?.currentRate || 'unknown'}%.`;
    
    case AlertType.SERVICE_DEGRADATION:
      return `Service degradation detected. Response times are ${details?.latencyMs || 'elevated'}ms above normal.`;
    
    default:
      return 'A security event has occurred on your account.';
  }
}

/**
 * Determine recipients based on alert type
 */
export function getAlertRecipients(
  type: AlertType,
  userId?: string,
  userEmail?: string,
  config?: AlertConfig
): AlertRecipient[] {
  const recipients: AlertRecipient[] = [];
  
  // User alerts - notify the user
  const userAlerts = [
    AlertType.NEW_DEVICE_LOGIN,
    AlertType.PASSWORD_CHANGED,
    AlertType.MFA_DISABLED,
    AlertType.MFA_ENABLED,
    AlertType.ACCOUNT_LOCKED,
    AlertType.SUSPICIOUS_LOGIN
  ];
  
  if (userAlerts.includes(type) && userEmail) {
    recipients.push({
      type: RecipientType.USER,
      email: userEmail
    });
  }
  
  // Admin alerts - notify admins
  const adminAlerts = [
    AlertType.FAILED_LOGIN_SPIKE,
    AlertType.CREDENTIAL_STUFFING,
    AlertType.IMPOSSIBLE_TRAVEL,
    AlertType.RATE_LIMIT_EXCEEDED,
    AlertType.BRUTE_FORCE_DETECTED,
    AlertType.HIGH_ERROR_RATE,
    AlertType.SERVICE_DEGRADATION
  ];
  
  if (adminAlerts.includes(type)) {
    recipients.push({
      type: RecipientType.ADMIN
    });
  }
  
  // Critical alerts - also notify security team
  const criticalAlerts = [
    AlertType.CREDENTIAL_STUFFING,
    AlertType.IMPOSSIBLE_TRAVEL,
    AlertType.BRUTE_FORCE_DETECTED
  ];
  
  if (criticalAlerts.includes(type)) {
    recipients.push({
      type: RecipientType.SECURITY_TEAM
    });
  }
  
  // Webhook for all alerts if configured
  if (config?.webhookUrl) {
    recipients.push({
      type: RecipientType.WEBHOOK,
      webhookUrl: config.webhookUrl
    });
  }
  
  return recipients;
}

/**
 * Check if alert should be throttled
 */
export function shouldThrottle(
  realmId: string,
  type: AlertType,
  config: AlertConfig = DEFAULT_ALERT_CONFIG
): boolean {
  if (!config.throttle.enabled) {
    return false;
  }
  
  const key = `${realmId}:${type}`;
  const now = Date.now();
  const state = throttleState.get(key);
  
  if (!state || now - state.windowStart > config.throttle.windowMs) {
    // New window
    throttleState.set(key, { count: 1, windowStart: now });
    return false;
  }
  
  if (state.count >= config.throttle.maxAlerts) {
    return true;
  }
  
  state.count++;
  return false;
}

/**
 * Reset throttle state (for testing)
 */
export function resetThrottleState(): void {
  throttleState.clear();
}

/**
 * Check if priority meets minimum threshold
 */
export function meetsPriorityThreshold(
  priority: AlertPriority,
  minPriority: AlertPriority
): boolean {
  const priorityOrder = [
    AlertPriority.LOW,
    AlertPriority.MEDIUM,
    AlertPriority.HIGH,
    AlertPriority.CRITICAL
  ];
  
  return priorityOrder.indexOf(priority) >= priorityOrder.indexOf(minPriority);
}

/**
 * Get realm-specific alert config
 */
export function getRealmAlertConfig(realmId: string): AlertConfig {
  // Healthcare realms get stricter config
  if (realmId.includes('clinisyn') || realmId.includes('healthcare') || realmId.includes('medical')) {
    return HEALTHCARE_ALERT_CONFIG;
  }
  
  return DEFAULT_ALERT_CONFIG;
}

/**
 * Create alert data from input
 */
export function createAlertData(
  input: AlertInput,
  config?: AlertConfig
): AlertData {
  const realmConfig = config || getRealmAlertConfig(input.realmId);
  const priority = getAlertPriority(input.type);
  const title = getAlertTitle(input.type);
  const message = input.customMessage || getAlertMessage(input.type, input.details);
  const recipients = getAlertRecipients(input.type, input.userId, input.userEmail, realmConfig);
  
  const throttled = shouldThrottle(input.realmId, input.type, realmConfig);
  const meetsPriority = meetsPriorityThreshold(priority, realmConfig.minPriority);
  
  return {
    id: generateAlertId(),
    type: input.type,
    priority,
    timestamp: new Date().toISOString(),
    
    realmId: input.realmId,
    userId: input.userId,
    userEmail: input.userEmail,
    ipAddress: input.ipAddress,
    
    title,
    message,
    details: input.details,
    
    recipients,
    channels: realmConfig.channels,
    
    sent: false,
    throttled: throttled || !meetsPriority || !realmConfig.enabled
  };
}

/**
 * Format alert for email
 */
export function formatAlertEmail(alert: AlertData): {
  subject: string;
  htmlBody: string;
  textBody: string;
} {
  const priorityEmoji = {
    [AlertPriority.LOW]: 'ℹ️',
    [AlertPriority.MEDIUM]: '⚠️',
    [AlertPriority.HIGH]: '🔶',
    [AlertPriority.CRITICAL]: '🚨'
  };
  
  const subject = `${priorityEmoji[alert.priority]} ${alert.title}`;
  
  const htmlBody = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
    .priority-critical { border-left: 4px solid #dc3545; }
    .priority-high { border-left: 4px solid #fd7e14; }
    .priority-medium { border-left: 4px solid #ffc107; }
    .priority-low { border-left: 4px solid #17a2b8; }
    .details { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 20px; }
    .footer { margin-top: 30px; font-size: 12px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header priority-${alert.priority}">
      <h2>${alert.title}</h2>
      <p><strong>Priority:</strong> ${alert.priority.toUpperCase()}</p>
      <p><strong>Time:</strong> ${alert.timestamp}</p>
    </div>
    
    <p>${alert.message}</p>
    
    ${alert.details ? `
    <div class="details">
      <h4>Details</h4>
      <ul>
        ${Object.entries(alert.details).map(([key, value]) => 
          `<li><strong>${key}:</strong> ${value}</li>`
        ).join('')}
      </ul>
    </div>
    ` : ''}
    
    ${alert.ipAddress ? `<p><strong>IP Address:</strong> ${alert.ipAddress}</p>` : ''}
    
    <div class="footer">
      <p>This is an automated security alert from Zalt.io.</p>
      <p>If you did not perform this action, please contact support immediately.</p>
    </div>
  </div>
</body>
</html>
  `.trim();
  
  const textBody = `
${alert.title}
${'='.repeat(alert.title.length)}

Priority: ${alert.priority.toUpperCase()}
Time: ${alert.timestamp}

${alert.message}

${alert.details ? `Details:\n${Object.entries(alert.details).map(([k, v]) => `- ${k}: ${v}`).join('\n')}` : ''}

${alert.ipAddress ? `IP Address: ${alert.ipAddress}` : ''}

---
This is an automated security alert from Zalt.io.
If you did not perform this action, please contact support immediately.
  `.trim();
  
  return { subject, htmlBody, textBody };
}

/**
 * Format alert for webhook
 */
export function formatAlertWebhook(alert: AlertData, secret?: string): {
  payload: Record<string, unknown>;
  signature?: string;
} {
  const payload = {
    id: alert.id,
    type: alert.type,
    priority: alert.priority,
    timestamp: alert.timestamp,
    realm_id: alert.realmId,
    user_id: alert.userId,
    title: alert.title,
    message: alert.message,
    details: alert.details,
    ip_address: alert.ipAddress
  };
  
  let signature: string | undefined;
  if (secret) {
    const payloadString = JSON.stringify(payload);
    signature = crypto
      .createHmac('sha256', secret)
      .update(payloadString)
      .digest('hex');
  }
  
  return { payload, signature };
}

/**
 * Send alert (mock implementation - actual sending via email.service)
 */
export async function sendAlert(
  input: AlertInput,
  config?: AlertConfig
): Promise<AlertData> {
  const alert = createAlertData(input, config);
  
  if (alert.throttled) {
    return alert;
  }
  
  // In production, this would:
  // 1. Send email via email.service
  // 2. Call webhook if configured
  // 3. Log to audit service
  
  alert.sent = true;
  alert.sentAt = new Date().toISOString();
  
  return alert;
}

/**
 * Send alert synchronously (for critical alerts)
 */
export async function sendAlertSync(input: AlertInput): Promise<AlertData> {
  const config = getRealmAlertConfig(input.realmId);
  // Disable throttling for sync alerts
  const syncConfig = { ...config, throttle: { ...config.throttle, enabled: false } };
  return sendAlert(input, syncConfig);
}

/**
 * Map audit event to alert type
 */
export function auditEventToAlertType(eventType: AuditEventType): AlertType | null {
  const mapping: Partial<Record<AuditEventType, AlertType>> = {
    [AuditEventType.NEW_DEVICE_LOGIN]: AlertType.NEW_DEVICE_LOGIN,
    [AuditEventType.PASSWORD_CHANGE]: AlertType.PASSWORD_CHANGED,
    [AuditEventType.MFA_DISABLE]: AlertType.MFA_DISABLED,
    [AuditEventType.MFA_ENABLE]: AlertType.MFA_ENABLED,
    [AuditEventType.ACCOUNT_LOCK]: AlertType.ACCOUNT_LOCKED,
    [AuditEventType.SUSPICIOUS_ACTIVITY]: AlertType.SUSPICIOUS_LOGIN,
    [AuditEventType.CREDENTIAL_STUFFING]: AlertType.CREDENTIAL_STUFFING,
    [AuditEventType.IMPOSSIBLE_TRAVEL]: AlertType.IMPOSSIBLE_TRAVEL,
    [AuditEventType.RATE_LIMIT_EXCEEDED]: AlertType.RATE_LIMIT_EXCEEDED
  };
  
  return mapping[eventType] || null;
}

/**
 * Helper functions for common alerts
 */
export const AlertHelpers = {
  newDeviceLogin: (params: {
    realmId: string;
    userId: string;
    userEmail: string;
    ipAddress: string;
    deviceInfo?: string;
    location?: string;
  }) => sendAlert({
    type: AlertType.NEW_DEVICE_LOGIN,
    realmId: params.realmId,
    userId: params.userId,
    userEmail: params.userEmail,
    ipAddress: params.ipAddress,
    details: {
      deviceInfo: params.deviceInfo,
      location: params.location
    }
  }),
  
  passwordChanged: (params: {
    realmId: string;
    userId: string;
    userEmail: string;
    ipAddress: string;
  }) => sendAlert({
    type: AlertType.PASSWORD_CHANGED,
    ...params
  }),
  
  mfaDisabled: (params: {
    realmId: string;
    userId: string;
    userEmail: string;
    ipAddress: string;
  }) => sendAlert({
    type: AlertType.MFA_DISABLED,
    ...params
  }),
  
  accountLocked: (params: {
    realmId: string;
    userId: string;
    userEmail: string;
    ipAddress: string;
    reason: string;
    lockDuration?: number;
  }) => sendAlert({
    type: AlertType.ACCOUNT_LOCKED,
    realmId: params.realmId,
    userId: params.userId,
    userEmail: params.userEmail,
    ipAddress: params.ipAddress,
    details: {
      reason: params.reason,
      lockDuration: params.lockDuration
    }
  }),
  
  credentialStuffing: (params: {
    realmId: string;
    ipAddress: string;
    blockedAttempts: number;
    pattern?: string;
  }) => sendAlertSync({
    type: AlertType.CREDENTIAL_STUFFING,
    realmId: params.realmId,
    ipAddress: params.ipAddress,
    details: {
      blockedAttempts: params.blockedAttempts,
      pattern: params.pattern
    }
  }),
  
  impossibleTravel: (params: {
    realmId: string;
    userId: string;
    userEmail: string;
    ipAddress: string;
    fromLocation: string;
    toLocation: string;
    distanceKm: number;
    timeHours: number;
  }) => sendAlertSync({
    type: AlertType.IMPOSSIBLE_TRAVEL,
    realmId: params.realmId,
    userId: params.userId,
    userEmail: params.userEmail,
    ipAddress: params.ipAddress,
    details: {
      fromLocation: params.fromLocation,
      toLocation: params.toLocation,
      distanceKm: params.distanceKm,
      timeHours: params.timeHours
    }
  }),
  
  failedLoginSpike: (params: {
    realmId: string;
    count: number;
    windowMinutes: number;
    topIPs?: string[];
  }) => sendAlert({
    type: AlertType.FAILED_LOGIN_SPIKE,
    realmId: params.realmId,
    details: {
      count: params.count,
      windowMinutes: params.windowMinutes,
      topIPs: params.topIPs
    }
  })
};
