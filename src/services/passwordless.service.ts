/**
 * Passwordless Authentication Service
 * Validates: Requirements 30.1-30.5 (Passwordless Authentication)
 * 
 * Implements passwordless authentication methods:
 * - Magic link authentication (email-based)
 * - Push notification authentication
 * - Passkeys as primary authentication (WebAuthn resident credentials)
 * 
 * SECURITY NOTES:
 * - Magic links expire after 15 minutes
 * - Push notifications expire after 2 minutes
 * - Passkeys use WebAuthn with resident credentials
 * - All tokens are cryptographically secure
 * - Rate limiting applied to prevent abuse
 * 
 * @healthcare HIPAA compliant - no PHI in tokens
 */

import crypto from 'crypto';
import { 
  generateRegistrationOptions, 
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  WebAuthnCredential,
  RegistrationResponse,
  AuthenticationResponse,
  WEBAUTHN_CONFIG
} from './webauthn.service';
import { 
  sendEmail, 
  hashToken, 
  verifyTokenHash,
  RealmBranding 
} from './email.service';

// ============================================
// Configuration
// ============================================

export const MAGIC_LINK_CONFIG = {
  tokenLength: 32,           // 256 bits
  expiryMinutes: 15,         // 15 minute expiry
  maxAttempts: 3,            // Max verification attempts
  rateLimitPerHour: 5,       // Max magic links per hour per email
  cooldownSeconds: 60        // Minimum time between requests
};

export const PUSH_AUTH_CONFIG = {
  expirySeconds: 120,        // 2 minute expiry
  maxPendingPerUser: 3,      // Max pending notifications per user
  pollIntervalMs: 2000,      // Client poll interval
  timeoutMs: 120000          // Total timeout
};

export const PASSKEY_CONFIG = {
  rpName: 'Zalt.io',
  rpId: 'zalt.io',
  origin: 'https://zalt.io',
  userVerification: 'required' as const,
  residentKey: 'required' as const,  // Required for passwordless
  authenticatorAttachment: 'platform' as const
};

// ============================================
// Types
// ============================================

/**
 * Magic Link Token Data
 */
export interface MagicLinkToken {
  id: string;
  token: string;
  tokenHash: string;
  email: string;
  realmId: string;
  expiresAt: number;
  createdAt: number;
  usedAt?: number;
  attempts: number;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Magic Link Send Result
 */
export interface MagicLinkSendResult {
  success: boolean;
  tokenId: string;
  expiresAt: number;
  error?: string;
}

/**
 * Magic Link Verification Result
 */
export interface MagicLinkVerifyResult {
  valid: boolean;
  email?: string;
  realmId?: string;
  userId?: string;
  error?: string;
  errorCode?: MagicLinkErrorCode;
}

export type MagicLinkErrorCode = 
  | 'TOKEN_NOT_FOUND'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_ALREADY_USED'
  | 'MAX_ATTEMPTS_EXCEEDED'
  | 'INVALID_TOKEN';

/**
 * Push Authentication Notification
 */
export interface PushAuthNotification {
  id: string;
  userId: string;
  deviceId: string;
  realmId: string;
  status: PushAuthStatus;
  createdAt: number;
  expiresAt: number;
  respondedAt?: number;
  approved?: boolean;
  ipAddress?: string;
  location?: string;
  deviceInfo?: string;
  metadata?: Record<string, unknown>;
}

export type PushAuthStatus = 
  | 'pending'
  | 'approved'
  | 'denied'
  | 'expired'
  | 'cancelled';

/**
 * Push Auth Send Result
 */
export interface PushAuthSendResult {
  success: boolean;
  notificationId: string;
  expiresAt: number;
  error?: string;
}

/**
 * Push Auth Verify Result
 */
export interface PushAuthVerifyResult {
  valid: boolean;
  approved: boolean;
  userId?: string;
  error?: string;
  errorCode?: PushAuthErrorCode;
}

export type PushAuthErrorCode = 
  | 'NOTIFICATION_NOT_FOUND'
  | 'NOTIFICATION_EXPIRED'
  | 'NOTIFICATION_ALREADY_RESPONDED'
  | 'NOTIFICATION_DENIED'
  | 'NOTIFICATION_CANCELLED';

/**
 * Passkey Registration Options
 */
export interface PasskeyRegistrationOptions {
  challenge: string;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{ alg: number; type: 'public-key' }>;
  timeout: number;
  attestation: 'none' | 'indirect' | 'direct' | 'enterprise';
  authenticatorSelection: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    residentKey: 'required';
    userVerification: 'required';
  };
  excludeCredentials?: Array<{
    id: string;
    type: 'public-key';
  }>;
}

/**
 * Passkey Authentication Options
 */
export interface PasskeyAuthenticationOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  userVerification: 'required';
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
  }>;
}

/**
 * Passkey Registration Result
 */
export interface PasskeyRegistrationResult {
  success: boolean;
  credential?: {
    id: string;
    credentialId: Buffer;
    publicKey: Buffer;
    counter: number;
    transports?: string[];
    aaguid?: string;
  };
  error?: string;
}

/**
 * Passkey Authentication Result
 */
export interface PasskeyAuthenticationResult {
  success: boolean;
  userId?: string;
  newCounter?: number;
  error?: string;
}

/**
 * Passwordless Configuration for a Realm
 */
export interface PasswordlessConfig {
  enabled: boolean;
  methods: PasswordlessMethod[];
  magicLinkEnabled: boolean;
  pushAuthEnabled: boolean;
  passkeyEnabled: boolean;
  passkeyRequired: boolean;  // If true, passkey is the only auth method
  allowedDomains?: string[];
  customRpId?: string;
  customRpName?: string;
}

export type PasswordlessMethod = 'magic_link' | 'push_notification' | 'passkey';

// ============================================
// Magic Link Authentication
// ============================================

/**
 * Generate a secure magic link token
 */
export function generateMagicLinkToken(): string {
  return crypto.randomBytes(MAGIC_LINK_CONFIG.tokenLength).toString('hex');
}

/**
 * Create magic link token data
 */
export function createMagicLinkToken(
  email: string,
  realmId: string,
  ipAddress?: string,
  userAgent?: string,
  metadata?: Record<string, unknown>
): MagicLinkToken {
  const token = generateMagicLinkToken();
  const now = Date.now();
  
  return {
    id: `ml_${crypto.randomBytes(12).toString('hex')}`,
    token,
    tokenHash: hashToken(token),
    email: email.toLowerCase().trim(),
    realmId,
    expiresAt: now + (MAGIC_LINK_CONFIG.expiryMinutes * 60 * 1000),
    createdAt: now,
    attempts: 0,
    ipAddress,
    userAgent,
    metadata
  };
}

/**
 * Validate magic link token format
 */
export function isValidMagicLinkTokenFormat(token: string): boolean {
  // Token should be 64 hex characters (32 bytes)
  return /^[a-f0-9]{64}$/i.test(token);
}

/**
 * Check if magic link token is expired
 */
export function isMagicLinkExpired(tokenData: MagicLinkToken): boolean {
  return Date.now() > tokenData.expiresAt;
}

/**
 * Check if magic link token is already used
 */
export function isMagicLinkUsed(tokenData: MagicLinkToken): boolean {
  return tokenData.usedAt !== undefined;
}

/**
 * Check if max attempts exceeded
 */
export function isMagicLinkMaxAttemptsExceeded(tokenData: MagicLinkToken): boolean {
  return tokenData.attempts >= MAGIC_LINK_CONFIG.maxAttempts;
}

/**
 * Verify magic link token
 */
export function verifyMagicLinkToken(
  token: string,
  tokenData: MagicLinkToken
): MagicLinkVerifyResult {
  // Validate token format
  if (!isValidMagicLinkTokenFormat(token)) {
    return {
      valid: false,
      error: 'Invalid token format',
      errorCode: 'INVALID_TOKEN'
    };
  }

  // Check if already used
  if (isMagicLinkUsed(tokenData)) {
    return {
      valid: false,
      error: 'Token has already been used',
      errorCode: 'TOKEN_ALREADY_USED'
    };
  }

  // Check if expired
  if (isMagicLinkExpired(tokenData)) {
    return {
      valid: false,
      error: 'Token has expired',
      errorCode: 'TOKEN_EXPIRED'
    };
  }

  // Check max attempts
  if (isMagicLinkMaxAttemptsExceeded(tokenData)) {
    return {
      valid: false,
      error: 'Maximum verification attempts exceeded',
      errorCode: 'MAX_ATTEMPTS_EXCEEDED'
    };
  }

  // Verify token hash (constant-time comparison)
  if (!verifyTokenHash(token, tokenData.tokenHash)) {
    return {
      valid: false,
      error: 'Invalid token',
      errorCode: 'INVALID_TOKEN'
    };
  }

  return {
    valid: true,
    email: tokenData.email,
    realmId: tokenData.realmId
  };
}

/**
 * Generate magic link URL
 */
export function generateMagicLinkUrl(
  token: string,
  baseUrl: string,
  realmId: string
): string {
  const url = new URL(`${baseUrl}/auth/magic-link`);
  url.searchParams.set('token', token);
  url.searchParams.set('realm', realmId);
  return url.toString();
}

/**
 * Magic Link Email Template
 */
export function getMagicLinkEmailTemplate(data: {
  magicLinkUrl: string;
  realmName: string;
  expiresMinutes: number;
  ipAddress?: string;
  location?: string;
}): { subject: string; html: string; text: string } {
  const escapeHtml = (text: string): string => {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  };

  return {
    subject: `${data.realmName} - Sign in to your account`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .button { display: inline-block; padding: 14px 28px; background: #2563eb; color: white !important; text-decoration: none; border-radius: 8px; margin: 20px 0; font-weight: 600; }
          .button:hover { background: #1d4ed8; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px; }
          .security-info { background: #f3f4f6; padding: 12px; border-radius: 6px; margin: 20px 0; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Sign in to ${escapeHtml(data.realmName)}</h2>
          <p>Click the button below to sign in to your account. This link will expire in ${data.expiresMinutes} minutes.</p>
          <p><a href="${escapeHtml(data.magicLinkUrl)}" class="button">Sign In</a></p>
          <p>Or copy and paste this link into your browser:</p>
          <p style="word-break: break-all; color: #6b7280; font-size: 14px;">${escapeHtml(data.magicLinkUrl)}</p>
          ${data.ipAddress || data.location ? `
          <div class="security-info">
            <strong>Request Details:</strong><br>
            ${data.ipAddress ? `IP Address: ${escapeHtml(data.ipAddress)}<br>` : ''}
            ${data.location ? `Location: ${escapeHtml(data.location)}<br>` : ''}
            Time: ${new Date().toISOString()}
          </div>
          ` : ''}
          <p><strong>Security Notice:</strong> If you didn't request this link, you can safely ignore this email.</p>
          <div class="footer">
            <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.realmName)}.</p>
            <p>This link can only be used once and will expire in ${data.expiresMinutes} minutes.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `Sign in to ${data.realmName}

Click the link below to sign in to your account:
${data.magicLinkUrl}

This link will expire in ${data.expiresMinutes} minutes.

${data.ipAddress ? `IP Address: ${data.ipAddress}` : ''}
${data.location ? `Location: ${data.location}` : ''}

If you didn't request this link, you can safely ignore this email.

This email was sent by Zalt.io on behalf of ${data.realmName}.`
  };
}

/**
 * Send magic link email
 */
export async function sendMagicLinkEmail(
  email: string,
  magicLinkUrl: string,
  realmName: string,
  branding?: RealmBranding,
  ipAddress?: string,
  location?: string
): Promise<{ success: boolean; messageId?: string; error?: string }> {
  const template = getMagicLinkEmailTemplate({
    magicLinkUrl,
    realmName: branding?.display_name || realmName,
    expiresMinutes: MAGIC_LINK_CONFIG.expiryMinutes,
    ipAddress,
    location
  });

  return sendEmail(email, template.subject, template.html, template.text, branding);
}

// ============================================
// Push Notification Authentication
// ============================================

/**
 * Generate push notification ID
 */
export function generatePushNotificationId(): string {
  return `push_${crypto.randomBytes(16).toString('hex')}`;
}

/**
 * Create push authentication notification
 */
export function createPushAuthNotification(
  userId: string,
  deviceId: string,
  realmId: string,
  ipAddress?: string,
  location?: string,
  deviceInfo?: string,
  metadata?: Record<string, unknown>
): PushAuthNotification {
  const now = Date.now();
  
  return {
    id: generatePushNotificationId(),
    userId,
    deviceId,
    realmId,
    status: 'pending',
    createdAt: now,
    expiresAt: now + (PUSH_AUTH_CONFIG.expirySeconds * 1000),
    ipAddress,
    location,
    deviceInfo,
    metadata
  };
}

/**
 * Check if push notification is expired
 */
export function isPushNotificationExpired(notification: PushAuthNotification): boolean {
  return Date.now() > notification.expiresAt;
}

/**
 * Check if push notification is pending
 */
export function isPushNotificationPending(notification: PushAuthNotification): boolean {
  return notification.status === 'pending' && !isPushNotificationExpired(notification);
}

/**
 * Check if push notification has been responded to
 */
export function isPushNotificationResponded(notification: PushAuthNotification): boolean {
  return notification.status === 'approved' || notification.status === 'denied';
}

/**
 * Respond to push notification (approve or deny)
 */
export function respondToPushNotification(
  notification: PushAuthNotification,
  approved: boolean
): PushAuthNotification {
  // Check if already responded
  if (isPushNotificationResponded(notification)) {
    return notification;
  }

  // Check if expired
  if (isPushNotificationExpired(notification)) {
    return {
      ...notification,
      status: 'expired'
    };
  }

  return {
    ...notification,
    status: approved ? 'approved' : 'denied',
    approved,
    respondedAt: Date.now()
  };
}

/**
 * Cancel push notification
 */
export function cancelPushNotification(
  notification: PushAuthNotification
): PushAuthNotification {
  if (isPushNotificationResponded(notification)) {
    return notification;
  }

  return {
    ...notification,
    status: 'cancelled',
    respondedAt: Date.now()
  };
}

/**
 * Verify push notification response
 */
export function verifyPushNotificationResponse(
  notification: PushAuthNotification
): PushAuthVerifyResult {
  // Check if notification exists (would be checked by caller)
  if (!notification) {
    return {
      valid: false,
      approved: false,
      error: 'Notification not found',
      errorCode: 'NOTIFICATION_NOT_FOUND'
    };
  }

  // Check if expired
  if (isPushNotificationExpired(notification) && notification.status === 'pending') {
    return {
      valid: false,
      approved: false,
      error: 'Notification has expired',
      errorCode: 'NOTIFICATION_EXPIRED'
    };
  }

  // Check status
  switch (notification.status) {
    case 'approved':
      return {
        valid: true,
        approved: true,
        userId: notification.userId
      };
    
    case 'denied':
      return {
        valid: false,
        approved: false,
        error: 'Authentication was denied',
        errorCode: 'NOTIFICATION_DENIED'
      };
    
    case 'cancelled':
      return {
        valid: false,
        approved: false,
        error: 'Notification was cancelled',
        errorCode: 'NOTIFICATION_CANCELLED'
      };
    
    case 'expired':
      return {
        valid: false,
        approved: false,
        error: 'Notification has expired',
        errorCode: 'NOTIFICATION_EXPIRED'
      };
    
    case 'pending':
      // Still waiting for response
      return {
        valid: false,
        approved: false,
        error: 'Waiting for response'
      };
    
    default:
      return {
        valid: false,
        approved: false,
        error: 'Unknown notification status'
      };
  }
}

/**
 * Push notification payload for mobile devices
 */
export interface PushNotificationPayload {
  title: string;
  body: string;
  data: {
    type: 'auth_request';
    notificationId: string;
    realmId: string;
    ipAddress?: string;
    location?: string;
    deviceInfo?: string;
    expiresAt: number;
  };
  android?: {
    priority: 'high';
    ttl: number;
  };
  apns?: {
    headers: {
      'apns-priority': '10';
      'apns-expiration': string;
    };
    payload: {
      aps: {
        alert: {
          title: string;
          body: string;
        };
        sound: 'default';
        badge: number;
        'content-available': 1;
      };
    };
  };
}

/**
 * Create push notification payload
 */
export function createPushNotificationPayload(
  notification: PushAuthNotification,
  realmName: string
): PushNotificationPayload {
  const title = `Sign-in Request`;
  const body = `Approve sign-in to ${realmName}${notification.location ? ` from ${notification.location}` : ''}?`;
  const ttlSeconds = Math.max(0, Math.floor((notification.expiresAt - Date.now()) / 1000));

  return {
    title,
    body,
    data: {
      type: 'auth_request',
      notificationId: notification.id,
      realmId: notification.realmId,
      ipAddress: notification.ipAddress,
      location: notification.location,
      deviceInfo: notification.deviceInfo,
      expiresAt: notification.expiresAt
    },
    android: {
      priority: 'high',
      ttl: ttlSeconds * 1000
    },
    apns: {
      headers: {
        'apns-priority': '10',
        'apns-expiration': Math.floor(notification.expiresAt / 1000).toString()
      },
      payload: {
        aps: {
          alert: {
            title,
            body
          },
          sound: 'default',
          badge: 1,
          'content-available': 1
        }
      }
    }
  };
}

// ============================================
// Passkey Authentication (WebAuthn Resident Credentials)
// ============================================

/**
 * Generate passkey registration options
 * Uses resident credentials for passwordless authentication
 */
export function generatePasskeyRegistrationOptions(
  userId: string,
  userEmail: string,
  userName: string,
  existingCredentials: WebAuthnCredential[] = [],
  config?: Partial<typeof PASSKEY_CONFIG>
): PasskeyRegistrationOptions {
  const rpId = config?.rpId || PASSKEY_CONFIG.rpId;
  const rpName = config?.rpName || PASSKEY_CONFIG.rpName;
  
  // Use WebAuthn service to generate base options
  const baseOptions = generateRegistrationOptions(
    userId,
    userEmail,
    userName,
    existingCredentials,
    rpId,
    rpName
  );

  // Override for passkey-specific settings
  return {
    ...baseOptions,
    authenticatorSelection: {
      authenticatorAttachment: config?.authenticatorAttachment || PASSKEY_CONFIG.authenticatorAttachment,
      residentKey: 'required',  // Required for passwordless
      userVerification: 'required'  // Required for passwordless
    }
  };
}

/**
 * Generate passkey authentication options
 * For passwordless login, allowCredentials can be empty (discoverable credentials)
 */
export function generatePasskeyAuthenticationOptions(
  credentials?: WebAuthnCredential[],
  config?: Partial<typeof PASSKEY_CONFIG>
): PasskeyAuthenticationOptions {
  const rpId = config?.rpId || PASSKEY_CONFIG.rpId;
  
  // For passwordless, we can use empty allowCredentials
  // The authenticator will use discoverable credentials
  const baseOptions = credentials && credentials.length > 0
    ? generateAuthenticationOptions(credentials, rpId)
    : {
        challenge: crypto.randomBytes(32).toString('base64url'),
        timeout: WEBAUTHN_CONFIG.timeout,
        rpId,
        userVerification: 'required' as const
      };

  return {
    ...baseOptions,
    userVerification: 'required'  // Required for passwordless
  };
}

/**
 * Verify passkey registration response
 */
export async function verifyPasskeyRegistration(
  response: RegistrationResponse,
  expectedChallenge: string,
  expectedOrigin: string,
  expectedRpId: string
): Promise<PasskeyRegistrationResult> {
  const result = await verifyRegistrationResponse(
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRpId
  );

  if (!result.verified || !result.credential) {
    return {
      success: false,
      error: result.error || 'Registration verification failed'
    };
  }

  return {
    success: true,
    credential: {
      id: response.id,
      credentialId: result.credential.credentialId,
      publicKey: result.credential.publicKey,
      counter: result.credential.counter,
      transports: result.credential.transports,
      aaguid: result.credential.aaguid
    }
  };
}

/**
 * Verify passkey authentication response
 */
export async function verifyPasskeyAuthentication(
  response: AuthenticationResponse,
  expectedChallenge: string,
  expectedOrigin: string,
  expectedRpId: string,
  credential: WebAuthnCredential
): Promise<PasskeyAuthenticationResult> {
  const result = await verifyAuthenticationResponse(
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRpId,
    credential
  );

  if (!result.verified) {
    return {
      success: false,
      error: result.error || 'Authentication verification failed'
    };
  }

  return {
    success: true,
    newCounter: result.newCounter
  };
}

// ============================================
// Passwordless Configuration
// ============================================

/**
 * Default passwordless configuration
 */
export const DEFAULT_PASSWORDLESS_CONFIG: PasswordlessConfig = {
  enabled: false,
  methods: [],
  magicLinkEnabled: false,
  pushAuthEnabled: false,
  passkeyEnabled: false,
  passkeyRequired: false
};

/**
 * Validate passwordless configuration
 */
export function validatePasswordlessConfig(config: Partial<PasswordlessConfig>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // If enabled, at least one method must be enabled
  if (config.enabled) {
    const hasMethod = config.magicLinkEnabled || config.pushAuthEnabled || config.passkeyEnabled;
    if (!hasMethod) {
      errors.push('At least one passwordless method must be enabled');
    }
  }

  // If passkeyRequired, passkeyEnabled must be true
  if (config.passkeyRequired && !config.passkeyEnabled) {
    errors.push('Passkey must be enabled if passkeyRequired is true');
  }

  // Validate custom RP ID format
  if (config.customRpId && !/^[a-z0-9.-]+$/.test(config.customRpId)) {
    errors.push('Invalid custom RP ID format');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Create passwordless configuration
 */
export function createPasswordlessConfig(
  options: Partial<PasswordlessConfig>
): PasswordlessConfig {
  const config: PasswordlessConfig = {
    ...DEFAULT_PASSWORDLESS_CONFIG,
    ...options
  };

  // Build methods array based on enabled flags
  const methods: PasswordlessMethod[] = [];
  if (config.magicLinkEnabled) methods.push('magic_link');
  if (config.pushAuthEnabled) methods.push('push_notification');
  if (config.passkeyEnabled) methods.push('passkey');
  config.methods = methods;

  // Set enabled flag based on methods
  config.enabled = methods.length > 0;

  return config;
}

/**
 * Check if a passwordless method is available for a realm
 */
export function isPasswordlessMethodAvailable(
  config: PasswordlessConfig,
  method: PasswordlessMethod
): boolean {
  if (!config.enabled) return false;
  return config.methods.includes(method);
}

// ============================================
// Rate Limiting Helpers
// ============================================

/**
 * Magic link rate limit key
 */
export function getMagicLinkRateLimitKey(email: string, realmId: string): string {
  return `magic_link:${realmId}:${email.toLowerCase()}`;
}

/**
 * Push auth rate limit key
 */
export function getPushAuthRateLimitKey(userId: string, realmId: string): string {
  return `push_auth:${realmId}:${userId}`;
}

/**
 * Check if within cooldown period
 */
export function isWithinCooldown(lastRequestTime: number): boolean {
  return Date.now() - lastRequestTime < MAGIC_LINK_CONFIG.cooldownSeconds * 1000;
}

// ============================================
// Utility Functions
// ============================================

/**
 * Mask email for display (e.g., "j***@example.com")
 */
export function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!domain) return '***';
  
  const maskedLocal = local.length > 2
    ? `${local[0]}${'*'.repeat(Math.min(local.length - 1, 3))}${local.slice(-1)}`
    : `${local[0]}***`;
  
  return `${maskedLocal}@${domain}`;
}

/**
 * Get remaining time for magic link in human-readable format
 */
export function getMagicLinkRemainingTime(tokenData: MagicLinkToken): string {
  const remaining = tokenData.expiresAt - Date.now();
  if (remaining <= 0) return 'expired';
  
  const minutes = Math.floor(remaining / 60000);
  const seconds = Math.floor((remaining % 60000) / 1000);
  
  if (minutes > 0) {
    return `${minutes} minute${minutes > 1 ? 's' : ''}`;
  }
  return `${seconds} second${seconds > 1 ? 's' : ''}`;
}

/**
 * Get remaining time for push notification in human-readable format
 */
export function getPushNotificationRemainingTime(notification: PushAuthNotification): string {
  const remaining = notification.expiresAt - Date.now();
  if (remaining <= 0) return 'expired';
  
  const seconds = Math.floor(remaining / 1000);
  return `${seconds} second${seconds > 1 ? 's' : ''}`;
}
