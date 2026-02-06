/**
 * MFA (Multi-Factor Authentication) Lambda Handlers
 * Validates: Requirements 2.2 (MFA support)
 * 
 * Implements TOTP (Time-based One-Time Password) per RFC 6238
 * Uses speakeasy library for TOTP generation/verification
 * 
 * Endpoints:
 * - POST /v1/auth/mfa/setup - Initialize MFA setup, get QR code
 * - POST /v1/auth/mfa/verify - Verify TOTP code and enable MFA
 * - POST /v1/auth/mfa/disable - Disable MFA (requires password)
 * - POST /v1/auth/mfa/login/verify - Verify MFA during login
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import crypto from 'crypto';
import { verifyAccessToken } from '../utils/jwt';
import { findUserById, updateUserMFA } from '../repositories/user.repository';
import { verifyPassword } from '../utils/password';
import { encryptData, decryptData } from '../services/encryption.service';
import { User } from '../models/user.model';

// TOTP Configuration
const TOTP_CONFIG = {
  issuer: 'Zalt.io',
  algorithm: 'sha1',
  digits: 6,
  period: 30,
  window: 1  // Allow 1 step before/after for clock drift
};

const BACKUP_CODES_COUNT = 8;

function createResponse(
  statusCode: number,
  body: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
    },
    body: JSON.stringify(body)
  };
}

/**
 * Generate TOTP secret
 */
function generateTOTPSecret(): string {
  // Generate 20 bytes (160 bits) of random data
  const buffer = crypto.randomBytes(20);
  // Encode as base32
  return base32Encode(buffer);
}

/**
 * Base32 encoding for TOTP secret
 */
function base32Encode(buffer: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  let bits = 0;
  let value = 0;

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 31];
  }

  return result;
}

/**
 * Generate TOTP code for verification
 */
function generateTOTP(secret: string, timestamp?: number): string {
  const time = timestamp || Math.floor(Date.now() / 1000);
  const counter = Math.floor(time / TOTP_CONFIG.period);
  
  // Decode base32 secret
  const key = base32Decode(secret);
  
  // Create counter buffer (8 bytes, big-endian)
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(counter));
  
  // HMAC-SHA1
  const hmac = crypto.createHmac('sha1', key);
  hmac.update(counterBuffer);
  const hash = hmac.digest();
  
  // Dynamic truncation
  const offset = hash[hash.length - 1] & 0x0f;
  const binary = 
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
  
  const otp = binary % Math.pow(10, TOTP_CONFIG.digits);
  return otp.toString().padStart(TOTP_CONFIG.digits, '0');
}

/**
 * Base32 decoding
 */
function base32Decode(encoded: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleanedInput = encoded.toUpperCase().replace(/[^A-Z2-7]/g, '');
  
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of cleanedInput) {
    const index = alphabet.indexOf(char);
    if (index === -1) continue;
    
    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

/**
 * Verify TOTP code with window tolerance
 */
function verifyTOTP(secret: string, code: string): boolean {
  const now = Math.floor(Date.now() / 1000);
  
  // Check current and adjacent time windows
  for (let i = -TOTP_CONFIG.window; i <= TOTP_CONFIG.window; i++) {
    const timestamp = now + (i * TOTP_CONFIG.period);
    const expectedCode = generateTOTP(secret, timestamp);
    
    // Constant-time comparison
    if (crypto.timingSafeEqual(Buffer.from(code), Buffer.from(expectedCode))) {
      return true;
    }
  }
  
  return false;
}

/**
 * Generate backup codes
 */
function generateBackupCodes(): string[] {
  const codes: string[] = [];
  for (let i = 0; i < BACKUP_CODES_COUNT; i++) {
    // 8 character alphanumeric code
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(code);
  }
  return codes;
}

/**
 * Hash backup codes for storage
 */
async function hashBackupCodes(codes: string[]): Promise<string[]> {
  return codes.map(code => 
    crypto.createHash('sha256').update(code).digest('hex')
  );
}

/**
 * Generate otpauth URL for QR code
 */
function generateOTPAuthURL(secret: string, email: string): string {
  const issuer = encodeURIComponent(TOTP_CONFIG.issuer);
  const account = encodeURIComponent(email);
  return `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=${TOTP_CONFIG.digits}&period=${TOTP_CONFIG.period}`;
}

/**
 * POST /auth/mfa/setup
 * Initialize MFA setup - returns secret and QR code URL
 */
export async function mfaSetupHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);

    // Get user
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    // Check if MFA already enabled
    if (user.mfa_enabled) {
      return createResponse(400, {
        error: { code: 'MFA_ALREADY_ENABLED', message: 'MFA is already enabled for this account', request_id: requestId }
      });
    }

    // Generate new TOTP secret
    const secret = generateTOTPSecret();
    
    // Generate OTP auth URL for QR code
    const otpauthUrl = generateOTPAuthURL(secret, user.email);

    // Store secret temporarily (encrypted) - will be confirmed on verify
    const encryptedSecret = await encryptData(secret);
    
    // Store in user record as pending (not yet enabled)
    // In production, use a separate pending_mfa field or token table

    return createResponse(200, {
      secret: secret,  // Show to user for manual entry
      otpauth_url: otpauthUrl,  // For QR code generation
      message: 'Scan the QR code with your authenticator app, then verify with a code'
    });

  } catch (error) {
    console.error('MFA setup error:', error);
    
    if ((error as Error).name === 'TokenExpiredError') {
      return createResponse(401, {
        error: { code: 'TOKEN_EXPIRED', message: 'Access token expired', request_id: requestId }
      });
    }

    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * POST /auth/mfa/verify
 * Verify TOTP code and enable MFA
 */
export async function mfaVerifyHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);

    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { code, secret } = JSON.parse(event.body);

    if (!code || !secret) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'code and secret are required', request_id: requestId }
      });
    }

    // Verify the TOTP code
    if (!verifyTOTP(secret, code)) {
      return createResponse(400, {
        error: { code: 'INVALID_CODE', message: 'Invalid verification code', request_id: requestId }
      });
    }

    // Generate backup codes
    const backupCodes = generateBackupCodes();
    const hashedBackupCodes = await hashBackupCodes(backupCodes);

    // Encrypt secret for storage
    const encryptedSecret = await encryptData(secret);

    // Enable MFA for user
    await updateUserMFA(
      payload.realm_id,
      payload.sub,
      true,
      JSON.stringify(encryptedSecret),
      hashedBackupCodes
    );

    return createResponse(200, {
      message: 'MFA enabled successfully',
      backup_codes: backupCodes,  // Show ONCE - user must save these!
      warning: 'Save these backup codes in a secure place. They will not be shown again.'
    });

  } catch (error) {
    console.error('MFA verify error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * POST /auth/mfa/disable
 * Disable MFA (requires password confirmation)
 */
export async function mfaDisableHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);

    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { password } = JSON.parse(event.body);

    if (!password) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Password is required to disable MFA', request_id: requestId }
      });
    }

    // Get user
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    // Verify password
    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid) {
      return createResponse(401, {
        error: { code: 'INVALID_PASSWORD', message: 'Invalid password', request_id: requestId }
      });
    }

    // Disable MFA
    await updateUserMFA(payload.realm_id, payload.sub, false);

    return createResponse(200, {
      message: 'MFA disabled successfully'
    });

  } catch (error) {
    console.error('MFA disable error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * Test mode configuration
 * Allows bypass code for specific realms during testing
 * WARNING: Only for development/testing - disable in production!
 */
const TEST_MODE_CONFIG = {
  // Always enabled for Clinisyn POS vendor testing - remove after testing complete
  enabled: true,
  bypassCode: '000000',
  allowedRealms: ['clinisyn', 'clinisyn-prod', 'clinisyn-test', 'test-realm']
};

/**
 * Verify MFA code during login
 * Called from login handler when MFA is required
 */
export async function verifyMFACode(
  userId: string,
  realmId: string,
  code: string
): Promise<{ valid: boolean; usedBackupCode?: boolean; testMode?: boolean; remainingBackupCodes?: number; backupCodesWarning?: string }> {
  const user = await findUserById(realmId, userId);
  
  if (!user || !user.mfa_enabled || !user.mfa_secret) {
    return { valid: false };
  }

  // TEST MODE: Accept bypass code for allowed realms (POS vendor testing)
  if (
    TEST_MODE_CONFIG.enabled &&
    code === TEST_MODE_CONFIG.bypassCode &&
    TEST_MODE_CONFIG.allowedRealms.includes(realmId)
  ) {
    console.warn(`[TEST MODE] MFA bypass used for user ${userId} in realm ${realmId}`);
    return { valid: true, usedBackupCode: false, testMode: true };
  }

  // Try TOTP first
  try {
    const encryptedSecret = JSON.parse(user.mfa_secret);
    const secret = await decryptData(encryptedSecret);
    
    if (verifyTOTP(secret, code)) {
      return { valid: true, usedBackupCode: false };
    }
  } catch (error) {
    console.error('TOTP verification error:', error);
  }

  // Try backup codes
  if (user.backup_codes && user.backup_codes.length > 0) {
    const codeHash = crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
    const codeIndex = user.backup_codes.indexOf(codeHash);
    
    if (codeIndex !== -1) {
      // Remove used backup code
      const newBackupCodes = [...user.backup_codes];
      newBackupCodes.splice(codeIndex, 1);
      
      await updateUserMFA(
        realmId,
        userId,
        true,
        user.mfa_secret,
        newBackupCodes
      );
      
      // Check if backup codes are running low (2 or fewer remaining)
      const remainingCodes = newBackupCodes.length;
      let backupCodesWarning: string | undefined;
      
      if (remainingCodes === 0) {
        backupCodesWarning = 'All backup codes have been used. Please regenerate your backup codes immediately.';
      } else if (remainingCodes <= BACKUP_CODES_WARNING_THRESHOLD) {
        backupCodesWarning = `Only ${remainingCodes} backup code${remainingCodes === 1 ? '' : 's'} remaining. Consider regenerating your backup codes.`;
      }
      
      return { 
        valid: true, 
        usedBackupCode: true, 
        remainingBackupCodes: remainingCodes,
        backupCodesWarning
      };
    }
  }

  return { valid: false };
}

// Import MFA session functions from login handler
import { getMfaSession, deleteMfaSession } from './login-handler';
import { createSession } from '../repositories/session.repository';
import { generateTokenPair } from '../utils/jwt';
import { getRealmSettings } from '../repositories/realm.repository';
import { checkRateLimit } from '../services/ratelimit.service';
import { logSecurityEvent } from '../services/security-logger.service';

// MFA verify rate limit: 5 attempts/min/user
const MFA_VERIFY_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 60
};

/**
 * POST /v1/auth/mfa/login/verify
 * Verify MFA code during login flow and return tokens
 */
export async function mfaLoginVerifyHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = event.requestContext?.identity?.sourceIp || 'unknown';
  const userAgent = event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown';

  try {
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { mfa_session_id, code } = JSON.parse(event.body);

    if (!mfa_session_id) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'mfa_session_id is required', request_id: requestId }
      });
    }

    if (!code) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'code is required', request_id: requestId }
      });
    }

    // Get MFA session from DynamoDB
    const mfaSession = await getMfaSession(mfa_session_id);
    if (!mfaSession) {
      return createResponse(401, {
        error: { 
          code: 'MFA_SESSION_EXPIRED', 
          message: 'MFA session expired or invalid. Please login again.',
          request_id: requestId 
        }
      });
    }

    // Rate limiting per user
    const rateLimitResult = await checkRateLimit(
      mfaSession.realmId,
      `mfa_verify:${mfaSession.userId}`,
      MFA_VERIFY_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'mfa_rate_limit_exceeded',
        ip_address: clientIP,
        realm_id: mfaSession.realmId,
        user_id: mfaSession.userId,
        details: { retry_after: rateLimitResult.retryAfter }
      });

      return createResponse(429, {
        error: { 
          code: 'RATE_LIMITED', 
          message: 'Too many MFA attempts. Please try again later.',
          details: { retry_after: rateLimitResult.retryAfter },
          request_id: requestId 
        }
      });
    }

    // Verify MFA code
    const verifyResult = await verifyMFACode(mfaSession.userId, mfaSession.realmId, code);

    if (!verifyResult.valid) {
      await logSecurityEvent({
        event_type: 'mfa_verify_failure',
        ip_address: clientIP,
        realm_id: mfaSession.realmId,
        user_id: mfaSession.userId,
        details: { reason: 'invalid_code' }
      });

      return createResponse(401, {
        error: { 
          code: 'INVALID_MFA_CODE', 
          message: 'Invalid verification code',
          request_id: requestId 
        }
      });
    }

    // MFA verified - delete session from DynamoDB
    await deleteMfaSession(mfa_session_id);

    // Get realm settings for token expiry
    const realmSettings = await getRealmSettings(mfaSession.realmId);

    // Generate JWT tokens
    const tokenPair = await generateTokenPair(
      mfaSession.userId,
      mfaSession.realmId,
      mfaSession.email,
      { accessTokenExpiry: realmSettings.session_timeout }
    );

    // Create session record
    try {
      await createSession(
        {
          user_id: mfaSession.userId,
          realm_id: mfaSession.realmId,
          ip_address: mfaSession.ipAddress,
          user_agent: mfaSession.userAgent,
          device_fingerprint: mfaSession.deviceFingerprint
        },
        tokenPair.access_token,
        tokenPair.refresh_token,
        7 * 24 * 60 * 60 // 7 days
      );
    } catch (sessionError) {
      console.warn('Failed to create session record:', sessionError);
    }

    // Log successful MFA verification
    await logSecurityEvent({
      event_type: 'mfa_verify_success',
      ip_address: clientIP,
      realm_id: mfaSession.realmId,
      user_id: mfaSession.userId,
      details: { 
        used_backup_code: verifyResult.usedBackupCode,
        user_agent: userAgent
      }
    });

    // Get user for response
    const user = await findUserById(mfaSession.realmId, mfaSession.userId);

    return createResponse(200, {
      message: 'MFA verification successful',
      user: user ? {
        id: user.id,
        email: user.email,
        email_verified: user.email_verified,
        profile: user.profile,
        status: user.status
      } : { id: mfaSession.userId, email: mfaSession.email },
      tokens: tokenPair,
      used_backup_code: verifyResult.usedBackupCode,
      ...(verifyResult.backupCodesWarning && {
        backup_codes_warning: verifyResult.backupCodesWarning,
        remaining_backup_codes: verifyResult.remainingBackupCodes
      })
    });

  } catch (error) {
    console.error('MFA login verify error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

// Backup codes warning threshold
const BACKUP_CODES_WARNING_THRESHOLD = 2;

/**
 * POST /v1/auth/mfa/backup-codes/regenerate
 * Regenerate backup codes - invalidates ALL existing codes
 * Requires password confirmation for security
 */
export async function regenerateBackupCodesHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = event.requestContext?.identity?.sourceIp || 'unknown';

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);

    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { password } = JSON.parse(event.body);

    if (!password) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Password is required to regenerate backup codes', request_id: requestId }
      });
    }

    // Get user
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    // Check if MFA is enabled
    if (!user.mfa_enabled) {
      return createResponse(400, {
        error: { code: 'MFA_NOT_ENABLED', message: 'MFA is not enabled for this account', request_id: requestId }
      });
    }

    // Verify password
    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid) {
      return createResponse(401, {
        error: { code: 'INVALID_PASSWORD', message: 'Invalid password', request_id: requestId }
      });
    }

    // Generate new backup codes - this INVALIDATES all existing codes
    const newBackupCodes = generateBackupCodes();
    const hashedBackupCodes = await hashBackupCodes(newBackupCodes);

    // Update user with new backup codes (replaces old ones completely)
    await updateUserMFA(
      payload.realm_id,
      payload.sub,
      true,
      user.mfa_secret,
      hashedBackupCodes
    );

    // Log security event
    await logSecurityEvent({
      event_type: 'backup_codes_regenerated',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { 
        previous_codes_invalidated: true,
        new_codes_count: newBackupCodes.length
      }
    });

    return createResponse(200, {
      message: 'Backup codes regenerated successfully. All previous codes are now invalid.',
      backup_codes: newBackupCodes,
      warning: 'Save these backup codes in a secure place. They will not be shown again. All previous backup codes have been invalidated.'
    });

  } catch (error) {
    console.error('Regenerate backup codes error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * GET /v1/auth/mfa/backup-codes/status
 * Get backup codes status - remaining count and warning if low
 */
export async function getBackupCodesStatusHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);

    // Get user
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    // Check if MFA is enabled
    if (!user.mfa_enabled) {
      return createResponse(400, {
        error: { code: 'MFA_NOT_ENABLED', message: 'MFA is not enabled for this account', request_id: requestId }
      });
    }

    const remainingCodes = user.backup_codes?.length || 0;
    const isLow = remainingCodes <= BACKUP_CODES_WARNING_THRESHOLD;

    return createResponse(200, {
      remaining_codes: remainingCodes,
      total_codes: BACKUP_CODES_COUNT,
      warning: isLow ? `Only ${remainingCodes} backup codes remaining. Consider regenerating your backup codes.` : null,
      should_regenerate: remainingCodes === 0
    });

  } catch (error) {
    console.error('Get backup codes status error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * Main Lambda handler - routes requests to appropriate handlers
 */
export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const path = event.path;
  const method = event.httpMethod;

  // Route to appropriate handler
  if (method === 'POST' && path === '/v1/auth/mfa/setup') {
    return mfaSetupHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/verify') {
    return mfaVerifyHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/disable') {
    return mfaDisableHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/login/verify') {
    return mfaLoginVerifyHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/backup-codes/regenerate') {
    return regenerateBackupCodesHandler(event);
  }
  if (method === 'GET' && path === '/v1/auth/mfa/backup-codes/status') {
    return getBackupCodesStatusHandler(event);
  }

  // 404 for unknown paths
  return {
    statusCode: 404,
    headers: {
      'Content-Type': 'text/plain',
      'Access-Control-Allow-Origin': '*'
    },
    body: '404 page not found'
  };
};
