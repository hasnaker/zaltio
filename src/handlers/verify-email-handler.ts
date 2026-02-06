/**
 * Email Verification Lambda Handlers
 * Validates: Requirements 5.2 (Email Verification)
 * 
 * SECURITY:
 * - 6-digit code, 15 minutes expiry
 * - Max 3 attempts per code
 * - Rate limiting: 5/hour/user
 * - Code hashed in storage
 * - No email enumeration
 * 
 * Endpoints:
 * - POST /v1/auth/verify-email/send - Send verification code
 * - POST /v1/auth/verify-email/confirm - Verify code
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { findUserById, findUserByEmail, updateUserEmailVerified } from '../repositories/user.repository';
import { verifyAccessToken } from '../utils/jwt';
import { logSecurityEvent } from '../services/security-logger.service';
import { checkRateLimit } from '../services/ratelimit.service';
import {
  createVerificationCodeData,
  verifyTokenHash,
  sendVerificationEmail,
  EMAIL_CONFIG
} from '../services/email.service';
import { findRealmById } from '../repositories/realm.repository';

// In-memory verification store (in production, use DynamoDB with TTL)
const verificationStore = new Map<string, {
  codeHash: string;
  expiresAt: number;
  attempts: number;
  userId: string;
  realmId: string;
}>();

// Rate limit configuration
const VERIFICATION_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 3600 // 5 per hour
};

function createResponse(
  statusCode: number,
  body: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
    body: JSON.stringify(body)
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 'unknown';
}

function getAuthToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.slice(7);
}

/**
 * Store verification code (in production, use DynamoDB)
 */
function storeVerificationCode(
  email: string,
  codeHash: string,
  userId: string,
  realmId: string
): void {
  verificationStore.set(email.toLowerCase(), {
    codeHash,
    expiresAt: Date.now() + EMAIL_CONFIG.verificationCodeExpiry,
    attempts: 0,
    userId,
    realmId
  });
}

/**
 * Get verification data
 */
function getVerificationData(email: string) {
  return verificationStore.get(email.toLowerCase());
}

/**
 * Update verification attempts
 */
function incrementAttempts(email: string): void {
  const data = verificationStore.get(email.toLowerCase());
  if (data) {
    data.attempts++;
    verificationStore.set(email.toLowerCase(), data);
  }
}

/**
 * Clear verification data
 */
function clearVerificationData(email: string): void {
  verificationStore.delete(email.toLowerCase());
}

/**
 * POST /v1/auth/verify-email/send
 * Send verification code to user's email
 */
export async function sendVerificationCodeHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify authentication
    const token = getAuthToken(event);
    if (!token) {
      return createResponse(401, {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
          request_id: requestId
        }
      });
    }

    let tokenPayload: { sub: string; realm_id: string; email: string };
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, {
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token',
          request_id: requestId
        }
      });
    }

    const { sub: userId, realm_id: realmId, email } = tokenPayload;

    // Rate limiting
    const rateLimitResult = await checkRateLimit(
      realmId,
      `verify-email:${userId}`,
      VERIFICATION_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'verification_rate_limited',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId
      });

      return createResponse(429, {
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many verification requests. Please try again later.',
          request_id: requestId
        }
      });
    }

    // Get user
    const user = await findUserById(realmId, userId);
    if (!user) {
      return createResponse(404, {
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
          request_id: requestId
        }
      });
    }

    // Check if already verified
    if (user.email_verified) {
      return createResponse(400, {
        error: {
          code: 'ALREADY_VERIFIED',
          message: 'Email is already verified',
          request_id: requestId
        }
      });
    }

    // Get realm for branding
    const realm = await findRealmById(realmId);
    const realmName = realm?.name || 'Zalt.io';

    // Generate verification code
    const codeData = createVerificationCodeData();

    // Store code hash
    storeVerificationCode(email, codeData.codeHash, userId, realmId);

    // Send email
    const emailResult = await sendVerificationEmail(email, codeData.code, realmName);

    if (!emailResult.success) {
      await logSecurityEvent({
        event_type: 'verification_email_failed',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId,
        details: { error: emailResult.error }
      });

      return createResponse(500, {
        error: {
          code: 'EMAIL_SEND_FAILED',
          message: 'Failed to send verification email. Please try again.',
          request_id: requestId
        }
      });
    }

    await logSecurityEvent({
      event_type: 'verification_code_sent',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId
    });

    return createResponse(200, {
      message: 'Verification code sent to your email',
      expires_in: Math.floor(EMAIL_CONFIG.verificationCodeExpiry / 1000)
    });

  } catch (error) {
    console.error('Send verification code error:', error);
    return createResponse(500, {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
        request_id: requestId
      }
    });
  }
}

/**
 * POST /v1/auth/verify-email/confirm
 * Verify the code and mark email as verified
 */
export async function confirmVerificationHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify authentication
    const token = getAuthToken(event);
    if (!token) {
      return createResponse(401, {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
          request_id: requestId
        }
      });
    }

    let tokenPayload: { sub: string; realm_id: string; email: string };
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, {
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token',
          request_id: requestId
        }
      });
    }

    const { sub: userId, realm_id: realmId, email } = tokenPayload;

    // Parse body
    if (!event.body) {
      return createResponse(400, {
        error: {
          code: 'INVALID_REQUEST',
          message: 'Request body is required',
          request_id: requestId
        }
      });
    }

    const body = JSON.parse(event.body);
    const { code } = body;

    if (!code || typeof code !== 'string') {
      return createResponse(400, {
        error: {
          code: 'INVALID_REQUEST',
          message: 'Verification code is required',
          request_id: requestId
        }
      });
    }

    // Validate code format (6 digits)
    if (!/^\d{6}$/.test(code)) {
      return createResponse(400, {
        error: {
          code: 'INVALID_CODE_FORMAT',
          message: 'Verification code must be 6 digits',
          request_id: requestId
        }
      });
    }

    // Get verification data
    const verificationData = getVerificationData(email);

    if (!verificationData) {
      await logSecurityEvent({
        event_type: 'verification_no_pending_code',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId
      });

      return createResponse(400, {
        error: {
          code: 'NO_PENDING_VERIFICATION',
          message: 'No pending verification. Please request a new code.',
          request_id: requestId
        }
      });
    }

    // Check expiry
    if (Date.now() > verificationData.expiresAt) {
      clearVerificationData(email);

      await logSecurityEvent({
        event_type: 'verification_code_expired',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId
      });

      return createResponse(400, {
        error: {
          code: 'CODE_EXPIRED',
          message: 'Verification code has expired. Please request a new code.',
          request_id: requestId
        }
      });
    }

    // Check attempts
    if (verificationData.attempts >= EMAIL_CONFIG.maxVerificationAttempts) {
      clearVerificationData(email);

      await logSecurityEvent({
        event_type: 'verification_max_attempts',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId
      });

      return createResponse(400, {
        error: {
          code: 'MAX_ATTEMPTS_EXCEEDED',
          message: 'Too many failed attempts. Please request a new code.',
          request_id: requestId
        }
      });
    }

    // Verify code
    const isValid = verifyTokenHash(code, verificationData.codeHash);

    if (!isValid) {
      incrementAttempts(email);
      const remainingAttempts = EMAIL_CONFIG.maxVerificationAttempts - verificationData.attempts - 1;

      await logSecurityEvent({
        event_type: 'verification_code_invalid',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId,
        details: { remaining_attempts: remainingAttempts }
      });

      return createResponse(400, {
        error: {
          code: 'INVALID_CODE',
          message: 'Invalid verification code',
          remaining_attempts: remainingAttempts,
          request_id: requestId
        }
      });
    }

    // Code is valid - mark email as verified
    await updateUserEmailVerified(realmId, userId, true);

    // Clear verification data
    clearVerificationData(email);

    await logSecurityEvent({
      event_type: 'email_verified',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId
    });

    return createResponse(200, {
      message: 'Email verified successfully',
      email_verified: true
    });

  } catch (error) {
    console.error('Confirm verification error:', error);
    return createResponse(500, {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
        request_id: requestId
      }
    });
  }
}

// Export for testing
export { verificationStore, storeVerificationCode, getVerificationData, clearVerificationData };

/**
 * Main Lambda handler - routes requests to appropriate handlers
 */
export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const path = event.path;
  const method = event.httpMethod;

  // Route to appropriate handler
  if (method === 'POST' && path === '/v1/auth/verify-email/send') {
    return sendVerificationCodeHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/verify-email/confirm') {
    return confirmVerificationHandler(event);
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
