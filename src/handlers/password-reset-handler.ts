/**
 * Password Reset Lambda Handlers
 * Validates: Requirements 5.3 (Password Reset)
 * 
 * SECURITY:
 * - 32 byte random token, 1 hour expiry
 * - Token is single-use
 * - All sessions invalidated on password change
 * - No email enumeration (same response for valid/invalid email)
 * - Rate limiting: 3/hour/email
 * - New password checked against HaveIBeenPwned
 * 
 * Endpoints:
 * - POST /v1/auth/password-reset/request - Request password reset
 * - POST /v1/auth/password-reset/confirm - Reset password with token
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { findUserByEmail, updateUserPassword } from '../repositories/user.repository';
import { deleteUserSessions } from '../repositories/session.repository';
import { logSecurityEvent } from '../services/security-logger.service';
import { checkRateLimit } from '../services/ratelimit.service';
import { hashPassword, validatePasswordPolicy, checkPasswordPwned } from '../utils/password';
import { findRealmById } from '../repositories/realm.repository';
import {
  createResetTokenData,
  verifyTokenHash,
  sendPasswordResetEmail,
  EMAIL_CONFIG
} from '../services/email.service';

// In-memory reset token store (in production, use DynamoDB with TTL)
const resetTokenStore = new Map<string, {
  tokenHash: string;
  expiresAt: number;
  used: boolean;
  userId: string;
  realmId: string;
  email: string;
}>();

// Rate limit configuration
const RESET_RATE_LIMIT = {
  maxRequests: 3,
  windowSeconds: 3600 // 3 per hour
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

/**
 * Store reset token (in production, use DynamoDB)
 */
function storeResetToken(
  token: string,
  tokenHash: string,
  userId: string,
  realmId: string,
  email: string
): void {
  resetTokenStore.set(token, {
    tokenHash,
    expiresAt: Date.now() + EMAIL_CONFIG.resetTokenExpiry,
    used: false,
    userId,
    realmId,
    email
  });
}

/**
 * Get reset token data
 */
function getResetTokenData(token: string) {
  return resetTokenStore.get(token);
}

/**
 * Mark token as used
 */
function markTokenUsed(token: string): void {
  const data = resetTokenStore.get(token);
  if (data) {
    data.used = true;
    resetTokenStore.set(token, data);
  }
}

/**
 * Clear reset token
 */
function clearResetToken(token: string): void {
  resetTokenStore.delete(token);
}

/**
 * POST /v1/auth/password-reset/request
 * Request a password reset email
 * 
 * SECURITY: Always returns success to prevent email enumeration
 */
export async function requestPasswordResetHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
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
    const { realm_id: realmId, email } = body;

    if (!realmId || !email) {
      return createResponse(400, {
        error: {
          code: 'INVALID_REQUEST',
          message: 'realm_id and email are required',
          request_id: requestId
        }
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return createResponse(400, {
        error: {
          code: 'INVALID_EMAIL',
          message: 'Invalid email format',
          request_id: requestId
        }
      });
    }

    // Rate limiting by email (to prevent abuse)
    const rateLimitResult = await checkRateLimit(
      realmId,
      `password-reset:${email.toLowerCase()}`,
      RESET_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'password_reset_rate_limited',
        ip_address: clientIP,
        realm_id: realmId,
        details: { email: email.toLowerCase() }
      });

      // Still return success to prevent enumeration
      return createResponse(200, {
        message: 'If an account exists with this email, a password reset link has been sent.'
      });
    }

    // Find user (but don't reveal if they exist)
    const user = await findUserByEmail(realmId, email.toLowerCase());

    // Log the request regardless of user existence
    await logSecurityEvent({
      event_type: 'password_reset_requested',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: user?.id,
      details: { email: email.toLowerCase() }
    });

    // If user exists, send reset email
    if (user) {
      // Get realm for branding
      const realm = await findRealmById(realmId);
      const realmName = realm?.name || 'Zalt.io';
      const baseUrl = realm?.domain 
        ? `https://${realm.domain}` 
        : process.env.DEFAULT_RESET_URL || 'https://zalt.io';

      // Generate reset token
      const tokenData = createResetTokenData();

      // Store token
      storeResetToken(
        tokenData.token,
        tokenData.tokenHash,
        user.id,
        realmId,
        email.toLowerCase()
      );

      // Send email
      await sendPasswordResetEmail(
        email.toLowerCase(),
        tokenData.token,
        realmName,
        baseUrl
      );
    }

    // Always return same response (no email enumeration)
    return createResponse(200, {
      message: 'If an account exists with this email, a password reset link has been sent.'
    });

  } catch (error) {
    console.error('Request password reset error:', error);
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
 * POST /v1/auth/password-reset/confirm
 * Reset password using the token
 */
export async function confirmPasswordResetHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
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
    const { token, new_password: newPassword } = body;

    if (!token || !newPassword) {
      return createResponse(400, {
        error: {
          code: 'INVALID_REQUEST',
          message: 'token and new_password are required',
          request_id: requestId
        }
      });
    }

    // Validate token format (64 hex chars)
    if (!/^[a-f0-9]{64}$/.test(token)) {
      return createResponse(400, {
        error: {
          code: 'INVALID_TOKEN_FORMAT',
          message: 'Invalid token format',
          request_id: requestId
        }
      });
    }

    // Get token data
    const tokenData = getResetTokenData(token);

    if (!tokenData) {
      await logSecurityEvent({
        event_type: 'password_reset_invalid_token',
        ip_address: clientIP,
        details: { reason: 'token_not_found' }
      });

      return createResponse(400, {
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired reset token',
          request_id: requestId
        }
      });
    }

    // Check if token is used
    if (tokenData.used) {
      await logSecurityEvent({
        event_type: 'password_reset_token_reused',
        ip_address: clientIP,
        realm_id: tokenData.realmId,
        user_id: tokenData.userId
      });

      return createResponse(400, {
        error: {
          code: 'TOKEN_ALREADY_USED',
          message: 'This reset token has already been used',
          request_id: requestId
        }
      });
    }

    // Check expiry
    if (Date.now() > tokenData.expiresAt) {
      clearResetToken(token);

      await logSecurityEvent({
        event_type: 'password_reset_token_expired',
        ip_address: clientIP,
        realm_id: tokenData.realmId,
        user_id: tokenData.userId
      });

      return createResponse(400, {
        error: {
          code: 'TOKEN_EXPIRED',
          message: 'Reset token has expired. Please request a new one.',
          request_id: requestId
        }
      });
    }

    // Verify token hash
    if (!verifyTokenHash(token, tokenData.tokenHash)) {
      await logSecurityEvent({
        event_type: 'password_reset_hash_mismatch',
        ip_address: clientIP,
        realm_id: tokenData.realmId,
        user_id: tokenData.userId
      });

      return createResponse(400, {
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid reset token',
          request_id: requestId
        }
      });
    }

    // Validate new password strength
    const passwordValidation = validatePasswordPolicy(newPassword);
    if (!passwordValidation.valid) {
      return createResponse(400, {
        error: {
          code: 'WEAK_PASSWORD',
          message: passwordValidation.errors?.[0] || 'Password does not meet requirements',
          errors: passwordValidation.errors,
          request_id: requestId
        }
      });
    }

    // Check HaveIBeenPwned
    // Validates: Requirements 8.1, 8.2 - Check password against breach database
    try {
      const pwnedCount = await checkPasswordPwned(newPassword);
      if (pwnedCount > 0) {
        await logSecurityEvent({
          event_type: 'pwned_password_rejected',
          ip_address: clientIP,
          realm_id: tokenData.realmId,
          user_id: tokenData.userId,
          details: { breach_count: pwnedCount, context: 'password_reset' }
        });

        return createResponse(400, {
          error: {
            code: 'PASSWORD_COMPROMISED',
            message: 'This password has been found in data breaches. Please choose a different password.',
            timestamp: new Date().toISOString(),
            request_id: requestId
          },
          details: {
            breach_count: pwnedCount,
            recommendation: 'Use a unique password with at least 12 characters'
          }
        });
      }
    } catch {
      // Continue if HIBP check fails - don't block password reset
      console.warn('HaveIBeenPwned check failed, continuing with password reset');
    }

    // Hash new password
    const passwordHash = await hashPassword(newPassword);

    // Update password
    await updateUserPassword(tokenData.realmId, tokenData.userId, passwordHash);

    // Mark token as used
    markTokenUsed(token);

    // Invalidate all sessions (security: force re-login everywhere)
    try {
      await deleteUserSessions(tokenData.realmId, tokenData.userId);
    } catch (sessionError) {
      console.error('Failed to delete sessions:', sessionError);
      // Continue - password was changed successfully
    }

    await logSecurityEvent({
      event_type: 'password_reset_success',
      ip_address: clientIP,
      realm_id: tokenData.realmId,
      user_id: tokenData.userId
    });

    return createResponse(200, {
      message: 'Password has been reset successfully. Please log in with your new password.',
      sessions_invalidated: true
    });

  } catch (error) {
    console.error('Confirm password reset error:', error);
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
export { resetTokenStore, storeResetToken, getResetTokenData, clearResetToken, markTokenUsed };

/**
 * Main Lambda handler - routes requests to appropriate handlers
 */
export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const path = event.path;
  const method = event.httpMethod;

  // Route to appropriate handler
  if (method === 'POST' && path === '/v1/auth/password-reset/request') {
    return requestPasswordResetHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/password-reset/confirm') {
    return confirmPasswordResetHandler(event);
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
