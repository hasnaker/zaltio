/**
 * WhatsApp MFA Lambda Handler
 * Meta Cloud API ile OTP doğrulama
 * 
 * Endpoints:
 * - POST /v1/auth/mfa/whatsapp/setup - WhatsApp MFA kur
 * - POST /v1/auth/mfa/whatsapp/send - OTP gönder
 * - POST /v1/auth/mfa/whatsapp/verify - OTP doğrula
 * - DELETE /v1/auth/mfa/whatsapp - WhatsApp MFA kapat
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { findUserById } from '../repositories/user.repository';
import { verifyAccessToken } from '../utils/jwt';
import { logSecurityEvent } from '../services/security-logger.service';
import { checkRateLimit } from '../services/ratelimit.service';
import {
  WHATSAPP_CONFIG,
  createWhatsAppOTPData,
  verifyOTPCode,
  validateWhatsAppNumber,
  normalizePhoneNumber,
  sendWhatsAppOTP,
} from '../services/whatsapp.service';
import { UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from '../services/dynamodb.service';

// In-memory verification store (production: use DynamoDB with TTL)
const whatsappVerificationStore = new Map<string, {
  codeHash: string;
  expiresAt: number;
  attempts: number;
  phoneNumber: string;
}>();

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
      'X-Frame-Options': 'DENY',
    },
    body: JSON.stringify(body),
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
 * POST /v1/auth/mfa/whatsapp/setup
 * Setup WhatsApp MFA
 */
export async function setupWhatsAppMFAHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);

  try {
    // Verify authentication
    const token = getAuthToken(event);
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
    }

    let tokenPayload: { sub: string; realm_id: string };
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, {
        error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' },
      });
    }

    const { sub: userId, realm_id: realmId } = tokenPayload;

    // Parse body
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required' },
      });
    }

    const body = JSON.parse(event.body);
    const { phone_number } = body;

    if (!phone_number) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'phone_number required' },
      });
    }

    // Validate phone number
    const phoneValidation = validateWhatsAppNumber(phone_number);
    if (!phoneValidation.valid) {
      return createResponse(400, {
        error: { code: 'INVALID_PHONE', message: phoneValidation.error },
      });
    }

    // Get user
    const user = await findUserById(realmId, userId);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found' },
      });
    }

    // Generate OTP
    const otpData = createWhatsAppOTPData(phone_number);
    const normalizedPhone = normalizePhoneNumber(phone_number);

    // Send via WhatsApp
    const sendResult = await sendWhatsAppOTP(normalizedPhone, otpData.code);

    if (!sendResult.success) {
      await logSecurityEvent({
        event_type: 'whatsapp_mfa_setup_send_failed',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId,
        details: { error: sendResult.error },
      });

      return createResponse(500, {
        error: {
          code: 'WHATSAPP_SEND_FAILED',
          message: sendResult.error || 'WhatsApp mesajı gönderilemedi',
        },
      });
    }

    // Store verification data
    whatsappVerificationStore.set(`setup:${userId}`, {
      codeHash: otpData.codeHash,
      expiresAt: otpData.expiresAt,
      attempts: 0,
      phoneNumber: normalizedPhone,
    });

    await logSecurityEvent({
      event_type: 'whatsapp_mfa_setup_initiated',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId,
      details: { phone_masked: normalizedPhone.slice(0, -4) + '****' },
    });

    return createResponse(200, {
      message: 'WhatsApp doğrulama kodu gönderildi.',
      phone_masked: normalizedPhone.slice(0, -4) + '****',
      expires_in: WHATSAPP_CONFIG.codeExpirySeconds,
      message_id: sendResult.messageId,
    });
  } catch (error) {
    console.error('WhatsApp MFA setup error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' },
    });
  }
}

/**
 * POST /v1/auth/mfa/whatsapp/send
 * Send WhatsApp OTP (for login MFA)
 */
export async function sendWhatsAppCodeHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);

  try {
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required' },
      });
    }

    const body = JSON.parse(event.body);
    const { mfa_session_id, user_id, realm_id } = body;

    if (!mfa_session_id || !user_id || !realm_id) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'mfa_session_id, user_id, realm_id required' },
      });
    }

    // Rate limiting
    const rateLimitResult = await checkRateLimit(
      realm_id,
      `whatsapp:${user_id}`,
      { maxRequests: WHATSAPP_CONFIG.rateLimitPerHour, windowSeconds: 3600 }
    );

    if (!rateLimitResult.allowed) {
      return createResponse(429, {
        error: {
          code: 'RATE_LIMITED',
          message: 'Çok fazla istek. Lütfen daha sonra tekrar deneyin.',
          retry_after: rateLimitResult.retryAfter,
        },
      });
    }

    // Get user
    const user = await findUserById(realm_id, user_id);
    if (!user || !user.whatsapp_phone_number) {
      return createResponse(400, {
        error: {
          code: 'WHATSAPP_NOT_CONFIGURED',
          message: 'WhatsApp MFA bu hesap için yapılandırılmamış.',
        },
      });
    }

    // Generate and send OTP
    const otpData = createWhatsAppOTPData(user.whatsapp_phone_number);

    const sendResult = await sendWhatsAppOTP(user.whatsapp_phone_number, otpData.code);

    if (!sendResult.success) {
      return createResponse(500, {
        error: {
          code: 'WHATSAPP_SEND_FAILED',
          message: sendResult.error || 'WhatsApp mesajı gönderilemedi',
        },
      });
    }

    // Store for verification
    whatsappVerificationStore.set(`mfa:${mfa_session_id}`, {
      codeHash: otpData.codeHash,
      expiresAt: otpData.expiresAt,
      attempts: 0,
      phoneNumber: user.whatsapp_phone_number,
    });

    await logSecurityEvent({
      event_type: 'whatsapp_mfa_code_sent',
      ip_address: clientIP,
      realm_id: realm_id,
      user_id: user_id,
    });

    return createResponse(200, {
      message: 'WhatsApp doğrulama kodu gönderildi.',
      phone_masked: user.whatsapp_phone_number.slice(0, -4) + '****',
      expires_in: WHATSAPP_CONFIG.codeExpirySeconds,
    });
  } catch (error) {
    console.error('WhatsApp send error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' },
    });
  }
}

/**
 * POST /v1/auth/mfa/whatsapp/verify
 * Verify WhatsApp OTP
 */
export async function verifyWhatsAppCodeHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);

  try {
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required' },
      });
    }

    const body = JSON.parse(event.body);
    const { code, mfa_session_id, setup_user_id } = body;

    if (!code || typeof code !== 'string') {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Verification code required' },
      });
    }

    // Validate code format
    if (!/^\d{6}$/.test(code)) {
      return createResponse(400, {
        error: { code: 'INVALID_CODE_FORMAT', message: 'Code must be 6 digits' },
      });
    }

    // Get verification data
    const storeKey = setup_user_id ? `setup:${setup_user_id}` : `mfa:${mfa_session_id}`;
    const verificationData = whatsappVerificationStore.get(storeKey);

    if (!verificationData) {
      return createResponse(400, {
        error: {
          code: 'NO_PENDING_VERIFICATION',
          message: 'Bekleyen doğrulama bulunamadı. Lütfen yeni kod isteyin.',
        },
      });
    }

    // Check expiry
    if (Date.now() > verificationData.expiresAt) {
      whatsappVerificationStore.delete(storeKey);
      return createResponse(400, {
        error: {
          code: 'CODE_EXPIRED',
          message: 'Doğrulama kodu süresi doldu. Lütfen yeni kod isteyin.',
        },
      });
    }

    // Check attempts
    if (verificationData.attempts >= WHATSAPP_CONFIG.maxAttempts) {
      whatsappVerificationStore.delete(storeKey);
      return createResponse(400, {
        error: {
          code: 'MAX_ATTEMPTS_EXCEEDED',
          message: 'Çok fazla başarısız deneme. Lütfen yeni kod isteyin.',
        },
      });
    }

    // Verify code
    const isValid = verifyOTPCode(code, verificationData.codeHash);

    if (!isValid) {
      verificationData.attempts++;
      whatsappVerificationStore.set(storeKey, verificationData);

      const remaining = WHATSAPP_CONFIG.maxAttempts - verificationData.attempts;

      return createResponse(400, {
        error: {
          code: 'INVALID_CODE',
          message: 'Geçersiz doğrulama kodu.',
          remaining_attempts: remaining,
        },
      });
    }

    // Code is valid - clean up
    whatsappVerificationStore.delete(storeKey);

    // If setup verification, save to user
    if (setup_user_id) {
      const token = getAuthToken(event);
      if (token) {
        try {
          const payload = await verifyAccessToken(token);

          // Update user with WhatsApp phone number
          const updateCommand = new UpdateCommand({
            TableName: TableNames.USERS,
            Key: {
              pk: `${payload.realm_id}#${setup_user_id}`,
              sk: `USER#${setup_user_id}`,
            },
            UpdateExpression: 'SET whatsapp_phone_number = :phone, whatsapp_mfa_enabled = :enabled, updated_at = :now',
            ExpressionAttributeValues: {
              ':phone': verificationData.phoneNumber,
              ':enabled': true,
              ':now': new Date().toISOString(),
            },
          });

          await dynamoDb.send(updateCommand);

          await logSecurityEvent({
            event_type: 'whatsapp_mfa_enabled',
            ip_address: clientIP,
            realm_id: payload.realm_id,
            user_id: setup_user_id,
            details: { phone_masked: verificationData.phoneNumber.slice(0, -4) + '****' },
          });

          return createResponse(200, {
            message: 'WhatsApp MFA başarıyla etkinleştirildi! 🎉',
            whatsapp_mfa_enabled: true,
            phone_masked: verificationData.phoneNumber.slice(0, -4) + '****',
          });
        } catch {
          // Token verification failed
        }
      }
    }

    // MFA login verification success
    return createResponse(200, {
      message: 'WhatsApp doğrulama başarılı.',
      verified: true,
    });
  } catch (error) {
    console.error('WhatsApp verify error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' },
    });
  }
}

/**
 * DELETE /v1/auth/mfa/whatsapp
 * Disable WhatsApp MFA
 */
export async function disableWhatsAppMFAHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);

  try {
    const token = getAuthToken(event);
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
    }

    let tokenPayload: { sub: string; realm_id: string };
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, {
        error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' },
      });
    }

    const { sub: userId, realm_id: realmId } = tokenPayload;

    // Remove WhatsApp MFA from user
    const updateCommand = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `${realmId}#${userId}`,
        sk: `USER#${userId}`,
      },
      UpdateExpression: 'SET whatsapp_mfa_enabled = :disabled, updated_at = :now REMOVE whatsapp_phone_number',
      ExpressionAttributeValues: {
        ':disabled': false,
        ':now': new Date().toISOString(),
      },
    });

    await dynamoDb.send(updateCommand);

    await logSecurityEvent({
      event_type: 'whatsapp_mfa_disabled',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId,
    });

    return createResponse(200, {
      message: 'WhatsApp MFA devre dışı bırakıldı.',
      whatsapp_mfa_enabled: false,
    });
  } catch (error) {
    console.error('WhatsApp MFA disable error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' },
    });
  }
}

/**
 * Main Lambda handler - routes requests
 */
export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'POST' && path === '/v1/auth/mfa/whatsapp/setup') {
    return setupWhatsAppMFAHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/whatsapp/send') {
    return sendWhatsAppCodeHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/whatsapp/verify') {
    return verifyWhatsAppCodeHandler(event);
  }
  if (method === 'DELETE' && path === '/v1/auth/mfa/whatsapp') {
    return disableWhatsAppMFAHandler(event);
  }

  return {
    statusCode: 404,
    headers: { 'Content-Type': 'text/plain' },
    body: '404 page not found',
  };
};
