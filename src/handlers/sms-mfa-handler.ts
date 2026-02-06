/**
 * SMS MFA Lambda Handlers
 * Validates: Requirements 2.2 (MFA - SMS with explicit risk acceptance)
 * 
 * ⚠️ SECURITY WARNING:
 * SMS MFA is the LEAST secure MFA method. It is vulnerable to:
 * - SS7 protocol attacks
 * - SIM swapping
 * - Social engineering
 * 
 * This implementation requires:
 * 1. Explicit risk acceptance from user
 * 2. Realm-level SMS MFA enablement
 * 3. Rate limiting (stricter than other methods)
 * 
 * Endpoints:
 * - GET  /v1/auth/mfa/sms/risk-warning - Get risk warning (must show before setup)
 * - POST /v1/auth/mfa/sms/setup - Setup SMS MFA (requires risk acceptance)
 * - POST /v1/auth/mfa/sms/send - Send verification code
 * - POST /v1/auth/mfa/sms/verify - Verify code
 * - DELETE /v1/auth/mfa/sms - Disable SMS MFA
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { findUserById } from '../repositories/user.repository';
import { findRealmById, getRealmSettings } from '../repositories/realm.repository';
import { verifyAccessToken } from '../utils/jwt';
import { logSecurityEvent } from '../services/security-logger.service';
import { checkRateLimit, RateLimitEndpoint } from '../services/ratelimit.service';
import {
  SMS_RISK_WARNING,
  SMS_CONFIG,
  createSMSVerificationData,
  sendSMSVerificationCode,
  verifySMSCode,
  validatePhoneNumber,
  normalizePhoneNumber,
  isSMSAllowedForRealm,
  getSMSSetupRequirements
} from '../services/sms.service';
import { UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from '../services/dynamodb.service';

// In-memory SMS verification store (in production, use DynamoDB with TTL)
const smsVerificationStore = new Map<string, {
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
 * GET /v1/auth/mfa/sms/risk-warning
 * Get SMS risk warning - MUST be shown to user before setup
 */
export async function getRiskWarningHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  return createResponse(200, {
    warning: SMS_RISK_WARNING,
    requirements: getSMSSetupRequirements().requirements,
    message: 'Bu uyarıyı kullanıcıya gösterin ve risk kabulü alın.'
  });
}

/**
 * POST /v1/auth/mfa/sms/setup
 * Setup SMS MFA - requires explicit risk acceptance
 */
export async function setupSMSMFAHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify authentication
    const token = getAuthToken(event);
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' }
      });
    }

    let tokenPayload: { sub: string; realm_id: string };
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, {
        error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' }
      });
    }

    const { sub: userId, realm_id: realmId } = tokenPayload;

    // Parse body
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required' }
      });
    }

    const body = JSON.parse(event.body);
    const { phone_number, accept_risk, risk_acknowledgement } = body;

    // Validate risk acceptance
    if (!accept_risk || risk_acknowledgement !== 'I understand SMS vulnerabilities') {
      await logSecurityEvent({
        event_type: 'sms_mfa_setup_rejected',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId,
        details: { reason: 'Risk not accepted' }
      });

      return createResponse(400, {
        error: {
          code: 'RISK_NOT_ACCEPTED',
          message: 'SMS MFA kurulumu için risk kabulü gereklidir.',
          required_acknowledgement: 'I understand SMS vulnerabilities',
          warning: SMS_RISK_WARNING
        }
      });
    }

    // Validate phone number
    const phoneValidation = validatePhoneNumber(phone_number);
    if (!phoneValidation.valid) {
      return createResponse(400, {
        error: {
          code: 'INVALID_PHONE',
          message: phoneValidation.error
        }
      });
    }

    // Check realm allows SMS MFA
    const realmSettings = await getRealmSettings(realmId);
    if (!isSMSAllowedForRealm(realmSettings)) {
      return createResponse(403, {
        error: {
          code: 'SMS_NOT_ALLOWED',
          message: 'Bu realm için SMS MFA etkin değil. Lütfen TOTP veya WebAuthn kullanın.'
        }
      });
    }

    // Get user
    const user = await findUserById(realmId, userId);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found' }
      });
    }

    // Generate and send verification code
    const normalizedPhone = normalizePhoneNumber(phone_number);
    const verificationData = createSMSVerificationData(normalizedPhone, true);

    // Get realm for branding
    const realm = await findRealmById(realmId);
    const realmName = realm?.name || 'Zalt.io';

    // Send SMS
    const smsResult = await sendSMSVerificationCode(
      normalizedPhone,
      verificationData.code,
      realmName
    );

    if (!smsResult.success) {
      await logSecurityEvent({
        event_type: 'sms_mfa_setup_send_failed',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId,
        details: { error: smsResult.error }
      });

      return createResponse(500, {
        error: {
          code: 'SMS_SEND_FAILED',
          message: 'SMS gönderilemedi. Lütfen tekrar deneyin.'
        }
      });
    }

    // Store verification data (pending confirmation)
    smsVerificationStore.set(`setup:${userId}`, {
      codeHash: verificationData.codeHash,
      expiresAt: verificationData.expiresAt,
      attempts: 0,
      phoneNumber: normalizedPhone
    });

    await logSecurityEvent({
      event_type: 'sms_mfa_setup_initiated',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId,
      details: { phone_masked: normalizedPhone.slice(0, -4) + '****' }
    });

    return createResponse(200, {
      message: 'Doğrulama kodu gönderildi. Lütfen kodu girin.',
      phone_masked: normalizedPhone.slice(0, -4) + '****',
      expires_in: SMS_CONFIG.codeExpirySeconds,
      next_step: 'POST /v1/auth/mfa/sms/verify ile kodu doğrulayın'
    });

  } catch (error) {
    console.error('SMS MFA setup error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' }
    });
  }
}

/**
 * POST /v1/auth/mfa/sms/send
 * Send SMS verification code (for login MFA)
 */
export async function sendSMSCodeHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Parse body for MFA session
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required' }
      });
    }

    const body = JSON.parse(event.body);
    const { mfa_session_id, user_id, realm_id } = body;

    if (!mfa_session_id || !user_id || !realm_id) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'mfa_session_id, user_id, realm_id required' }
      });
    }

    // Rate limiting (stricter for SMS)
    const rateLimitResult = await checkRateLimit(
      realm_id,
      `sms:${user_id}`,
      { maxRequests: SMS_CONFIG.rateLimitPerHour, windowSeconds: 3600 }
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'sms_rate_limited',
        ip_address: clientIP,
        realm_id: realm_id,
        user_id: user_id
      });

      return createResponse(429, {
        error: {
          code: 'RATE_LIMITED',
          message: 'Çok fazla SMS isteği. Lütfen daha sonra tekrar deneyin.',
          retry_after: rateLimitResult.retryAfter
        }
      });
    }

    // Get user
    const user = await findUserById(realm_id, user_id);
    if (!user || !user.sms_phone_number) {
      return createResponse(400, {
        error: {
          code: 'SMS_NOT_CONFIGURED',
          message: 'SMS MFA bu hesap için yapılandırılmamış.'
        }
      });
    }

    // Generate and send code
    const verificationData = createSMSVerificationData(user.sms_phone_number, true);

    // Get realm for branding
    const realm = await findRealmById(realm_id);
    const realmName = realm?.name || 'Zalt.io';

    const smsResult = await sendSMSVerificationCode(
      user.sms_phone_number,
      verificationData.code,
      realmName
    );

    if (!smsResult.success) {
      return createResponse(500, {
        error: {
          code: 'SMS_SEND_FAILED',
          message: 'SMS gönderilemedi. Lütfen tekrar deneyin.'
        }
      });
    }

    // Store for verification
    smsVerificationStore.set(`mfa:${mfa_session_id}`, {
      codeHash: verificationData.codeHash,
      expiresAt: verificationData.expiresAt,
      attempts: 0,
      phoneNumber: user.sms_phone_number
    });

    await logSecurityEvent({
      event_type: 'sms_mfa_code_sent',
      ip_address: clientIP,
      realm_id: realm_id,
      user_id: user_id
    });

    return createResponse(200, {
      message: 'Doğrulama kodu gönderildi.',
      phone_masked: user.sms_phone_number.slice(0, -4) + '****',
      expires_in: SMS_CONFIG.codeExpirySeconds
    });

  } catch (error) {
    console.error('SMS send error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' }
    });
  }
}

/**
 * POST /v1/auth/mfa/sms/verify
 * Verify SMS code
 */
export async function verifySMSCodeHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required' }
      });
    }

    const body = JSON.parse(event.body);
    const { code, mfa_session_id, setup_user_id } = body;

    if (!code || typeof code !== 'string') {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Verification code required' }
      });
    }

    // Validate code format
    if (!/^\d{6}$/.test(code)) {
      return createResponse(400, {
        error: { code: 'INVALID_CODE_FORMAT', message: 'Code must be 6 digits' }
      });
    }

    // Determine verification type (setup or MFA login)
    const storeKey = setup_user_id ? `setup:${setup_user_id}` : `mfa:${mfa_session_id}`;
    const verificationData = smsVerificationStore.get(storeKey);

    if (!verificationData) {
      return createResponse(400, {
        error: {
          code: 'NO_PENDING_VERIFICATION',
          message: 'Bekleyen doğrulama bulunamadı. Lütfen yeni kod isteyin.'
        }
      });
    }

    // Check expiry
    if (Date.now() > verificationData.expiresAt) {
      smsVerificationStore.delete(storeKey);
      return createResponse(400, {
        error: {
          code: 'CODE_EXPIRED',
          message: 'Doğrulama kodu süresi doldu. Lütfen yeni kod isteyin.'
        }
      });
    }

    // Check attempts
    if (verificationData.attempts >= SMS_CONFIG.maxAttempts) {
      smsVerificationStore.delete(storeKey);
      return createResponse(400, {
        error: {
          code: 'MAX_ATTEMPTS_EXCEEDED',
          message: 'Çok fazla başarısız deneme. Lütfen yeni kod isteyin.'
        }
      });
    }

    // Verify code
    const isValid = verifySMSCode(code, verificationData.codeHash);

    if (!isValid) {
      verificationData.attempts++;
      smsVerificationStore.set(storeKey, verificationData);

      const remaining = SMS_CONFIG.maxAttempts - verificationData.attempts;

      return createResponse(400, {
        error: {
          code: 'INVALID_CODE',
          message: 'Geçersiz doğrulama kodu.',
          remaining_attempts: remaining
        }
      });
    }

    // Code is valid - clean up
    smsVerificationStore.delete(storeKey);

    // If this is setup verification, save phone number to user
    if (setup_user_id) {
      // Get token to find realm
      const token = getAuthToken(event);
      if (token) {
        try {
          const payload = await verifyAccessToken(token);
          
          // Update user with SMS phone number
          const updateCommand = new UpdateCommand({
            TableName: TableNames.USERS,
            Key: {
              pk: `${payload.realm_id}#${setup_user_id}`,
              sk: `USER#${setup_user_id}`
            },
            UpdateExpression: 'SET sms_phone_number = :phone, sms_mfa_enabled = :enabled, sms_risk_accepted = :risk, updated_at = :now',
            ExpressionAttributeValues: {
              ':phone': verificationData.phoneNumber,
              ':enabled': true,
              ':risk': true,
              ':now': new Date().toISOString()
            }
          });

          await dynamoDb.send(updateCommand);

          await logSecurityEvent({
            event_type: 'sms_mfa_enabled',
            ip_address: clientIP,
            realm_id: payload.realm_id,
            user_id: setup_user_id,
            details: { phone_masked: verificationData.phoneNumber.slice(0, -4) + '****' }
          });

          return createResponse(200, {
            message: 'SMS MFA başarıyla etkinleştirildi.',
            sms_mfa_enabled: true,
            phone_masked: verificationData.phoneNumber.slice(0, -4) + '****',
            warning: 'SMS MFA, TOTP veya WebAuthn\'dan daha az güvenlidir. Mümkünse daha güvenli bir yönteme geçmeyi düşünün.'
          });
        } catch {
          // Token verification failed
        }
      }
    }

    // MFA login verification success
    return createResponse(200, {
      message: 'SMS doğrulama başarılı.',
      verified: true
    });

  } catch (error) {
    console.error('SMS verify error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' }
    });
  }
}

/**
 * DELETE /v1/auth/mfa/sms
 * Disable SMS MFA
 */
export async function disableSMSMFAHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);

  try {
    const token = getAuthToken(event);
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' }
      });
    }

    let tokenPayload: { sub: string; realm_id: string };
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, {
        error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' }
      });
    }

    const { sub: userId, realm_id: realmId } = tokenPayload;

    // Remove SMS MFA from user
    const updateCommand = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: `${realmId}#${userId}`,
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET sms_mfa_enabled = :disabled, updated_at = :now REMOVE sms_phone_number, sms_risk_accepted',
      ExpressionAttributeValues: {
        ':disabled': false,
        ':now': new Date().toISOString()
      }
    });

    await dynamoDb.send(updateCommand);

    await logSecurityEvent({
      event_type: 'sms_mfa_disabled',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId
    });

    return createResponse(200, {
      message: 'SMS MFA devre dışı bırakıldı.',
      sms_mfa_enabled: false
    });

  } catch (error) {
    console.error('SMS MFA disable error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' }
    });
  }
}

/**
 * Main Lambda handler - routes requests
 */
export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'GET' && path === '/v1/auth/mfa/sms/risk-warning') {
    return getRiskWarningHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/sms/setup') {
    return setupSMSMFAHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/sms/send') {
    return sendSMSCodeHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/sms/verify') {
    return verifySMSCodeHandler(event);
  }
  if (method === 'DELETE' && path === '/v1/auth/mfa/sms') {
    return disableSMSMFAHandler(event);
  }

  return {
    statusCode: 404,
    headers: { 'Content-Type': 'text/plain' },
    body: '404 page not found'
  };
};
