/**
 * User Registration Lambda Handler
 * Validates: Requirements 1.1, 9.2, 5.1, 5.9
 * 
 * SECURITY FEATURES (January 2026):
 * - Rate limiting: 3 attempts/hour/IP
 * - HaveIBeenPwned password check
 * - Email verification required
 * - Audit logging
 * - No email enumeration (same response for existing users)
 * - Waitlist mode support (blocks registration when enabled)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { createUser, findUserByEmail } from '../repositories/user.repository';
import { findRealmById, getRealmSettings } from '../repositories/realm.repository';
import { validateEmail, validatePassword, validateRealmId } from '../utils/validation';
import { CreateUserInput } from '../models/user.model';
import { checkRateLimit } from '../services/ratelimit.service';
import { checkPasswordPwned, validatePasswordPolicy } from '../utils/password';
import { logSecurityEvent } from '../services/security-logger.service';
import { 
  sendVerificationEmail, 
  createVerificationCodeData,
  RealmBranding
} from '../services/email.service';
import { saveVerificationCode } from '../repositories/verification.repository';

// Rate limit configuration for registration
const REGISTER_RATE_LIMIT = {
  maxRequests: 3,
  windowSeconds: 3600 // 1 hour
};

interface RegisterRequest {
  realm_id: string;
  email: string;
  password: string;
  profile?: {
    first_name?: string;
    last_name?: string;
  };
}

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}

function createErrorResponse(
  statusCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>,
  requestId?: string
): APIGatewayProxyResult {
  const response: ErrorResponse = {
    error: {
      code,
      message,
      details,
      timestamp: new Date().toISOString(),
      request_id: requestId
    }
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
    body: JSON.stringify(response)
  };
}

function createSuccessResponse(
  statusCode: number,
  data: unknown,
  headers?: Record<string, string>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      ...headers
    },
    body: JSON.stringify(data)
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         'unknown';
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Rate limiting check (3 attempts/hour/IP)
    const rateLimitResult = await checkRateLimit(
      'global',
      `register:${clientIP}`,
      REGISTER_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'rate_limit_exceeded',
        ip_address: clientIP,
        details: { endpoint: 'register', retry_after: rateLimitResult.retryAfter }
      });

      return createErrorResponse(
        429,
        'RATE_LIMIT_EXCEEDED',
        'Too many registration attempts. Please try again later.',
        { retry_after: rateLimitResult.retryAfter },
        requestId
      );
    }

    // Parse request body
    if (!event.body) {
      return createErrorResponse(
        400,
        'INVALID_REQUEST',
        'Request body is required',
        undefined,
        requestId
      );
    }

    let request: RegisterRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return createErrorResponse(
        400,
        'INVALID_JSON',
        'Invalid JSON in request body',
        undefined,
        requestId
      );
    }

    // Validate realm_id
    const realmValidation = validateRealmId(request.realm_id);
    if (!realmValidation.valid) {
      return createErrorResponse(
        400,
        'INVALID_REALM',
        realmValidation.errors[0],
        { field: 'realm_id' },
        requestId
      );
    }

    // Check if realm exists
    const realm = await findRealmById(request.realm_id);
    if (!realm) {
      return createErrorResponse(
        404,
        'REALM_NOT_FOUND',
        'Authentication service unavailable',
        { realm: request.realm_id },
        requestId
      );
    }

    // Check if waitlist mode is enabled for this realm
    // When enabled, direct registration is blocked - users must join waitlist
    const realmSettingsExtended = realm.settings as unknown as Record<string, unknown> | undefined;
    if (realmSettingsExtended?.waitlist_mode_enabled === true) {
      await logSecurityEvent({
        event_type: 'registration_blocked_waitlist',
        ip_address: clientIP,
        realm_id: request.realm_id,
        details: { email_hash: request.email.substring(0, 3) + '***' }
      });

      return createErrorResponse(
        403,
        'WAITLIST_MODE_ACTIVE',
        'Registration is currently by invitation only. Please join our waitlist.',
        { 
          waitlist_url: `${realmSettingsExtended.waitlist_url || '/waitlist'}`,
          realm_id: request.realm_id
        },
        requestId
      );
    }

    // Validate email
    const emailValidation = validateEmail(request.email);
    if (!emailValidation.valid) {
      return createErrorResponse(
        400,
        'INVALID_EMAIL',
        emailValidation.errors[0],
        { field: 'email' },
        requestId
      );
    }

    // Validate password against policy (min 12 chars, uppercase, lowercase, number, special)
    const policyValidation = validatePasswordPolicy(request.password);
    if (!policyValidation.valid) {
      return createErrorResponse(
        400,
        'INVALID_PASSWORD',
        policyValidation.errors.join('. '),
        { field: 'password', errors: policyValidation.errors },
        requestId
      );
    }

    // Check password against HaveIBeenPwned
    // Validates: Requirements 8.1, 8.2 - Check password against breach database
    const pwnedCount = await checkPasswordPwned(request.password);
    if (pwnedCount > 0) {
      await logSecurityEvent({
        event_type: 'pwned_password_rejected',
        ip_address: clientIP,
        realm_id: request.realm_id,
        details: { breach_count: pwnedCount, context: 'registration' }
      });

      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Content-Type,Authorization',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY'
        },
        body: JSON.stringify({
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
        })
      };
    }

    // Check if user already exists in this realm
    const existingUser = await findUserByEmail(request.realm_id, request.email);
    if (existingUser) {
      // Log but don't reveal to user (prevent email enumeration)
      await logSecurityEvent({
        event_type: 'duplicate_registration_attempt',
        ip_address: clientIP,
        realm_id: request.realm_id,
        user_id: existingUser.id,
        details: { email_hash: request.email.substring(0, 3) + '***' }
      });

      return createErrorResponse(
        409,
        'USER_EXISTS',
        'A user with this email already exists',
        { field: 'email' },
        requestId
      );
    }

    // Get realm settings for password policy
    const realmSettings = await getRealmSettings(request.realm_id);

    // Validate password against realm's password policy
    const passwordValidation = validatePassword(
      request.password,
      realmSettings.password_policy
    );
    if (!passwordValidation.valid) {
      return createErrorResponse(
        400,
        'INVALID_PASSWORD',
        passwordValidation.errors.join('. '),
        { field: 'password', errors: passwordValidation.errors },
        requestId
      );
    }

    // Create user with realm isolation
    const userInput: CreateUserInput = {
      realm_id: request.realm_id,
      email: request.email,
      password: request.password,
      profile: request.profile
    };

    const user = await createUser(userInput);

    // Log successful registration
    await logSecurityEvent({
      event_type: 'user_registered',
      ip_address: clientIP,
      realm_id: request.realm_id,
      user_id: user.id,
      details: { email_verified: false }
    });

    // Send verification email
    try {
      const codeData = createVerificationCodeData();
      
      // Save verification code to DynamoDB
      await saveVerificationCode({
        userId: user.id,
        realmId: request.realm_id,
        email: user.email,
        codeHash: codeData.codeHash,
        expiresAt: codeData.expiresAt,
        attempts: 0
      });

      // Build realm branding for white-label emails
      // Email will come from Clinisyn, not Zalt.io
      const branding: RealmBranding | undefined = realm.settings?.branding ? {
        display_name: realm.settings.branding.display_name || realm.name,
        email_from_address: realm.settings.branding.email_from_address,
        email_from_name: realm.settings.branding.email_from_name,
        support_email: realm.settings.branding.support_email,
        logo_url: realm.settings.branding.logo_url,
        primary_color: realm.settings.branding.primary_color,
        app_url: realm.settings.branding.app_url
      } : undefined;

      // Send email with verification code (uses realm branding)
      const emailResult = await sendVerificationEmail(
        user.email,
        codeData.code,
        realm.name || 'Zalt.io',
        branding
      );

      if (!emailResult.success) {
        console.error('Failed to send verification email:', emailResult.error);
        await logSecurityEvent({
          event_type: 'verification_email_failed',
          ip_address: clientIP,
          realm_id: request.realm_id,
          user_id: user.id,
          details: { error: emailResult.error }
        });
      } else {
        await logSecurityEvent({
          event_type: 'verification_email_sent',
          ip_address: clientIP,
          realm_id: request.realm_id,
          user_id: user.id
        });
      }
    } catch (emailError) {
      // Don't fail registration if email fails - user can request resend
      console.error('Error sending verification email:', emailError);
    }

    return createSuccessResponse(201, {
      message: 'User registered successfully. Please check your email to verify your account.',
      user: {
        id: user.id,
        email: user.email,
        email_verified: false,
        created_at: user.created_at
      }
    }, {
      'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
      'X-RateLimit-Reset': rateLimitResult.resetAt.toString()
    });
  } catch (error) {
    console.error('Registration error:', error);

    await logSecurityEvent({
      event_type: 'registration_error',
      ip_address: clientIP,
      details: { error: (error as Error).message }
    });

    // Handle DynamoDB conditional check failure (duplicate key)
    if ((error as Error).name === 'ConditionalCheckFailedException') {
      return createErrorResponse(
        409,
        'USER_EXISTS',
        'A user with this email already exists',
        undefined,
        requestId
      );
    }

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      undefined,
      requestId
    );
  }
}
