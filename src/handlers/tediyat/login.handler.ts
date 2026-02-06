/**
 * Tediyat Login Handler
 * Returns user info + tenant list with roles
 * 
 * Validates: Requirements 2.1-2.8
 * Property 4: Login Returns Complete Tenant List
 * Property 5: No Email Enumeration
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import crypto from 'crypto';
import { findUserByEmail, updateUserLoginAttempts } from '../../repositories/user.repository';
import { validateEmail } from '../../utils/validation';
import { verifyPassword } from '../../utils/password';
import { generateTokenPair } from '../../utils/jwt';
import { checkRateLimit } from '../../services/ratelimit.service';
import { logSecurityEvent } from '../../services/security-logger.service';
import { createSession, createMfaSession } from '../../repositories/session.repository';
import * as membershipService from '../../services/tediyat/membership.service';
import * as tenantService from '../../services/tediyat/tenant.service';

// Tediyat realm ID
const TEDIYAT_REALM_ID = 'tediyat';

// Rate limit configuration for login
const LOGIN_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 900, // 15 minutes
};

// Account lockout configuration
const LOCKOUT_CONFIG = {
  maxAttempts: 5,
  lockoutDuration: 900, // 15 minutes in seconds
};

// Progressive delay configuration (in milliseconds)
const PROGRESSIVE_DELAYS = [1000, 2000, 4000, 8000, 16000];

// MFA session configuration
const MFA_SESSION_CONFIG = {
  expirySeconds: 300, // 5 minutes to complete MFA
};

// Tediyat token configuration
const TEDIYAT_TOKEN_CONFIG = {
  accessTokenExpiry: 3600, // 1 hour
  refreshTokenExpiry: 30 * 24 * 60 * 60, // 30 days
};

interface TediyatLoginRequest {
  email: string;
  password: string;
  device_fingerprint?: {
    userAgent?: string;
    screen?: string;
    timezone?: string;
    language?: string;
    platform?: string;
  };
}

interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  role: string;
  role_name: string;
  is_default: boolean;
}

interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}

interface SuccessResponse {
  success: true;
  data: {
    user: {
      id: string;
      email: string;
      firstName: string;
      lastName: string;
      email_verified: boolean;
    };
    tenants: TenantInfo[];
    defaultTenant?: TenantInfo;
    tokens: {
      accessToken: string;
      refreshToken: string;
      expiresIn: number;
    };
  };
}

interface MfaRequiredResponse {
  success: true;
  data: {
    mfa_required: true;
    mfa_session_id: string;
    mfa_expires_in: number;
    allowed_methods: string[];
    user: {
      id: string;
      email: string;
    };
  };
}

function createErrorResponse(
  statusCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>,
  requestId?: string,
  headers?: Record<string, string>
): APIGatewayProxyResult {
  const response: ErrorResponse = {
    success: false,
    error: {
      code,
      message,
      details,
      timestamp: new Date().toISOString(),
      request_id: requestId,
    },
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      ...headers,
    },
    body: JSON.stringify(response),
  };
}

function createSuccessResponse(
  statusCode: number,
  data: SuccessResponse['data'] | MfaRequiredResponse['data'],
  headers?: Record<string, string>
): APIGatewayProxyResult {
  const response = {
    success: true,
    data,
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      ...headers,
    },
    body: JSON.stringify(response),
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return (
    event.requestContext?.identity?.sourceIp ||
    event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
    'unknown'
  );
}

function getUserAgent(event: APIGatewayProxyEvent): string {
  return event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown';
}

async function applyProgressiveDelay(failedAttempts: number): Promise<void> {
  const delayIndex = Math.min(failedAttempts - 1, PROGRESSIVE_DELAYS.length - 1);
  if (delayIndex >= 0) {
    const delay = PROGRESSIVE_DELAYS[delayIndex];
    await new Promise((resolve) => setTimeout(resolve, delay));
  }
}

function isAccountLocked(user: { failed_login_attempts?: number; locked_until?: string }): boolean {
  if (!user.locked_until) return false;
  return new Date(user.locked_until) > new Date();
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);
  const userAgent = getUserAgent(event);

  try {
    // Rate limiting check (5 attempts/15min/IP)
    const rateLimitResult = await checkRateLimit(
      TEDIYAT_REALM_ID,
      `login:${clientIP}`,
      LOGIN_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'rate_limit_exceeded',
        ip_address: clientIP,
        realm_id: TEDIYAT_REALM_ID,
        details: { endpoint: 'tediyat_login', retry_after: rateLimitResult.retryAfter },
      });

      return createErrorResponse(
        429,
        'RATE_LIMITED',
        'Çok fazla giriş denemesi. Lütfen daha sonra tekrar deneyin.',
        { retry_after: rateLimitResult.retryAfter },
        requestId,
        { 'Retry-After': String(rateLimitResult.retryAfter) }
      );
    }

    // Parse request body
    if (!event.body) {
      return createErrorResponse(
        400,
        'INVALID_REQUEST',
        'İstek gövdesi gerekli',
        undefined,
        requestId
      );
    }

    let request: TediyatLoginRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return createErrorResponse(
        400,
        'INVALID_JSON',
        'Geçersiz JSON formatı',
        undefined,
        requestId
      );
    }

    // Validate email
    const emailValidation = validateEmail(request.email);
    if (!emailValidation.valid) {
      return createErrorResponse(
        400,
        'INVALID_EMAIL',
        'Geçersiz email adresi',
        { field: 'email' },
        requestId
      );
    }

    // Validate password is provided
    if (!request.password || typeof request.password !== 'string') {
      return createErrorResponse(
        400,
        'INVALID_PASSWORD',
        'Şifre gerekli',
        { field: 'password' },
        requestId
      );
    }

    // Find user by email
    const user = await findUserByEmail(TEDIYAT_REALM_ID, request.email);

    // SECURITY: Same response for invalid email (prevent enumeration)
    if (!user) {
      await logSecurityEvent({
        event_type: 'login_failure',
        ip_address: clientIP,
        realm_id: TEDIYAT_REALM_ID,
        details: { reason: 'user_not_found', email_prefix: request.email.substring(0, 3) },
      });

      // Apply progressive delay even for non-existent users
      await applyProgressiveDelay(1);

      return createErrorResponse(
        401,
        'INVALID_CREDENTIALS',
        'Email veya şifre hatalı',
        undefined,
        requestId
      );
    }

    // Check if account is locked
    if (isAccountLocked(user)) {
      await logSecurityEvent({
        event_type: 'login_blocked',
        ip_address: clientIP,
        realm_id: TEDIYAT_REALM_ID,
        user_id: user.id,
        details: { reason: 'account_locked', locked_until: user.locked_until },
      });

      return createErrorResponse(
        423,
        'ACCOUNT_LOCKED',
        'Hesabınız çok fazla başarısız giriş denemesi nedeniyle geçici olarak kilitlendi.',
        { locked_until: user.locked_until },
        requestId
      );
    }

    // Check if user is suspended
    if (user.status === 'suspended') {
      await logSecurityEvent({
        event_type: 'login_blocked',
        ip_address: clientIP,
        realm_id: TEDIYAT_REALM_ID,
        user_id: user.id,
        details: { reason: 'account_suspended' },
      });

      return createErrorResponse(
        423,
        'ACCOUNT_SUSPENDED',
        'Hesabınız askıya alınmış. Lütfen destek ile iletişime geçin.',
        undefined,
        requestId
      );
    }

    // Apply progressive delay based on failed attempts
    const failedAttempts = user.failed_login_attempts || 0;
    if (failedAttempts > 0) {
      await applyProgressiveDelay(failedAttempts);
    }

    // Verify password
    const passwordValid = await verifyPassword(request.password, user.password_hash);

    if (!passwordValid) {
      // Increment failed attempts
      const newFailedAttempts = failedAttempts + 1;
      const shouldLock = newFailedAttempts >= LOCKOUT_CONFIG.maxAttempts;
      const lockedUntil = shouldLock
        ? new Date(Date.now() + LOCKOUT_CONFIG.lockoutDuration * 1000).toISOString()
        : undefined;

      await updateUserLoginAttempts(user.id, newFailedAttempts, lockedUntil);

      await logSecurityEvent({
        event_type: 'login_failure',
        ip_address: clientIP,
        realm_id: TEDIYAT_REALM_ID,
        user_id: user.id,
        details: {
          reason: 'invalid_password',
          failed_attempts: newFailedAttempts,
          locked: shouldLock,
        },
      });

      if (shouldLock) {
        return createErrorResponse(
          423,
          'ACCOUNT_LOCKED',
          'Hesabınız çok fazla başarısız giriş denemesi nedeniyle geçici olarak kilitlendi.',
          { locked_until: lockedUntil },
          requestId
        );
      }

      return createErrorResponse(
        401,
        'INVALID_CREDENTIALS',
        'Email veya şifre hatalı',
        { attempts_remaining: LOCKOUT_CONFIG.maxAttempts - newFailedAttempts },
        requestId
      );
    }

    // Check if MFA is required
    if (user.mfa_enabled) {
      const mfaSessionId = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + MFA_SESSION_CONFIG.expirySeconds * 1000;

      await createMfaSession(mfaSessionId, {
        userId: user.id,
        realmId: TEDIYAT_REALM_ID,
        email: user.email,
        expiresAt,
        deviceFingerprint: request.device_fingerprint
          ? JSON.stringify(request.device_fingerprint)
          : undefined,
        ipAddress: clientIP,
        userAgent,
      });

      await logSecurityEvent({
        event_type: 'mfa_challenge_issued',
        ip_address: clientIP,
        realm_id: TEDIYAT_REALM_ID,
        user_id: user.id,
        details: { mfa_session_id: mfaSessionId.substring(0, 8) + '...' },
      });

      return createSuccessResponse(200, {
        mfa_required: true,
        mfa_session_id: mfaSessionId,
        mfa_expires_in: MFA_SESSION_CONFIG.expirySeconds,
        allowed_methods: ['totp'],
        user: {
          id: user.id,
          email: user.email,
        },
      });
    }

    // Reset failed login attempts on successful login
    if (failedAttempts > 0) {
      await updateUserLoginAttempts(user.id, 0, undefined);
    }

    // Get user's tenant memberships
    const membershipsResult = await membershipService.listUserMemberships(user.id);
    const memberships = membershipsResult.success ? membershipsResult.data || [] : [];

    // Get tenant details with roles
    const tenantsResult = await tenantService.listUserTenants(user.id, memberships);
    const tenants: TenantInfo[] = (tenantsResult.data || []).map((t) => ({
      id: t.id,
      name: t.name,
      slug: t.slug,
      role: t.role,
      role_name: t.role_name || t.role,
      is_default: t.is_default,
    }));

    // Find default tenant
    const defaultTenant = tenants.find((t) => t.is_default) || tenants[0];

    // Generate tokens
    const tokenPair = await generateTokenPair(
      user.id,
      TEDIYAT_REALM_ID,
      user.email,
      {
        accessTokenExpiry: TEDIYAT_TOKEN_CONFIG.accessTokenExpiry,
        orgId: defaultTenant?.id,
        orgIds: tenants.map((t) => t.id),
        roles: defaultTenant ? [defaultTenant.role] : [],
        permissions: defaultTenant?.role === 'role_owner' ? ['*'] : [],
      }
    );

    // Create session
    try {
      await createSession(
        {
          user_id: user.id,
          realm_id: TEDIYAT_REALM_ID,
          ip_address: clientIP,
          user_agent: userAgent,
          device_fingerprint: request.device_fingerprint
            ? JSON.stringify(request.device_fingerprint)
            : undefined,
        },
        tokenPair.access_token,
        tokenPair.refresh_token,
        TEDIYAT_TOKEN_CONFIG.refreshTokenExpiry
      );
    } catch (sessionError) {
      console.warn('Failed to create session record:', sessionError);
    }

    // Log successful login
    await logSecurityEvent({
      event_type: 'login_success',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      user_id: user.id,
      details: {
        tenant_count: tenants.length,
        default_tenant: defaultTenant?.id,
      },
    });

    return createSuccessResponse(
      200,
      {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.profile?.first_name || '',
          lastName: user.profile?.last_name || '',
          email_verified: user.email_verified,
        },
        tenants,
        defaultTenant,
        tokens: {
          accessToken: tokenPair.access_token,
          refreshToken: tokenPair.refresh_token,
          expiresIn: TEDIYAT_TOKEN_CONFIG.accessTokenExpiry,
        },
      },
      {
        'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
        'X-RateLimit-Reset': rateLimitResult.resetAt.toString(),
      }
    );
  } catch (error) {
    console.error('Tediyat login error:', error);

    await logSecurityEvent({
      event_type: 'login_error',
      ip_address: clientIP,
      realm_id: TEDIYAT_REALM_ID,
      details: { error: (error as Error).message },
    });

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'Beklenmeyen bir hata oluştu',
      undefined,
      requestId
    );
  }
}
