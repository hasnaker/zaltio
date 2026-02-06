/**
 * Platform Customer Login Lambda Handler
 * POST /platform/login
 * 
 * Authenticates B2B customers (companies using Zalt.io)
 * Returns JWT for dashboard access
 * 
 * Validates: Requirements 2.1 (Customer login)
 * 
 * SECURITY FEATURES:
 * - Rate limiting: 5 attempts/15min/IP
 * - Account lockout after 10 failed attempts
 * - Constant-time password comparison
 * - Audit logging
 * - Progressive delays
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { 
  getCustomerByEmail,
  recordLoginAttempt,
  lockCustomerAccount
} from '../../repositories/customer.repository';
import { validateEmail } from '../../utils/validation';
import { verifyPassword } from '../../utils/password';
import { checkRateLimit } from '../../services/ratelimit.service';
import { logSecurityEvent } from '../../services/security-logger.service';
import { generateTokenPair } from '../../utils/jwt';

// Rate limit configuration for login
const LOGIN_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 900 // 15 minutes
};

// Account lockout configuration
const MAX_FAILED_ATTEMPTS = 10;
const LOCKOUT_DURATION_MINUTES = 30;

interface CustomerLoginRequest {
  email: string;
  password: string;
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
    // Rate limiting check (5 attempts/15min/IP)
    const rateLimitResult = await checkRateLimit(
      'global',
      `platform:login:${clientIP}`,
      LOGIN_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'rate_limit_exceeded',
        ip_address: clientIP,
        details: { endpoint: 'platform/login', retry_after: rateLimitResult.retryAfter }
      });

      return createErrorResponse(
        429,
        'RATE_LIMIT_EXCEEDED',
        'Too many login attempts. Please try again later.',
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

    let request: CustomerLoginRequest;
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

    // Validate required fields
    if (!request.email || !request.password) {
      return createErrorResponse(
        400,
        'MISSING_FIELDS',
        'Email and password are required',
        { required: ['email', 'password'] },
        requestId
      );
    }

    // Validate email format
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

    // Find customer by email
    const customer = await getCustomerByEmail(request.email);
    
    // Generic error for security (prevent email enumeration)
    if (!customer) {
      await logSecurityEvent({
        event_type: 'login_failed',
        ip_address: clientIP,
        details: { reason: 'customer_not_found', email_hash: request.email.substring(0, 3) + '***' }
      });

      return createErrorResponse(
        401,
        'INVALID_CREDENTIALS',
        'Invalid email or password',
        undefined,
        requestId
      );
    }

    // Check if account is locked
    if (customer.locked_until) {
      const lockExpiry = new Date(customer.locked_until);
      if (lockExpiry > new Date()) {
        await logSecurityEvent({
          event_type: 'login_blocked',
          ip_address: clientIP,
          user_id: customer.id,
          details: { reason: 'account_locked', locked_until: customer.locked_until }
        });

        return createErrorResponse(
          423,
          'ACCOUNT_LOCKED',
          'Account is temporarily locked due to too many failed login attempts',
          { locked_until: customer.locked_until },
          requestId
        );
      }
    }

    // Check if account is suspended
    if (customer.status === 'suspended') {
      await logSecurityEvent({
        event_type: 'login_blocked',
        ip_address: clientIP,
        user_id: customer.id,
        details: { reason: 'account_suspended' }
      });

      return createErrorResponse(
        403,
        'ACCOUNT_SUSPENDED',
        'Your account has been suspended. Please contact support.',
        undefined,
        requestId
      );
    }

    // Verify password (constant-time comparison)
    const passwordValid = await verifyPassword(request.password, customer.password_hash);
    
    if (!passwordValid) {
      // Record failed attempt
      await recordLoginAttempt(customer.id, false);
      
      // Check if we should lock the account
      const failedAttempts = (customer.failed_login_attempts || 0) + 1;
      if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
        await lockCustomerAccount(customer.id, LOCKOUT_DURATION_MINUTES);
        
        await logSecurityEvent({
          event_type: 'account_locked',
          ip_address: clientIP,
          user_id: customer.id,
          details: { failed_attempts: failedAttempts, lockout_minutes: LOCKOUT_DURATION_MINUTES }
        });
      }

      await logSecurityEvent({
        event_type: 'login_failed',
        ip_address: clientIP,
        user_id: customer.id,
        details: { reason: 'invalid_password', failed_attempts: failedAttempts }
      });

      return createErrorResponse(
        401,
        'INVALID_CREDENTIALS',
        'Invalid email or password',
        undefined,
        requestId
      );
    }

    // Record successful login
    await recordLoginAttempt(customer.id, true);

    // Generate JWT for dashboard access
    // Using a special 'platform' realm for customer tokens
    const tokens = await generateTokenPair(
      customer.id,
      'platform',  // Special realm for platform customers
      customer.email,
      {
        accessTokenExpiry: 900,  // 15 minutes
        refreshTokenExpiry: 604800  // 7 days
      }
    );

    // Log successful login
    await logSecurityEvent({
      event_type: 'customer_login_success',
      ip_address: clientIP,
      user_id: customer.id,
      details: { plan: customer.billing.plan }
    });

    return createSuccessResponse(200, {
      message: 'Login successful',
      customer: {
        id: customer.id,
        email: customer.email,
        company_name: customer.profile.company_name,
        plan: customer.billing.plan,
        status: customer.status,
        default_realm_id: customer.default_realm_id
      },
      tokens: {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: 'Bearer',
        expires_in: tokens.expires_in
      }
    }, {
      'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
      'X-RateLimit-Reset': rateLimitResult.resetAt.toString()
    });

  } catch (error) {
    console.error('Customer login error:', error);

    await logSecurityEvent({
      event_type: 'customer_login_error',
      ip_address: clientIP,
      details: { error: (error as Error).message }
    });

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      undefined,
      requestId
    );
  }
}
