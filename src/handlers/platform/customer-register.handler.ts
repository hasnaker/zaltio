/**
 * Platform Customer Registration Lambda Handler
 * POST /platform/register
 * 
 * Creates a new B2B customer account (company using Zalt.io)
 * - Creates customer account
 * - Creates default realm
 * - Generates API keys (pk_live_xxx, sk_live_xxx)
 * - Sends verification email
 * 
 * Validates: Requirements 1.2, 1.3, 1.4 (Customer account system)
 * 
 * SECURITY FEATURES:
 * - Rate limiting: 3 attempts/hour/IP
 * - HaveIBeenPwned password check
 * - Email verification required
 * - Audit logging
 * - Argon2id password hashing
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { 
  createCustomer, 
  getCustomerByEmail,
  setDefaultRealm 
} from '../../repositories/customer.repository';
import { createDefaultAPIKeys } from '../../repositories/api-key.repository';
import { createRealm } from '../../repositories/realm.repository';
import { validateEmail } from '../../utils/validation';
import { checkRateLimit } from '../../services/ratelimit.service';
import { checkPasswordPwned, validatePasswordPolicy } from '../../utils/password';
import { logSecurityEvent } from '../../services/security-logger.service';
import { CustomerPlan } from '../../models/customer.model';
import { DEFAULT_REALM_SETTINGS } from '../../models/realm.model';

// Rate limit configuration for registration
const REGISTER_RATE_LIMIT = {
  maxRequests: 3,
  windowSeconds: 3600 // 1 hour
};

interface CustomerRegisterRequest {
  email: string;
  password: string;
  company_name: string;
  company_website?: string;
  plan?: CustomerPlan;
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

/**
 * Generate URL-safe slug from company name
 */
function generateSlug(companyName: string): string {
  return companyName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 50);
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
      `platform:register:${clientIP}`,
      REGISTER_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'rate_limit_exceeded',
        ip_address: clientIP,
        details: { endpoint: 'platform/register', retry_after: rateLimitResult.retryAfter }
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

    let request: CustomerRegisterRequest;
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
    if (!request.email || !request.password || !request.company_name) {
      return createErrorResponse(
        400,
        'MISSING_FIELDS',
        'Email, password, and company_name are required',
        { required: ['email', 'password', 'company_name'] },
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

    // Validate password against policy
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
    const pwnedCount = await checkPasswordPwned(request.password);
    if (pwnedCount > 0) {
      await logSecurityEvent({
        event_type: 'pwned_password_rejected',
        ip_address: clientIP,
        details: { breach_count: pwnedCount, endpoint: 'platform/register' }
      });

      return createErrorResponse(
        400,
        'PASSWORD_COMPROMISED',
        'This password has been found in data breaches. Please choose a different password.',
        { field: 'password', breach_count: pwnedCount },
        requestId
      );
    }

    // Validate company name
    if (request.company_name.length < 2 || request.company_name.length > 100) {
      return createErrorResponse(
        400,
        'INVALID_COMPANY_NAME',
        'Company name must be between 2 and 100 characters',
        { field: 'company_name' },
        requestId
      );
    }

    // Check if customer already exists
    const existingCustomer = await getCustomerByEmail(request.email);
    if (existingCustomer) {
      await logSecurityEvent({
        event_type: 'duplicate_customer_registration',
        ip_address: clientIP,
        details: { email_hash: request.email.substring(0, 3) + '***' }
      });

      return createErrorResponse(
        409,
        'CUSTOMER_EXISTS',
        'An account with this email already exists',
        { field: 'email' },
        requestId
      );
    }

    // Create customer account
    const customer = await createCustomer({
      email: request.email,
      password: request.password,
      company_name: request.company_name,
      company_website: request.company_website,
      plan: request.plan
    });

    // Create default realm for customer
    const realmSlug = generateSlug(request.company_name);
    const realm = await createRealm({
      name: request.company_name,
      domain: `${realmSlug}.zalt.io`,
      settings: {
        ...DEFAULT_REALM_SETTINGS,
        branding: {
          display_name: request.company_name
        }
      }
    });

    // Update customer with default realm
    await setDefaultRealm(customer.id, realm.id);

    // Generate API keys for the realm
    const { publishableKey, secretKey } = await createDefaultAPIKeys(
      customer.id,
      realm.id
    );

    // Log successful registration
    await logSecurityEvent({
      event_type: 'customer_registered',
      ip_address: clientIP,
      user_id: customer.id,
      realm_id: realm.id,
      details: { 
        company_name: request.company_name,
        plan: customer.billing.plan
      }
    });

    // Return success with API keys (only time secret key is shown)
    return createSuccessResponse(201, {
      message: 'Account created successfully. Please verify your email to activate your account.',
      customer: {
        id: customer.id,
        email: customer.email,
        company_name: customer.profile.company_name,
        plan: customer.billing.plan,
        status: customer.status,
        created_at: customer.created_at
      },
      realm: {
        id: realm.id,
        name: realm.name,
        domain: realm.domain
      },
      api_keys: {
        publishable_key: publishableKey.full_key,
        secret_key: secretKey.full_key,
        warning: 'Save your secret key now. It will not be shown again.'
      }
    }, {
      'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
      'X-RateLimit-Reset': rateLimitResult.resetAt.toString()
    });

  } catch (error) {
    console.error('Customer registration error:', error);

    await logSecurityEvent({
      event_type: 'customer_registration_error',
      ip_address: clientIP,
      details: { error: (error as Error).message }
    });

    // Handle DynamoDB conditional check failure (duplicate key)
    if ((error as Error).name === 'ConditionalCheckFailedException') {
      return createErrorResponse(
        409,
        'CUSTOMER_EXISTS',
        'An account with this email already exists',
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
