/**
 * Platform Billing Lambda Handler
 * Handles Stripe checkout, portal, and billing operations
 * 
 * Endpoints:
 * - GET /platform/billing - Get billing info
 * - POST /platform/billing/checkout - Create checkout session
 * - POST /platform/billing/portal - Create portal session
 * 
 * Validates: Requirements 8.1, 8.2, 8.3, 8.4
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import Stripe from 'stripe';
import { verifyAccessToken } from '../../utils/jwt';
import { getCustomerById, updateCustomerBilling } from '../../repositories/customer.repository';
import { logSecurityEvent } from '../../services/security-logger.service';

// Initialize Stripe
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2025-02-24.acacia' as Stripe.LatestApiVersion })
  : null;

// Price IDs from environment
const PRICE_IDS = {
  pro: process.env.STRIPE_PRICE_PRO || '',
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE || '',
};

// Plan limits
const PLAN_LIMITS = {
  free: { max_mau: 1000, max_api_calls: 10000, max_realms: 1 },
  pro: { max_mau: 10000, max_api_calls: 100000, max_realms: 5 },
  enterprise: { max_mau: 100000, max_api_calls: 1000000, max_realms: 50 },
};

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
    },
    body: JSON.stringify(response),
  };
}

function createSuccessResponse(
  statusCode: number,
  data: unknown
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
    body: JSON.stringify(data),
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return (
    event.requestContext?.identity?.sourceIp ||
    event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
    'unknown'
  );
}

function extractBearerToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }

  return parts[1];
}

/**
 * GET /platform/billing - Get billing info
 */
export async function getBillingHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    const token = extractBearerToken(event);
    if (!token) {
      return createErrorResponse(401, 'UNAUTHORIZED', 'Authorization required', undefined, requestId);
    }

    const payload = await verifyAccessToken(token);
    const customer = await getCustomerById(payload.sub);

    if (!customer) {
      return createErrorResponse(404, 'NOT_FOUND', 'Customer not found', undefined, requestId);
    }

    // Get Stripe subscription if exists
    let subscription: Stripe.Subscription | null = null;
    if (stripe && customer.billing.stripe_subscription_id) {
      try {
        subscription = await stripe.subscriptions.retrieve(customer.billing.stripe_subscription_id);
      } catch {
        // Subscription may have been deleted
      }
    }

    // Get period end from subscription
    const periodEnd = subscription 
      ? new Date((subscription as unknown as { current_period_end: number }).current_period_end * 1000).toISOString()
      : customer.billing.plan_expires_at;

    return createSuccessResponse(200, {
      plan: customer.billing.plan,
      status: subscription?.status || 'active',
      current_period_end: periodEnd,
      stripe_customer_id: customer.billing.stripe_customer_id,
      limits: customer.usage_limits || PLAN_LIMITS[customer.billing.plan as keyof typeof PLAN_LIMITS],
    });
  } catch (error) {
    console.error('Get billing error:', error);
    await logSecurityEvent({
      event_type: 'billing_error',
      ip_address: clientIP,
      details: { error: (error as Error).message },
    });
    return createErrorResponse(500, 'INTERNAL_ERROR', 'An error occurred', undefined, requestId);
  }
}

/**
 * POST /platform/billing/checkout - Create checkout session
 */
export async function createCheckoutHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    if (!stripe) {
      return createErrorResponse(503, 'SERVICE_UNAVAILABLE', 'Billing not configured', undefined, requestId);
    }

    const token = extractBearerToken(event);
    if (!token) {
      return createErrorResponse(401, 'UNAUTHORIZED', 'Authorization required', undefined, requestId);
    }

    const payload = await verifyAccessToken(token);
    const customer = await getCustomerById(payload.sub);

    if (!customer) {
      return createErrorResponse(404, 'NOT_FOUND', 'Customer not found', undefined, requestId);
    }

    // Parse request body
    if (!event.body) {
      return createErrorResponse(400, 'INVALID_REQUEST', 'Request body required', undefined, requestId);
    }

    const body = JSON.parse(event.body);
    const { plan, success_url, cancel_url } = body;

    if (!plan || !['pro', 'enterprise'].includes(plan)) {
      return createErrorResponse(400, 'INVALID_PLAN', 'Invalid plan specified', undefined, requestId);
    }

    if (!success_url || !cancel_url) {
      return createErrorResponse(400, 'MISSING_URLS', 'success_url and cancel_url required', undefined, requestId);
    }

    const priceId = PRICE_IDS[plan as keyof typeof PRICE_IDS];
    if (!priceId) {
      return createErrorResponse(503, 'PRICE_NOT_CONFIGURED', 'Price not configured for this plan', undefined, requestId);
    }

    // Get or create Stripe customer
    let stripeCustomerId = customer.billing.stripe_customer_id;
    if (!stripeCustomerId) {
      const stripeCustomer = await stripe.customers.create({
        email: customer.email,
        name: customer.profile.company_name,
        metadata: {
          zalt_customer_id: customer.id,
        },
      });
      stripeCustomerId = stripeCustomer.id;

      // Update customer with Stripe ID
      await updateCustomerBilling(customer.id, {
        stripe_customer_id: stripeCustomerId,
      });
    }

    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: stripeCustomerId,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url,
      cancel_url,
      metadata: {
        zalt_customer_id: customer.id,
        plan,
      },
      subscription_data: {
        metadata: {
          zalt_customer_id: customer.id,
          plan,
        },
      },
    });

    await logSecurityEvent({
      event_type: 'checkout_created',
      ip_address: clientIP,
      user_id: customer.id,
      details: { plan, session_id: session.id },
    });

    return createSuccessResponse(200, {
      checkout_url: session.url,
      session_id: session.id,
    });
  } catch (error) {
    console.error('Create checkout error:', error);
    await logSecurityEvent({
      event_type: 'checkout_error',
      ip_address: clientIP,
      details: { error: (error as Error).message },
    });
    return createErrorResponse(500, 'INTERNAL_ERROR', 'An error occurred', undefined, requestId);
  }
}

/**
 * POST /platform/billing/portal - Create portal session
 */
export async function createPortalHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    if (!stripe) {
      return createErrorResponse(503, 'SERVICE_UNAVAILABLE', 'Billing not configured', undefined, requestId);
    }

    const token = extractBearerToken(event);
    if (!token) {
      return createErrorResponse(401, 'UNAUTHORIZED', 'Authorization required', undefined, requestId);
    }

    const payload = await verifyAccessToken(token);
    const customer = await getCustomerById(payload.sub);

    if (!customer) {
      return createErrorResponse(404, 'NOT_FOUND', 'Customer not found', undefined, requestId);
    }

    if (!customer.billing.stripe_customer_id) {
      return createErrorResponse(400, 'NO_SUBSCRIPTION', 'No active subscription', undefined, requestId);
    }

    // Parse request body
    if (!event.body) {
      return createErrorResponse(400, 'INVALID_REQUEST', 'Request body required', undefined, requestId);
    }

    const body = JSON.parse(event.body);
    const { return_url } = body;

    if (!return_url) {
      return createErrorResponse(400, 'MISSING_URL', 'return_url required', undefined, requestId);
    }

    // Create portal session
    const session = await stripe.billingPortal.sessions.create({
      customer: customer.billing.stripe_customer_id,
      return_url,
    });

    await logSecurityEvent({
      event_type: 'portal_accessed',
      ip_address: clientIP,
      user_id: customer.id,
      details: { session_id: session.id },
    });

    return createSuccessResponse(200, {
      portal_url: session.url,
    });
  } catch (error) {
    console.error('Create portal error:', error);
    await logSecurityEvent({
      event_type: 'portal_error',
      ip_address: clientIP,
      details: { error: (error as Error).message },
    });
    return createErrorResponse(500, 'INTERNAL_ERROR', 'An error occurred', undefined, requestId);
  }
}

/**
 * Main handler - routes to appropriate function
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const path = event.path || event.resource;
  const method = event.httpMethod;

  if (method === 'GET' && path === '/platform/billing') {
    return getBillingHandler(event);
  }

  if (method === 'POST' && path === '/platform/billing/checkout') {
    return createCheckoutHandler(event);
  }

  if (method === 'POST' && path === '/platform/billing/portal') {
    return createPortalHandler(event);
  }

  return createErrorResponse(404, 'NOT_FOUND', 'Endpoint not found');
}
