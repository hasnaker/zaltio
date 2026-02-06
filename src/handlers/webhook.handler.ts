/**
 * Webhook Handler - API endpoints for webhook management
 * 
 * Endpoints:
 * - POST /webhooks - Create webhook
 * - GET /webhooks - List webhooks
 * - GET /webhooks/{id} - Get webhook
 * - DELETE /webhooks/{id} - Delete webhook
 * - POST /webhooks/{id}/test - Test webhook
 * - GET /webhooks/{id}/deliveries - Get delivery logs
 * - POST /webhooks/{id}/rotate-secret - Rotate secret
 * 
 * Validates: Requirements 12.6, 12.7, 12.9
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { WebhookService, WebhookServiceError, WebhookErrorCode } from '../services/webhook.service';
import { WebhookEventType } from '../models/webhook.model';
import { createSuccessResponse, createErrorResponse } from '../utils/response';
import { checkRateLimit, RateLimitEndpoint } from '../services/ratelimit.service';

const webhookService = new WebhookService();

/**
 * Extract realm ID from request (from JWT or header)
 */
function getRealmId(event: APIGatewayProxyEvent): string {
  // From JWT claims or header
  const claims = event.requestContext.authorizer?.claims;
  if (claims?.realm_id) return claims.realm_id;
  
  const header = event.headers['x-realm-id'] || event.headers['X-Realm-Id'];
  if (header) return header;
  
  throw new Error('Realm ID not found');
}

/**
 * Extract user ID from request
 */
function getUserId(event: APIGatewayProxyEvent): string | undefined {
  const claims = event.requestContext.authorizer?.claims;
  return claims?.sub || claims?.user_id;
}

/**
 * POST /webhooks - Create a new webhook
 */
async function createWebhook(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const realmId = getRealmId(event);
  const userId = getUserId(event);
  
  if (!event.body) {
    return createErrorResponse(event, 400, 'MISSING_BODY', 'Request body is required');
  }

  const body = JSON.parse(event.body);
  const { url, events, description } = body;

  if (!url || !events || !Array.isArray(events)) {
    return createErrorResponse(event, 400, 'INVALID_INPUT', 'url and events are required');
  }

  const result = await webhookService.create({
    realm_id: realmId,
    url,
    events: events as WebhookEventType[],
    description,
    created_by: userId
  });

  return createSuccessResponse(event, 201, {
    webhook: {
      id: result.webhook.id,
      url: result.webhook.url,
      events: result.webhook.events,
      status: result.webhook.status,
      description: result.webhook.description,
      created_at: result.webhook.created_at
    },
    secret: result.secret // Only returned on creation
  });
}

/**
 * GET /webhooks - List webhooks
 */
async function listWebhooks(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const realmId = getRealmId(event);
  const status = event.queryStringParameters?.status as 'active' | 'inactive' | undefined;
  const limit = parseInt(event.queryStringParameters?.limit || '50', 10);
  const cursor = event.queryStringParameters?.cursor;

  const result = await webhookService.list(realmId, { status, limit, cursor });

  return createSuccessResponse(event, 200, {
    webhooks: result.webhooks,
    next_cursor: result.next_cursor
  });
}

/**
 * GET /webhooks/{id} - Get webhook by ID
 */
async function getWebhook(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const realmId = getRealmId(event);
  const webhookId = event.pathParameters?.id;

  if (!webhookId) {
    return createErrorResponse(event, 400, 'MISSING_ID', 'Webhook ID is required');
  }

  const webhook = await webhookService.getById(realmId, webhookId);

  if (!webhook) {
    return createErrorResponse(event, 404, 'NOT_FOUND', 'Webhook not found');
  }

  return createSuccessResponse(event, 200, { webhook });
}

/**
 * DELETE /webhooks/{id} - Delete webhook
 */
async function deleteWebhook(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const realmId = getRealmId(event);
  const webhookId = event.pathParameters?.id;
  const userId = getUserId(event);

  if (!webhookId) {
    return createErrorResponse(event, 400, 'MISSING_ID', 'Webhook ID is required');
  }

  const deleted = await webhookService.delete(realmId, webhookId, userId);

  if (!deleted) {
    return createErrorResponse(event, 404, 'NOT_FOUND', 'Webhook not found');
  }

  return createSuccessResponse(event, 200, { deleted: true });
}

/**
 * POST /webhooks/{id}/test - Test webhook
 */
async function testWebhook(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const realmId = getRealmId(event);
  const webhookId = event.pathParameters?.id;
  const userId = getUserId(event);

  if (!webhookId) {
    return createErrorResponse(event, 400, 'MISSING_ID', 'Webhook ID is required');
  }

  const delivery = await webhookService.test({
    webhook_id: webhookId,
    realm_id: realmId,
    tested_by: userId
  });

  return createSuccessResponse(event, 200, { delivery });
}

/**
 * GET /webhooks/{id}/deliveries - Get delivery logs
 */
async function getDeliveryLogs(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const realmId = getRealmId(event);
  const webhookId = event.pathParameters?.id;
  const limit = parseInt(event.queryStringParameters?.limit || '100', 10);
  const cursor = event.queryStringParameters?.cursor;

  if (!webhookId) {
    return createErrorResponse(event, 400, 'MISSING_ID', 'Webhook ID is required');
  }

  const result = await webhookService.getDeliveryLogs({
    webhook_id: webhookId,
    realm_id: realmId,
    limit,
    cursor
  });

  return createSuccessResponse(event, 200, {
    deliveries: result.deliveries,
    next_cursor: result.next_cursor
  });
}

/**
 * POST /webhooks/{id}/rotate-secret - Rotate webhook secret
 */
async function rotateSecret(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const realmId = getRealmId(event);
  const webhookId = event.pathParameters?.id;
  const userId = getUserId(event);

  if (!webhookId) {
    return createErrorResponse(event, 400, 'MISSING_ID', 'Webhook ID is required');
  }

  const result = await webhookService.rotateSecret({
    webhook_id: webhookId,
    realm_id: realmId,
    rotated_by: userId
  });

  return createSuccessResponse(event, 200, {
    webhook_id: result.webhook.id,
    secret: result.secret // New secret
  });
}

/**
 * Main handler - routes requests to appropriate function
 */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    // Rate limiting
    const ip = event.requestContext.identity?.sourceIp || 'unknown';
    let realmId: string;
    try {
      realmId = getRealmId(event);
    } catch {
      return createErrorResponse(event, 401, 'UNAUTHORIZED', 'Authentication required');
    }
    
    const rateLimitResult = await checkRateLimit(realmId, `${RateLimitEndpoint.API_GENERAL}:${ip}`);
    
    if (!rateLimitResult.allowed) {
      return createErrorResponse(event, 429, 'RATE_LIMITED', 'Too many requests', {
        retry_after: rateLimitResult.retryAfter
      });
    }

    const method = event.httpMethod;
    const path = event.resource;
    const hasId = path.includes('{id}');

    // Route to appropriate handler
    if (method === 'POST' && path === '/webhooks') {
      return await createWebhook(event);
    }
    if (method === 'GET' && path === '/webhooks') {
      return await listWebhooks(event);
    }
    if (method === 'GET' && hasId && !path.includes('/deliveries')) {
      return await getWebhook(event);
    }
    if (method === 'DELETE' && hasId) {
      return await deleteWebhook(event);
    }
    if (method === 'POST' && path.includes('/test')) {
      return await testWebhook(event);
    }
    if (method === 'GET' && path.includes('/deliveries')) {
      return await getDeliveryLogs(event);
    }
    if (method === 'POST' && path.includes('/rotate-secret')) {
      return await rotateSecret(event);
    }

    return createErrorResponse(event, 404, 'NOT_FOUND', 'Endpoint not found');
  } catch (error) {
    console.error('Webhook handler error:', error);

    if (error instanceof WebhookServiceError) {
      const statusMap: Record<WebhookErrorCode, number> = {
        [WebhookErrorCode.INVALID_URL]: 400,
        [WebhookErrorCode.INVALID_EVENT]: 400,
        [WebhookErrorCode.WEBHOOK_NOT_FOUND]: 404,
        [WebhookErrorCode.WEBHOOK_DISABLED]: 400,
        [WebhookErrorCode.MAX_WEBHOOKS_EXCEEDED]: 400,
        [WebhookErrorCode.DISPATCH_FAILED]: 500,
        [WebhookErrorCode.INVALID_SIGNATURE]: 401,
        [WebhookErrorCode.SIGNATURE_EXPIRED]: 401
      };
      return createErrorResponse(event, statusMap[error.code] || 500, error.code, error.message);
    }

    return createErrorResponse(event, 500, 'INTERNAL_ERROR', 'An unexpected error occurred');
  }
}
