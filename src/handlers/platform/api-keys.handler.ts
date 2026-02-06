/**
 * Platform API Keys Lambda Handler
 * 
 * Endpoints:
 * - GET /platform/api-keys - List customer's API keys
 * - POST /platform/api-keys - Create new API key
 * - DELETE /platform/api-keys/{id} - Revoke API key
 * 
 * Validates: Requirements 4.1, 4.2, 4.3, 4.4 (API Key management)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { 
  createAPIKey,
  listAPIKeysByCustomer,
  revokeAPIKey,
  getAPIKeyById
} from '../../repositories/api-key.repository';
import { getCustomerById } from '../../repositories/customer.repository';
import { verifyAccessToken } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
import { APIKeyType, APIKeyEnvironment, APIKeyResponse } from '../../models/api-key.model';

interface CreateAPIKeyRequest {
  realm_id: string;
  type: APIKeyType;
  environment: APIKeyEnvironment;
  name: string;
  description?: string;
  expires_at?: string;
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
  data: unknown
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
    body: JSON.stringify(data)
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         'unknown';
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
 * Authenticate request and return customer ID
 */
async function authenticateRequest(
  event: APIGatewayProxyEvent,
  requestId?: string
): Promise<{ customerId: string } | APIGatewayProxyResult> {
  const token = extractBearerToken(event);
  if (!token) {
    return createErrorResponse(
      401,
      'UNAUTHORIZED',
      'Authorization header with Bearer token is required',
      undefined,
      requestId
    );
  }

  try {
    const payload = await verifyAccessToken(token);
    return { customerId: payload.sub };
  } catch {
    return createErrorResponse(
      401,
      'INVALID_TOKEN',
      'Invalid or expired token',
      undefined,
      requestId
    );
  }
}

/**
 * GET /platform/api-keys - List API keys
 */
async function handleListKeys(
  event: APIGatewayProxyEvent,
  customerId: string,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const keys = await listAPIKeysByCustomer(customerId);
  
  // Return masked keys (no full key or hash)
  const maskedKeys: APIKeyResponse[] = keys.map(key => ({
    id: key.id,
    type: key.type,
    environment: key.environment,
    key_prefix: key.key_prefix,
    key_hint: key.key_hint,
    name: key.name,
    description: key.description,
    status: key.status,
    last_used_at: key.last_used_at,
    usage_count: key.usage_count,
    created_at: key.created_at,
    expires_at: key.expires_at
  }));

  return createSuccessResponse(200, {
    api_keys: maskedKeys,
    total: maskedKeys.length
  });
}

/**
 * POST /platform/api-keys - Create API key
 */
async function handleCreateKey(
  event: APIGatewayProxyEvent,
  customerId: string,
  clientIP: string,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  if (!event.body) {
    return createErrorResponse(
      400,
      'INVALID_REQUEST',
      'Request body is required',
      undefined,
      requestId
    );
  }

  let request: CreateAPIKeyRequest;
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
  if (!request.realm_id || !request.type || !request.environment || !request.name) {
    return createErrorResponse(
      400,
      'MISSING_FIELDS',
      'realm_id, type, environment, and name are required',
      { required: ['realm_id', 'type', 'environment', 'name'] },
      requestId
    );
  }

  // Validate type
  if (!['publishable', 'secret'].includes(request.type)) {
    return createErrorResponse(
      400,
      'INVALID_TYPE',
      'Type must be "publishable" or "secret"',
      { field: 'type' },
      requestId
    );
  }

  // Validate environment
  if (!['live', 'test'].includes(request.environment)) {
    return createErrorResponse(
      400,
      'INVALID_ENVIRONMENT',
      'Environment must be "live" or "test"',
      { field: 'environment' },
      requestId
    );
  }

  // Validate name length
  if (request.name.length < 1 || request.name.length > 100) {
    return createErrorResponse(
      400,
      'INVALID_NAME',
      'Name must be between 1 and 100 characters',
      { field: 'name' },
      requestId
    );
  }

  // Check customer's plan limits
  const customer = await getCustomerById(customerId);
  if (!customer) {
    return createErrorResponse(
      404,
      'CUSTOMER_NOT_FOUND',
      'Customer not found',
      undefined,
      requestId
    );
  }

  // Count existing keys
  const existingKeys = await listAPIKeysByCustomer(customerId);
  const maxKeys = customer.billing.plan === 'enterprise' ? -1 : 
                  customer.billing.plan === 'pro' ? 20 : 5;
  
  if (maxKeys !== -1 && existingKeys.length >= maxKeys) {
    return createErrorResponse(
      403,
      'KEY_LIMIT_EXCEEDED',
      `Your plan allows a maximum of ${maxKeys} API keys`,
      { current: existingKeys.length, limit: maxKeys },
      requestId
    );
  }

  // Create the key
  const newKey = await createAPIKey({
    customer_id: customerId,
    realm_id: request.realm_id,
    type: request.type,
    environment: request.environment,
    name: request.name,
    description: request.description,
    expires_at: request.expires_at
  });

  await logSecurityEvent({
    event_type: 'api_key_created',
    ip_address: clientIP,
    user_id: customerId,
    realm_id: request.realm_id,
    details: { 
      key_id: newKey.id,
      type: request.type,
      environment: request.environment
    }
  });

  return createSuccessResponse(201, {
    message: 'API key created successfully',
    api_key: {
      id: newKey.id,
      type: newKey.type,
      environment: newKey.environment,
      key_prefix: newKey.key_prefix,
      key_hint: newKey.key_hint,
      name: newKey.name,
      description: newKey.description,
      status: newKey.status,
      created_at: newKey.created_at,
      full_key: newKey.full_key
    },
    warning: 'Save your API key now. It will not be shown again.'
  });
}

/**
 * DELETE /platform/api-keys/{id} - Revoke API key
 */
async function handleRevokeKey(
  event: APIGatewayProxyEvent,
  customerId: string,
  clientIP: string,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const keyId = event.pathParameters?.id;
  
  if (!keyId) {
    return createErrorResponse(
      400,
      'MISSING_KEY_ID',
      'API key ID is required',
      undefined,
      requestId
    );
  }

  // Check if key exists and belongs to customer
  const existingKey = await getAPIKeyById(keyId, customerId);
  if (!existingKey) {
    return createErrorResponse(
      404,
      'KEY_NOT_FOUND',
      'API key not found',
      undefined,
      requestId
    );
  }

  if (existingKey.status === 'revoked') {
    return createErrorResponse(
      400,
      'KEY_ALREADY_REVOKED',
      'API key is already revoked',
      undefined,
      requestId
    );
  }

  // Revoke the key
  const revokedKey = await revokeAPIKey(keyId, customerId, customerId, 'User requested revocation');

  await logSecurityEvent({
    event_type: 'api_key_revoked',
    ip_address: clientIP,
    user_id: customerId,
    details: { 
      key_id: keyId,
      type: existingKey.type,
      environment: existingKey.environment
    }
  });

  return createSuccessResponse(200, {
    message: 'API key revoked successfully',
    api_key: {
      id: revokedKey?.id,
      status: revokedKey?.status,
      revoked_at: revokedKey?.revoked_at
    }
  });
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);
  const method = event.httpMethod;

  try {
    // Authenticate request
    const authResult = await authenticateRequest(event, requestId);
    if ('statusCode' in authResult) {
      return authResult; // Return error response
    }
    const { customerId } = authResult;

    // Route to appropriate handler
    switch (method) {
      case 'GET':
        return await handleListKeys(event, customerId, requestId);
      
      case 'POST':
        return await handleCreateKey(event, customerId, clientIP, requestId);
      
      case 'DELETE':
        return await handleRevokeKey(event, customerId, clientIP, requestId);
      
      default:
        return createErrorResponse(
          405,
          'METHOD_NOT_ALLOWED',
          `Method ${method} not allowed`,
          undefined,
          requestId
        );
    }

  } catch (error) {
    console.error('API keys handler error:', error);

    await logSecurityEvent({
      event_type: 'api_keys_error',
      ip_address: clientIP,
      details: { error: (error as Error).message, method }
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
