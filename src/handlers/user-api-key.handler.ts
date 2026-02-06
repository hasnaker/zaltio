/**
 * User API Key Lambda Handler
 * User-generated API key management endpoints
 * 
 * Validates: Requirements 2.7, 2.9 (User API Key Endpoints)
 * 
 * Endpoints:
 * - POST /api-keys - Create API key
 * - GET /api-keys - List user's API keys
 * - GET /api-keys/{id} - Get API key details
 * - DELETE /api-keys/{id} - Revoke API key
 * - PATCH /api-keys/{id} - Update API key
 * 
 * Security:
 * - User authentication required
 * - Rate limiting on creation
 * - Audit logging for all operations
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { userAPIKeyService, UserAPIKeyError } from '../services/user-api-key.service';
import { checkRateLimit } from '../services/ratelimit.service';

// Rate limit for key creation
const CREATE_RATE_LIMIT = {
  maxRequests: 10,
  windowSeconds: 3600 // 10 keys per hour per user
};

// CORS headers
const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,DELETE,PATCH,OPTIONS',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY'
};

/**
 * Create error response
 */
function errorResponse(
  statusCode: number,
  code: string,
  message: string
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify({
      error: {
        code,
        message,
        timestamp: new Date().toISOString()
      }
    })
  };
}

/**
 * Create success response
 */
function successResponse(
  statusCode: number,
  data: unknown
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify(data)
  };
}

/**
 * Extract user context from JWT token
 */
function getUserContext(event: APIGatewayProxyEvent): { 
  userId: string; 
  realmId: string; 
  tenantId?: string 
} | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  
  // Extract from authorizer context (set by API Gateway)
  const authorizer = event.requestContext?.authorizer;
  if (authorizer) {
    return {
      userId: authorizer.userId as string || '',
      realmId: authorizer.realmId as string || '',
      tenantId: authorizer.tenantId as string | undefined
    };
  }
  
  return null;
}

/**
 * Main handler - routes to appropriate function
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const method = event.httpMethod;
  const path = event.path;
  
  // Handle CORS preflight
  if (method === 'OPTIONS') {
    return successResponse(200, {});
  }
  
  try {
    // Route to appropriate handler
    if (path === '/api-keys' && method === 'POST') {
      return await handleCreateKey(event);
    }
    
    if (path === '/api-keys' && method === 'GET') {
      return await handleListKeys(event);
    }
    
    // Path pattern: /api-keys/{id}
    const keyIdMatch = path.match(/^\/api-keys\/([^/]+)$/);
    if (keyIdMatch) {
      const keyId = keyIdMatch[1];
      
      if (method === 'GET') {
        return await handleGetKey(event, keyId);
      }
      
      if (method === 'DELETE') {
        return await handleRevokeKey(event, keyId);
      }
      
      if (method === 'PATCH') {
        return await handleUpdateKey(event, keyId);
      }
    }
    
    return errorResponse(404, 'NOT_FOUND', 'Endpoint not found');
    
  } catch (error) {
    console.error('Handler error:', error);
    
    if (error instanceof UserAPIKeyError) {
      return errorResponse(error.statusCode, error.code, error.message);
    }
    
    return errorResponse(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
  }
}

/**
 * POST /api-keys - Create a new API key
 */
async function handleCreateKey(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Rate limiting
  const rateLimitResult = await checkRateLimit(
    userContext.realmId,
    `api_key_create:${userContext.userId}`,
    CREATE_RATE_LIMIT
  );
  
  if (!rateLimitResult.allowed) {
    return {
      statusCode: 429,
      headers: {
        ...CORS_HEADERS,
        'Retry-After': String(rateLimitResult.retryAfter || 60)
      },
      body: JSON.stringify({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many API key creation requests',
          retryAfter: rateLimitResult.retryAfter
        }
      })
    };
  }
  
  // Parse request body
  let body: {
    name?: string;
    description?: string;
    scopes?: string[];
    expires_at?: string;
    ip_restrictions?: string[];
  };
  
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // Validate required fields
  if (!body.name) {
    return errorResponse(400, 'MISSING_NAME', 'API key name is required');
  }
  
  // Create the key
  const result = await userAPIKeyService.createKey(
    userContext.userId,
    userContext.realmId,
    {
      name: body.name,
      description: body.description,
      scopes: body.scopes,
      expiresAt: body.expires_at,
      tenantId: userContext.tenantId,
      ipRestrictions: body.ip_restrictions
    }
  );
  
  return successResponse(201, {
    message: 'API key created successfully',
    key: result.key,
    full_key: result.full_key
  });
}

/**
 * GET /api-keys - List user's API keys
 */
async function handleListKeys(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  const keys = await userAPIKeyService.listKeys(userContext.userId);
  
  return successResponse(200, {
    keys,
    count: keys.length
  });
}

/**
 * GET /api-keys/{id} - Get API key details
 */
async function handleGetKey(
  event: APIGatewayProxyEvent,
  keyId: string
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  const key = await userAPIKeyService.getKey(userContext.userId, keyId);
  
  if (!key) {
    return errorResponse(404, 'KEY_NOT_FOUND', 'API key not found');
  }
  
  return successResponse(200, { key });
}

/**
 * DELETE /api-keys/{id} - Revoke API key
 */
async function handleRevokeKey(
  event: APIGatewayProxyEvent,
  keyId: string
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  await userAPIKeyService.revokeKey(userContext.userId, keyId);
  
  return successResponse(200, {
    message: 'API key revoked successfully'
  });
}

/**
 * PATCH /api-keys/{id} - Update API key
 */
async function handleUpdateKey(
  event: APIGatewayProxyEvent,
  keyId: string
): Promise<APIGatewayProxyResult> {
  // Verify user authentication
  const userContext = getUserContext(event);
  if (!userContext || !userContext.userId) {
    return errorResponse(401, 'UNAUTHORIZED', 'Authentication required');
  }
  
  // Parse request body
  let body: {
    name?: string;
    description?: string;
    scopes?: string[];
    expires_at?: string;
    ip_restrictions?: string[];
  };
  
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return errorResponse(400, 'INVALID_JSON', 'Invalid JSON in request body');
  }
  
  // At least one field must be provided
  if (!body.name && !body.description && !body.scopes && !body.expires_at && !body.ip_restrictions) {
    return errorResponse(400, 'NO_UPDATES', 'At least one field must be provided for update');
  }
  
  const updatedKey = await userAPIKeyService.updateKey(
    userContext.userId,
    keyId,
    {
      name: body.name,
      description: body.description,
      scopes: body.scopes,
      expiresAt: body.expires_at,
      ipRestrictions: body.ip_restrictions
    }
  );
  
  return successResponse(200, {
    message: 'API key updated successfully',
    key: updatedKey
  });
}
