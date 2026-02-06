/**
 * Machine Authentication Lambda Handler
 * M2M (Machine-to-Machine) authentication endpoints
 * 
 * Validates: Requirements 1.7, 1.8 (M2M Authentication)
 * 
 * Endpoints:
 * - POST /machines - Create machine
 * - POST /machines/token - Get M2M token
 * - GET /machines - List machines
 * - GET /machines/{id} - Get machine details
 * - DELETE /machines/{id} - Delete machine
 * - POST /machines/{id}/rotate - Rotate credentials
 * 
 * Security:
 * - Admin authentication required for management endpoints
 * - Rate limiting on token endpoint
 * - Audit logging for all operations
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { MachineAuthService, MachineAuthError } from '../services/machine-auth.service';
import { checkRateLimit } from '../services/ratelimit.service';

const machineAuthService = new MachineAuthService();

// Rate limit for token endpoint
const TOKEN_RATE_LIMIT = {
  maxRequests: 100,
  windowSeconds: 60 // 100 requests per minute per client_id
};

// CORS headers
const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
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
 * Extract admin context from JWT token
 */
function getAdminContext(event: APIGatewayProxyEvent): { adminId: string; realmId: string } | null {
  // In production, this would decode and verify the JWT
  // For now, extract from headers or authorizer context
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  
  // Mock admin context for development
  // In production, decode JWT and verify admin role
  const authorizer = event.requestContext?.authorizer;
  if (authorizer) {
    return {
      adminId: authorizer.userId as string || 'admin_unknown',
      realmId: authorizer.realmId as string || ''
    };
  }
  
  return null;
}

/**
 * Get client IP for rate limiting
 */
function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp ||
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         'unknown';
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
    if (path === '/machines/token' && method === 'POST') {
      return await handleGetToken(event);
    }
    
    if (path === '/machines' && method === 'POST') {
      return await handleCreateMachine(event);
    }
    
    if (path === '/machines' && method === 'GET') {
      return await handleListMachines(event);
    }
    
    // Path pattern: /machines/{id}
    const machineIdMatch = path.match(/^\/machines\/([^/]+)$/);
    if (machineIdMatch) {
      const machineId = machineIdMatch[1];
      
      if (method === 'GET') {
        return await handleGetMachine(event, machineId);
      }
      
      if (method === 'DELETE') {
        return await handleDeleteMachine(event, machineId);
      }
    }
    
    // Path pattern: /machines/{id}/rotate
    const rotateMatch = path.match(/^\/machines\/([^/]+)\/rotate$/);
    if (rotateMatch && method === 'POST') {
      const machineId = rotateMatch[1];
      return await handleRotateCredentials(event, machineId);
    }
    
    return errorResponse(404, 'NOT_FOUND', 'Endpoint not found');
    
  } catch (error) {
    console.error('Machine handler error:', error);
    
    if (error instanceof MachineAuthError) {
      const statusCode = getStatusCodeForError(error.code);
      return errorResponse(statusCode, error.code, error.message);
    }
    
    return errorResponse(500, 'INTERNAL_ERROR', 'An unexpected error occurred');
  }
}

/**
 * POST /machines/token - Get M2M token
 * OAuth 2.0 Client Credentials Grant
 */
async function handleGetToken(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Parse request body (supports both JSON and form-urlencoded)
  let clientId: string;
  let clientSecret: string;
  let scope: string | undefined;
  
  const contentType = event.headers?.['Content-Type'] || event.headers?.['content-type'] || '';
  
  if (contentType.includes('application/x-www-form-urlencoded')) {
    // Parse form data
    const params = new URLSearchParams(event.body || '');
    const grantType = params.get('grant_type');
    
    if (grantType !== 'client_credentials') {
      return errorResponse(400, 'UNSUPPORTED_GRANT_TYPE', 'Only client_credentials grant type is supported');
    }
    
    clientId = params.get('client_id') || '';
    clientSecret = params.get('client_secret') || '';
    scope = params.get('scope') || undefined;
  } else {
    // Parse JSON
    const body = JSON.parse(event.body || '{}');
    clientId = body.client_id || '';
    clientSecret = body.client_secret || '';
    scope = body.scope;
  }
  
  if (!clientId || !clientSecret) {
    return errorResponse(400, 'INVALID_REQUEST', 'client_id and client_secret are required');
  }
  
  // Rate limiting
  const rateLimitKey = `m2m_token:${clientId}`;
  const rateLimitResult = await checkRateLimit('global', rateLimitKey);
  
  if (!rateLimitResult.allowed) {
    return {
      statusCode: 429,
      headers: {
        ...CORS_HEADERS,
        'Retry-After': String(rateLimitResult.retryAfter || 60)
      },
      body: JSON.stringify({
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many token requests',
          retry_after: rateLimitResult.retryAfter
        }
      })
    };
  }
  
  // Parse scopes if provided
  const scopes = scope ? scope.split(' ').filter(s => s) : undefined;
  
  // Authenticate and get token
  const result = await machineAuthService.authenticateMachine({
    client_id: clientId,
    client_secret: clientSecret,
    scopes
  });
  
  return successResponse(200, result);
}

/**
 * POST /machines - Create machine
 */
async function handleCreateMachine(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Require admin authentication
  const adminContext = getAdminContext(event);
  if (!adminContext) {
    return errorResponse(401, 'UNAUTHORIZED', 'Admin authentication required');
  }
  
  const body = JSON.parse(event.body || '{}');
  
  // Validate required fields
  if (!body.realm_id) {
    return errorResponse(400, 'VALIDATION_ERROR', 'realm_id is required');
  }
  
  if (!body.name) {
    return errorResponse(400, 'VALIDATION_ERROR', 'name is required');
  }
  
  if (!body.scopes || !Array.isArray(body.scopes) || body.scopes.length === 0) {
    return errorResponse(400, 'VALIDATION_ERROR', 'scopes array is required');
  }
  
  // Create machine
  const result = await machineAuthService.createMachine({
    realm_id: body.realm_id,
    name: body.name,
    description: body.description,
    scopes: body.scopes,
    allowed_targets: body.allowed_targets,
    rate_limit: body.rate_limit,
    allowed_ips: body.allowed_ips,
    created_by: adminContext.adminId
  });
  
  return successResponse(201, {
    message: 'Machine created successfully',
    machine: result.machine,
    client_secret: result.client_secret
  });
}

/**
 * GET /machines - List machines
 */
async function handleListMachines(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // Require admin authentication
  const adminContext = getAdminContext(event);
  if (!adminContext) {
    return errorResponse(401, 'UNAUTHORIZED', 'Admin authentication required');
  }
  
  const realmId = event.queryStringParameters?.realm_id || adminContext.realmId;
  
  if (!realmId) {
    return errorResponse(400, 'VALIDATION_ERROR', 'realm_id is required');
  }
  
  const machines = await machineAuthService.listMachines(realmId);
  
  return successResponse(200, {
    machines
  });
}

/**
 * GET /machines/{id} - Get machine details
 */
async function handleGetMachine(
  event: APIGatewayProxyEvent,
  machineId: string
): Promise<APIGatewayProxyResult> {
  // Require admin authentication
  const adminContext = getAdminContext(event);
  if (!adminContext) {
    return errorResponse(401, 'UNAUTHORIZED', 'Admin authentication required');
  }
  
  const realmId = event.queryStringParameters?.realm_id || adminContext.realmId;
  
  if (!realmId) {
    return errorResponse(400, 'VALIDATION_ERROR', 'realm_id is required');
  }
  
  const machine = await machineAuthService.getMachine(realmId, machineId);
  
  if (!machine) {
    return errorResponse(404, 'NOT_FOUND', 'Machine not found');
  }
  
  // Return machine without sensitive data
  const { client_secret_hash, ...machineResponse } = machine;
  
  return successResponse(200, {
    machine: machineResponse
  });
}

/**
 * DELETE /machines/{id} - Delete machine
 */
async function handleDeleteMachine(
  event: APIGatewayProxyEvent,
  machineId: string
): Promise<APIGatewayProxyResult> {
  // Require admin authentication
  const adminContext = getAdminContext(event);
  if (!adminContext) {
    return errorResponse(401, 'UNAUTHORIZED', 'Admin authentication required');
  }
  
  const realmId = event.queryStringParameters?.realm_id || adminContext.realmId;
  
  if (!realmId) {
    return errorResponse(400, 'VALIDATION_ERROR', 'realm_id is required');
  }
  
  const deleted = await machineAuthService.deleteMachine(
    realmId,
    machineId,
    adminContext.adminId
  );
  
  if (!deleted) {
    return errorResponse(404, 'NOT_FOUND', 'Machine not found');
  }
  
  return successResponse(200, {
    message: 'Machine deleted successfully'
  });
}

/**
 * POST /machines/{id}/rotate - Rotate credentials
 */
async function handleRotateCredentials(
  event: APIGatewayProxyEvent,
  machineId: string
): Promise<APIGatewayProxyResult> {
  // Require admin authentication
  const adminContext = getAdminContext(event);
  if (!adminContext) {
    return errorResponse(401, 'UNAUTHORIZED', 'Admin authentication required');
  }
  
  const realmId = event.queryStringParameters?.realm_id || adminContext.realmId;
  
  if (!realmId) {
    return errorResponse(400, 'VALIDATION_ERROR', 'realm_id is required');
  }
  
  const result = await machineAuthService.rotateCredentials(
    realmId,
    machineId,
    adminContext.adminId
  );
  
  return successResponse(200, {
    message: 'Credentials rotated successfully',
    client_id: result.clientId,
    client_secret: result.clientSecret
  });
}

/**
 * Map error codes to HTTP status codes
 */
function getStatusCodeForError(code: string): number {
  const statusMap: Record<string, number> = {
    'INVALID_CLIENT_ID': 400,
    'INVALID_CREDENTIALS': 401,
    'INVALID_SCOPES': 400,
    'SCOPE_NOT_ALLOWED': 403,
    'TOKEN_EXPIRED': 401,
    'INVALID_TOKEN': 401,
    'INVALID_TOKEN_TYPE': 401,
    'MACHINE_NOT_FOUND': 404
  };
  
  return statusMap[code] || 500;
}
