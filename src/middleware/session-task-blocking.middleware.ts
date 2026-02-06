/**
 * Session Task Blocking Middleware for Zalt.io Auth Platform
 * 
 * Enforces session task completion before allowing API access:
 * - Checks for pending blocking tasks
 * - Returns 403 SESSION_TASK_PENDING if blocked
 * - Allows whitelisted endpoints (task completion, logout, etc.)
 * - Includes X-Session-Task-Pending header in response
 * 
 * Validates: Requirements 4.2 (Session Task Blocking)
 * 
 * SECURITY:
 * - Blocking tasks prevent API access until completed
 * - Audit logging for all blocking checks
 * - No information leakage in error messages
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { SessionTasksService, sessionTasksService, SessionTask } from '../services/session-tasks.service';
import { toSessionTaskResponse, SessionTaskResponse } from '../models/session-task.model';

/**
 * Session task blocking validation result
 */
export interface SessionTaskBlockingResult {
  valid: boolean;
  isBlocked: boolean;
  blockingTasks?: SessionTaskResponse[];
  error?: {
    code: string;
    message: string;
    statusCode: number;
    tasks?: SessionTaskResponse[];
  };
}

/**
 * Middleware options
 */
export interface SessionTaskBlockingMiddlewareOptions {
  /** Skip blocking check */
  skipBlockingCheck?: boolean;
  /** Custom whitelisted endpoints */
  customWhitelist?: WhitelistedEndpoint[];
  /** Service instance (for testing) */
  service?: SessionTasksService;
}

/**
 * Whitelisted endpoint definition
 */
export interface WhitelistedEndpoint {
  /** Endpoint path pattern (supports wildcards with *) */
  endpoint: string;
  /** HTTP method (or '*' for all methods) */
  method: string;
}

/**
 * Default whitelisted endpoints that bypass session task blocking
 * These endpoints are essential for task completion and session management
 */
export const DEFAULT_WHITELISTED_ENDPOINTS: WhitelistedEndpoint[] = [
  // Session task endpoints - must be accessible to complete tasks
  { endpoint: '/session/tasks', method: 'GET' },
  { endpoint: '/session/tasks/*/complete', method: 'POST' },
  { endpoint: '/session/tasks/*/skip', method: 'POST' },
  
  // Authentication endpoints - logout must always work
  { endpoint: '/logout', method: 'POST' },
  { endpoint: '/auth/logout', method: 'POST' },
  { endpoint: '/sessions/current', method: 'DELETE' },
  
  // Password reset endpoints - needed for reset_password task
  { endpoint: '/me/password', method: 'PUT' },
  { endpoint: '/me/password', method: 'POST' },
  { endpoint: '/password/reset', method: 'POST' },
  { endpoint: '/password/change', method: 'POST' },
  
  // MFA setup endpoints - needed for setup_mfa task
  { endpoint: '/mfa/setup', method: 'POST' },
  { endpoint: '/mfa/totp/setup', method: 'POST' },
  { endpoint: '/mfa/webauthn/setup', method: 'POST' },
  { endpoint: '/mfa/verify', method: 'POST' },
  
  // Organization selection endpoints - needed for choose_organization task
  { endpoint: '/organizations/select', method: 'POST' },
  { endpoint: '/organizations/switch', method: 'POST' },
  { endpoint: '/me/organization', method: 'PUT' },
  
  // Terms acceptance endpoints - needed for accept_terms task
  { endpoint: '/terms/accept', method: 'POST' },
  { endpoint: '/me/terms', method: 'POST' },
  
  // Health check and public endpoints
  { endpoint: '/health', method: 'GET' },
  { endpoint: '/health/*', method: 'GET' },
  { endpoint: '/.well-known/*', method: 'GET' },
  
  // Reverification endpoints - may be needed during task completion
  { endpoint: '/reverify/*', method: 'POST' },
  
  // User info endpoint - needed for SDK to understand current state
  { endpoint: '/me', method: 'GET' },
  { endpoint: '/auth/me', method: 'GET' }
];

/**
 * Extract session ID from request
 * Supports multiple sources:
 * - X-Session-Id header
 * - Authorization header (JWT sessionId claim via authorizer)
 * - Cookie (zalt_session)
 */
export function extractSessionId(event: APIGatewayProxyEvent): string | null {
  // Check X-Session-Id header first (preferred)
  const sessionHeader = event.headers?.['X-Session-Id'] || event.headers?.['x-session-id'];
  if (sessionHeader) {
    return sessionHeader;
  }
  
  // Check authorizer context (from JWT validation)
  const authorizer = event.requestContext?.authorizer;
  if (authorizer) {
    // Try sessionId first, then jti (JWT ID which may be session ID)
    const authorizerSessionId = authorizer.sessionId || authorizer.jti;
    if (authorizerSessionId) {
      return authorizerSessionId as string;
    }
  }
  
  // Check cookie
  const cookieHeader = event.headers?.Cookie || event.headers?.cookie;
  if (cookieHeader) {
    const cookies = parseCookies(cookieHeader);
    if (cookies.zalt_session) {
      return cookies.zalt_session;
    }
  }
  
  return null;
}

/**
 * Parse cookies from header
 */
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  
  cookieHeader.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name && rest.length > 0) {
      cookies[name] = rest.join('=');
    }
  });
  
  return cookies;
}

/**
 * Get endpoint path from event
 * Normalizes path for matching against whitelist
 */
export function getEndpointPath(event: APIGatewayProxyEvent): string {
  // Use resource path if available (contains path parameters)
  const path = event.resource || event.path || '';
  
  // Normalize path (remove trailing slash, ensure leading slash)
  let normalized = path.replace(/\/+$/, '');
  if (!normalized.startsWith('/')) {
    normalized = '/' + normalized;
  }
  
  return normalized;
}

/**
 * Check if endpoint matches a pattern
 * Supports wildcards (*) for path segments
 */
export function matchEndpoint(endpoint: string, pattern: string): boolean {
  // Exact match
  if (endpoint === pattern) {
    return true;
  }
  
  // Convert pattern to regex
  // Escape special regex characters except *
  const regexPattern = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '[^/]+');
  
  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(endpoint);
}

/**
 * Check if endpoint is whitelisted
 */
export function isEndpointWhitelisted(
  event: APIGatewayProxyEvent,
  customWhitelist?: WhitelistedEndpoint[]
): boolean {
  const endpoint = getEndpointPath(event);
  const method = event.httpMethod;
  
  // Combine default and custom whitelist
  const whitelist = [...DEFAULT_WHITELISTED_ENDPOINTS, ...(customWhitelist || [])];
  
  for (const entry of whitelist) {
    // Check method match (or wildcard)
    if (entry.method !== '*' && entry.method !== method) {
      continue;
    }
    
    // Check endpoint match
    if (matchEndpoint(endpoint, entry.endpoint)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Validate session task blocking status for a request
 */
export async function validateSessionTaskBlocking(
  event: APIGatewayProxyEvent,
  options: SessionTaskBlockingMiddlewareOptions = {}
): Promise<SessionTaskBlockingResult> {
  // Skip if configured
  if (options.skipBlockingCheck) {
    return { valid: true, isBlocked: false };
  }
  
  // Check if endpoint is whitelisted
  if (isEndpointWhitelisted(event, options.customWhitelist)) {
    return { valid: true, isBlocked: false };
  }
  
  // Extract session ID
  const sessionId = extractSessionId(event);
  
  // No session = no blocking (authentication middleware should handle this)
  if (!sessionId) {
    return { valid: true, isBlocked: false };
  }
  
  // Check for blocking tasks
  const service = options.service || sessionTasksService;
  const hasBlocking = await service.hasBlockingTasks(sessionId);
  
  if (!hasBlocking) {
    return { valid: true, isBlocked: false };
  }
  
  // Get blocking tasks for response
  const blockingTasks = await service.getBlockingTasks(sessionId);
  const taskResponses = blockingTasks.map(toSessionTaskResponse);
  
  // Log the blocking event
  logAuditEvent('session_task.blocked', {
    sessionId,
    endpoint: getEndpointPath(event),
    method: event.httpMethod,
    blockingTaskCount: blockingTasks.length,
    taskTypes: blockingTasks.map(t => t.type),
    ip: getClientIP(event)
  });
  
  return {
    valid: false,
    isBlocked: true,
    blockingTasks: taskResponses,
    error: {
      code: 'SESSION_TASK_PENDING',
      message: 'You have pending tasks that must be completed before accessing this resource',
      statusCode: 403,
      tasks: taskResponses
    }
  };
}

/**
 * Create error response for session task blocking
 */
export function createSessionTaskBlockingErrorResponse(
  error: NonNullable<SessionTaskBlockingResult['error']>,
  requestId?: string
): APIGatewayProxyResult {
  const body: Record<string, unknown> = {
    error: {
      code: error.code,
      message: error.message,
      timestamp: new Date().toISOString(),
      request_id: requestId
    }
  };
  
  // Include task details for SESSION_TASK_PENDING
  if (error.code === 'SESSION_TASK_PENDING' && error.tasks) {
    body.session_tasks = {
      pending: true,
      count: error.tasks.length,
      tasks: error.tasks.map(task => ({
        id: task.id,
        type: task.type,
        priority: task.priority,
        metadata: task.metadata
      })),
      endpoints: {
        list: '/session/tasks',
        complete: '/session/tasks/{id}/complete',
        skip: '/session/tasks/{id}/skip'
      }
    };
  }
  
  return {
    statusCode: error.statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Session-Id',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-Session-Task-Pending': 'true',
      'X-Session-Task-Count': String(error.tasks?.length || 0)
    },
    body: JSON.stringify(body)
  };
}

/**
 * Get client IP from request
 */
function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp ||
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         'unknown';
}

/**
 * Log audit event
 */
function logAuditEvent(
  event: string,
  data: Record<string, unknown>
): void {
  if (process.env.NODE_ENV !== 'test') {
    console.log(`[AUDIT] ${event}`, JSON.stringify({
      ...data,
      timestamp: new Date().toISOString()
    }));
  }
}

/**
 * Session task blocking middleware wrapper
 * Use this to wrap Lambda handlers that should be blocked by pending tasks
 * 
 * Usage:
 * ```typescript
 * export const handler = withSessionTaskBlocking(
 *   async (event) => {
 *     // Handler logic - only runs if no blocking tasks
 *   }
 * );
 * ```
 */
export function withSessionTaskBlocking(
  handler: (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>,
  options: SessionTaskBlockingMiddlewareOptions = {}
): (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult> {
  return async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const validation = await validateSessionTaskBlocking(event, options);
    
    if (!validation.valid) {
      return createSessionTaskBlockingErrorResponse(
        validation.error!,
        event.requestContext?.requestId
      );
    }
    
    // Call the actual handler
    const response = await handler(event);
    
    // Add header to indicate no pending tasks (for SDK)
    if (response.headers) {
      response.headers['X-Session-Task-Pending'] = 'false';
    } else {
      response.headers = { 'X-Session-Task-Pending': 'false' };
    }
    
    return response;
  };
}

/**
 * Middleware for checking session task blocking inline
 * Returns validation result for manual handling
 * 
 * Usage:
 * ```typescript
 * export async function handler(event: APIGatewayProxyEvent) {
 *   const blocking = await sessionTaskBlockingMiddleware(event);
 *   if (!blocking.valid) {
 *     return blocking.response!;
 *   }
 *   
 *   // Continue with handler logic
 * }
 * ```
 */
export async function sessionTaskBlockingMiddleware(
  event: APIGatewayProxyEvent,
  options: SessionTaskBlockingMiddlewareOptions = {}
): Promise<{
  valid: boolean;
  isBlocked: boolean;
  blockingTasks?: SessionTaskResponse[];
  response?: APIGatewayProxyResult;
}> {
  const validation = await validateSessionTaskBlocking(event, options);
  
  if (!validation.valid) {
    return {
      valid: false,
      isBlocked: validation.isBlocked,
      blockingTasks: validation.blockingTasks,
      response: createSessionTaskBlockingErrorResponse(
        validation.error!,
        event.requestContext?.requestId
      )
    };
  }
  
  return {
    valid: true,
    isBlocked: false
  };
}

/**
 * Check if response indicates session task is pending
 * Useful for SDK to detect and handle session tasks
 */
export function isSessionTaskPending(response: APIGatewayProxyResult): boolean {
  return response.statusCode === 403 &&
         response.headers?.['X-Session-Task-Pending'] === 'true';
}

/**
 * Extract session task details from error response
 */
export function extractSessionTaskDetails(response: APIGatewayProxyResult): {
  pending: boolean;
  count: number;
  tasks: Array<{
    id: string;
    type: string;
    priority: number;
    metadata?: Record<string, unknown>;
  }>;
} | null {
  if (!isSessionTaskPending(response)) {
    return null;
  }
  
  try {
    const body = JSON.parse(response.body);
    return body.session_tasks || null;
  } catch {
    return null;
  }
}

/**
 * Add endpoint to whitelist dynamically
 * Useful for custom task completion endpoints
 */
export function addToWhitelist(
  whitelist: WhitelistedEndpoint[],
  endpoint: string,
  method: string = '*'
): WhitelistedEndpoint[] {
  return [...whitelist, { endpoint, method }];
}

/**
 * Create a custom whitelist from an array of endpoint patterns
 */
export function createWhitelist(
  endpoints: Array<{ endpoint: string; method?: string }>
): WhitelistedEndpoint[] {
  return endpoints.map(e => ({
    endpoint: e.endpoint,
    method: e.method || '*'
  }));
}
