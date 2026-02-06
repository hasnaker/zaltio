/**
 * Response Utilities for HSD Auth Platform
 * Validates: Requirements 2.1, 2.4, 5.3
 * 
 * Provides standardized response format and request/response transformation
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { getCORSHeaders, getMinimalCORSHeaders, isPreflightRequest } from '../middleware/cors.middleware';

/**
 * Standard error response structure
 */
export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}

/**
 * Standard success response structure
 */
export interface SuccessResponse<T = unknown> {
  data?: T;
  message?: string;
  meta?: {
    timestamp: string;
    request_id?: string;
  };
}

/**
 * Response headers type
 */
export type ResponseHeaders = Record<string, string>;

/**
 * Create standardized error response with CORS headers
 */
export function createErrorResponse(
  event: APIGatewayProxyEvent,
  statusCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>,
  additionalHeaders?: ResponseHeaders
): APIGatewayProxyResult {
  const requestId = event.requestContext?.requestId;
  const corsHeaders = getMinimalCORSHeaders(event);
  
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
      ...corsHeaders,
      ...additionalHeaders
    },
    body: JSON.stringify(response)
  };
}

/**
 * Create standardized success response with CORS headers
 */
export function createSuccessResponse<T = unknown>(
  event: APIGatewayProxyEvent,
  statusCode: number,
  data?: T,
  message?: string,
  additionalHeaders?: ResponseHeaders
): APIGatewayProxyResult {
  const requestId = event.requestContext?.requestId;
  const corsHeaders = getMinimalCORSHeaders(event);
  
  const response: SuccessResponse<T> = {
    data,
    message,
    meta: {
      timestamp: new Date().toISOString(),
      request_id: requestId
    }
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
      ...additionalHeaders
    },
    body: JSON.stringify(response)
  };
}

/**
 * Create CORS preflight response
 */
export function createPreflightResponse(
  event: APIGatewayProxyEvent
): APIGatewayProxyResult {
  const corsHeaders = getCORSHeaders(event);
  
  return {
    statusCode: 204,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders
    },
    body: ''
  };
}

/**
 * Handle CORS preflight if needed
 * Returns preflight response if it's a preflight request, null otherwise
 */
export function handlePreflight(
  event: APIGatewayProxyEvent
): APIGatewayProxyResult | null {
  if (isPreflightRequest(event)) {
    return createPreflightResponse(event);
  }
  return null;
}

/**
 * Parse JSON request body safely
 */
export function parseRequestBody<T = unknown>(
  event: APIGatewayProxyEvent
): { success: true; data: T } | { success: false; error: string } {
  if (!event.body) {
    return { success: false, error: 'Request body is required' };
  }

  try {
    const data = JSON.parse(event.body) as T;
    return { success: true, data };
  } catch {
    return { success: false, error: 'Invalid JSON in request body' };
  }
}

/**
 * Extract request metadata
 */
export function getRequestMetadata(event: APIGatewayProxyEvent): {
  requestId: string | undefined;
  sourceIp: string;
  userAgent: string;
  origin: string | undefined;
} {
  return {
    requestId: event.requestContext?.requestId,
    sourceIp: event.requestContext?.identity?.sourceIp || 'unknown',
    userAgent: event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown',
    origin: event.headers?.Origin || event.headers?.origin
  };
}
