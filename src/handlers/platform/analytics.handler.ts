/**
 * Platform Analytics Lambda Handler
 * GET /platform/analytics
 * GET /platform/analytics/dau
 * GET /platform/analytics/logins
 * GET /platform/analytics/mfa
 * 
 * Returns analytics data for dashboard charts
 * 
 * Validates: Requirements 9.1, 9.2, 9.3
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
import {
  getDailyActiveUsersChart,
  getLoginMetricsChart,
  getMFAAdoptionChart,
  getFullAnalyticsSummary,
} from '../../services/analytics.service';

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
      'Cache-Control': 'private, max-age=60', // Cache for 1 minute
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
 * Validate date format (YYYY-MM-DD)
 */
function isValidDate(dateStr: string): boolean {
  const regex = /^\d{4}-\d{2}-\d{2}$/;
  if (!regex.test(dateStr)) return false;
  const date = new Date(dateStr);
  return !isNaN(date.getTime());
}

/**
 * Main analytics handler - routes to specific endpoints
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);
  const path = event.path || event.resource || '';

  try {
    // Extract and validate token
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

    // Verify JWT token
    let payload;
    try {
      payload = await verifyAccessToken(token);
    } catch (error) {
      await logSecurityEvent({
        event_type: 'invalid_token',
        ip_address: clientIP,
        details: { error: (error as Error).message },
      });

      return createErrorResponse(
        401,
        'INVALID_TOKEN',
        'Invalid or expired token',
        undefined,
        requestId
      );
    }

    const customerId = payload.sub;

    // Get query parameters
    const startDate = event.queryStringParameters?.start_date;
    const endDate = event.queryStringParameters?.end_date;
    const realmId = event.queryStringParameters?.realm_id;

    // Validate dates if provided
    if (startDate && !isValidDate(startDate)) {
      return createErrorResponse(
        400,
        'INVALID_DATE',
        'Invalid start_date format. Use YYYY-MM-DD',
        undefined,
        requestId
      );
    }

    if (endDate && !isValidDate(endDate)) {
      return createErrorResponse(
        400,
        'INVALID_DATE',
        'Invalid end_date format. Use YYYY-MM-DD',
        undefined,
        requestId
      );
    }

    // Route to specific endpoint
    if (path.endsWith('/dau')) {
      return handleDAURequest(customerId, startDate, endDate, realmId, requestId);
    }

    if (path.endsWith('/logins')) {
      return handleLoginsRequest(customerId, startDate, endDate, realmId, requestId);
    }

    if (path.endsWith('/mfa')) {
      return handleMFARequest(customerId, realmId, requestId);
    }

    // Default: return full analytics summary
    return handleSummaryRequest(customerId, startDate, endDate, realmId, requestId);

  } catch (error) {
    console.error('Analytics handler error:', error);

    await logSecurityEvent({
      event_type: 'analytics_handler_error',
      ip_address: clientIP,
      details: { error: (error as Error).message },
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

/**
 * Handle DAU chart request
 * GET /platform/analytics/dau
 */
async function handleDAURequest(
  customerId: string,
  startDate?: string,
  endDate?: string,
  realmId?: string,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const result = await getDailyActiveUsersChart(customerId, startDate, endDate, realmId);

  if (!result.success) {
    return createErrorResponse(
      400,
      'ANALYTICS_ERROR',
      result.error || 'Failed to get DAU data',
      undefined,
      requestId
    );
  }

  return createSuccessResponse(200, {
    chart_type: 'daily_active_users',
    data: result.data,
    period: {
      start: startDate || result.data?.[0]?.date,
      end: endDate || result.data?.[result.data.length - 1]?.date,
    },
  });
}

/**
 * Handle login metrics request
 * GET /platform/analytics/logins
 */
async function handleLoginsRequest(
  customerId: string,
  startDate?: string,
  endDate?: string,
  realmId?: string,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const result = await getLoginMetricsChart(customerId, startDate, endDate, realmId);

  if (!result.success) {
    return createErrorResponse(
      400,
      'ANALYTICS_ERROR',
      result.error || 'Failed to get login metrics',
      undefined,
      requestId
    );
  }

  // Calculate summary stats
  const data = result.data || [];
  const totalSuccess = data.reduce((sum, d) => sum + d.success_count, 0);
  const totalFailure = data.reduce((sum, d) => sum + d.failure_count, 0);
  const totalLogins = totalSuccess + totalFailure;

  return createSuccessResponse(200, {
    chart_type: 'login_metrics',
    data: result.data,
    summary: {
      total_logins: totalLogins,
      total_success: totalSuccess,
      total_failure: totalFailure,
      overall_success_rate: totalLogins > 0 
        ? Math.round((totalSuccess / totalLogins) * 10000) / 100 
        : 0,
    },
    period: {
      start: startDate || data[0]?.date,
      end: endDate || data[data.length - 1]?.date,
    },
  });
}

/**
 * Handle MFA adoption request
 * GET /platform/analytics/mfa
 */
async function handleMFARequest(
  customerId: string,
  realmId?: string,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const result = await getMFAAdoptionChart(customerId, realmId);

  if (!result.success) {
    return createErrorResponse(
      400,
      'ANALYTICS_ERROR',
      result.error || 'Failed to get MFA metrics',
      undefined,
      requestId
    );
  }

  return createSuccessResponse(200, {
    chart_type: 'mfa_adoption',
    data: result.data,
  });
}

/**
 * Handle full analytics summary request
 * GET /platform/analytics
 */
async function handleSummaryRequest(
  customerId: string,
  startDate?: string,
  endDate?: string,
  realmId?: string,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const result = await getFullAnalyticsSummary(customerId, startDate, endDate, realmId);

  if (!result.success) {
    return createErrorResponse(
      400,
      'ANALYTICS_ERROR',
      result.error || 'Failed to get analytics summary',
      undefined,
      requestId
    );
  }

  return createSuccessResponse(200, result.data);
}
