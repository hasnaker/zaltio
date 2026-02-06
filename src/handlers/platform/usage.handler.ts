/**
 * Platform Usage Lambda Handler
 * GET /platform/usage
 * 
 * Returns customer's usage statistics and limits
 * 
 * Validates: Requirements 7.1, 7.2, 7.3
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../../utils/jwt';
import { logSecurityEvent } from '../../services/security-logger.service';
import {
  getUsageSummary,
  getCustomerUsageHistory,
  checkAllLimits,
} from '../../services/usage.service';

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
      'Cache-Control': 'no-store, no-cache, must-revalidate',
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

/**
 * Extract Bearer token from Authorization header
 */
function extractBearerToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }

  return parts[1];
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

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
    const includeHistory = event.queryStringParameters?.history === 'true';
    const historyMonths = parseInt(event.queryStringParameters?.months || '6', 10);

    // Get current usage summary
    const summary = await getUsageSummary(customerId);

    if (!summary) {
      return createErrorResponse(
        404,
        'CUSTOMER_NOT_FOUND',
        'Customer account not found',
        undefined,
        requestId
      );
    }

    // Check all limits
    const limitStatus = await checkAllLimits(customerId);

    // Build response
    const response: Record<string, unknown> = {
      usage: {
        mau: summary.mau,
        api_calls: summary.api_calls,
        realms: summary.realms,
      },
      limits: summary.limits,
      percentages: {
        mau: Math.round(summary.mau_percentage * 100) / 100,
        api_calls: Math.round(summary.api_calls_percentage * 100) / 100,
        realms: Math.round(summary.realms_percentage * 100) / 100,
      },
      warnings: limitStatus.warnings,
      period: {
        start: new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString(),
        end: new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0).toISOString(),
      },
    };

    // Include history if requested
    if (includeHistory) {
      const history = await getCustomerUsageHistory(customerId, historyMonths);
      response.history = history.map((record) => ({
        period: record.period.replace('MONTH#', ''),
        mau: record.mau,
        api_calls: record.api_calls,
        realms: record.realms_count,
        logins: record.logins_count,
        registrations: record.registrations_count,
      }));
    }

    return createSuccessResponse(200, response);
  } catch (error) {
    console.error('Usage handler error:', error);

    await logSecurityEvent({
      event_type: 'usage_handler_error',
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
