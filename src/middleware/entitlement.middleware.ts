/**
 * Entitlement Enforcement Middleware
 * 
 * Checks feature access on protected endpoints based on tenant's subscription plan.
 * Returns 403 PLAN_LIMIT_EXCEEDED if feature not available or limit exceeded.
 * 
 * Security Requirements:
 * - Validate tenant has active subscription
 * - Check feature access against plan
 * - Track usage for usage-based billing
 * - Audit logging for access denials
 * 
 * Validates: Requirements 7.6 (Entitlement Enforcement)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { billingService, EntitlementResult, BillingServiceError, BillingErrorCode } from '../services/billing.service';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';

// ============================================================================
// Types
// ============================================================================

/**
 * Entitlement configuration for an endpoint
 */
export interface EntitlementConfig {
  /** Required feature for this endpoint */
  feature?: string;
  /** Required limit key (e.g., 'users', 'api_calls') */
  limitKey?: string;
  /** Current usage getter function */
  getUsage?: (tenantId: string) => Promise<number>;
  /** Whether to skip entitlement check (for public endpoints) */
  skip?: boolean;
}

/**
 * Entitlement check result
 */
export interface EntitlementCheckResult {
  allowed: boolean;
  reason?: string;
  feature?: string;
  limit?: number;
  currentUsage?: number;
  upgradeRequired?: boolean;
}

/**
 * Handler function type
 */
export type HandlerFunction = (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>;

// ============================================================================
// Error Response
// ============================================================================

/**
 * Create entitlement error response
 */
function createEntitlementErrorResponse(
  result: EntitlementCheckResult,
  requestId?: string
): APIGatewayProxyResult {
  const errorCode = result.limit !== undefined ? 'PLAN_LIMIT_EXCEEDED' : 'FEATURE_NOT_AVAILABLE';
  
  return {
    statusCode: 403,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
    body: JSON.stringify({
      error: {
        code: errorCode,
        message: result.reason || 'Access denied based on your current plan',
        details: {
          feature: result.feature,
          limit: result.limit,
          current_usage: result.currentUsage,
          upgrade_required: result.upgradeRequired
        },
        timestamp: new Date().toISOString(),
        request_id: requestId
      }
    })
  };
}

// ============================================================================
// Middleware Functions
// ============================================================================

/**
 * Extract tenant ID from event
 * Looks in authorizer context, path parameters, or query string
 */
export function extractTenantId(event: APIGatewayProxyEvent): string | null {
  // From Lambda authorizer context
  const authContext = event.requestContext?.authorizer;
  if (authContext?.tenantId) {
    return authContext.tenantId as string;
  }
  if (authContext?.tenant_id) {
    return authContext.tenant_id as string;
  }
  
  // From path parameters
  if (event.pathParameters?.tenantId) {
    return event.pathParameters.tenantId;
  }
  if (event.pathParameters?.tenant_id) {
    return event.pathParameters.tenant_id;
  }
  
  // From query string
  if (event.queryStringParameters?.tenantId) {
    return event.queryStringParameters.tenantId;
  }
  if (event.queryStringParameters?.tenant_id) {
    return event.queryStringParameters.tenant_id;
  }
  
  // From request body (for POST/PUT)
  if (event.body) {
    try {
      const body = JSON.parse(event.body);
      if (body.tenantId || body.tenant_id) {
        return body.tenantId || body.tenant_id;
      }
    } catch {
      // Ignore parse errors
    }
  }
  
  return null;
}

/**
 * Check feature entitlement for a tenant
 */
export async function checkFeatureEntitlement(
  tenantId: string,
  feature: string
): Promise<EntitlementCheckResult> {
  try {
    const result = await billingService.checkEntitlementDetailed(tenantId, feature);
    
    return {
      allowed: result.has_access,
      reason: result.reason,
      feature,
      upgradeRequired: result.upgrade_required
    };
  } catch (error) {
    if (error instanceof BillingServiceError) {
      return {
        allowed: false,
        reason: error.message,
        feature,
        upgradeRequired: error.code === BillingErrorCode.NO_ACTIVE_SUBSCRIPTION
      };
    }
    throw error;
  }
}

/**
 * Check limit entitlement for a tenant
 */
export async function checkLimitEntitlement(
  tenantId: string,
  limitKey: string,
  currentUsage: number
): Promise<EntitlementCheckResult> {
  try {
    const result = await billingService.checkLimit(tenantId, limitKey, currentUsage);
    
    return {
      allowed: result.has_access,
      reason: result.reason,
      limit: result.limit,
      currentUsage: result.current_usage,
      upgradeRequired: result.upgrade_required
    };
  } catch (error) {
    if (error instanceof BillingServiceError) {
      return {
        allowed: false,
        reason: error.message,
        upgradeRequired: error.code === BillingErrorCode.NO_ACTIVE_SUBSCRIPTION
      };
    }
    throw error;
  }
}

/**
 * Entitlement enforcement middleware
 * 
 * Wraps a handler function to check entitlements before execution.
 * 
 * @param handler - The handler function to wrap
 * @param config - Entitlement configuration
 * @returns Wrapped handler function
 * 
 * @example
 * ```typescript
 * // Require 'sso' feature
 * export const handler = withEntitlement(myHandler, { feature: 'sso' });
 * 
 * // Require 'users' limit check
 * export const handler = withEntitlement(myHandler, {
 *   limitKey: 'users',
 *   getUsage: async (tenantId) => getUserCount(tenantId)
 * });
 * ```
 */
export function withEntitlement(
  handler: HandlerFunction,
  config: EntitlementConfig
): HandlerFunction {
  return async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const requestId = event.requestContext?.requestId;
    
    // Skip if configured
    if (config.skip) {
      return handler(event);
    }
    
    // Extract tenant ID
    const tenantId = extractTenantId(event);
    if (!tenantId) {
      return {
        statusCode: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
          error: {
            code: 'TENANT_ID_REQUIRED',
            message: 'Tenant ID is required for this endpoint',
            timestamp: new Date().toISOString(),
            request_id: requestId
          }
        })
      };
    }
    
    // Check feature entitlement
    if (config.feature) {
      const result = await checkFeatureEntitlement(tenantId, config.feature);
      
      if (!result.allowed) {
        // Audit log the denial
        await logEntitlementDenial(tenantId, 'feature', config.feature, result, event);
        return createEntitlementErrorResponse(result, requestId);
      }
    }
    
    // Check limit entitlement
    if (config.limitKey && config.getUsage) {
      const currentUsage = await config.getUsage(tenantId);
      const result = await checkLimitEntitlement(tenantId, config.limitKey, currentUsage);
      
      if (!result.allowed) {
        // Audit log the denial
        await logEntitlementDenial(tenantId, 'limit', config.limitKey, result, event);
        return createEntitlementErrorResponse(result, requestId);
      }
    }
    
    // Entitlement check passed, execute handler
    return handler(event);
  };
}

/**
 * Create entitlement middleware for specific feature
 */
export function requireFeature(feature: string): (handler: HandlerFunction) => HandlerFunction {
  return (handler: HandlerFunction) => withEntitlement(handler, { feature });
}

/**
 * Create entitlement middleware for specific limit
 */
export function requireLimit(
  limitKey: string,
  getUsage: (tenantId: string) => Promise<number>
): (handler: HandlerFunction) => HandlerFunction {
  return (handler: HandlerFunction) => withEntitlement(handler, { limitKey, getUsage });
}

// ============================================================================
// Audit Logging
// ============================================================================

/**
 * Log entitlement denial for audit
 */
async function logEntitlementDenial(
  tenantId: string,
  checkType: 'feature' | 'limit',
  checkKey: string,
  result: EntitlementCheckResult,
  event: APIGatewayProxyEvent
): Promise<void> {
  try {
    await logAuditEvent({
      eventType: AuditEventType.RATE_LIMIT_EXCEEDED, // Using rate limit as closest match for entitlement denial
      result: AuditResult.FAILURE,
      realmId: 'system',
      userId: tenantId,
      ipAddress: event.requestContext?.identity?.sourceIp || 'unknown',
      action: 'entitlement_check',
      resource: `${checkType}:${checkKey}`,
      details: {
        tenant_id: tenantId,
        check_type: checkType,
        check_key: checkKey,
        reason: result.reason,
        limit: result.limit,
        current_usage: result.currentUsage,
        upgrade_required: result.upgradeRequired,
        endpoint: event.path,
        method: event.httpMethod
      }
    });
  } catch (error) {
    // Log but don't fail the request
    console.error('Failed to log entitlement denial:', error);
  }
}

// ============================================================================
// Endpoint Configuration
// ============================================================================

/**
 * Default entitlement configurations for common endpoints
 */
export const ENDPOINT_ENTITLEMENTS: Record<string, EntitlementConfig> = {
  // SSO endpoints require 'sso' feature
  '/sso/*': { feature: 'sso' },
  '/saml/*': { feature: 'sso' },
  
  // API key endpoints require 'api_keys' feature
  '/api-keys/*': { feature: 'api_keys' },
  
  // Webhook endpoints require 'webhooks' feature
  '/webhooks/*': { feature: 'webhooks' },
  
  // Advanced MFA requires 'advanced_mfa' feature
  '/mfa/webauthn/*': { feature: 'advanced_mfa' },
  
  // Audit logs require 'audit_logs' feature
  '/audit/*': { feature: 'audit_logs' },
  
  // SCIM provisioning requires 'scim' feature
  '/scim/*': { feature: 'scim' }
};

/**
 * Get entitlement config for an endpoint
 */
export function getEndpointEntitlement(path: string): EntitlementConfig | null {
  for (const [pattern, config] of Object.entries(ENDPOINT_ENTITLEMENTS)) {
    const regex = new RegExp('^' + pattern.replace('*', '.*') + '$');
    if (regex.test(path)) {
      return config;
    }
  }
  return null;
}

/**
 * Auto-apply entitlement middleware based on endpoint
 */
export function withAutoEntitlement(handler: HandlerFunction): HandlerFunction {
  return async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const config = getEndpointEntitlement(event.path || '');
    
    if (config) {
      return withEntitlement(handler, config)(event);
    }
    
    return handler(event);
  };
}
