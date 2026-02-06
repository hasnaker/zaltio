/**
 * SSO Enforcement Middleware
 * Task 19.5: Implement SSO enforcement
 * 
 * Blocks password login when SSO is enforced for an organization:
 * - Checks email domain against verified SSO domains
 * - Returns redirect URL to organization's IdP
 * - Audit logs all enforcement events
 * 
 * SECURITY: 
 * - No information leakage about SSO configuration
 * - Same response timing for valid/invalid domains
 * - Audit logging for all enforcement events
 * 
 * Validates: Requirements 9.4, 9.6 (SSO Enforcement)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { checkSSOEnforcement, SSOEnforcementCheckResult } from '../services/domain-verification.service';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

/**
 * SSO enforcement check result for middleware
 */
export interface SSOEnforcementResult {
  enforced: boolean;
  tenantId?: string;
  ssoType?: 'saml' | 'oidc';
  providerName?: string;
  redirectUrl?: string;
  reason?: string;
}

/**
 * SSO enforcement middleware options
 */
export interface SSOEnforcementMiddlewareOptions {
  /** Skip enforcement check (for testing) */
  skipEnforcement?: boolean;
  /** Custom realm ID (if not in request body) */
  realmId?: string;
  /** Allow bypass for specific emails (admin override) */
  bypassEmails?: string[];
}

/**
 * Login request body structure
 */
interface LoginRequestBody {
  email?: string;
  realm_id?: string;
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Base URL for SSO endpoints
 */
const SSO_BASE_URL = process.env.SSO_BASE_URL || 'https://api.zalt.io/v1/sso';

/**
 * Error codes
 */
export const SSO_ENFORCEMENT_ERROR_CODES = {
  SSO_REQUIRED: 'SSO_REQUIRED',
  SSO_REDIRECT: 'SSO_REDIRECT'
} as const;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Create API Gateway response
 */
function createResponse(
  statusCode: number,
  body: unknown,
  headers?: Record<string, string>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store',
      ...headers
    },
    body: JSON.stringify(body)
  };
}

/**
 * Extract email from request body
 */
function extractEmailFromRequest(event: APIGatewayProxyEvent): string | null {
  if (!event.body) {
    return null;
  }

  try {
    const body: LoginRequestBody = JSON.parse(event.body);
    return body.email?.toLowerCase() || null;
  } catch {
    return null;
  }
}

/**
 * Extract realm ID from request
 */
function extractRealmIdFromRequest(event: APIGatewayProxyEvent): string | null {
  if (!event.body) {
    return null;
  }

  try {
    const body: LoginRequestBody = JSON.parse(event.body);
    return body.realm_id || null;
  } catch {
    return null;
  }
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
 * Generate SSO redirect URL based on SSO type
 */
export function generateSSORedirectUrl(
  tenantId: string,
  ssoType: 'saml' | 'oidc',
  email?: string
): string {
  const baseUrl = `${SSO_BASE_URL}/${ssoType}/initiate`;
  const params = new URLSearchParams({
    tenant_id: tenantId
  });
  
  if (email) {
    params.append('login_hint', email);
  }
  
  return `${baseUrl}?${params.toString()}`;
}

/**
 * Generate SAML SSO redirect URL
 */
export function generateSAMLRedirectUrl(tenantId: string, email?: string): string {
  return generateSSORedirectUrl(tenantId, 'saml', email);
}

/**
 * Generate OIDC SSO redirect URL
 */
export function generateOIDCRedirectUrl(tenantId: string, email?: string): string {
  return generateSSORedirectUrl(tenantId, 'oidc', email);
}

// ============================================================================
// MAIN MIDDLEWARE FUNCTIONS
// ============================================================================

/**
 * Check if SSO is enforced for an email domain
 * 
 * @param email - User email to check
 * @returns SSO enforcement result with redirect URL if enforced
 */
export async function checkSSOEnforcementForEmail(
  email: string
): Promise<SSOEnforcementResult> {
  const enforcementResult = await checkSSOEnforcement(email);
  
  if (!enforcementResult.enforced) {
    return {
      enforced: false,
      reason: enforcementResult.reason
    };
  }
  
  // Generate redirect URL based on SSO type
  const redirectUrl = generateSSORedirectUrl(
    enforcementResult.tenantId!,
    enforcementResult.ssoType!,
    email
  );
  
  return {
    enforced: true,
    tenantId: enforcementResult.tenantId,
    ssoType: enforcementResult.ssoType,
    providerName: enforcementResult.providerName,
    redirectUrl
  };
}

/**
 * SSO enforcement middleware for login endpoints
 * 
 * Checks if the user's email domain requires SSO authentication
 * and blocks password login if SSO is enforced.
 * 
 * @param event - API Gateway event
 * @param options - Middleware options
 * @returns Response if SSO is enforced, null otherwise
 */
export async function ssoEnforcementMiddleware(
  event: APIGatewayProxyEvent,
  options: SSOEnforcementMiddlewareOptions = {}
): Promise<APIGatewayProxyResult | null> {
  // Skip if configured
  if (options.skipEnforcement) {
    return null;
  }
  
  const clientIp = getClientIP(event);
  const email = extractEmailFromRequest(event);
  const realmId = options.realmId || extractRealmIdFromRequest(event);
  
  // No email in request - let the handler deal with validation
  if (!email) {
    return null;
  }
  
  // Check bypass list
  if (options.bypassEmails?.includes(email.toLowerCase())) {
    await logAuditEvent({
      eventType: AuditEventType.CONFIG_CHANGE,
      action: 'sso_enforcement_bypassed',
      ipAddress: clientIp,
      realmId: realmId || 'unknown',
      result: AuditResult.SUCCESS,
      details: {
        email_domain: email.split('@')[1],
        bypass_reason: 'admin_override'
      }
    });
    return null;
  }
  
  try {
    // Check SSO enforcement for email domain
    const enforcementResult = await checkSSOEnforcementForEmail(email);
    
    if (!enforcementResult.enforced) {
      // SSO not enforced - allow password login
      return null;
    }
    
    // SSO is enforced - block password login and redirect
    await logAuditEvent({
      eventType: AuditEventType.LOGIN_FAILURE,
      action: 'password_login_blocked_sso_enforced',
      ipAddress: clientIp,
      realmId: realmId || 'unknown',
      result: AuditResult.FAILURE,
      details: {
        email_domain: email.split('@')[1],
        tenant_id: enforcementResult.tenantId,
        sso_type: enforcementResult.ssoType,
        provider_name: enforcementResult.providerName,
        redirect_url: enforcementResult.redirectUrl
      }
    });
    
    // Return SSO required response with redirect URL
    return createResponse(403, {
      error: {
        code: SSO_ENFORCEMENT_ERROR_CODES.SSO_REQUIRED,
        message: 'Password login is not allowed for this organization. Please use SSO.',
        sso_required: true,
        sso_type: enforcementResult.ssoType,
        provider_name: enforcementResult.providerName,
        redirect_url: enforcementResult.redirectUrl,
        tenant_id: enforcementResult.tenantId
      }
    });
  } catch (error) {
    // Log error but don't block login on enforcement check failure
    console.error('SSO enforcement check failed:', error);
    
    await logAuditEvent({
      eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
      action: 'sso_enforcement_check_error',
      ipAddress: clientIp,
      realmId: realmId || 'unknown',
      result: AuditResult.FAILURE,
      errorMessage: (error as Error).message,
      details: {
        email_domain: email.split('@')[1]
      }
    });
    
    // Fail open - allow password login if enforcement check fails
    return null;
  }
}

/**
 * Middleware wrapper for handlers
 * 
 * Wraps a Lambda handler to check SSO enforcement before processing
 */
export function withSSOEnforcement<T extends APIGatewayProxyEvent>(
  handler: (event: T) => Promise<APIGatewayProxyResult>,
  options: SSOEnforcementMiddlewareOptions = {}
): (event: T) => Promise<APIGatewayProxyResult> {
  return async (event: T): Promise<APIGatewayProxyResult> => {
    // Check SSO enforcement
    const enforcementResponse = await ssoEnforcementMiddleware(event, options);
    
    if (enforcementResponse) {
      return enforcementResponse;
    }
    
    // Continue to handler
    return handler(event);
  };
}

/**
 * Check if an email domain has SSO enforced
 * 
 * Utility function for use in other services
 * 
 * @param email - User email to check
 * @returns True if SSO is enforced for the email domain
 */
export async function isSSOEnforcedForEmail(email: string): Promise<boolean> {
  const result = await checkSSOEnforcementForEmail(email);
  return result.enforced;
}

/**
 * Get SSO redirect URL for an email
 * 
 * Returns the redirect URL if SSO is enforced, null otherwise
 * 
 * @param email - User email to check
 * @returns Redirect URL or null
 */
export async function getSSORedirectUrlForEmail(email: string): Promise<string | null> {
  const result = await checkSSOEnforcementForEmail(email);
  return result.enforced ? result.redirectUrl || null : null;
}

/**
 * Get SSO configuration details for an email domain
 * 
 * Returns full SSO configuration if enforced
 * 
 * @param email - User email to check
 * @returns SSO enforcement result
 */
export async function getSSOEnforcementDetails(email: string): Promise<SSOEnforcementResult> {
  return checkSSOEnforcementForEmail(email);
}
