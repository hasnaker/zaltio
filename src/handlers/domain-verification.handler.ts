/**
 * Domain Verification Lambda Handler - DNS TXT record verification for SSO enforcement
 * 
 * Endpoints:
 * - POST /tenants/{tenantId}/sso/domains - Add domain for verification
 * - GET /tenants/{tenantId}/sso/domains - List all domains
 * - GET /tenants/{tenantId}/sso/domains/{domain} - Get domain status
 * - POST /tenants/{tenantId}/sso/domains/{domain}/verify - Verify domain ownership
 * - DELETE /tenants/{tenantId}/sso/domains/{domain} - Remove domain
 * - POST /tenants/{tenantId}/sso/domains/{domain}/regenerate - Regenerate verification token
 * - POST /tenants/{tenantId}/sso/enforcement/enable - Enable SSO enforcement
 * - POST /tenants/{tenantId}/sso/enforcement/disable - Disable SSO enforcement
 * 
 * Security Requirements:
 * - Admin authentication required
 * - Audit logging for all domain operations
 * - Input validation
 * - Rate limiting
 * 
 * Validates: Requirements 9.5 (Domain verification for SSO enforcement)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  addDomain,
  verifyDomain,
  removeDomain,
  getDomainStatus,
  listDomains,
  regenerateVerificationToken,
  enableSSOEnforcement,
  disableSSOEnforcement,
  validateDomainForTenant,
  getDnsRecordName
} from '../services/domain-verification.service';
import { isValidDomain } from '../models/org-sso.model';

// ============================================================================
// TYPES
// ============================================================================

interface ErrorResponse {
  error: string;
  error_description?: string;
  details?: Record<string, unknown>;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function createErrorResponse(
  statusCode: number,
  error: string,
  errorDescription?: string,
  details?: Record<string, unknown>
): APIGatewayProxyResult {
  const response: ErrorResponse = { error };
  if (errorDescription) {
    response.error_description = errorDescription;
  }
  if (details) {
    response.details = details;
  }

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Cache-Control': 'no-store'
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
      'Cache-Control': 'no-store'
    },
    body: JSON.stringify(data)
  };
}

/**
 * Get client IP from event
 */
function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext.identity?.sourceIp || 
         event.headers['X-Forwarded-For']?.split(',')[0]?.trim() || 
         'unknown';
}

/**
 * Get user ID from authorization context
 * In production, this would be extracted from the JWT token
 */
function getUserId(event: APIGatewayProxyEvent): string | undefined {
  // Extract from authorizer context if available
  const authorizer = event.requestContext.authorizer;
  if (authorizer?.claims?.sub) {
    return authorizer.claims.sub as string;
  }
  if (authorizer?.userId) {
    return authorizer.userId as string;
  }
  return undefined;
}

/**
 * Parse JSON body safely
 */
function parseBody(event: APIGatewayProxyEvent): Record<string, unknown> | null {
  if (!event.body) {
    return null;
  }
  
  try {
    const body = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf-8')
      : event.body;
    return JSON.parse(body);
  } catch {
    return null;
  }
}

// ============================================================================
// HANDLERS
// ============================================================================

/**
 * Add domain for verification
 * POST /tenants/{tenantId}/sso/domains
 * 
 * Body:
 * - domain: string (required) - Domain to add (e.g., "acme.com")
 */
export async function addDomainHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const tenantId = event.pathParameters?.tenantId;
  
  if (!tenantId) {
    return createErrorResponse(400, 'invalid_request', 'Missing tenantId');
  }
  
  const body = parseBody(event);
  if (!body || typeof body.domain !== 'string') {
    return createErrorResponse(400, 'invalid_request', 'Missing or invalid domain in request body');
  }
  
  const domain = body.domain.trim().toLowerCase();
  
  // Validate domain format
  if (!isValidDomain(domain)) {
    return createErrorResponse(400, 'invalid_domain', `Invalid domain format: ${domain}`);
  }
  
  try {
    // Validate domain can be added to this tenant
    const validation = await validateDomainForTenant(domain, tenantId);
    if (!validation.valid) {
      return createErrorResponse(409, 'domain_conflict', validation.error);
    }
    
    const result = await addDomain({
      tenantId,
      domain,
      userId: getUserId(event),
      ipAddress: getClientIP(event)
    });
    
    return createSuccessResponse(201, {
      success: true,
      domain: result,
      instructions: {
        step1: `Add a DNS TXT record to your domain`,
        recordName: result.dnsRecordName,
        recordValue: result.dnsRecordValue,
        step2: `Wait for DNS propagation (may take up to 48 hours)`,
        step3: `Call POST /tenants/${tenantId}/sso/domains/${domain}/verify to complete verification`
      }
    });
  } catch (error) {
    console.error('Add domain error:', error);
    
    if (error instanceof Error) {
      if (error.message.includes('not found')) {
        return createErrorResponse(404, 'not_found', error.message);
      }
      if (error.message.includes('already exists')) {
        return createErrorResponse(409, 'domain_exists', error.message);
      }
    }
    
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to add domain'
    );
  }
}

/**
 * List all domains for a tenant
 * GET /tenants/{tenantId}/sso/domains
 */
export async function listDomainsHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const tenantId = event.pathParameters?.tenantId;
  
  if (!tenantId) {
    return createErrorResponse(400, 'invalid_request', 'Missing tenantId');
  }
  
  try {
    const domains = await listDomains(tenantId);
    
    return createSuccessResponse(200, {
      domains,
      total: domains.length
    });
  } catch (error) {
    console.error('List domains error:', error);
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to list domains'
    );
  }
}

/**
 * Get domain verification status
 * GET /tenants/{tenantId}/sso/domains/{domain}
 */
export async function getDomainStatusHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const tenantId = event.pathParameters?.tenantId;
  const domain = event.pathParameters?.domain;
  
  if (!tenantId || !domain) {
    return createErrorResponse(400, 'invalid_request', 'Missing tenantId or domain');
  }
  
  try {
    const status = await getDomainStatus(tenantId, domain);
    
    if (!status) {
      return createErrorResponse(404, 'not_found', `Domain ${domain} not found`);
    }
    
    return createSuccessResponse(200, status);
  } catch (error) {
    console.error('Get domain status error:', error);
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to get domain status'
    );
  }
}

/**
 * Verify domain ownership
 * POST /tenants/{tenantId}/sso/domains/{domain}/verify
 */
export async function verifyDomainHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const tenantId = event.pathParameters?.tenantId;
  const domain = event.pathParameters?.domain;
  
  if (!tenantId || !domain) {
    return createErrorResponse(400, 'invalid_request', 'Missing tenantId or domain');
  }
  
  try {
    const result = await verifyDomain({
      tenantId,
      domain,
      userId: getUserId(event),
      ipAddress: getClientIP(event)
    });
    
    if (!result.success) {
      return createErrorResponse(400, 'verification_failed', result.error, {
        domain: result.domain,
        status: result.status,
        dnsRecordName: getDnsRecordName(domain),
        hint: 'Ensure the DNS TXT record is properly configured and has propagated'
      });
    }
    
    return createSuccessResponse(200, {
      success: true,
      domain: result.domain,
      status: result.status,
      verifiedAt: result.verifiedAt,
      message: 'Domain verified successfully. You can now enable SSO enforcement.'
    });
  } catch (error) {
    console.error('Verify domain error:', error);
    
    if (error instanceof Error && error.message.includes('not found')) {
      return createErrorResponse(404, 'not_found', error.message);
    }
    
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to verify domain'
    );
  }
}

/**
 * Remove domain from SSO configuration
 * DELETE /tenants/{tenantId}/sso/domains/{domain}
 */
export async function removeDomainHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const tenantId = event.pathParameters?.tenantId;
  const domain = event.pathParameters?.domain;
  
  if (!tenantId || !domain) {
    return createErrorResponse(400, 'invalid_request', 'Missing tenantId or domain');
  }
  
  try {
    await removeDomain({
      tenantId,
      domain,
      userId: getUserId(event),
      ipAddress: getClientIP(event)
    });
    
    return createSuccessResponse(200, {
      success: true,
      message: `Domain ${domain} removed successfully`
    });
  } catch (error) {
    console.error('Remove domain error:', error);
    
    if (error instanceof Error) {
      if (error.message.includes('not found')) {
        return createErrorResponse(404, 'not_found', error.message);
      }
      if (error.message.includes('Cannot remove')) {
        return createErrorResponse(400, 'removal_blocked', error.message);
      }
    }
    
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to remove domain'
    );
  }
}

/**
 * Regenerate verification token for a domain
 * POST /tenants/{tenantId}/sso/domains/{domain}/regenerate
 */
export async function regenerateTokenHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const tenantId = event.pathParameters?.tenantId;
  const domain = event.pathParameters?.domain;
  
  if (!tenantId || !domain) {
    return createErrorResponse(400, 'invalid_request', 'Missing tenantId or domain');
  }
  
  try {
    const result = await regenerateVerificationToken(
      tenantId,
      domain,
      getUserId(event),
      getClientIP(event)
    );
    
    return createSuccessResponse(200, {
      success: true,
      domain: result,
      instructions: {
        step1: `Update your DNS TXT record`,
        recordName: result.dnsRecordName,
        recordValue: result.dnsRecordValue,
        step2: `Wait for DNS propagation`,
        step3: `Call POST /tenants/${tenantId}/sso/domains/${domain}/verify to complete verification`
      }
    });
  } catch (error) {
    console.error('Regenerate token error:', error);
    
    if (error instanceof Error) {
      if (error.message.includes('not found')) {
        return createErrorResponse(404, 'not_found', error.message);
      }
      if (error.message.includes('already verified')) {
        return createErrorResponse(400, 'already_verified', error.message);
      }
    }
    
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to regenerate token'
    );
  }
}

/**
 * Enable SSO enforcement for a tenant
 * POST /tenants/{tenantId}/sso/enforcement/enable
 */
export async function enableEnforcementHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const tenantId = event.pathParameters?.tenantId;
  
  if (!tenantId) {
    return createErrorResponse(400, 'invalid_request', 'Missing tenantId');
  }
  
  try {
    await enableSSOEnforcement(
      tenantId,
      getUserId(event),
      getClientIP(event)
    );
    
    return createSuccessResponse(200, {
      success: true,
      message: 'SSO enforcement enabled. Users with verified domain emails must now use SSO to login.',
      warning: 'Password login is now blocked for users with emails matching verified domains.'
    });
  } catch (error) {
    console.error('Enable enforcement error:', error);
    
    if (error instanceof Error) {
      if (error.message.includes('not found')) {
        return createErrorResponse(404, 'not_found', error.message);
      }
      if (error.message.includes('must be enabled') || error.message.includes('verified domain')) {
        return createErrorResponse(400, 'precondition_failed', error.message);
      }
    }
    
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to enable enforcement'
    );
  }
}

/**
 * Disable SSO enforcement for a tenant
 * POST /tenants/{tenantId}/sso/enforcement/disable
 */
export async function disableEnforcementHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const tenantId = event.pathParameters?.tenantId;
  
  if (!tenantId) {
    return createErrorResponse(400, 'invalid_request', 'Missing tenantId');
  }
  
  try {
    await disableSSOEnforcement(
      tenantId,
      getUserId(event),
      getClientIP(event)
    );
    
    return createSuccessResponse(200, {
      success: true,
      message: 'SSO enforcement disabled. Users can now login with password or SSO.'
    });
  } catch (error) {
    console.error('Disable enforcement error:', error);
    
    if (error instanceof Error && error.message.includes('not found')) {
      return createErrorResponse(404, 'not_found', error.message);
    }
    
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to disable enforcement'
    );
  }
}

// ============================================================================
// MAIN HANDLER ROUTER
// ============================================================================

/**
 * Main handler router for domain verification endpoints
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const path = event.path;
  const method = event.httpMethod;
  
  // Handle CORS preflight
  if (method === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400'
      },
      body: ''
    };
  }
  
  try {
    // POST /tenants/{tenantId}/sso/domains
    if (path.match(/\/tenants\/[^/]+\/sso\/domains$/) && method === 'POST') {
      return addDomainHandler(event);
    }
    
    // GET /tenants/{tenantId}/sso/domains
    if (path.match(/\/tenants\/[^/]+\/sso\/domains$/) && method === 'GET') {
      return listDomainsHandler(event);
    }
    
    // POST /tenants/{tenantId}/sso/domains/{domain}/verify
    if (path.match(/\/tenants\/[^/]+\/sso\/domains\/[^/]+\/verify$/) && method === 'POST') {
      return verifyDomainHandler(event);
    }
    
    // POST /tenants/{tenantId}/sso/domains/{domain}/regenerate
    if (path.match(/\/tenants\/[^/]+\/sso\/domains\/[^/]+\/regenerate$/) && method === 'POST') {
      return regenerateTokenHandler(event);
    }
    
    // GET /tenants/{tenantId}/sso/domains/{domain}
    if (path.match(/\/tenants\/[^/]+\/sso\/domains\/[^/]+$/) && method === 'GET') {
      return getDomainStatusHandler(event);
    }
    
    // DELETE /tenants/{tenantId}/sso/domains/{domain}
    if (path.match(/\/tenants\/[^/]+\/sso\/domains\/[^/]+$/) && method === 'DELETE') {
      return removeDomainHandler(event);
    }
    
    // POST /tenants/{tenantId}/sso/enforcement/enable
    if (path.match(/\/tenants\/[^/]+\/sso\/enforcement\/enable$/) && method === 'POST') {
      return enableEnforcementHandler(event);
    }
    
    // POST /tenants/{tenantId}/sso/enforcement/disable
    if (path.match(/\/tenants\/[^/]+\/sso\/enforcement\/disable$/) && method === 'POST') {
      return disableEnforcementHandler(event);
    }
    
    return createErrorResponse(404, 'not_found', 'Endpoint not found');
  } catch (error) {
    console.error('Domain verification handler error:', error);
    return createErrorResponse(500, 'server_error', 'Internal server error');
  }
}
