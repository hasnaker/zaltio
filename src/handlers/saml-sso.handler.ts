/**
 * SAML SSO Lambda Handler - SAML 2.0 SSO endpoints for organization-level SSO
 * 
 * Endpoints:
 * - GET /sso/saml/{realmId}/{tenantId}/login - Initiate SAML SSO
 * - POST /sso/saml/{realmId}/{tenantId}/acs - Assertion Consumer Service
 * - GET /sso/saml/{realmId}/{tenantId}/metadata - SP metadata
 * - POST /sso/saml/{realmId}/{tenantId}/slo - Single Logout
 * 
 * Security Requirements:
 * - Validate SAML response signature
 * - Validate assertion signature
 * - Check NotBefore/NotOnOrAfter conditions
 * - Validate Audience restriction
 * - Prevent replay attacks (check InResponseTo)
 * - Audit logging for all SSO events
 * 
 * Validates: Requirements 9.2 (SAML 2.0 per organization)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as crypto from 'crypto';
import {
  initiateSAMLSSO,
  processSAMLResponse,
  generateTenantSPMetadata,
  generateLogoutRequest,
  ExtractedUserAttributes
} from '../services/saml.service';
import { getSSOConfig, recordSSOLogin } from '../repositories/org-sso.repository';
import { findUserByEmail, createUser } from '../repositories/user.repository';
import { createSession } from '../repositories/session.repository';
import { findRealmById } from '../repositories/realm.repository';
import { generateTokenPair } from '../utils/jwt';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';

// ============================================================================
// TYPES
// ============================================================================

interface ErrorResponse {
  error: string;
  error_description?: string;
}

interface SAMLLoginSuccessResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'Bearer';
  expires_in: number;
  user: {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
  };
  sso: {
    provider: string;
    sessionIndex?: string;
  };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function createErrorResponse(
  statusCode: number,
  error: string,
  errorDescription?: string
): APIGatewayProxyResult {
  const response: ErrorResponse = { error };
  if (errorDescription) {
    response.error_description = errorDescription;
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
  data: unknown,
  additionalHeaders?: Record<string, string>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Cache-Control': 'no-store',
      ...additionalHeaders
    },
    body: JSON.stringify(data)
  };
}

function createRedirectResponse(
  location: string,
  statusCode: number = 302
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      Location: location,
      'Cache-Control': 'no-store'
    },
    body: ''
  };
}

function createXmlResponse(
  xml: string,
  statusCode: number = 200
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/xml',
      'Cache-Control': 'public, max-age=86400'
    },
    body: xml
  };
}

/**
 * Extract path parameters from event
 */
function getPathParams(event: APIGatewayProxyEvent): { realmId: string; tenantId: string } | null {
  const realmId = event.pathParameters?.realmId;
  const tenantId = event.pathParameters?.tenantId;
  
  if (!realmId || !tenantId) {
    return null;
  }
  
  return { realmId, tenantId };
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
 * Get user agent from event
 */
function getUserAgent(event: APIGatewayProxyEvent): string {
  return event.headers['User-Agent'] || event.headers['user-agent'] || 'unknown';
}

// ============================================================================
// HANDLERS
// ============================================================================

/**
 * Initiate SAML SSO - SP-initiated flow
 * GET /sso/saml/{realmId}/{tenantId}/login
 * 
 * Query Parameters:
 * - redirect_uri: URL to redirect after successful login
 * - force_authn: Force re-authentication at IdP
 */
export async function loginHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const params = getPathParams(event);
  if (!params) {
    return createErrorResponse(400, 'invalid_request', 'Missing realmId or tenantId');
  }
  
  const { realmId, tenantId } = params;
  const queryParams = event.queryStringParameters || {};
  
  try {
    // Get SSO configuration
    const ssoConfig = await getSSOConfig(tenantId);
    
    if (!ssoConfig) {
      return createErrorResponse(404, 'not_found', 'SSO not configured for this organization');
    }
    
    if (ssoConfig.realmId !== realmId) {
      return createErrorResponse(400, 'invalid_request', 'Realm mismatch');
    }
    
    if (ssoConfig.ssoType !== 'saml') {
      return createErrorResponse(400, 'invalid_request', 'SSO type is not SAML');
    }
    
    if (!ssoConfig.enabled) {
      return createErrorResponse(403, 'sso_disabled', 'SSO is not enabled for this organization');
    }
    
    // Build RelayState with redirect URI
    const relayState = queryParams.redirect_uri 
      ? Buffer.from(JSON.stringify({ redirect_uri: queryParams.redirect_uri })).toString('base64')
      : undefined;
    
    // Initiate SAML SSO
    const { redirectUrl } = await initiateSAMLSSO(ssoConfig, {
      forceAuthn: queryParams.force_authn === 'true',
      relayState
    });
    
    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.OAUTH_LOGIN,
      result: AuditResult.PENDING,
      realmId,
      ipAddress: getClientIP(event),
      userAgent: getUserAgent(event),
      action: 'SAML SSO initiated',
      details: {
        tenantId,
        provider: ssoConfig.providerName,
        ssoType: 'saml'
      }
    });
    
    return createRedirectResponse(redirectUrl);
  } catch (error) {
    console.error('SAML login error:', error);
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to initiate SSO'
    );
  }
}

/**
 * Assertion Consumer Service - Process SAML Response
 * POST /sso/saml/{realmId}/{tenantId}/acs
 * 
 * Body (form-urlencoded):
 * - SAMLResponse: Base64 encoded SAML Response
 * - RelayState: Optional state from login request
 */
export async function acsHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const params = getPathParams(event);
  if (!params) {
    return createErrorResponse(400, 'invalid_request', 'Missing realmId or tenantId');
  }
  
  const { realmId, tenantId } = params;
  
  if (!event.body) {
    return createErrorResponse(400, 'invalid_request', 'Missing request body');
  }
  
  try {
    // Parse form data
    const formData = new URLSearchParams(
      event.isBase64Encoded 
        ? Buffer.from(event.body, 'base64').toString('utf-8')
        : event.body
    );
    
    const samlResponse = formData.get('SAMLResponse');
    const relayState = formData.get('RelayState');
    
    if (!samlResponse) {
      return createErrorResponse(400, 'invalid_request', 'Missing SAMLResponse');
    }
    
    // Get SSO configuration
    const ssoConfig = await getSSOConfig(tenantId);
    
    if (!ssoConfig) {
      return createErrorResponse(404, 'not_found', 'SSO not configured for this organization');
    }
    
    if (ssoConfig.realmId !== realmId) {
      return createErrorResponse(400, 'invalid_request', 'Realm mismatch');
    }
    
    // Process SAML Response
    const result = await processSAMLResponse(ssoConfig, samlResponse);
    
    if (!result.success || !result.user) {
      // Audit log failure
      await logAuditEvent({
        eventType: AuditEventType.OAUTH_LOGIN,
        result: AuditResult.FAILURE,
        realmId,
        ipAddress: getClientIP(event),
        userAgent: getUserAgent(event),
        action: 'SAML SSO authentication failed',
        errorMessage: result.error,
        details: {
          tenantId,
          provider: ssoConfig.providerName
        }
      });
      
      return createErrorResponse(401, 'authentication_failed', result.error);
    }
    
    // Find or create user
    const userResult = await findOrCreateSSOUser(
      realmId,
      tenantId,
      result.user,
      ssoConfig
    );
    
    if (!userResult.success || !userResult.user) {
      return createErrorResponse(500, 'user_creation_failed', userResult.error);
    }
    
    // Create session with proper parameters
    const sessionInput = {
      user_id: userResult.user.id,
      realm_id: realmId,
      ip_address: getClientIP(event),
      user_agent: getUserAgent(event)
    };
    
    // Generate tokens first
    const tokens = await generateTokenPair(
      userResult.user.id,
      realmId,
      userResult.user.email
    );
    
    // Create session with tokens
    await createSession(
      sessionInput,
      tokens.access_token,
      tokens.refresh_token
    );
    
    // Record SSO login
    await recordSSOLogin(tenantId);
    
    // Audit log success
    await logAuditEvent({
      eventType: AuditEventType.OAUTH_LOGIN,
      result: AuditResult.SUCCESS,
      realmId,
      userId: userResult.user.id,
      userEmail: userResult.user.email,
      ipAddress: getClientIP(event),
      userAgent: getUserAgent(event),
      action: 'SAML SSO authentication successful',
      details: {
        tenantId,
        provider: ssoConfig.providerName,
        ssoType: 'saml',
        jitProvisioned: userResult.created
      }
    });
    
    // Parse RelayState for redirect URI
    let redirectUri: string | undefined;
    if (relayState) {
      try {
        const stateData = JSON.parse(Buffer.from(relayState, 'base64').toString('utf-8'));
        redirectUri = stateData.redirect_uri;
      } catch {
        // Invalid RelayState, ignore
      }
    }
    
    // If redirect URI provided, redirect with tokens
    if (redirectUri) {
      const redirectUrl = new URL(redirectUri);
      redirectUrl.searchParams.set('access_token', tokens.access_token);
      redirectUrl.searchParams.set('token_type', 'Bearer');
      redirectUrl.searchParams.set('expires_in', '900');
      
      return createRedirectResponse(redirectUrl.toString());
    }
    
    // Otherwise return JSON response
    const response: SAMLLoginSuccessResponse = {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      token_type: 'Bearer',
      expires_in: 900,
      user: {
        id: userResult.user.id,
        email: userResult.user.email,
        firstName: result.user.firstName,
        lastName: result.user.lastName
      },
      sso: {
        provider: ssoConfig.providerName,
        sessionIndex: result.sessionIndex
      }
    };
    
    return createSuccessResponse(200, response);
  } catch (error) {
    console.error('SAML ACS error:', error);
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to process SAML response'
    );
  }
}

/**
 * SP Metadata endpoint
 * GET /sso/saml/{realmId}/{tenantId}/metadata
 */
export async function metadataHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const params = getPathParams(event);
  if (!params) {
    return createErrorResponse(400, 'invalid_request', 'Missing realmId or tenantId');
  }
  
  const { realmId, tenantId } = params;
  
  try {
    // Get realm for organization name
    const realm = await findRealmById(realmId);
    
    // Generate SP metadata
    const metadata = generateTenantSPMetadata(realmId, tenantId, {
      organizationName: realm?.name || 'Zalt.io'
    });
    
    return createXmlResponse(metadata);
  } catch (error) {
    console.error('SAML metadata error:', error);
    return createErrorResponse(
      500,
      'server_error',
      'Failed to generate SP metadata'
    );
  }
}

/**
 * Single Logout endpoint
 * POST /sso/saml/{realmId}/{tenantId}/slo
 * 
 * Handles both SP-initiated and IdP-initiated logout
 */
export async function sloHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const params = getPathParams(event);
  if (!params) {
    return createErrorResponse(400, 'invalid_request', 'Missing realmId or tenantId');
  }
  
  const { realmId, tenantId } = params;
  
  try {
    // Get SSO configuration
    const ssoConfig = await getSSOConfig(tenantId);
    
    if (!ssoConfig) {
      return createErrorResponse(404, 'not_found', 'SSO not configured');
    }
    
    // Parse request body
    let samlRequest: string | null = null;
    let samlResponse: string | null = null;
    
    if (event.body) {
      const formData = new URLSearchParams(
        event.isBase64Encoded 
          ? Buffer.from(event.body, 'base64').toString('utf-8')
          : event.body
      );
      
      samlRequest = formData.get('SAMLRequest');
      samlResponse = formData.get('SAMLResponse');
    }
    
    // Handle IdP-initiated logout (SAMLRequest from IdP)
    if (samlRequest) {
      // TODO: Parse and validate LogoutRequest from IdP
      // For now, just acknowledge the logout
      
      await logAuditEvent({
        eventType: AuditEventType.LOGOUT,
        result: AuditResult.SUCCESS,
        realmId,
        ipAddress: getClientIP(event),
        userAgent: getUserAgent(event),
        action: 'SAML SSO IdP-initiated logout',
        details: {
          tenantId,
          provider: ssoConfig.providerName
        }
      });
      
      // Return LogoutResponse
      return createSuccessResponse(200, {
        success: true,
        message: 'Logout processed'
      });
    }
    
    // Handle SP-initiated logout response (SAMLResponse from IdP)
    if (samlResponse) {
      // TODO: Validate LogoutResponse from IdP
      
      await logAuditEvent({
        eventType: AuditEventType.LOGOUT,
        result: AuditResult.SUCCESS,
        realmId,
        ipAddress: getClientIP(event),
        userAgent: getUserAgent(event),
        action: 'SAML SSO logout completed',
        details: {
          tenantId,
          provider: ssoConfig.providerName
        }
      });
      
      return createSuccessResponse(200, {
        success: true,
        message: 'Logout completed'
      });
    }
    
    return createErrorResponse(400, 'invalid_request', 'Missing SAMLRequest or SAMLResponse');
  } catch (error) {
    console.error('SAML SLO error:', error);
    return createErrorResponse(
      500,
      'server_error',
      'Failed to process logout'
    );
  }
}

/**
 * Initiate SP-initiated logout
 * GET /sso/saml/{realmId}/{tenantId}/logout
 */
export async function logoutHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const params = getPathParams(event);
  if (!params) {
    return createErrorResponse(400, 'invalid_request', 'Missing realmId or tenantId');
  }
  
  const { realmId, tenantId } = params;
  const queryParams = event.queryStringParameters || {};
  
  try {
    // Get SSO configuration
    const ssoConfig = await getSSOConfig(tenantId);
    
    if (!ssoConfig) {
      return createErrorResponse(404, 'not_found', 'SSO not configured');
    }
    
    const nameId = queryParams.name_id;
    const sessionIndex = queryParams.session_index;
    
    if (!nameId) {
      return createErrorResponse(400, 'invalid_request', 'Missing name_id parameter');
    }
    
    // Generate logout request
    const logoutResult = await generateLogoutRequest(ssoConfig, nameId, sessionIndex);
    
    if (!logoutResult) {
      return createErrorResponse(400, 'slo_not_supported', 'Single Logout not configured for this IdP');
    }
    
    await logAuditEvent({
      eventType: AuditEventType.LOGOUT,
      result: AuditResult.PENDING,
      realmId,
      ipAddress: getClientIP(event),
      userAgent: getUserAgent(event),
      action: 'SAML SSO SP-initiated logout',
      details: {
        tenantId,
        provider: ssoConfig.providerName,
        nameId
      }
    });
    
    return createRedirectResponse(logoutResult.redirectUrl);
  } catch (error) {
    console.error('SAML logout error:', error);
    return createErrorResponse(
      500,
      'server_error',
      'Failed to initiate logout'
    );
  }
}

// ============================================================================
// JIT USER PROVISIONING
// ============================================================================

/**
 * Find or create user from SSO attributes (JIT provisioning)
 */
async function findOrCreateSSOUser(
  realmId: string,
  _tenantId: string,
  attributes: ExtractedUserAttributes,
  ssoConfig: { jitProvisioning: { enabled: boolean; defaultRole?: string; autoVerifyEmail?: boolean } }
): Promise<{ success: boolean; user?: { id: string; email: string }; created?: boolean; error?: string }> {
  try {
    // Try to find existing user by email
    const existingUser = await findUserByEmail(realmId, attributes.email);
    
    if (existingUser) {
      return {
        success: true,
        user: {
          id: existingUser.id,
          email: existingUser.email
        },
        created: false
      };
    }
    
    // Check if JIT provisioning is enabled
    if (!ssoConfig.jitProvisioning.enabled) {
      return {
        success: false,
        error: 'User not found and JIT provisioning is disabled'
      };
    }
    
    // Generate a random password for SSO users (they won't use it - they authenticate via IdP)
    // This is required by the CreateUserInput interface but SSO users never use password auth
    const randomPassword = `SSO_${crypto.randomUUID()}_${Date.now()}!Aa1`;
    
    // Create new user
    const newUser = await createUser({
      realm_id: realmId,
      email: attributes.email,
      password: randomPassword,
      profile: {
        first_name: attributes.firstName,
        last_name: attributes.lastName,
        metadata: {
          sso_provisioned: true,
          sso_groups: attributes.groups,
          department: attributes.department,
          employee_id: attributes.employeeId
        }
      }
    });
    
    return {
      success: true,
      user: {
        id: newUser.id,
        email: newUser.email
      },
      created: true
    };
  } catch (error) {
    console.error('JIT provisioning error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to provision user'
    };
  }
}

// ============================================================================
// MAIN HANDLER ROUTER
// ============================================================================

/**
 * Main handler router for SAML SSO endpoints
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
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400'
      },
      body: ''
    };
  }
  
  try {
    // Route based on path pattern
    // /sso/saml/{realmId}/{tenantId}/login
    if (path.match(/\/sso\/saml\/[^/]+\/[^/]+\/login$/) && method === 'GET') {
      return loginHandler(event);
    }
    
    // /sso/saml/{realmId}/{tenantId}/acs
    if (path.match(/\/sso\/saml\/[^/]+\/[^/]+\/acs$/) && method === 'POST') {
      return acsHandler(event);
    }
    
    // /sso/saml/{realmId}/{tenantId}/metadata
    if (path.match(/\/sso\/saml\/[^/]+\/[^/]+\/metadata$/) && method === 'GET') {
      return metadataHandler(event);
    }
    
    // /sso/saml/{realmId}/{tenantId}/slo
    if (path.match(/\/sso\/saml\/[^/]+\/[^/]+\/slo$/) && method === 'POST') {
      return sloHandler(event);
    }
    
    // /sso/saml/{realmId}/{tenantId}/logout
    if (path.match(/\/sso\/saml\/[^/]+\/[^/]+\/logout$/) && method === 'GET') {
      return logoutHandler(event);
    }
    
    return createErrorResponse(404, 'not_found', 'Endpoint not found');
  } catch (error) {
    console.error('SAML SSO handler error:', error);
    return createErrorResponse(500, 'server_error', 'Internal server error');
  }
}
