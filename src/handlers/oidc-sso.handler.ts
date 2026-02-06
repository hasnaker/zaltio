/**
 * OIDC SSO Lambda Handler - OIDC SSO endpoints for organization-level SSO
 * 
 * Endpoints:
 * - GET /sso/oidc/{realmId}/{tenantId}/login - Initiate OIDC SSO
 * - GET /sso/oidc/{realmId}/{tenantId}/callback - OIDC callback
 * - GET /sso/oidc/{realmId}/{tenantId}/logout - Initiate logout
 * 
 * Supported Providers:
 * - Google Workspace
 * - Microsoft Entra (Azure AD)
 * - Okta
 * - Custom OIDC providers
 * 
 * Security Requirements:
 * - PKCE for authorization code flow
 * - State parameter for CSRF protection
 * - Nonce for ID token replay protection
 * - Audit logging for all SSO events
 * 
 * Validates: Requirements 9.3 (OIDC per organization)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import * as crypto from 'crypto';
import {
  initiateOIDCSSO,
  processOIDCCallback,
  ExtractedOIDCUserAttributes
} from '../services/oidc.service';
import { getSSOConfig, recordSSOLogin } from '../repositories/org-sso.repository';
import { findUserByEmail, createUser } from '../repositories/user.repository';
import { createSession } from '../repositories/session.repository';
import { generateTokenPair } from '../utils/jwt';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';


// ============================================================================
// TYPES
// ============================================================================

interface ErrorResponse {
  error: string;
  error_description?: string;
}

interface OIDCLoginSuccessResponse {
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
    providerType: 'oidc';
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
 * Initiate OIDC SSO - Authorization Code Flow with PKCE
 * GET /sso/oidc/{realmId}/{tenantId}/login
 * 
 * Query Parameters:
 * - redirect_uri: URL to redirect after successful login
 * - login_hint: Pre-fill email in IdP login form
 * - force_login: Force re-authentication at IdP
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
    
    if (ssoConfig.ssoType !== 'oidc') {
      return createErrorResponse(400, 'invalid_request', 'SSO type is not OIDC');
    }
    
    if (!ssoConfig.enabled) {
      return createErrorResponse(403, 'sso_disabled', 'SSO is not enabled for this organization');
    }
    
    // Initiate OIDC SSO
    const { authorizationUrl } = await initiateOIDCSSO(ssoConfig, {
      forceLogin: queryParams.force_login === 'true',
      loginHint: queryParams.login_hint,
      redirectUri: queryParams.redirect_uri
    });
    
    // Audit log
    await logAuditEvent({
      eventType: AuditEventType.OAUTH_LOGIN,
      result: AuditResult.PENDING,
      realmId,
      ipAddress: getClientIP(event),
      userAgent: getUserAgent(event),
      action: 'OIDC SSO initiated',
      details: {
        tenantId,
        provider: ssoConfig.providerName,
        ssoType: 'oidc',
        providerPreset: ssoConfig.oidcConfig?.providerPreset
      }
    });
    
    return createRedirectResponse(authorizationUrl);
  } catch (error) {
    console.error('OIDC login error:', error);
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to initiate SSO'
    );
  }
}


/**
 * OIDC Callback - Process authorization code
 * GET /sso/oidc/{realmId}/{tenantId}/callback
 * 
 * Query Parameters:
 * - code: Authorization code from IdP
 * - state: State parameter for CSRF protection
 * - error: Error code if authentication failed
 * - error_description: Error description
 */
export async function callbackHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const params = getPathParams(event);
  if (!params) {
    return createErrorResponse(400, 'invalid_request', 'Missing realmId or tenantId');
  }
  
  const { realmId, tenantId } = params;
  const queryParams = event.queryStringParameters || {};
  
  // Check for error from IdP
  if (queryParams.error) {
    await logAuditEvent({
      eventType: AuditEventType.OAUTH_LOGIN,
      result: AuditResult.FAILURE,
      realmId,
      ipAddress: getClientIP(event),
      userAgent: getUserAgent(event),
      action: 'OIDC SSO authentication failed at IdP',
      errorMessage: queryParams.error_description || queryParams.error,
      details: { tenantId, error: queryParams.error }
    });
    
    return createErrorResponse(
      401,
      queryParams.error,
      queryParams.error_description || 'Authentication failed at identity provider'
    );
  }
  
  // Validate required parameters
  if (!queryParams.code) {
    return createErrorResponse(400, 'invalid_request', 'Missing authorization code');
  }
  
  if (!queryParams.state) {
    return createErrorResponse(400, 'invalid_request', 'Missing state parameter');
  }
  
  try {
    // Get SSO configuration
    const ssoConfig = await getSSOConfig(tenantId);
    
    if (!ssoConfig) {
      return createErrorResponse(404, 'not_found', 'SSO not configured for this organization');
    }
    
    if (ssoConfig.realmId !== realmId) {
      return createErrorResponse(400, 'invalid_request', 'Realm mismatch');
    }
    
    // Process OIDC callback
    const result = await processOIDCCallback(ssoConfig, queryParams.code, queryParams.state);
    
    if (!result.success || !result.user) {
      // Audit log failure
      await logAuditEvent({
        eventType: AuditEventType.OAUTH_LOGIN,
        result: AuditResult.FAILURE,
        realmId,
        ipAddress: getClientIP(event),
        userAgent: getUserAgent(event),
        action: 'OIDC SSO authentication failed',
        errorMessage: result.error,
        details: { tenantId, provider: ssoConfig.providerName }
      });
      
      return createErrorResponse(401, 'authentication_failed', result.error);
    }
    
    // Find or create user
    const userResult = await findOrCreateOIDCUser(
      realmId,
      tenantId,
      result.user,
      ssoConfig
    );
    
    if (!userResult.success || !userResult.user) {
      return createErrorResponse(500, 'user_creation_failed', userResult.error);
    }
    
    // Create session
    const sessionInput = {
      user_id: userResult.user.id,
      realm_id: realmId,
      ip_address: getClientIP(event),
      user_agent: getUserAgent(event)
    };
    
    // Generate tokens
    const tokens = await generateTokenPair(
      userResult.user.id,
      realmId,
      userResult.user.email
    );
    
    // Create session with tokens
    await createSession(sessionInput, tokens.access_token, tokens.refresh_token);
    
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
      action: 'OIDC SSO authentication successful',
      details: {
        tenantId,
        provider: ssoConfig.providerName,
        ssoType: 'oidc',
        providerPreset: ssoConfig.oidcConfig?.providerPreset,
        jitProvisioned: userResult.created
      }
    });
    
    // Get redirect URI from state if available
    // The state contains the original redirect_uri
    let redirectUri: string | undefined;
    try {
      // State is encrypted, but we can check if there was a redirect_uri in the original request
      // For now, check query params for a redirect_uri (some IdPs pass it through)
      redirectUri = queryParams.redirect_uri;
    } catch {
      // Ignore
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
    const response: OIDCLoginSuccessResponse = {
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
        providerType: 'oidc'
      }
    };
    
    return createSuccessResponse(200, response);
  } catch (error) {
    console.error('OIDC callback error:', error);
    return createErrorResponse(
      500,
      'server_error',
      error instanceof Error ? error.message : 'Failed to process OIDC callback'
    );
  }
}


/**
 * Initiate OIDC logout
 * GET /sso/oidc/{realmId}/{tenantId}/logout
 * 
 * Query Parameters:
 * - post_logout_redirect_uri: URL to redirect after logout
 * - id_token_hint: ID token for logout hint
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
    
    // For OIDC, we typically just clear the local session
    // Some providers support end_session_endpoint for RP-initiated logout
    
    await logAuditEvent({
      eventType: AuditEventType.LOGOUT,
      result: AuditResult.SUCCESS,
      realmId,
      ipAddress: getClientIP(event),
      userAgent: getUserAgent(event),
      action: 'OIDC SSO logout',
      details: {
        tenantId,
        provider: ssoConfig.providerName
      }
    });
    
    // If post_logout_redirect_uri is provided, redirect there
    if (queryParams.post_logout_redirect_uri) {
      return createRedirectResponse(queryParams.post_logout_redirect_uri);
    }
    
    return createSuccessResponse(200, {
      success: true,
      message: 'Logout completed'
    });
  } catch (error) {
    console.error('OIDC logout error:', error);
    return createErrorResponse(
      500,
      'server_error',
      'Failed to process logout'
    );
  }
}

// ============================================================================
// JIT USER PROVISIONING
// ============================================================================

/**
 * Find or create user from OIDC attributes (JIT provisioning)
 */
async function findOrCreateOIDCUser(
  realmId: string,
  _tenantId: string,
  attributes: ExtractedOIDCUserAttributes,
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
    
    // Generate a random password for SSO users (they won't use it)
    const randomPassword = `SSO_OIDC_${crypto.randomUUID()}_${Date.now()}!Aa1`;
    
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
          sso_type: 'oidc',
          sso_groups: attributes.groups,
          picture: attributes.picture,
          locale: attributes.locale,
          email_verified_by_idp: attributes.emailVerified
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
    console.error('OIDC JIT provisioning error:', error);
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
 * Main handler router for OIDC SSO endpoints
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
    // /sso/oidc/{realmId}/{tenantId}/login
    if (path.match(/\/sso\/oidc\/[^/]+\/[^/]+\/login$/) && method === 'GET') {
      return loginHandler(event);
    }
    
    // /sso/oidc/{realmId}/{tenantId}/callback
    if (path.match(/\/sso\/oidc\/[^/]+\/[^/]+\/callback$/) && method === 'GET') {
      return callbackHandler(event);
    }
    
    // /sso/oidc/{realmId}/{tenantId}/logout
    if (path.match(/\/sso\/oidc\/[^/]+\/[^/]+\/logout$/) && method === 'GET') {
      return logoutHandler(event);
    }
    
    return createErrorResponse(404, 'not_found', 'Endpoint not found');
  } catch (error) {
    console.error('OIDC SSO handler error:', error);
    return createErrorResponse(500, 'server_error', 'Internal server error');
  }
}
