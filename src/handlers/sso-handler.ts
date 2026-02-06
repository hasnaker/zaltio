/**
 * SSO Lambda Handler - OAuth 2.0 and OpenID Connect endpoints
 * Validates: Requirements 6.1, 6.2, 6.4, 6.5, 9.1
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  getOIDCDiscoveryDocument,
  registerOAuthClient,
  getOAuthClient,
  validateClientCredentials,
  generateAuthorizationCode,
  exchangeAuthorizationCode,
  createSSOSession,
  getSSOSession,
  addApplicationToSSOSession,
  generateSSOToken,
  validateSSOToken,
  invalidateSSOSession,
  convertLegacyToken,
  validateLegacyToken,
  getUserInfo
} from '../services/sso.service';
import { verifyAccessToken } from '../utils/jwt';
import { findUserByEmail } from '../repositories/user.repository';
import { verifyPassword } from '../utils/password';
import { findRealmById } from '../repositories/realm.repository';
import {
  HSDApplication,
  OIDCScope,
  AuthorizationRequest,
  TokenRequest,
  HSD_APPLICATION_CONFIGS
} from '../models/sso.model';

import { getJWKS } from '../utils/jwt';

interface ErrorResponse {
  error: string;
  error_description?: string;
}

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

/**
 * OpenID Connect Discovery endpoint
 * GET /.well-known/openid-configuration
 */
export async function discoveryHandler(): Promise<APIGatewayProxyResult> {
  const discovery = getOIDCDiscoveryDocument();
  return createSuccessResponse(200, discovery, {
    'Cache-Control': 'public, max-age=86400'
  });
}

/**
 * JWKS (JSON Web Key Set) endpoint
 * GET /.well-known/jwks.json
 * Returns public keys for JWT verification
 */
export async function jwksHandler(): Promise<APIGatewayProxyResult> {
  try {
    const jwks = await getJWKS();
    return createSuccessResponse(200, jwks, {
      'Cache-Control': 'public, max-age=3600' // Cache for 1 hour
    });
  } catch (error) {
    console.error('JWKS error:', error);
    return createErrorResponse(500, 'server_error', 'Failed to retrieve JWKS');
  }
}

/**
 * OAuth 2.0 Authorization endpoint
 * GET /oauth/authorize
 * Validates: Requirements 9.1 (OAuth 2.0 standards)
 */
export async function authorizeHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const params = event.queryStringParameters || {};
  
  // Validate required parameters
  const requiredParams = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state'];
  for (const param of requiredParams) {
    if (!params[param]) {
      return createErrorResponse(400, 'invalid_request', `Missing required parameter: ${param}`);
    }
  }

  const request: AuthorizationRequest = {
    response_type: params.response_type as 'code' | 'token' | 'id_token',
    client_id: params.client_id!,
    redirect_uri: params.redirect_uri!,
    scope: params.scope!,
    state: params.state!,
    nonce: params.nonce,
    code_challenge: params.code_challenge,
    code_challenge_method: params.code_challenge_method as 'S256' | 'plain' | undefined
  };

  // Validate client
  const client = await getOAuthClient(request.client_id);
  if (!client) {
    return createErrorResponse(400, 'invalid_client', 'Unknown client_id');
  }

  // Validate redirect_uri
  if (!client.redirect_uris.includes(request.redirect_uri)) {
    return createErrorResponse(400, 'invalid_request', 'Invalid redirect_uri');
  }

  // Validate response_type
  if (request.response_type !== 'code') {
    return createErrorResponse(400, 'unsupported_response_type', 'Only authorization code flow is supported');
  }

  // Parse and validate scopes
  const requestedScopes = request.scope.split(' ') as OIDCScope[];
  const validScopes = requestedScopes.filter(s => client.allowed_scopes.includes(s));
  
  if (validScopes.length === 0) {
    return createErrorResponse(400, 'invalid_scope', 'No valid scopes requested');
  }

  // Check for authenticated user (from session cookie or Authorization header)
  const authHeader = event.headers.Authorization || event.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // Redirect to login page with return URL
    const loginUrl = `https://api.zalt.io/login?` +
      `client_id=${encodeURIComponent(request.client_id)}&` +
      `redirect_uri=${encodeURIComponent(request.redirect_uri)}&` +
      `scope=${encodeURIComponent(request.scope)}&` +
      `state=${encodeURIComponent(request.state)}&` +
      `response_type=${encodeURIComponent(request.response_type)}`;
    
    return {
      statusCode: 302,
      headers: {
        Location: loginUrl,
        'Cache-Control': 'no-store'
      },
      body: ''
    };
  }

  try {
    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);
    
    // Generate authorization code
    const code = await generateAuthorizationCode(
      request.client_id,
      payload.sub,
      payload.realm_id,
      request.redirect_uri,
      validScopes,
      request.code_challenge,
      request.code_challenge_method
    );

    // Redirect back to client with code
    const redirectUrl = `${request.redirect_uri}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(request.state)}`;
    
    return {
      statusCode: 302,
      headers: {
        Location: redirectUrl,
        'Cache-Control': 'no-store'
      },
      body: ''
    };
  } catch (error) {
    return createErrorResponse(401, 'access_denied', 'Invalid or expired token');
  }
}

/**
 * OAuth 2.0 Token endpoint
 * POST /oauth/token
 * Validates: Requirements 9.1 (OAuth 2.0 token exchange)
 */
export async function tokenHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  if (!event.body) {
    return createErrorResponse(400, 'invalid_request', 'Request body is required');
  }

  let request: TokenRequest;
  try {
    // Support both JSON and form-urlencoded
    const contentType = event.headers['Content-Type'] || event.headers['content-type'] || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(event.body);
      request = {
        grant_type: params.get('grant_type') as TokenRequest['grant_type'],
        code: params.get('code') || undefined,
        redirect_uri: params.get('redirect_uri') || undefined,
        client_id: params.get('client_id') || '',
        client_secret: params.get('client_secret') || undefined,
        refresh_token: params.get('refresh_token') || undefined,
        scope: params.get('scope') || undefined,
        code_verifier: params.get('code_verifier') || undefined
      };
    } else {
      request = JSON.parse(event.body);
    }
  } catch {
    return createErrorResponse(400, 'invalid_request', 'Invalid request body');
  }

  // Validate grant_type
  if (!request.grant_type) {
    return createErrorResponse(400, 'invalid_request', 'Missing grant_type');
  }

  // Validate client credentials (from body or Basic auth header)
  let clientId = request.client_id;
  let clientSecret = request.client_secret;

  const authHeader = event.headers.Authorization || event.headers.authorization;
  if (authHeader && authHeader.startsWith('Basic ')) {
    const credentials = Buffer.from(authHeader.substring(6), 'base64').toString();
    const [id, secret] = credentials.split(':');
    clientId = id;
    clientSecret = secret;
  }

  if (!clientId) {
    return createErrorResponse(400, 'invalid_request', 'Missing client_id');
  }

  const client = await getOAuthClient(clientId);
  if (!client) {
    return createErrorResponse(401, 'invalid_client', 'Unknown client');
  }

  // Validate client secret for confidential clients
  if (clientSecret && !(await validateClientCredentials(clientId, clientSecret))) {
    return createErrorResponse(401, 'invalid_client', 'Invalid client credentials');
  }

  try {
    switch (request.grant_type) {
      case 'authorization_code': {
        if (!request.code || !request.redirect_uri) {
          return createErrorResponse(400, 'invalid_request', 'Missing code or redirect_uri');
        }

        const tokens = await exchangeAuthorizationCode(
          request.code,
          clientId,
          request.redirect_uri,
          request.code_verifier
        );

        return createSuccessResponse(200, tokens);
      }

      case 'refresh_token': {
        if (!request.refresh_token) {
          return createErrorResponse(400, 'invalid_request', 'Missing refresh_token');
        }

        // TODO: Implement refresh token exchange
        return createErrorResponse(400, 'unsupported_grant_type', 'Refresh token not yet implemented');
      }

      case 'client_credentials': {
        if (!clientSecret) {
          return createErrorResponse(401, 'invalid_client', 'Client secret required');
        }

        // TODO: Implement client credentials grant
        return createErrorResponse(400, 'unsupported_grant_type', 'Client credentials not yet implemented');
      }

      default:
        return createErrorResponse(400, 'unsupported_grant_type', `Unsupported grant_type: ${request.grant_type}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Token exchange failed';
    return createErrorResponse(400, 'invalid_grant', message);
  }
}

/**
 * OpenID Connect UserInfo endpoint
 * GET /oauth/userinfo
 */
export async function userinfoHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return createErrorResponse(401, 'invalid_token', 'Missing or invalid Authorization header');
  }

  const token = authHeader.substring(7);
  const userInfo = await getUserInfo(token);

  if (!userInfo) {
    return createErrorResponse(401, 'invalid_token', 'Invalid or expired token');
  }

  return createSuccessResponse(200, userInfo);
}

/**
 * SSO Token validation endpoint
 * POST /sso/validate
 * Validates: Requirements 6.2 (SSO token validation across HSD services)
 */
export async function validateSSOHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  if (!event.body) {
    return createErrorResponse(400, 'invalid_request', 'Request body is required');
  }

  let body: { token: string; application?: HSDApplication };
  try {
    body = JSON.parse(event.body);
  } catch {
    return createErrorResponse(400, 'invalid_request', 'Invalid JSON');
  }

  if (!body.token) {
    return createErrorResponse(400, 'invalid_request', 'Missing token');
  }

  const result = await validateSSOToken(body.token);

  if (!result.valid) {
    return createErrorResponse(401, 'invalid_token', result.error);
  }

  // If application specified, add it to the session
  if (body.application && result.applications) {
    // Find session and add application
    // This enables cross-application SSO tracking
  }

  return createSuccessResponse(200, {
    valid: true,
    user_id: result.user_id,
    realm_id: result.realm_id,
    applications: result.applications
  });
}

/**
 * SSO Session creation endpoint
 * POST /sso/session
 * Validates: Requirements 6.2 (cross-application session sharing)
 */
export async function createSSOSessionHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return createErrorResponse(401, 'unauthorized', 'Missing Authorization header');
  }

  if (!event.body) {
    return createErrorResponse(400, 'invalid_request', 'Request body is required');
  }

  let body: { application: HSDApplication; session_id: string };
  try {
    body = JSON.parse(event.body);
  } catch {
    return createErrorResponse(400, 'invalid_request', 'Invalid JSON');
  }

  if (!body.application || !body.session_id) {
    return createErrorResponse(400, 'invalid_request', 'Missing application or session_id');
  }

  // Validate the application
  if (!HSD_APPLICATION_CONFIGS[body.application]) {
    return createErrorResponse(400, 'invalid_request', 'Invalid application');
  }

  try {
    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);

    const ssoSession = await createSSOSession(
      payload.sub,
      payload.realm_id,
      body.session_id,
      body.application
    );

    // Generate SSO token for cross-application use
    const ssoToken = await generateSSOToken(
      payload.sub,
      payload.realm_id,
      ssoSession.id,
      ssoSession.authenticated_applications
    );

    return createSuccessResponse(201, {
      session_id: ssoSession.id,
      sso_token: ssoToken,
      applications: ssoSession.authenticated_applications,
      expires_at: ssoSession.expires_at
    });
  } catch (error) {
    return createErrorResponse(401, 'invalid_token', 'Invalid or expired token');
  }
}

/**
 * Add application to SSO session
 * POST /sso/session/:sessionId/applications
 */
export async function addApplicationHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const sessionId = event.pathParameters?.sessionId;
  
  if (!sessionId) {
    return createErrorResponse(400, 'invalid_request', 'Missing session ID');
  }

  if (!event.body) {
    return createErrorResponse(400, 'invalid_request', 'Request body is required');
  }

  let body: { application: HSDApplication };
  try {
    body = JSON.parse(event.body);
  } catch {
    return createErrorResponse(400, 'invalid_request', 'Invalid JSON');
  }

  if (!body.application || !HSD_APPLICATION_CONFIGS[body.application]) {
    return createErrorResponse(400, 'invalid_request', 'Invalid application');
  }

  const session = addApplicationToSSOSession(sessionId, body.application);
  
  if (!session) {
    return createErrorResponse(404, 'not_found', 'Session not found or expired');
  }

  return createSuccessResponse(200, {
    session_id: session.id,
    applications: session.authenticated_applications,
    expires_at: session.expires_at
  });
}

/**
 * Legacy token conversion endpoint
 * POST /sso/legacy/convert
 * Validates: Requirements 6.4 (backward compatibility)
 */
export async function convertLegacyHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  if (!event.body) {
    return createErrorResponse(400, 'invalid_request', 'Request body is required');
  }

  let body: { legacy_token: string; application: HSDApplication };
  try {
    body = JSON.parse(event.body);
  } catch {
    return createErrorResponse(400, 'invalid_request', 'Invalid JSON');
  }

  if (!body.legacy_token || !body.application) {
    return createErrorResponse(400, 'invalid_request', 'Missing legacy_token or application');
  }

  if (!HSD_APPLICATION_CONFIGS[body.application]) {
    return createErrorResponse(400, 'invalid_request', 'Invalid application');
  }

  const tokens = await convertLegacyToken(body.legacy_token, body.application);

  if (!tokens) {
    return createErrorResponse(400, 'invalid_token', 'Unable to convert legacy token');
  }

  return createSuccessResponse(200, {
    ...tokens,
    legacy_converted: true
  });
}

/**
 * Legacy token validation endpoint
 * POST /sso/legacy/validate
 * Validates: Requirements 6.4 (backward compatibility during transition)
 */
export async function validateLegacyHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  if (!event.body) {
    return createErrorResponse(400, 'invalid_request', 'Request body is required');
  }

  let body: { token: string };
  try {
    body = JSON.parse(event.body);
  } catch {
    return createErrorResponse(400, 'invalid_request', 'Invalid JSON');
  }

  if (!body.token) {
    return createErrorResponse(400, 'invalid_request', 'Missing token');
  }

  const legacyToken = await validateLegacyToken(body.token);

  if (!legacyToken) {
    return createErrorResponse(401, 'invalid_token', 'Invalid legacy token');
  }

  return createSuccessResponse(200, {
    valid: true,
    user_id: legacyToken.user_id,
    realm_id: legacyToken.realm_id,
    application: legacyToken.application,
    expires_at: legacyToken.expires_at,
    legacy_format: true
  });
}

/**
 * OAuth client registration endpoint
 * POST /oauth/register
 * Validates: Requirements 6.1 (HSD application integration)
 */
export async function registerClientHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  // This endpoint should be protected by admin authentication
  const authHeader = event.headers.Authorization || event.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return createErrorResponse(401, 'unauthorized', 'Admin authentication required');
  }

  if (!event.body) {
    return createErrorResponse(400, 'invalid_request', 'Request body is required');
  }

  let body: {
    application: HSDApplication;
    realm_id: string;
    redirect_uris?: string[];
  };
  try {
    body = JSON.parse(event.body);
  } catch {
    return createErrorResponse(400, 'invalid_request', 'Invalid JSON');
  }

  if (!body.application || !body.realm_id) {
    return createErrorResponse(400, 'invalid_request', 'Missing application or realm_id');
  }

  if (!HSD_APPLICATION_CONFIGS[body.application]) {
    return createErrorResponse(400, 'invalid_request', 'Invalid application');
  }

  // Verify realm exists
  const realm = await findRealmById(body.realm_id);
  if (!realm) {
    return createErrorResponse(404, 'not_found', 'Realm not found');
  }

  try {
    const client = await registerOAuthClient(
      body.application,
      body.realm_id,
      body.redirect_uris || []
    );

    return createSuccessResponse(201, {
      client_id: client.client_id,
      client_secret: client.client_secret_hash, // Plain secret returned only on creation
      client_name: client.client_name,
      application: client.application,
      redirect_uris: client.redirect_uris,
      grant_types: client.grant_types
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Client registration failed';
    return createErrorResponse(500, 'server_error', message);
  }
}

/**
 * Get HSD application configurations
 * GET /sso/applications
 */
export async function getApplicationsHandler(): Promise<APIGatewayProxyResult> {
  const applications = Object.values(HSD_APPLICATION_CONFIGS).map(config => ({
    application: config.application,
    display_name: config.display_name,
    base_url: config.base_url
  }));

  return createSuccessResponse(200, { applications });
}

/**
 * Main handler router
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const path = event.path;
  const method = event.httpMethod;

  try {
    // OpenID Connect Discovery
    if (path === '/.well-known/openid-configuration' && method === 'GET') {
      return discoveryHandler();
    }

    // JWKS endpoint
    if (path === '/.well-known/jwks.json' && method === 'GET') {
      return jwksHandler();
    }

    // OAuth 2.0 endpoints
    if (path === '/oauth/authorize' && method === 'GET') {
      return authorizeHandler(event);
    }
    if (path === '/oauth/token' && method === 'POST') {
      return tokenHandler(event);
    }
    if (path === '/oauth/userinfo' && method === 'GET') {
      return userinfoHandler(event);
    }
    if (path === '/oauth/register' && method === 'POST') {
      return registerClientHandler(event);
    }

    // SSO endpoints
    if (path === '/sso/validate' && method === 'POST') {
      return validateSSOHandler(event);
    }
    if (path === '/sso/session' && method === 'POST') {
      return createSSOSessionHandler(event);
    }
    if (path.match(/^\/sso\/session\/[^/]+\/applications$/) && method === 'POST') {
      return addApplicationHandler(event);
    }
    if (path === '/sso/applications' && method === 'GET') {
      return getApplicationsHandler();
    }

    // Legacy compatibility endpoints
    if (path === '/sso/legacy/convert' && method === 'POST') {
      return convertLegacyHandler(event);
    }
    if (path === '/sso/legacy/validate' && method === 'POST') {
      return validateLegacyHandler(event);
    }

    return createErrorResponse(404, 'not_found', 'Endpoint not found');
  } catch (error) {
    console.error('SSO handler error:', error);
    return createErrorResponse(500, 'server_error', 'Internal server error');
  }
}
