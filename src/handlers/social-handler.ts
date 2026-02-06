/**
 * Social Login Lambda Handlers
 * Validates: Requirements 4.1, 4.2 (Social Login)
 * 
 * IMPORTANT: OAuth credentials belong to REALM (customer)
 * - Google shows "Clinisyn" not "Zalt.io"
 * - Each realm has its own OAuth app credentials
 * 
 * Endpoints:
 * - GET /v1/auth/social/google/authorize - Start Google OAuth
 * - GET /v1/auth/social/google/callback - Google OAuth callback
 * - GET /v1/auth/social/apple/authorize - Start Apple Sign-In
 * - POST /v1/auth/social/apple/callback - Apple Sign-In callback
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { findRealmById } from '../repositories/realm.repository';
import { findUserByEmail, createUser } from '../repositories/user.repository';
import { createSession } from '../repositories/session.repository';
import { generateTokenPair } from '../utils/jwt';
import { logSecurityEvent } from '../services/security-logger.service';
import { checkRateLimit } from '../services/ratelimit.service';
import { User, UserResponse } from '../models/user.model';
import {
  generatePKCE,
  generateNonce,
  generateGoogleAuthorizationURL,
  generateAppleAuthorizationURL,
  exchangeGoogleCode,
  exchangeAppleCode,
  verifyIDToken,
  getGoogleUserInfo,
  validateCallbackParams,
  generateAppleClientSecret,
  OAuthState,
  OAuthProviderConfig
} from '../services/oauth.service';

// Rate limit configuration
const OAUTH_RATE_LIMIT = {
  maxRequests: 10,
  windowSeconds: 60 // 10 requests per minute
};

// In-memory PKCE store (in production, use DynamoDB with TTL)
const pkceStore = new Map<string, {
  codeVerifier: string;
  expiresAt: number;
}>();

// Default scopes
const GOOGLE_SCOPES = ['openid', 'email', 'profile'];
const APPLE_SCOPES = ['name', 'email'];

function createResponse(
  statusCode: number,
  body: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
    body: JSON.stringify(body)
  };
}

function createRedirectResponse(location: string): APIGatewayProxyResult {
  return {
    statusCode: 302,
    headers: {
      'Location': location,
      'Cache-Control': 'no-store'
    },
    body: ''
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 'unknown';
}

function getUserAgent(event: APIGatewayProxyEvent): string {
  return event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown';
}

/**
 * Get OAuth config for realm
 * In production, this would fetch from DynamoDB
 */
async function getRealmOAuthConfig(
  realmId: string,
  provider: 'google' | 'apple'
): Promise<OAuthProviderConfig | null> {
  const realm = await findRealmById(realmId);
  if (!realm) return null;

  // In production, OAuth credentials are stored per-realm
  // For now, use environment variables as fallback
  if (provider === 'google') {
    const clientId = process.env[`OAUTH_GOOGLE_CLIENT_ID_${realmId.toUpperCase().replace(/-/g, '_')}`] 
      || process.env.OAUTH_GOOGLE_CLIENT_ID;
    const clientSecret = process.env[`OAUTH_GOOGLE_CLIENT_SECRET_${realmId.toUpperCase().replace(/-/g, '_')}`]
      || process.env.OAUTH_GOOGLE_CLIENT_SECRET;
    
    if (!clientId || !clientSecret) return null;

    return {
      clientId,
      clientSecret,
      redirectUri: `${process.env.API_BASE_URL || 'https://api.zalt.io'}/v1/auth/social/google/callback`,
      scopes: GOOGLE_SCOPES
    };
  }

  if (provider === 'apple') {
    const clientId = process.env[`OAUTH_APPLE_CLIENT_ID_${realmId.toUpperCase().replace(/-/g, '_')}`]
      || process.env.OAUTH_APPLE_CLIENT_ID;
    const teamId = process.env[`OAUTH_APPLE_TEAM_ID_${realmId.toUpperCase().replace(/-/g, '_')}`]
      || process.env.OAUTH_APPLE_TEAM_ID;
    const keyId = process.env[`OAUTH_APPLE_KEY_ID_${realmId.toUpperCase().replace(/-/g, '_')}`]
      || process.env.OAUTH_APPLE_KEY_ID;
    const privateKey = process.env[`OAUTH_APPLE_PRIVATE_KEY_${realmId.toUpperCase().replace(/-/g, '_')}`]
      || process.env.OAUTH_APPLE_PRIVATE_KEY;
    
    if (!clientId || !teamId || !keyId || !privateKey) return null;

    // Generate Apple client secret (JWT signed with private key)
    const clientSecret = generateAppleClientSecret(teamId, clientId, keyId, privateKey);

    return {
      clientId,
      clientSecret,
      redirectUri: `${process.env.API_BASE_URL || 'https://api.zalt.io'}/v1/auth/social/apple/callback`,
      scopes: APPLE_SCOPES
    };
  }

  return null;
}

/**
 * Store PKCE code verifier for later use
 */
function storePKCE(nonce: string, codeVerifier: string): void {
  pkceStore.set(nonce, {
    codeVerifier,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  });
}

/**
 * Get and delete PKCE code verifier
 */
function getPKCE(nonce: string): string | null {
  const stored = pkceStore.get(nonce);
  if (!stored) return null;
  
  if (Date.now() > stored.expiresAt) {
    pkceStore.delete(nonce);
    return null;
  }
  
  pkceStore.delete(nonce);
  return stored.codeVerifier;
}

/**
 * GET /v1/auth/social/google/authorize
 * Start Google OAuth flow
 */
export async function googleAuthorizeHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Rate limiting
    const rateLimitResult = await checkRateLimit(
      'global',
      `oauth:${clientIP}`,
      OAUTH_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      return createResponse(429, {
        error: { 
          code: 'RATE_LIMITED', 
          message: 'Too many requests',
          request_id: requestId 
        }
      });
    }

    // Get realm_id from query params
    const realmId = event.queryStringParameters?.realm_id;
    if (!realmId) {
      return createResponse(400, {
        error: { 
          code: 'INVALID_REQUEST', 
          message: 'realm_id is required',
          request_id: requestId 
        }
      });
    }

    // Get OAuth config for realm
    const config = await getRealmOAuthConfig(realmId, 'google');
    if (!config) {
      return createResponse(400, {
        error: { 
          code: 'OAUTH_NOT_CONFIGURED', 
          message: 'Google OAuth is not configured for this realm',
          request_id: requestId 
        }
      });
    }

    // redirect_url is REQUIRED - Clinisyn must provide their callback URL
    const redirectUrl = event.queryStringParameters?.redirect_url;
    if (!redirectUrl) {
      return createResponse(400, {
        error: { 
          code: 'INVALID_REQUEST', 
          message: 'redirect_url is required. Example: ?realm_id=clinisyn&redirect_url=http://localhost:3000/auth/callback',
          request_id: requestId 
        }
      });
    }

    // TODO: Validate redirect_url against realm's allowed_redirect_uris

    // Generate PKCE
    const pkce = generatePKCE();
    const nonce = generateNonce();

    // Store PKCE for callback
    storePKCE(nonce, pkce.codeVerifier);

    // Create state with redirect_url
    const state: OAuthState = {
      realmId,
      nonce,
      redirectUrl,
      timestamp: Date.now()
    };

    // Generate authorization URL
    const authUrl = generateGoogleAuthorizationURL(config, state, pkce);

    await logSecurityEvent({
      event_type: 'oauth_authorize_started',
      ip_address: clientIP,
      realm_id: realmId,
      details: { provider: 'google' }
    });

    // Redirect to Google
    return createRedirectResponse(authUrl);

  } catch (error) {
    console.error('Google authorize error:', error);
    return createResponse(500, {
      error: { 
        code: 'INTERNAL_ERROR', 
        message: 'An unexpected error occurred',
        request_id: requestId 
      }
    });
  }
}

/**
 * GET /v1/auth/social/google/callback
 * Handle Google OAuth callback
 */
export async function googleCallbackHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);
  const userAgent = getUserAgent(event);

  try {
    // Validate callback parameters
    const validation = validateCallbackParams({
      code: event.queryStringParameters?.code,
      state: event.queryStringParameters?.state,
      error: event.queryStringParameters?.error,
      error_description: event.queryStringParameters?.error_description
    });

    if (!validation.valid || !validation.state) {
      await logSecurityEvent({
        event_type: 'oauth_callback_failed',
        ip_address: clientIP,
        details: { provider: 'google', error: validation.error }
      });

      return createResponse(400, {
        error: { 
          code: 'OAUTH_ERROR', 
          message: validation.error || 'OAuth callback failed',
          request_id: requestId 
        }
      });
    }

    const { realmId, nonce, redirectUrl } = validation.state;

    // Get PKCE code verifier
    const codeVerifier = getPKCE(nonce);
    if (!codeVerifier) {
      return createResponse(400, {
        error: { 
          code: 'PKCE_EXPIRED', 
          message: 'Authorization session expired',
          request_id: requestId 
        }
      });
    }

    // Get OAuth config
    const config = await getRealmOAuthConfig(realmId, 'google');
    if (!config) {
      return createResponse(400, {
        error: { 
          code: 'OAUTH_NOT_CONFIGURED', 
          message: 'Google OAuth is not configured',
          request_id: requestId 
        }
      });
    }

    // Exchange code for tokens
    const tokens = await exchangeGoogleCode(
      event.queryStringParameters!.code!,
      config,
      codeVerifier
    );

    // Verify ID token
    if (tokens.idToken) {
      const idTokenResult = await verifyIDToken(
        tokens.idToken,
        'google',
        config.clientId,
        nonce
      );

      if (!idTokenResult.valid) {
        return createResponse(400, {
          error: { 
            code: 'INVALID_ID_TOKEN', 
            message: idTokenResult.error || 'ID token verification failed',
            request_id: requestId 
          }
        });
      }
    }

    // Get user info from Google
    const googleUser = await getGoogleUserInfo(tokens.accessToken);

    // Find or create user
    const existingUser = await findUserByEmail(realmId, googleUser.email);
    let isNewUser = false;
    let userId: string;
    let userEmail: string;
    let userProfile: User['profile'] | UserResponse['profile'];

    if (!existingUser) {
      // Create new user
      const newUser = await createUser({
        realm_id: realmId,
        email: googleUser.email,
        password: '', // No password for OAuth users
        profile: {
          first_name: googleUser.givenName,
          last_name: googleUser.familyName,
          avatar_url: googleUser.picture,
          metadata: {
            oauth_provider: 'google',
            oauth_id: googleUser.id
          }
        }
      });
      isNewUser = true;
      userId = newUser.id;
      userEmail = newUser.email;
      userProfile = newUser.profile;

      // Mark email as verified (Google verified it)
      // TODO: Update user email_verified = true
    } else {
      userId = existingUser.id;
      userEmail = existingUser.email;
      userProfile = existingUser.profile;
    }

    // Generate Zalt.io tokens
    const tokenPair = await generateTokenPair(
      userId,
      realmId,
      userEmail
    );

    // Create session
    await createSession(
      {
        user_id: userId,
        realm_id: realmId,
        ip_address: clientIP,
        user_agent: userAgent
      },
      tokenPair.access_token,
      tokenPair.refresh_token,
      7 * 24 * 60 * 60
    );

    await logSecurityEvent({
      event_type: isNewUser ? 'oauth_register_success' : 'oauth_login_success',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId,
      details: { provider: 'google' }
    });

    // ALWAYS redirect to Clinisyn's callback URL with tokens
    // redirect_url is required in authorize step, so it should always be present
    if (!redirectUrl) {
      return createResponse(400, {
        error: { 
          code: 'MISSING_REDIRECT_URL', 
          message: 'OAuth session missing redirect URL',
          request_id: requestId 
        }
      });
    }

    const redirectParams = new URLSearchParams({
      access_token: tokenPair.access_token,
      refresh_token: tokenPair.refresh_token,
      expires_in: tokenPair.expires_in.toString(),
      token_type: 'Bearer'
    });
    return createRedirectResponse(`${redirectUrl}?${redirectParams.toString()}`);

  } catch (error) {
    console.error('Google callback error:', error);

    await logSecurityEvent({
      event_type: 'oauth_callback_error',
      ip_address: clientIP,
      details: { provider: 'google', error: (error as Error).message }
    });

    return createResponse(500, {
      error: { 
        code: 'INTERNAL_ERROR', 
        message: 'An unexpected error occurred',
        request_id: requestId 
      }
    });
  }
}

/**
 * GET /v1/auth/social/apple/authorize
 * Start Apple Sign-In flow
 */
export async function appleAuthorizeHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Rate limiting
    const rateLimitResult = await checkRateLimit(
      'global',
      `oauth:${clientIP}`,
      OAUTH_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      return createResponse(429, {
        error: { 
          code: 'RATE_LIMITED', 
          message: 'Too many requests',
          request_id: requestId 
        }
      });
    }

    // Get realm_id from query params
    const realmId = event.queryStringParameters?.realm_id;
    if (!realmId) {
      return createResponse(400, {
        error: { 
          code: 'INVALID_REQUEST', 
          message: 'realm_id is required',
          request_id: requestId 
        }
      });
    }

    // redirect_url is REQUIRED - Clinisyn must provide their callback URL
    const redirectUrl = event.queryStringParameters?.redirect_url;
    if (!redirectUrl) {
      return createResponse(400, {
        error: { 
          code: 'INVALID_REQUEST', 
          message: 'redirect_url is required. Example: ?realm_id=clinisyn&redirect_url=http://localhost:3000/auth/callback',
          request_id: requestId 
        }
      });
    }

    // TODO: Validate redirect_url against realm's allowed_redirect_uris

    // Get OAuth config for realm
    const config = await getRealmOAuthConfig(realmId, 'apple');
    if (!config) {
      return createResponse(400, {
        error: { 
          code: 'OAUTH_NOT_CONFIGURED', 
          message: 'Apple Sign-In is not configured for this realm',
          request_id: requestId 
        }
      });
    }

    // Generate nonce
    const nonce = generateNonce();

    // Create state with redirect_url
    const state: OAuthState = {
      realmId,
      nonce,
      redirectUrl,
      timestamp: Date.now()
    };

    // Generate authorization URL
    const authUrl = generateAppleAuthorizationURL(config, state);

    await logSecurityEvent({
      event_type: 'oauth_authorize_started',
      ip_address: clientIP,
      realm_id: realmId,
      details: { provider: 'apple' }
    });

    // Redirect to Apple
    return createRedirectResponse(authUrl);

  } catch (error) {
    console.error('Apple authorize error:', error);
    return createResponse(500, {
      error: { 
        code: 'INTERNAL_ERROR', 
        message: 'An unexpected error occurred',
        request_id: requestId 
      }
    });
  }
}

/**
 * POST /v1/auth/social/apple/callback
 * Handle Apple Sign-In callback (Apple uses POST!)
 */
export async function appleCallbackHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);
  const userAgent = getUserAgent(event);

  try {
    // Parse form data (Apple sends as application/x-www-form-urlencoded)
    const body = event.body || '';
    const params = new URLSearchParams(body);

    // Validate callback parameters
    const validation = validateCallbackParams({
      code: params.get('code') || undefined,
      state: params.get('state') || undefined,
      error: params.get('error') || undefined,
      error_description: params.get('error_description') || undefined
    });

    if (!validation.valid || !validation.state) {
      await logSecurityEvent({
        event_type: 'oauth_callback_failed',
        ip_address: clientIP,
        details: { provider: 'apple', error: validation.error }
      });

      return createResponse(400, {
        error: { 
          code: 'OAUTH_ERROR', 
          message: validation.error || 'OAuth callback failed',
          request_id: requestId 
        }
      });
    }

    const { realmId, nonce, redirectUrl } = validation.state;

    // Get OAuth config
    const config = await getRealmOAuthConfig(realmId, 'apple');
    if (!config) {
      return createResponse(400, {
        error: { 
          code: 'OAUTH_NOT_CONFIGURED', 
          message: 'Apple Sign-In is not configured',
          request_id: requestId 
        }
      });
    }

    // Exchange code for tokens
    const tokens = await exchangeAppleCode(
      params.get('code')!,
      config,
      config.clientSecret
    );

    // Verify ID token
    if (!tokens.idToken) {
      return createResponse(400, {
        error: { 
          code: 'MISSING_ID_TOKEN', 
          message: 'Apple did not return ID token',
          request_id: requestId 
        }
      });
    }

    const idTokenResult = await verifyIDToken(
      tokens.idToken,
      'apple',
      config.clientId,
      nonce
    );

    if (!idTokenResult.valid || !idTokenResult.claims) {
      return createResponse(400, {
        error: { 
          code: 'INVALID_ID_TOKEN', 
          message: idTokenResult.error || 'ID token verification failed',
          request_id: requestId 
        }
      });
    }

    const claims = idTokenResult.claims;
    
    // Apple may provide user info only on first sign-in
    const userJson = params.get('user');
    let userName: { firstName?: string; lastName?: string } = {};
    if (userJson) {
      try {
        const userData = JSON.parse(userJson);
        userName = {
          firstName: userData.name?.firstName,
          lastName: userData.name?.lastName
        };
      } catch {
        // Ignore parse errors
      }
    }

    // Email might be a relay address (privaterelay.appleid.com)
    const email = claims.email;
    if (!email) {
      return createResponse(400, {
        error: { 
          code: 'MISSING_EMAIL', 
          message: 'Email not provided by Apple',
          request_id: requestId 
        }
      });
    }

    // Find or create user
    const existingUser = await findUserByEmail(realmId, email);
    let isNewUser = false;
    let userId: string;
    let userEmail: string;
    let userProfile: User['profile'] | UserResponse['profile'];

    if (!existingUser) {
      const newUser = await createUser({
        realm_id: realmId,
        email,
        password: '',
        profile: {
          first_name: userName.firstName,
          last_name: userName.lastName,
          metadata: {
            oauth_provider: 'apple',
            oauth_id: claims.sub,
            is_private_relay: email.includes('privaterelay.appleid.com')
          }
        }
      });
      isNewUser = true;
      userId = newUser.id;
      userEmail = newUser.email;
      userProfile = newUser.profile;
    } else {
      userId = existingUser.id;
      userEmail = existingUser.email;
      userProfile = existingUser.profile;
    }

    // Generate Zalt.io tokens
    const tokenPair = await generateTokenPair(
      userId,
      realmId,
      userEmail
    );

    // Create session
    await createSession(
      {
        user_id: userId,
        realm_id: realmId,
        ip_address: clientIP,
        user_agent: userAgent
      },
      tokenPair.access_token,
      tokenPair.refresh_token,
      7 * 24 * 60 * 60
    );

    await logSecurityEvent({
      event_type: isNewUser ? 'oauth_register_success' : 'oauth_login_success',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId,
      details: { provider: 'apple' }
    });

    // ALWAYS redirect to Clinisyn's callback URL with tokens
    if (!redirectUrl) {
      return createResponse(400, {
        error: { 
          code: 'MISSING_REDIRECT_URL', 
          message: 'OAuth session missing redirect URL',
          request_id: requestId 
        }
      });
    }

    const redirectParams = new URLSearchParams({
      access_token: tokenPair.access_token,
      refresh_token: tokenPair.refresh_token,
      expires_in: tokenPair.expires_in.toString(),
      token_type: 'Bearer'
    });
    return createRedirectResponse(`${redirectUrl}?${redirectParams.toString()}`);

  } catch (error) {
    console.error('Apple callback error:', error);

    await logSecurityEvent({
      event_type: 'oauth_callback_error',
      ip_address: clientIP,
      details: { provider: 'apple', error: (error as Error).message }
    });

    return createResponse(500, {
      error: { 
        code: 'INTERNAL_ERROR', 
        message: 'An unexpected error occurred',
        request_id: requestId 
      }
    });
  }
}

/**
 * Main Lambda handler - routes to appropriate function based on path
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const path = event.path || '';
  const method = event.httpMethod || '';

  console.log(`Social Login Handler: ${method} ${path}`);

  // Route based on path
  if (path.includes('/google/authorize') && method === 'GET') {
    return googleAuthorizeHandler(event);
  }
  
  if (path.includes('/google/callback') && method === 'GET') {
    return googleCallbackHandler(event);
  }
  
  if (path.includes('/apple/authorize') && method === 'GET') {
    return appleAuthorizeHandler(event);
  }
  
  if (path.includes('/apple/callback') && method === 'POST') {
    return appleCallbackHandler(event);
  }

  // Unknown route
  return createResponse(404, {
    error: {
      code: 'NOT_FOUND',
      message: 'Endpoint not found'
    }
  });
}
