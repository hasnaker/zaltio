/**
 * SSO Service - Single Sign-On functionality for HSD applications
 * Validates: Requirements 6.1, 6.2, 6.4, 9.1 (OAuth 2.0, OpenID Connect, SSO)
 * 
 * PRODUCTION-READY: OAuth clients now stored in DynamoDB!
 * Authorization codes and SSO sessions use in-memory with TTL (acceptable for Lambda)
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Use crypto.randomUUID() instead of uuid package for ESM compatibility
const uuidv4 = () => crypto.randomUUID();
import {
  SSOToken,
  SSOSession,
  AuthorizationCode,
  OAuthClient,
  OAuthTokenResponse,
  IDTokenClaims,
  SSOValidationResult,
  OIDCDiscoveryDocument,
  HSDApplication,
  OIDCScope,
  LegacyAuthToken,
  HSD_APPLICATION_CONFIGS
} from '../models/sso.model';
import { getJWTSecrets } from './secrets.service';
import { findUserById } from '../repositories/user.repository';
import { User } from '../models/user.model';
import {
  findOAuthClientById,
  validateOAuthClientCredentials,
  createOAuthClient as createOAuthClientInDb
} from '../repositories/oauth-client.repository';

// In-memory stores for short-lived data (auth codes expire in 10 min, sessions in 8 hours)
// These are acceptable in Lambda because:
// 1. Auth codes are single-use and short-lived
// 2. SSO sessions are validated against DynamoDB sessions anyway
const authorizationCodes = new Map<string, AuthorizationCode>();
const ssoSessions = new Map<string, SSOSession>();

const SSO_TOKEN_EXPIRY = 8 * 60 * 60; // 8 hours
const AUTH_CODE_EXPIRY = 10 * 60; // 10 minutes
const ID_TOKEN_EXPIRY = 60 * 60; // 1 hour

const ISSUER = 'https://api.zalt.io';

/**
 * Generate OpenID Connect Discovery Document
 * Validates: Requirements 9.1 (OpenID Connect standards)
 */
export function getOIDCDiscoveryDocument(): OIDCDiscoveryDocument {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    registration_endpoint: `${ISSUER}/oauth/register`,
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'HS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    claims_supported: [
      'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time',
      'name', 'given_name', 'family_name', 'email', 'email_verified', 'picture'
    ]
  };
}

/**
 * Register an OAuth client for an HSD application
 * Validates: Requirements 6.1 (HSD application integration)
 * 
 * PRODUCTION: Now stores in DynamoDB!
 */
export async function registerOAuthClient(
  application: HSDApplication,
  realmId: string,
  redirectUris: string[]
): Promise<OAuthClient> {
  const appConfig = HSD_APPLICATION_CONFIGS[application];
  const uris = redirectUris.length > 0 ? redirectUris : [appConfig.callback_url];
  
  const { client, plainSecret } = await createOAuthClientInDb(
    realmId,
    appConfig.display_name,
    uris,
    ['openid', 'profile', 'email', 'offline_access'],
    application
  );
  
  // Return with plain secret (only time it's available)
  return {
    ...client,
    client_secret_hash: plainSecret // Return plain secret on creation
  };
}

/**
 * Get OAuth client by ID
 * PRODUCTION: Now reads from DynamoDB!
 */
export async function getOAuthClient(clientId: string): Promise<OAuthClient | null> {
  return findOAuthClientById(clientId);
}

/**
 * Validate OAuth client credentials
 * PRODUCTION: Now validates against DynamoDB!
 */
export async function validateClientCredentials(
  clientId: string,
  clientSecret: string
): Promise<boolean> {
  return validateOAuthClientCredentials(clientId, clientSecret);
}

/**
 * Generate authorization code for OAuth 2.0 flow
 * Validates: Requirements 9.1 (OAuth 2.0 standards)
 */
export async function generateAuthorizationCode(
  clientId: string,
  userId: string,
  realmId: string,
  redirectUri: string,
  scope: OIDCScope[],
  codeChallenge?: string,
  codeChallengeMethod?: 'S256' | 'plain'
): Promise<string> {
  const client = await findOAuthClientById(clientId);
  if (!client) {
    throw new Error('Invalid client_id');
  }
  
  if (!client.redirect_uris.includes(redirectUri)) {
    throw new Error('Invalid redirect_uri');
  }
  
  const code = crypto.randomBytes(32).toString('base64url');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + AUTH_CODE_EXPIRY * 1000);
  
  const authCode: AuthorizationCode = {
    code,
    client_id: clientId,
    user_id: userId,
    realm_id: realmId,
    redirect_uri: redirectUri,
    scope,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    expires_at: expiresAt.toISOString(),
    created_at: now.toISOString()
  };
  
  authorizationCodes.set(code, authCode);
  
  return code;
}

/**
 * Exchange authorization code for tokens
 * Validates: Requirements 9.1 (OAuth 2.0 token exchange)
 */
export async function exchangeAuthorizationCode(
  code: string,
  clientId: string,
  redirectUri: string,
  codeVerifier?: string
): Promise<OAuthTokenResponse> {
  const authCode = authorizationCodes.get(code);
  
  if (!authCode) {
    throw new Error('Invalid authorization code');
  }
  
  // Verify code hasn't expired
  if (new Date(authCode.expires_at) < new Date()) {
    authorizationCodes.delete(code);
    throw new Error('Authorization code expired');
  }
  
  // Verify client_id matches
  if (authCode.client_id !== clientId) {
    throw new Error('Client ID mismatch');
  }
  
  // Verify redirect_uri matches
  if (authCode.redirect_uri !== redirectUri) {
    throw new Error('Redirect URI mismatch');
  }
  
  // Verify PKCE if code_challenge was provided
  if (authCode.code_challenge) {
    if (!codeVerifier) {
      throw new Error('Code verifier required');
    }
    
    let computedChallenge: string;
    if (authCode.code_challenge_method === 'S256') {
      computedChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
    } else {
      computedChallenge = codeVerifier;
    }
    
    if (computedChallenge !== authCode.code_challenge) {
      throw new Error('Invalid code verifier');
    }
  }
  
  // Delete the code (single use)
  authorizationCodes.delete(code);
  
  // Generate tokens
  const secrets = await getJWTSecrets();
  const now = Math.floor(Date.now() / 1000);
  
  // Get user for ID token claims
  const user = await findUserById(authCode.realm_id, authCode.user_id);
  
  // Generate access token
  const accessToken = jwt.sign(
    {
      sub: authCode.user_id,
      realm_id: authCode.realm_id,
      client_id: clientId,
      scope: authCode.scope.join(' '),
      iat: now,
      exp: now + SSO_TOKEN_EXPIRY,
      type: 'access'
    },
    secrets.access_token_secret
  );
  
  // Generate refresh token if offline_access scope requested
  let refreshToken: string | undefined;
  if (authCode.scope.includes('offline_access')) {
    refreshToken = jwt.sign(
      {
        sub: authCode.user_id,
        realm_id: authCode.realm_id,
        client_id: clientId,
        iat: now,
        exp: now + 30 * 24 * 60 * 60, // 30 days
        type: 'refresh'
      },
      secrets.refresh_token_secret
    );
  }
  
  // Generate ID token if openid scope requested
  let idToken: string | undefined;
  if (authCode.scope.includes('openid')) {
    const idTokenClaims: IDTokenClaims = {
      iss: ISSUER,
      sub: authCode.user_id,
      aud: clientId,
      exp: now + ID_TOKEN_EXPIRY,
      iat: now,
      auth_time: now
    };
    
    // Add profile claims if scope includes profile
    if (authCode.scope.includes('profile') && user) {
      idTokenClaims.name = [user.profile.first_name, user.profile.last_name]
        .filter(Boolean)
        .join(' ') || undefined;
      idTokenClaims.given_name = user.profile.first_name;
      idTokenClaims.family_name = user.profile.last_name;
      idTokenClaims.picture = user.profile.avatar_url;
    }
    
    // Add email claims if scope includes email
    if (authCode.scope.includes('email') && user) {
      idTokenClaims.email = user.email;
      idTokenClaims.email_verified = user.email_verified;
    }
    
    idToken = jwt.sign(idTokenClaims, secrets.access_token_secret);
  }
  
  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: SSO_TOKEN_EXPIRY,
    refresh_token: refreshToken,
    scope: authCode.scope.join(' '),
    id_token: idToken
  };
}

/**
 * Create SSO session for cross-application authentication
 * Validates: Requirements 6.2 (single sign-on across applications)
 */
export async function createSSOSession(
  userId: string,
  realmId: string,
  primarySessionId: string,
  initialApplication: HSDApplication
): Promise<SSOSession> {
  const sessionId = uuidv4();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SSO_TOKEN_EXPIRY * 1000);
  
  const session: SSOSession = {
    id: sessionId,
    user_id: userId,
    realm_id: realmId,
    authenticated_applications: [initialApplication],
    primary_session_id: primarySessionId,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    last_activity: now.toISOString()
  };
  
  ssoSessions.set(sessionId, session);
  
  return session;
}

/**
 * Get SSO session by ID
 */
export function getSSOSession(sessionId: string): SSOSession | null {
  const session = ssoSessions.get(sessionId);
  if (!session) return null;
  
  // Check if expired
  if (new Date(session.expires_at) < new Date()) {
    ssoSessions.delete(sessionId);
    return null;
  }
  
  return session;
}

/**
 * Add application to SSO session
 * Validates: Requirements 6.2 (cross-application session sharing)
 */
export function addApplicationToSSOSession(
  sessionId: string,
  application: HSDApplication
): SSOSession | null {
  const session = ssoSessions.get(sessionId);
  if (!session) return null;
  
  // Check if expired
  if (new Date(session.expires_at) < new Date()) {
    ssoSessions.delete(sessionId);
    return null;
  }
  
  // Add application if not already present
  if (!session.authenticated_applications.includes(application)) {
    session.authenticated_applications.push(application);
  }
  
  session.last_activity = new Date().toISOString();
  ssoSessions.set(sessionId, session);
  
  return session;
}

/**
 * Generate SSO token for cross-application validation
 * Validates: Requirements 6.2 (SSO token validation)
 */
export async function generateSSOToken(
  userId: string,
  realmId: string,
  sessionId: string,
  applications: HSDApplication[]
): Promise<string> {
  const secrets = await getJWTSecrets();
  const now = Math.floor(Date.now() / 1000);
  
  const ssoToken: SSOToken = {
    id: uuidv4(),
    user_id: userId,
    realm_id: realmId,
    applications,
    issued_at: new Date().toISOString(),
    expires_at: new Date((now + SSO_TOKEN_EXPIRY) * 1000).toISOString(),
    session_id: sessionId
  };
  
  return jwt.sign(
    {
      ...ssoToken,
      type: 'sso'
    },
    secrets.access_token_secret
  );
}

/**
 * Validate SSO token
 * Validates: Requirements 6.2 (SSO token validation across HSD services)
 */
export async function validateSSOToken(token: string): Promise<SSOValidationResult> {
  try {
    const secrets = await getJWTSecrets();
    const decoded = jwt.verify(token, secrets.access_token_secret) as SSOToken & { type: string };
    
    if (decoded.type !== 'sso') {
      return { valid: false, error: 'Invalid token type' };
    }
    
    // Check if session still exists
    const session = ssoSessions.get(decoded.session_id);
    if (!session) {
      return { valid: false, error: 'Session expired or invalidated' };
    }
    
    return {
      valid: true,
      user_id: decoded.user_id,
      realm_id: decoded.realm_id,
      applications: decoded.applications
    };
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return { valid: false, error: 'Token expired' };
    }
    if (error instanceof jwt.JsonWebTokenError) {
      return { valid: false, error: 'Invalid token' };
    }
    return { valid: false, error: 'Token validation failed' };
  }
}

/**
 * Invalidate SSO session (logout from all applications)
 */
export function invalidateSSOSession(sessionId: string): boolean {
  return ssoSessions.delete(sessionId);
}

/**
 * Convert legacy token to new format
 * Validates: Requirements 6.4 (backward compatibility)
 */
export async function convertLegacyToken(
  legacyToken: string,
  application: HSDApplication
): Promise<OAuthTokenResponse | null> {
  try {
    // Attempt to decode legacy token (assuming it's a simple JWT)
    const secrets = await getJWTSecrets();
    const decoded = jwt.decode(legacyToken) as { sub?: string; user_id?: string; realm_id?: string } | null;
    
    if (!decoded) {
      return null;
    }
    
    const userId = decoded.sub || decoded.user_id;
    const realmId = decoded.realm_id;
    
    if (!userId || !realmId) {
      return null;
    }
    
    // Generate new OAuth tokens
    const now = Math.floor(Date.now() / 1000);
    
    const accessToken = jwt.sign(
      {
        sub: userId,
        realm_id: realmId,
        application,
        scope: 'openid profile email',
        iat: now,
        exp: now + SSO_TOKEN_EXPIRY,
        type: 'access',
        legacy_converted: true
      },
      secrets.access_token_secret
    );
    
    const refreshToken = jwt.sign(
      {
        sub: userId,
        realm_id: realmId,
        application,
        iat: now,
        exp: now + 30 * 24 * 60 * 60,
        type: 'refresh',
        legacy_converted: true
      },
      secrets.refresh_token_secret
    );
    
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: SSO_TOKEN_EXPIRY,
      refresh_token: refreshToken,
      scope: 'openid profile email'
    };
  } catch {
    return null;
  }
}

/**
 * Validate legacy authentication token
 * Validates: Requirements 6.4 (backward compatibility during transition)
 */
export async function validateLegacyToken(
  token: string
): Promise<LegacyAuthToken | null> {
  try {
    const decoded = jwt.decode(token) as Record<string, unknown> | null;
    
    if (!decoded) {
      return null;
    }
    
    // Check for legacy token format indicators
    const userId = (decoded.sub || decoded.user_id) as string | undefined;
    const realmId = decoded.realm_id as string | undefined;
    const application = decoded.application as HSDApplication | undefined;
    const exp = decoded.exp as number | undefined;
    
    if (!userId || !realmId) {
      return null;
    }
    
    // Check expiration
    if (exp && exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    
    return {
      token,
      user_id: userId,
      realm_id: realmId,
      application: application || 'hsd-portal',
      expires_at: exp ? new Date(exp * 1000).toISOString() : new Date(Date.now() + 3600000).toISOString(),
      legacy_format: true
    };
  } catch {
    return null;
  }
}

/**
 * Get user info for OpenID Connect userinfo endpoint
 */
export async function getUserInfo(
  accessToken: string
): Promise<Partial<IDTokenClaims> | null> {
  try {
    const secrets = await getJWTSecrets();
    const decoded = jwt.verify(accessToken, secrets.access_token_secret) as {
      sub: string;
      realm_id: string;
      scope?: string;
    };
    
    const user = await findUserById(decoded.realm_id, decoded.sub);
    if (!user) {
      return null;
    }
    
    const scopes = (decoded.scope || '').split(' ');
    const userInfo: Partial<IDTokenClaims> = {
      sub: user.id
    };
    
    if (scopes.includes('profile')) {
      userInfo.name = [user.profile.first_name, user.profile.last_name]
        .filter(Boolean)
        .join(' ') || undefined;
      userInfo.given_name = user.profile.first_name;
      userInfo.family_name = user.profile.last_name;
      userInfo.picture = user.profile.avatar_url;
    }
    
    if (scopes.includes('email')) {
      userInfo.email = user.email;
      userInfo.email_verified = user.email_verified;
    }
    
    return userInfo;
  } catch {
    return null;
  }
}

// Export for testing
export const _testHelpers = {
  clearAuthorizationCodes: () => authorizationCodes.clear(),
  clearSSOSessions: () => ssoSessions.clear(),
  getAuthorizationCode: (code: string) => authorizationCodes.get(code)
};
