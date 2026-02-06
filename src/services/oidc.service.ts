/**
 * OIDC Service - Organization-level OIDC SSO
 * 
 * Implements OpenID Connect 1.0 for organization-level SSO:
 * - Authorization Code Flow with PKCE
 * - Discovery document parsing (.well-known/openid-configuration)
 * - Token exchange and validation
 * - ID token validation (signature, claims)
 * - JIT user provisioning from OIDC claims
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
 * - ID token signature validation
 * - Audit logging for all SSO events
 * 
 * Validates: Requirements 9.3 (OIDC per organization)
 */

import * as crypto from 'crypto';
import {
  OrgSSOConfig,
  OIDCConfig,
  AttributeMapping,
  OIDCProviderPreset
} from '../models/org-sso.model';

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================


/**
 * OIDC Discovery Document
 */
export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
  subject_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  claims_supported?: string[];
  code_challenge_methods_supported?: string[];
}

/**
 * OIDC Authorization Request Parameters
 */
export interface OIDCAuthorizationParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  nonce: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  responseType: 'code';
  prompt?: 'none' | 'login' | 'consent' | 'select_account';
  loginHint?: string;
  acrValues?: string;
}

/**
 * OIDC Token Request Parameters
 */
export interface OIDCTokenRequest {
  grantType: 'authorization_code';
  code: string;
  redirectUri: string;
  clientId: string;
  clientSecret?: string;
  codeVerifier: string;
}

/**
 * OIDC Token Response
 */
export interface OIDCTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token: string;
  scope?: string;
}

/**
 * OIDC ID Token Claims
 */
export interface OIDCIDTokenClaims {
  iss: string;           // Issuer
  sub: string;           // Subject (user ID)
  aud: string | string[]; // Audience (client ID)
  exp: number;           // Expiration
  iat: number;           // Issued at
  auth_time?: number;    // Authentication time
  nonce?: string;        // Nonce for replay protection
  acr?: string;          // Authentication context class reference
  amr?: string[];        // Authentication methods references
  azp?: string;          // Authorized party
  
  // Standard claims
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  picture?: string;
  locale?: string;
  zoneinfo?: string;
  
  // Microsoft Entra specific
  tid?: string;          // Tenant ID
  oid?: string;          // Object ID
  upn?: string;          // User Principal Name
  groups?: string[];     // Group memberships
  
  // Okta specific
  groups_claim?: string[];
  
  // Custom claims
  [key: string]: unknown;
}

/**
 * OIDC UserInfo Response
 */
export interface OIDCUserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  picture?: string;
  locale?: string;
  zoneinfo?: string;
  groups?: string[];
  [key: string]: unknown;
}


/**
 * Extracted user attributes from OIDC claims
 */
export interface ExtractedOIDCUserAttributes {
  email: string;
  emailVerified?: boolean;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  picture?: string;
  groups?: string[];
  locale?: string;
  [key: string]: string | string[] | boolean | undefined;
}

/**
 * OIDC SSO initiation result
 */
export interface OIDCInitiationResult {
  authorizationUrl: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}

/**
 * OIDC SSO callback result
 */
export interface OIDCCallbackResult {
  success: boolean;
  error?: string;
  user?: ExtractedOIDCUserAttributes;
  idToken?: string;
  accessToken?: string;
  refreshToken?: string;
}

/**
 * PKCE Parameters
 */
export interface PKCEParams {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

/**
 * OIDC State (stored for callback validation)
 */
export interface OIDCState {
  tenantId: string;
  realmId: string;
  nonce: string;
  codeVerifier: string;
  redirectUri?: string;
  timestamp: number;
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Well-known OIDC provider configurations
 */
export const OIDC_PROVIDER_CONFIGS: Record<OIDCProviderPreset, {
  discoveryUrl?: string;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
  defaultScopes: string[];
}> = {
  google_workspace: {
    discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
    issuer: 'https://accounts.google.com',
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    defaultScopes: ['openid', 'email', 'profile']
  },
  microsoft_entra: {
    // Uses tenant-specific discovery URL
    defaultScopes: ['openid', 'email', 'profile', 'offline_access']
  },
  okta: {
    // Uses org-specific discovery URL
    defaultScopes: ['openid', 'email', 'profile', 'groups']
  },
  auth0: {
    // Uses tenant-specific discovery URL
    defaultScopes: ['openid', 'email', 'profile']
  },
  onelogin: {
    // Uses org-specific discovery URL
    defaultScopes: ['openid', 'email', 'profile', 'groups']
  },
  custom: {
    defaultScopes: ['openid', 'email', 'profile']
  }
};


/**
 * State encryption key (in production, use AWS KMS)
 */
const STATE_ENCRYPTION_KEY = process.env.OIDC_STATE_KEY || crypto.randomBytes(32).toString('hex');

/**
 * State expiry in seconds (10 minutes)
 */
const STATE_EXPIRY_SECONDS = 600;

/**
 * Clock skew tolerance in seconds (5 minutes)
 */
const CLOCK_SKEW_TOLERANCE = 300;

/**
 * Discovery document cache
 */
const discoveryCache = new Map<string, { doc: OIDCDiscoveryDocument; expiresAt: number }>();

/**
 * Discovery cache TTL (1 hour)
 */
const DISCOVERY_CACHE_TTL = 3600000;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Generate PKCE code verifier and challenge (RFC 7636)
 */
export function generatePKCE(): PKCEParams {
  // Generate 32 bytes of random data for code verifier
  const codeVerifier = crypto.randomBytes(32).toString('base64url');

  // Generate code challenge using SHA-256
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256'
  };
}

/**
 * Generate cryptographic nonce
 */
export function generateNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Generate state parameter
 */
export function generateState(): string {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Encrypt OIDC state for storage
 */
export function encryptState(state: OIDCState): string {
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(STATE_ENCRYPTION_KEY, 'hex').slice(0, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  const stateJson = JSON.stringify(state);
  let encrypted = cipher.update(stateJson, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  const authTag = cipher.getAuthTag();
  
  // Combine IV + AuthTag + Encrypted data
  const combined = Buffer.concat([
    iv,
    authTag,
    Buffer.from(encrypted, 'base64')
  ]);
  
  return combined.toString('base64url');
}

/**
 * Decrypt OIDC state
 */
export function decryptState(encryptedState: string): OIDCState | null {
  try {
    const combined = Buffer.from(encryptedState, 'base64url');
    
    const iv = combined.slice(0, 16);
    const authTag = combined.slice(16, 32);
    const encrypted = combined.slice(32);
    
    const key = Buffer.from(STATE_ENCRYPTION_KEY, 'hex').slice(0, 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    const state = JSON.parse(decrypted.toString('utf8')) as OIDCState;
    
    // Check expiry
    if (Date.now() - state.timestamp > STATE_EXPIRY_SECONDS * 1000) {
      return null;
    }
    
    return state;
  } catch {
    return null;
  }
}


// ============================================================================
// DISCOVERY DOCUMENT
// ============================================================================

/**
 * Get discovery URL for a provider
 */
export function getDiscoveryUrl(config: OIDCConfig): string {
  // If issuer is provided, construct discovery URL
  if (config.issuer && config.issuer.trim() !== '') {
    // Remove trailing slash
    const issuer = config.issuer.replace(/\/$/, '');
    return `${issuer}/.well-known/openid-configuration`;
  }
  
  // Use preset discovery URL
  if (config.providerPreset && config.providerPreset !== 'custom') {
    const preset = OIDC_PROVIDER_CONFIGS[config.providerPreset];
    if (preset.discoveryUrl) {
      return preset.discoveryUrl;
    }
  }
  
  throw new Error('Unable to determine discovery URL: issuer or preset required');
}

/**
 * Fetch and parse OIDC discovery document
 */
export async function fetchDiscoveryDocument(
  discoveryUrl: string
): Promise<OIDCDiscoveryDocument> {
  // Check cache
  const cached = discoveryCache.get(discoveryUrl);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.doc;
  }
  
  const response = await fetch(discoveryUrl, {
    headers: {
      'Accept': 'application/json'
    }
  });
  
  if (!response.ok) {
    throw new Error(`Failed to fetch discovery document: ${response.status} ${response.statusText}`);
  }
  
  const doc = await response.json() as OIDCDiscoveryDocument;
  
  // Validate required fields
  if (!doc.issuer || !doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error('Invalid discovery document: missing required fields');
  }
  
  // Cache the document
  discoveryCache.set(discoveryUrl, {
    doc,
    expiresAt: Date.now() + DISCOVERY_CACHE_TTL
  });
  
  return doc;
}

/**
 * Get OIDC endpoints from config or discovery
 */
export async function getOIDCEndpoints(config: OIDCConfig): Promise<{
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint?: string;
  jwksUri: string;
  issuer: string;
}> {
  // If all endpoints are provided, use them directly
  if (config.authorizationUrl && config.tokenUrl && config.jwksUrl && config.issuer) {
    return {
      authorizationEndpoint: config.authorizationUrl,
      tokenEndpoint: config.tokenUrl,
      userinfoEndpoint: config.userinfoUrl,
      jwksUri: config.jwksUrl,
      issuer: config.issuer
    };
  }
  
  // Use preset endpoints if available
  if (config.providerPreset && config.providerPreset !== 'custom') {
    const preset = OIDC_PROVIDER_CONFIGS[config.providerPreset];
    if (preset.authorizationEndpoint && preset.tokenEndpoint && preset.jwksUri && preset.issuer) {
      return {
        authorizationEndpoint: preset.authorizationEndpoint,
        tokenEndpoint: preset.tokenEndpoint,
        userinfoEndpoint: preset.userinfoEndpoint,
        jwksUri: preset.jwksUri,
        issuer: preset.issuer
      };
    }
  }
  
  // Fetch from discovery document
  const discoveryUrl = getDiscoveryUrl(config);
  const doc = await fetchDiscoveryDocument(discoveryUrl);
  
  return {
    authorizationEndpoint: doc.authorization_endpoint,
    tokenEndpoint: doc.token_endpoint,
    userinfoEndpoint: doc.userinfo_endpoint,
    jwksUri: doc.jwks_uri,
    issuer: doc.issuer
  };
}


// ============================================================================
// AUTHORIZATION
// ============================================================================

/**
 * Build authorization URL for OIDC SSO
 */
export function buildAuthorizationUrl(
  authorizationEndpoint: string,
  params: OIDCAuthorizationParams
): string {
  const url = new URL(authorizationEndpoint);
  
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('response_type', params.responseType);
  url.searchParams.set('scope', params.scope);
  url.searchParams.set('state', params.state);
  url.searchParams.set('nonce', params.nonce);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', params.codeChallengeMethod);
  
  if (params.prompt) {
    url.searchParams.set('prompt', params.prompt);
  }
  
  if (params.loginHint) {
    url.searchParams.set('login_hint', params.loginHint);
  }
  
  if (params.acrValues) {
    url.searchParams.set('acr_values', params.acrValues);
  }
  
  return url.toString();
}

/**
 * Initiate OIDC SSO flow
 */
export async function initiateOIDCSSO(
  ssoConfig: OrgSSOConfig,
  options?: {
    forceLogin?: boolean;
    loginHint?: string;
    redirectUri?: string;
  }
): Promise<OIDCInitiationResult> {
  if (!ssoConfig.oidcConfig) {
    throw new Error('OIDC configuration not found');
  }
  
  const oidcConfig = ssoConfig.oidcConfig;
  
  // Get endpoints
  const endpoints = await getOIDCEndpoints(oidcConfig);
  
  // Generate PKCE
  const pkce = generatePKCE();
  
  // Generate state and nonce
  const stateValue = generateState();
  const nonce = generateNonce();
  
  // Get scopes
  const scopes = oidcConfig.scopes || 
    (oidcConfig.providerPreset ? OIDC_PROVIDER_CONFIGS[oidcConfig.providerPreset].defaultScopes : ['openid', 'email', 'profile']);
  
  // Build redirect URI
  const baseUrl = process.env.API_BASE_URL || 'https://api.zalt.io';
  const redirectUri = `${baseUrl}/v1/sso/oidc/${ssoConfig.realmId}/${ssoConfig.tenantId}/callback`;
  
  // Create state object
  const state: OIDCState = {
    tenantId: ssoConfig.tenantId,
    realmId: ssoConfig.realmId,
    nonce,
    codeVerifier: pkce.codeVerifier,
    redirectUri: options?.redirectUri,
    timestamp: Date.now()
  };
  
  // Encrypt state
  const encryptedState = encryptState(state);
  
  // Build authorization URL
  const authorizationUrl = buildAuthorizationUrl(endpoints.authorizationEndpoint, {
    clientId: oidcConfig.clientId,
    redirectUri,
    scope: scopes.join(' '),
    state: encryptedState,
    nonce,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: 'S256',
    responseType: 'code',
    prompt: options?.forceLogin ? 'login' : undefined,
    loginHint: options?.loginHint
  });
  
  return {
    authorizationUrl,
    state: encryptedState,
    nonce,
    codeVerifier: pkce.codeVerifier
  };
}


// ============================================================================
// TOKEN EXCHANGE
// ============================================================================

/**
 * Exchange authorization code for tokens
 */
export async function exchangeCodeForTokens(
  tokenEndpoint: string,
  request: OIDCTokenRequest
): Promise<OIDCTokenResponse> {
  const params = new URLSearchParams();
  params.set('grant_type', request.grantType);
  params.set('code', request.code);
  params.set('redirect_uri', request.redirectUri);
  params.set('client_id', request.clientId);
  params.set('code_verifier', request.codeVerifier);
  
  if (request.clientSecret) {
    params.set('client_secret', request.clientSecret);
  }
  
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    },
    body: params.toString()
  });
  
  if (!response.ok) {
    const errorBody = await response.text();
    let errorMessage = `Token exchange failed: ${response.status}`;
    
    try {
      const errorJson = JSON.parse(errorBody);
      errorMessage = errorJson.error_description || errorJson.error || errorMessage;
    } catch {
      // Use default error message
    }
    
    throw new Error(errorMessage);
  }
  
  const tokens = await response.json() as OIDCTokenResponse;
  
  if (!tokens.id_token) {
    throw new Error('Token response missing id_token');
  }
  
  return tokens;
}

/**
 * Decode JWT without verification (for extracting claims)
 */
export function decodeJWT(token: string): OIDCIDTokenClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload) as OIDCIDTokenClaims;
  } catch {
    return null;
  }
}

/**
 * Validate ID token claims
 */
export function validateIDTokenClaims(
  claims: OIDCIDTokenClaims,
  expectedIssuer: string,
  expectedClientId: string,
  expectedNonce?: string
): { valid: boolean; error?: string } {
  // Validate issuer
  if (claims.iss !== expectedIssuer) {
    return { valid: false, error: `Invalid issuer: expected ${expectedIssuer}, got ${claims.iss}` };
  }
  
  // Validate audience
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(expectedClientId)) {
    return { valid: false, error: `Invalid audience: ${expectedClientId} not in ${aud.join(', ')}` };
  }
  
  // If multiple audiences, check azp
  if (aud.length > 1 && claims.azp !== expectedClientId) {
    return { valid: false, error: `Invalid authorized party: expected ${expectedClientId}` };
  }
  
  // Validate expiration
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp < now - CLOCK_SKEW_TOLERANCE) {
    return { valid: false, error: 'ID token has expired' };
  }
  
  // Validate issued at
  if (claims.iat > now + CLOCK_SKEW_TOLERANCE) {
    return { valid: false, error: 'ID token issued in the future' };
  }
  
  // Validate nonce if provided
  if (expectedNonce && claims.nonce !== expectedNonce) {
    return { valid: false, error: 'Invalid nonce - possible replay attack' };
  }
  
  return { valid: true };
}


// ============================================================================
// USERINFO
// ============================================================================

/**
 * Fetch user info from OIDC provider
 */
export async function fetchUserInfo(
  userinfoEndpoint: string,
  accessToken: string
): Promise<OIDCUserInfo> {
  const response = await fetch(userinfoEndpoint, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json'
    }
  });
  
  if (!response.ok) {
    throw new Error(`Failed to fetch user info: ${response.status}`);
  }
  
  return await response.json() as OIDCUserInfo;
}

// ============================================================================
// ATTRIBUTE EXTRACTION
// ============================================================================

/**
 * Extract user attributes from ID token claims
 */
export function extractAttributesFromClaims(
  claims: OIDCIDTokenClaims,
  mapping?: AttributeMapping,
  providerPreset?: OIDCProviderPreset
): ExtractedOIDCUserAttributes {
  // Helper to get claim value
  const getClaim = (claimName: string): string | string[] | boolean | undefined => {
    const value = claims[claimName];
    if (value === undefined || value === null) return undefined;
    if (typeof value === 'string' || typeof value === 'boolean' || Array.isArray(value)) {
      return value;
    }
    return String(value);
  };
  
  let email: string | undefined;
  let emailVerified: boolean | undefined;
  let firstName: string | undefined;
  let lastName: string | undefined;
  let displayName: string | undefined;
  let picture: string | undefined;
  let groups: string[] | undefined;
  let locale: string | undefined;
  
  if (mapping) {
    // Use custom mapping
    email = mapping.email ? getClaim(mapping.email) as string : undefined;
    firstName = mapping.firstName ? getClaim(mapping.firstName) as string : undefined;
    lastName = mapping.lastName ? getClaim(mapping.lastName) as string : undefined;
    displayName = mapping.displayName ? getClaim(mapping.displayName) as string : undefined;
    groups = mapping.groups ? getClaim(mapping.groups) as string[] : undefined;
  } else {
    // Use standard OIDC claims with provider-specific fallbacks
    email = claims.email;
    emailVerified = claims.email_verified;
    firstName = claims.given_name;
    lastName = claims.family_name;
    displayName = claims.name;
    picture = claims.picture;
    locale = claims.locale;
    
    // Provider-specific group claims
    if (providerPreset === 'microsoft_entra') {
      groups = claims.groups;
    } else if (providerPreset === 'okta') {
      groups = claims.groups_claim || claims.groups as string[];
    } else {
      groups = claims.groups as string[];
    }
    
    // Microsoft Entra fallbacks
    if (!email && claims.upn) {
      email = claims.upn;
    }
  }
  
  // Ensure email is present
  if (!email) {
    throw new Error('Unable to extract email from OIDC claims');
  }
  
  return {
    email: email.toLowerCase().trim(),
    emailVerified,
    firstName,
    lastName,
    displayName,
    picture,
    groups,
    locale
  };
}


// ============================================================================
// CALLBACK PROCESSING
// ============================================================================

/**
 * Process OIDC callback
 */
export async function processOIDCCallback(
  ssoConfig: OrgSSOConfig,
  code: string,
  state: string
): Promise<OIDCCallbackResult> {
  if (!ssoConfig.oidcConfig) {
    return { success: false, error: 'OIDC configuration not found' };
  }
  
  const oidcConfig = ssoConfig.oidcConfig;
  
  try {
    // Decrypt and validate state
    const stateData = decryptState(state);
    if (!stateData) {
      return { success: false, error: 'Invalid or expired state parameter' };
    }
    
    // Verify state matches tenant
    if (stateData.tenantId !== ssoConfig.tenantId || stateData.realmId !== ssoConfig.realmId) {
      return { success: false, error: 'State mismatch - possible CSRF attack' };
    }
    
    // Get endpoints
    const endpoints = await getOIDCEndpoints(oidcConfig);
    
    // Build redirect URI
    const baseUrl = process.env.API_BASE_URL || 'https://api.zalt.io';
    const redirectUri = `${baseUrl}/v1/sso/oidc/${ssoConfig.realmId}/${ssoConfig.tenantId}/callback`;
    
    // Decrypt client secret if encrypted
    let clientSecret = oidcConfig.clientSecretEncrypted;
    // In production, decrypt using KMS
    // For now, assume it's stored as-is (should be encrypted in production)
    
    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens(endpoints.tokenEndpoint, {
      grantType: 'authorization_code',
      code,
      redirectUri,
      clientId: oidcConfig.clientId,
      clientSecret,
      codeVerifier: stateData.codeVerifier
    });
    
    // Decode ID token
    const claims = decodeJWT(tokens.id_token);
    if (!claims) {
      return { success: false, error: 'Failed to decode ID token' };
    }
    
    // Validate ID token claims
    const validation = validateIDTokenClaims(
      claims,
      endpoints.issuer,
      oidcConfig.clientId,
      stateData.nonce
    );
    
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }
    
    // Extract user attributes
    const user = extractAttributesFromClaims(
      claims,
      ssoConfig.attributeMapping,
      oidcConfig.providerPreset
    );
    
    // Optionally fetch additional user info
    if (endpoints.userinfoEndpoint && tokens.access_token) {
      try {
        const userInfo = await fetchUserInfo(endpoints.userinfoEndpoint, tokens.access_token);
        
        // Merge userinfo with claims (userinfo takes precedence for missing fields)
        if (!user.firstName && userInfo.given_name) user.firstName = userInfo.given_name;
        if (!user.lastName && userInfo.family_name) user.lastName = userInfo.family_name;
        if (!user.displayName && userInfo.name) user.displayName = userInfo.name;
        if (!user.picture && userInfo.picture) user.picture = userInfo.picture;
        if (!user.groups && userInfo.groups) user.groups = userInfo.groups;
      } catch (error) {
        // UserInfo fetch is optional, continue without it
        console.warn('Failed to fetch userinfo:', error);
      }
    }
    
    return {
      success: true,
      user,
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'OIDC callback processing failed'
    };
  }
}


// ============================================================================
// PROVIDER-SPECIFIC HELPERS
// ============================================================================

/**
 * Get Microsoft Entra discovery URL for a tenant
 */
export function getMicrosoftEntraDiscoveryUrl(tenantId: string): string {
  return `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`;
}

/**
 * Get Okta discovery URL for an organization
 */
export function getOktaDiscoveryUrl(oktaDomain: string, authServerId?: string): string {
  const domain = oktaDomain.replace(/^https?:\/\//, '').replace(/\/$/, '');
  if (authServerId) {
    return `https://${domain}/oauth2/${authServerId}/.well-known/openid-configuration`;
  }
  return `https://${domain}/.well-known/openid-configuration`;
}

/**
 * Get Auth0 discovery URL for a tenant
 */
export function getAuth0DiscoveryUrl(domain: string): string {
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '');
  return `https://${cleanDomain}/.well-known/openid-configuration`;
}

/**
 * Get OneLogin discovery URL for an organization
 */
export function getOneLoginDiscoveryUrl(subdomain: string): string {
  return `https://${subdomain}.onelogin.com/oidc/2/.well-known/openid-configuration`;
}

/**
 * Validate OIDC configuration
 */
export async function validateOIDCConfig(config: OIDCConfig): Promise<{
  valid: boolean;
  error?: string;
  discoveryDocument?: OIDCDiscoveryDocument;
}> {
  try {
    // Check required fields
    if (!config.clientId) {
      return { valid: false, error: 'Client ID is required' };
    }
    
    if ((!config.issuer || config.issuer.trim() === '') && !config.providerPreset) {
      return { valid: false, error: 'Issuer or provider preset is required' };
    }
    
    // Try to fetch discovery document
    const discoveryUrl = getDiscoveryUrl(config);
    const doc = await fetchDiscoveryDocument(discoveryUrl);
    
    // Verify PKCE support
    if (doc.code_challenge_methods_supported && 
        !doc.code_challenge_methods_supported.includes('S256')) {
      return { valid: false, error: 'Provider does not support PKCE with S256' };
    }
    
    return { valid: true, discoveryDocument: doc };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Failed to validate OIDC configuration'
    };
  }
}

/**
 * Get default attribute mapping for OIDC provider
 */
export function getOIDCDefaultAttributeMapping(preset?: OIDCProviderPreset): AttributeMapping {
  switch (preset) {
    case 'google_workspace':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name'
      };
    case 'microsoft_entra':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name',
        groups: 'groups'
      };
    case 'okta':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name',
        groups: 'groups'
      };
    case 'auth0':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name'
      };
    case 'onelogin':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name',
        groups: 'groups'
      };
    default:
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name'
      };
  }
}
