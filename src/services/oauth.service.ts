/**
 * OAuth 2.0 + PKCE Service
 * Validates: Requirements 4.1 (Social Login)
 * 
 * IMPORTANT: OAuth credentials belong to REALM (customer)
 * - Google shows "Clinisyn" not "Zalt.io"
 * - Each realm has its own OAuth app credentials
 * 
 * Security:
 * - PKCE for authorization code flow
 * - State parameter encrypted with realm_id
 * - Nonce for ID token replay protection
 */

import crypto from 'crypto';

/**
 * OAuth Provider Configuration
 */
export interface OAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
}

/**
 * Realm OAuth Configuration
 */
export interface RealmOAuthConfig {
  google?: OAuthProviderConfig;
  apple?: OAuthProviderConfig;
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
 * OAuth State (encrypted in URL)
 */
export interface OAuthState {
  realmId: string;
  nonce: string;
  redirectUrl?: string;
  timestamp: number;
}

/**
 * OAuth Token Response
 */
export interface OAuthTokenResponse {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType: string;
  expiresIn: number;
  scope?: string;
}

/**
 * Decoded ID Token Claims
 */
export interface IDTokenClaims {
  iss: string;           // Issuer
  sub: string;           // Subject (user ID)
  aud: string;           // Audience (client ID)
  exp: number;           // Expiration
  iat: number;           // Issued at
  nonce?: string;        // Nonce for replay protection
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
}

/**
 * OAuth Provider URLs
 */
export const OAUTH_PROVIDERS = {
  google: {
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    userInfoEndpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    issuer: 'https://accounts.google.com'
  },
  apple: {
    authorizationEndpoint: 'https://appleid.apple.com/auth/authorize',
    tokenEndpoint: 'https://appleid.apple.com/auth/token',
    jwksUri: 'https://appleid.apple.com/auth/keys',
    issuer: 'https://appleid.apple.com'
  }
} as const;

// State encryption key (in production, use AWS KMS)
const STATE_ENCRYPTION_KEY = process.env.OAUTH_STATE_KEY || crypto.randomBytes(32).toString('hex');
const STATE_EXPIRY_SECONDS = 600; // 10 minutes

/**
 * Generate PKCE code verifier and challenge
 * RFC 7636 compliant
 */
export function generatePKCE(): PKCEParams {
  // Generate 32 bytes of random data for code verifier
  // Base64url encoding of 32 bytes = 43 characters (minimum per RFC 7636)
  const codeVerifier = crypto.randomBytes(32)
    .toString('base64url');

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
 * Generate cryptographic nonce for ID token
 */
export function generateNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Encrypt OAuth state parameter
 */
export function encryptState(state: OAuthState): string {
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
 * Decrypt OAuth state parameter
 */
export function decryptState(encryptedState: string): OAuthState | null {
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
    
    const state = JSON.parse(decrypted.toString('utf8')) as OAuthState;
    
    // Check expiry
    if (Date.now() - state.timestamp > STATE_EXPIRY_SECONDS * 1000) {
      return null;
    }
    
    return state;
  } catch {
    return null;
  }
}

/**
 * Generate Google OAuth authorization URL
 */
export function generateGoogleAuthorizationURL(
  config: OAuthProviderConfig,
  state: OAuthState,
  pkce: PKCEParams
): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: config.scopes.join(' '),
    state: encryptState(state),
    code_challenge: pkce.codeChallenge,
    code_challenge_method: pkce.codeChallengeMethod,
    nonce: state.nonce,
    access_type: 'offline',  // Get refresh token
    prompt: 'consent'        // Always show consent screen
  });

  return `${OAUTH_PROVIDERS.google.authorizationEndpoint}?${params.toString()}`;
}

/**
 * Generate Apple OAuth authorization URL
 */
export function generateAppleAuthorizationURL(
  config: OAuthProviderConfig,
  state: OAuthState
): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code id_token',
    scope: config.scopes.join(' '),
    state: encryptState(state),
    nonce: state.nonce,
    response_mode: 'form_post'  // Apple uses POST for callback
  });

  return `${OAUTH_PROVIDERS.apple.authorizationEndpoint}?${params.toString()}`;
}

/**
 * Exchange authorization code for tokens (Google)
 */
export async function exchangeGoogleCode(
  code: string,
  config: OAuthProviderConfig,
  codeVerifier: string
): Promise<OAuthTokenResponse> {
  const params = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    code_verifier: codeVerifier,
    grant_type: 'authorization_code',
    redirect_uri: config.redirectUri
  });

  const response = await fetch(OAUTH_PROVIDERS.google.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: params.toString()
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Google token exchange failed: ${error}`);
  }

  const data = await response.json() as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    token_type: string;
    expires_in: number;
    scope?: string;
  };
  
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    idToken: data.id_token,
    tokenType: data.token_type,
    expiresIn: data.expires_in,
    scope: data.scope
  };
}

/**
 * Exchange authorization code for tokens (Apple)
 */
export async function exchangeAppleCode(
  code: string,
  config: OAuthProviderConfig,
  clientSecret: string  // Apple requires JWT client secret
): Promise<OAuthTokenResponse> {
  const params = new URLSearchParams({
    client_id: config.clientId,
    client_secret: clientSecret,
    code,
    grant_type: 'authorization_code',
    redirect_uri: config.redirectUri
  });

  const response = await fetch(OAUTH_PROVIDERS.apple.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: params.toString()
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Apple token exchange failed: ${error}`);
  }

  const data = await response.json() as {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    token_type: string;
    expires_in: number;
  };
  
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    idToken: data.id_token,
    tokenType: data.token_type,
    expiresIn: data.expires_in
  };
}

/**
 * Decode JWT without verification (for extracting claims)
 * Use verifyIDToken for actual verification
 */
export function decodeJWT(token: string): IDTokenClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload) as IDTokenClaims;
  } catch {
    return null;
  }
}

/**
 * Verify ID token signature and claims
 * In production, fetch JWKS and verify signature
 */
export async function verifyIDToken(
  idToken: string,
  provider: 'google' | 'apple',
  expectedClientId: string,
  expectedNonce?: string
): Promise<{ valid: boolean; claims?: IDTokenClaims; error?: string }> {
  const claims = decodeJWT(idToken);
  
  if (!claims) {
    return { valid: false, error: 'Invalid token format' };
  }

  // Verify issuer
  const expectedIssuer = OAUTH_PROVIDERS[provider].issuer;
  if (claims.iss !== expectedIssuer) {
    return { valid: false, error: `Invalid issuer: expected ${expectedIssuer}` };
  }

  // Verify audience (client ID)
  if (claims.aud !== expectedClientId) {
    return { valid: false, error: 'Invalid audience' };
  }

  // Verify expiration
  if (claims.exp * 1000 < Date.now()) {
    return { valid: false, error: 'Token expired' };
  }

  // Verify nonce if provided
  if (expectedNonce && claims.nonce !== expectedNonce) {
    return { valid: false, error: 'Invalid nonce' };
  }

  // TODO: In production, verify signature using JWKS
  // const jwks = await fetchJWKS(OAUTH_PROVIDERS[provider].jwksUri);
  // const verified = verifySignature(idToken, jwks);

  return { valid: true, claims };
}

/**
 * Get user info from Google
 */
export async function getGoogleUserInfo(accessToken: string): Promise<{
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  givenName?: string;
  familyName?: string;
  picture?: string;
}> {
  const response = await fetch(OAUTH_PROVIDERS.google.userInfoEndpoint, {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });

  if (!response.ok) {
    throw new Error('Failed to fetch Google user info');
  }

  const data = await response.json() as {
    sub: string;
    email: string;
    email_verified: boolean;
    name?: string;
    given_name?: string;
    family_name?: string;
    picture?: string;
  };
  
  return {
    id: data.sub,
    email: data.email,
    emailVerified: data.email_verified,
    name: data.name,
    givenName: data.given_name,
    familyName: data.family_name,
    picture: data.picture
  };
}

/**
 * Generate Apple client secret (JWT)
 * Apple requires a JWT signed with your private key using ES256
 */
export function generateAppleClientSecret(
  teamId: string,
  clientId: string,
  keyId: string,
  privateKey: string
): string {
  const header = {
    alg: 'ES256',
    kid: keyId
  };

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: teamId,
    iat: now,
    exp: now + 15777000, // 6 months max
    aud: 'https://appleid.apple.com',
    sub: clientId
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${headerB64}.${payloadB64}`;

  // Sign with ES256 (ECDSA P-256 + SHA-256)
  const sign = crypto.createSign('SHA256');
  sign.update(signingInput);
  sign.end();

  // Convert PEM private key - handle escaped newlines
  const formattedKey = privateKey.replace(/\\n/g, '\n');
  
  // Sign and get DER format signature
  const derSignature = sign.sign(formattedKey);
  
  // Convert DER to raw R||S format (64 bytes) for ES256
  // DER format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
  const signature = derToRaw(derSignature);
  const signatureB64 = signature.toString('base64url');

  return `${signingInput}.${signatureB64}`;
}

/**
 * Convert DER signature to raw R||S format for ES256
 */
function derToRaw(derSignature: Buffer): Buffer {
  // DER structure: 0x30 [len] 0x02 [r-len] [r] 0x02 [s-len] [s]
  let offset = 2; // Skip 0x30 and total length
  
  // Read R
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature: expected 0x02 for R');
  }
  offset++;
  const rLen = derSignature[offset];
  offset++;
  let r = derSignature.slice(offset, offset + rLen);
  offset += rLen;
  
  // Read S
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature: expected 0x02 for S');
  }
  offset++;
  const sLen = derSignature[offset];
  offset++;
  let s = derSignature.slice(offset, offset + sLen);
  
  // Remove leading zeros (DER uses signed integers)
  if (r.length === 33 && r[0] === 0) r = r.slice(1);
  if (s.length === 33 && s[0] === 0) s = s.slice(1);
  
  // Pad to 32 bytes each
  const rPadded = Buffer.alloc(32);
  const sPadded = Buffer.alloc(32);
  r.copy(rPadded, 32 - r.length);
  s.copy(sPadded, 32 - s.length);
  
  return Buffer.concat([rPadded, sPadded]);
}

/**
 * Validate OAuth callback parameters
 */
export function validateCallbackParams(params: {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}): { valid: boolean; error?: string; state?: OAuthState } {
  if (params.error) {
    return { 
      valid: false, 
      error: params.error_description || params.error 
    };
  }

  if (!params.code) {
    return { valid: false, error: 'Missing authorization code' };
  }

  if (!params.state) {
    return { valid: false, error: 'Missing state parameter' };
  }

  const state = decryptState(params.state);
  if (!state) {
    return { valid: false, error: 'Invalid or expired state' };
  }

  return { valid: true, state };
}
