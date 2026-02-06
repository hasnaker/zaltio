/**
 * SSO Model - Single Sign-On data structures
 * Validates: Requirements 6.1, 6.2, 9.1 (OAuth 2.0, OpenID Connect, SSO)
 */

/**
 * Supported HSD applications for SSO integration
 */
export type HSDApplication = 
  | 'hsd-portal'
  | 'hsd-chat'
  | 'hsd-tasks'
  | 'hsd-docs'
  | 'hsd-crm';

/**
 * OAuth 2.0 Grant Types supported
 */
export type OAuthGrantType = 
  | 'authorization_code'
  | 'refresh_token'
  | 'client_credentials';

/**
 * OpenID Connect scopes
 */
export type OIDCScope = 
  | 'openid'
  | 'profile'
  | 'email'
  | 'offline_access';

/**
 * SSO Token for cross-application authentication
 */
export interface SSOToken {
  id: string;
  user_id: string;
  realm_id: string;
  applications: HSDApplication[];
  issued_at: string;
  expires_at: string;
  session_id: string;
}

/**
 * OAuth 2.0 Authorization Code
 */
export interface AuthorizationCode {
  code: string;
  client_id: string;
  user_id: string;
  realm_id: string;
  redirect_uri: string;
  scope: OIDCScope[];
  code_challenge?: string;
  code_challenge_method?: 'S256' | 'plain';
  expires_at: string;
  created_at: string;
}

/**
 * OAuth 2.0 Client Registration
 */
export interface OAuthClient {
  client_id: string;
  client_secret_hash: string;
  client_name: string;
  application: HSDApplication;
  redirect_uris: string[];
  allowed_scopes: OIDCScope[];
  grant_types: OAuthGrantType[];
  realm_id: string;
  created_at: string;
  updated_at: string;
}

/**
 * OpenID Connect ID Token Claims
 */
export interface IDTokenClaims {
  iss: string;           // Issuer
  sub: string;           // Subject (user_id)
  aud: string;           // Audience (client_id)
  exp: number;           // Expiration time
  iat: number;           // Issued at
  auth_time?: number;    // Authentication time
  nonce?: string;        // Nonce for replay protection
  acr?: string;          // Authentication context class reference
  amr?: string[];        // Authentication methods references
  azp?: string;          // Authorized party
  // Profile claims
  name?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
}

/**
 * OAuth 2.0 Token Response
 */
export interface OAuthTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
  id_token?: string;     // OpenID Connect
}

/**
 * OAuth 2.0 Authorization Request
 */
export interface AuthorizationRequest {
  response_type: 'code' | 'token' | 'id_token';
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: 'S256' | 'plain';
}

/**
 * OAuth 2.0 Token Request
 */
export interface TokenRequest {
  grant_type: OAuthGrantType;
  code?: string;
  redirect_uri?: string;
  client_id: string;
  client_secret?: string;
  refresh_token?: string;
  scope?: string;
  code_verifier?: string;
}

/**
 * SSO Session for cross-application sharing
 */
export interface SSOSession {
  id: string;
  user_id: string;
  realm_id: string;
  authenticated_applications: HSDApplication[];
  primary_session_id: string;
  created_at: string;
  expires_at: string;
  last_activity: string;
}

/**
 * Legacy authentication token for backward compatibility
 */
export interface LegacyAuthToken {
  token: string;
  user_id: string;
  realm_id: string;
  application: HSDApplication;
  expires_at: string;
  legacy_format: boolean;
}

/**
 * SSO Validation Result
 */
export interface SSOValidationResult {
  valid: boolean;
  user_id?: string;
  realm_id?: string;
  applications?: HSDApplication[];
  error?: string;
}

/**
 * OpenID Connect Discovery Document
 */
export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
  scopes_supported: OIDCScope[];
  response_types_supported: string[];
  grant_types_supported: OAuthGrantType[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  claims_supported: string[];
}

/**
 * HSD Application configuration for SSO
 */
export interface HSDApplicationConfig {
  application: HSDApplication;
  display_name: string;
  base_url: string;
  callback_url: string;
  logout_url: string;
  icon_url?: string;
}

/**
 * Default HSD application configurations
 */
export const HSD_APPLICATION_CONFIGS: Record<HSDApplication, HSDApplicationConfig> = {
  'hsd-portal': {
    application: 'hsd-portal',
    display_name: 'HSD Portal',
    base_url: 'https://portal.hsdcore.com',
    callback_url: 'https://portal.hsdcore.com/auth/callback',
    logout_url: 'https://portal.hsdcore.com/auth/logout'
  },
  'hsd-chat': {
    application: 'hsd-chat',
    display_name: 'HSD Chat',
    base_url: 'https://chat.hsdcore.com',
    callback_url: 'https://chat.hsdcore.com/auth/callback',
    logout_url: 'https://chat.hsdcore.com/auth/logout'
  },
  'hsd-tasks': {
    application: 'hsd-tasks',
    display_name: 'HSD Task Management',
    base_url: 'https://tasks.hsdcore.com',
    callback_url: 'https://tasks.hsdcore.com/auth/callback',
    logout_url: 'https://tasks.hsdcore.com/auth/logout'
  },
  'hsd-docs': {
    application: 'hsd-docs',
    display_name: 'HSD Docs',
    base_url: 'https://docs.hsdcore.com',
    callback_url: 'https://docs.hsdcore.com/auth/callback',
    logout_url: 'https://docs.hsdcore.com/auth/logout'
  },
  'hsd-crm': {
    application: 'hsd-crm',
    display_name: 'HSD CRM',
    base_url: 'https://crm.hsdcore.com',
    callback_url: 'https://crm.hsdcore.com/auth/callback',
    logout_url: 'https://crm.hsdcore.com/auth/logout'
  }
};
