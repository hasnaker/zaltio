/**
 * OIDC Service Tests
 * 
 * Tests for organization-level OIDC SSO functionality:
 * - PKCE generation
 * - State encryption/decryption
 * - Discovery document parsing
 * - Authorization URL building
 * - Token exchange
 * - ID token validation
 * - Attribute extraction
 * 
 * Validates: Requirements 9.3 (OIDC per organization)
 */

import {
  generatePKCE,
  generateNonce,
  generateState,
  encryptState,
  decryptState,
  buildAuthorizationUrl,
  decodeJWT,
  validateIDTokenClaims,
  extractAttributesFromClaims,
  getDiscoveryUrl,
  validateOIDCConfig,
  getOIDCDefaultAttributeMapping,
  getMicrosoftEntraDiscoveryUrl,
  getOktaDiscoveryUrl,
  getAuth0DiscoveryUrl,
  getOneLoginDiscoveryUrl,
  OIDCState,
  OIDCIDTokenClaims,
  OIDCAuthorizationParams
} from './oidc.service';

describe('OIDC Service', () => {
  describe('PKCE Generation', () => {
    it('should generate valid PKCE parameters', () => {
      const pkce = generatePKCE();
      
      expect(pkce.codeVerifier).toBeDefined();
      expect(pkce.codeChallenge).toBeDefined();
      expect(pkce.codeChallengeMethod).toBe('S256');
      
      // Code verifier should be base64url encoded
      expect(pkce.codeVerifier).toMatch(/^[A-Za-z0-9_-]+$/);
      
      // Code challenge should be base64url encoded
      expect(pkce.codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
    });
    
    it('should generate unique PKCE parameters each time', () => {
      const pkce1 = generatePKCE();
      const pkce2 = generatePKCE();
      
      expect(pkce1.codeVerifier).not.toBe(pkce2.codeVerifier);
      expect(pkce1.codeChallenge).not.toBe(pkce2.codeChallenge);
    });
  });
  
  describe('Nonce and State Generation', () => {
    it('should generate valid nonce', () => {
      const nonce = generateNonce();
      
      expect(nonce).toBeDefined();
      expect(nonce.length).toBe(32); // 16 bytes = 32 hex chars
      expect(nonce).toMatch(/^[a-f0-9]+$/);
    });
    
    it('should generate unique nonces', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      
      expect(nonce1).not.toBe(nonce2);
    });
    
    it('should generate valid state', () => {
      const state = generateState();
      
      expect(state).toBeDefined();
      expect(state.length).toBe(32);
      expect(state).toMatch(/^[a-f0-9]+$/);
    });
  });

  
  describe('State Encryption/Decryption', () => {
    it('should encrypt and decrypt state correctly', () => {
      const state: OIDCState = {
        tenantId: 'tenant_123',
        realmId: 'realm_456',
        nonce: 'test-nonce-123',
        codeVerifier: 'test-code-verifier',
        redirectUri: 'https://app.example.com/callback',
        timestamp: Date.now()
      };
      
      const encrypted = encryptState(state);
      expect(encrypted).toBeDefined();
      expect(encrypted).not.toContain('tenant_123'); // Should be encrypted
      
      const decrypted = decryptState(encrypted);
      expect(decrypted).not.toBeNull();
      expect(decrypted?.tenantId).toBe(state.tenantId);
      expect(decrypted?.realmId).toBe(state.realmId);
      expect(decrypted?.nonce).toBe(state.nonce);
      expect(decrypted?.codeVerifier).toBe(state.codeVerifier);
      expect(decrypted?.redirectUri).toBe(state.redirectUri);
    });
    
    it('should return null for invalid encrypted state', () => {
      const result = decryptState('invalid-encrypted-state');
      expect(result).toBeNull();
    });
    
    it('should return null for expired state', () => {
      const state: OIDCState = {
        tenantId: 'tenant_123',
        realmId: 'realm_456',
        nonce: 'test-nonce',
        codeVerifier: 'test-verifier',
        timestamp: Date.now() - 700000 // 11+ minutes ago (expired)
      };
      
      const encrypted = encryptState(state);
      const decrypted = decryptState(encrypted);
      
      expect(decrypted).toBeNull();
    });
    
    it('should handle state without optional fields', () => {
      const state: OIDCState = {
        tenantId: 'tenant_123',
        realmId: 'realm_456',
        nonce: 'test-nonce',
        codeVerifier: 'test-verifier',
        timestamp: Date.now()
      };
      
      const encrypted = encryptState(state);
      const decrypted = decryptState(encrypted);
      
      expect(decrypted).not.toBeNull();
      expect(decrypted?.redirectUri).toBeUndefined();
    });
  });
  
  describe('Authorization URL Building', () => {
    it('should build valid authorization URL with all parameters', () => {
      const params: OIDCAuthorizationParams = {
        clientId: 'client_123',
        redirectUri: 'https://api.zalt.io/callback',
        scope: 'openid email profile',
        state: 'encrypted-state',
        nonce: 'test-nonce',
        codeChallenge: 'code-challenge-value',
        codeChallengeMethod: 'S256',
        responseType: 'code',
        prompt: 'login',
        loginHint: 'user@example.com'
      };
      
      const url = buildAuthorizationUrl('https://accounts.google.com/o/oauth2/v2/auth', params);
      
      expect(url).toContain('https://accounts.google.com/o/oauth2/v2/auth');
      expect(url).toContain('client_id=client_123');
      expect(url).toContain('redirect_uri=https%3A%2F%2Fapi.zalt.io%2Fcallback');
      expect(url).toContain('scope=openid+email+profile');
      expect(url).toContain('state=encrypted-state');
      expect(url).toContain('nonce=test-nonce');
      expect(url).toContain('code_challenge=code-challenge-value');
      expect(url).toContain('code_challenge_method=S256');
      expect(url).toContain('response_type=code');
      expect(url).toContain('prompt=login');
      expect(url).toContain('login_hint=user%40example.com');
    });
    
    it('should omit optional parameters when not provided', () => {
      const params: OIDCAuthorizationParams = {
        clientId: 'client_123',
        redirectUri: 'https://api.zalt.io/callback',
        scope: 'openid email',
        state: 'state',
        nonce: 'nonce',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        responseType: 'code'
      };
      
      const url = buildAuthorizationUrl('https://example.com/auth', params);
      
      expect(url).not.toContain('prompt=');
      expect(url).not.toContain('login_hint=');
      expect(url).not.toContain('acr_values=');
    });
  });

  
  describe('JWT Decoding', () => {
    it('should decode valid JWT', () => {
      // Create a test JWT (header.payload.signature)
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({
        iss: 'https://accounts.google.com',
        sub: 'user_123',
        aud: 'client_456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        email: 'user@example.com',
        email_verified: true,
        name: 'Test User',
        given_name: 'Test',
        family_name: 'User'
      })).toString('base64url');
      const signature = 'fake-signature';
      
      const token = `${header}.${payload}.${signature}`;
      const claims = decodeJWT(token);
      
      expect(claims).not.toBeNull();
      expect(claims?.iss).toBe('https://accounts.google.com');
      expect(claims?.sub).toBe('user_123');
      expect(claims?.email).toBe('user@example.com');
      expect(claims?.email_verified).toBe(true);
      expect(claims?.given_name).toBe('Test');
      expect(claims?.family_name).toBe('User');
    });
    
    it('should return null for invalid JWT format', () => {
      expect(decodeJWT('invalid')).toBeNull();
      expect(decodeJWT('only.two')).toBeNull();
      expect(decodeJWT('')).toBeNull();
    });
    
    it('should return null for invalid base64 payload', () => {
      const token = 'header.!!!invalid-base64!!!.signature';
      expect(decodeJWT(token)).toBeNull();
    });
  });
  
  describe('ID Token Claims Validation', () => {
    const validClaims: OIDCIDTokenClaims = {
      iss: 'https://accounts.google.com',
      sub: 'user_123',
      aud: 'client_456',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      nonce: 'test-nonce'
    };
    
    it('should validate correct claims', () => {
      const result = validateIDTokenClaims(
        validClaims,
        'https://accounts.google.com',
        'client_456',
        'test-nonce'
      );
      
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });
    
    it('should reject invalid issuer', () => {
      const result = validateIDTokenClaims(
        validClaims,
        'https://wrong-issuer.com',
        'client_456'
      );
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid issuer');
    });
    
    it('should reject invalid audience', () => {
      const result = validateIDTokenClaims(
        validClaims,
        'https://accounts.google.com',
        'wrong_client'
      );
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid audience');
    });
    
    it('should handle array audience', () => {
      const claimsWithArrayAud: OIDCIDTokenClaims = {
        ...validClaims,
        aud: ['client_456', 'other_client'],
        azp: 'client_456'
      };
      
      const result = validateIDTokenClaims(
        claimsWithArrayAud,
        'https://accounts.google.com',
        'client_456'
      );
      
      expect(result.valid).toBe(true);
    });
    
    it('should reject expired token', () => {
      const expiredClaims: OIDCIDTokenClaims = {
        ...validClaims,
        exp: Math.floor(Date.now() / 1000) - 600 // 10 minutes ago
      };
      
      const result = validateIDTokenClaims(
        expiredClaims,
        'https://accounts.google.com',
        'client_456'
      );
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });
    
    it('should reject token issued in the future', () => {
      const futureClaims: OIDCIDTokenClaims = {
        ...validClaims,
        iat: Math.floor(Date.now() / 1000) + 600 // 10 minutes in future
      };
      
      const result = validateIDTokenClaims(
        futureClaims,
        'https://accounts.google.com',
        'client_456'
      );
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('future');
    });
    
    it('should reject invalid nonce', () => {
      const result = validateIDTokenClaims(
        validClaims,
        'https://accounts.google.com',
        'client_456',
        'wrong-nonce'
      );
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('nonce');
    });
    
    it('should allow missing nonce when not expected', () => {
      const claimsWithoutNonce: OIDCIDTokenClaims = {
        ...validClaims,
        nonce: undefined
      };
      
      const result = validateIDTokenClaims(
        claimsWithoutNonce,
        'https://accounts.google.com',
        'client_456'
        // No expected nonce
      );
      
      expect(result.valid).toBe(true);
    });
  });

  
  describe('Attribute Extraction', () => {
    it('should extract standard OIDC claims', () => {
      const claims: OIDCIDTokenClaims = {
        iss: 'https://accounts.google.com',
        sub: 'user_123',
        aud: 'client_456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        email: 'user@example.com',
        email_verified: true,
        given_name: 'John',
        family_name: 'Doe',
        name: 'John Doe',
        picture: 'https://example.com/photo.jpg',
        locale: 'en-US'
      };
      
      const attrs = extractAttributesFromClaims(claims);
      
      expect(attrs.email).toBe('user@example.com');
      expect(attrs.emailVerified).toBe(true);
      expect(attrs.firstName).toBe('John');
      expect(attrs.lastName).toBe('Doe');
      expect(attrs.displayName).toBe('John Doe');
      expect(attrs.picture).toBe('https://example.com/photo.jpg');
      expect(attrs.locale).toBe('en-US');
    });
    
    it('should normalize email to lowercase', () => {
      const claims: OIDCIDTokenClaims = {
        iss: 'https://example.com',
        sub: 'user_123',
        aud: 'client_456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        email: 'User@EXAMPLE.COM'
      };
      
      const attrs = extractAttributesFromClaims(claims);
      expect(attrs.email).toBe('user@example.com');
    });
    
    it('should use custom attribute mapping', () => {
      const claims: OIDCIDTokenClaims = {
        iss: 'https://example.com',
        sub: 'user_123',
        aud: 'client_456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        custom_email: 'custom@example.com',
        first: 'Custom',
        last: 'User'
      };
      
      const mapping = {
        email: 'custom_email',
        firstName: 'first',
        lastName: 'last'
      };
      
      const attrs = extractAttributesFromClaims(claims, mapping);
      
      expect(attrs.email).toBe('custom@example.com');
      expect(attrs.firstName).toBe('Custom');
      expect(attrs.lastName).toBe('User');
    });
    
    it('should extract Microsoft Entra groups', () => {
      const claims: OIDCIDTokenClaims = {
        iss: 'https://login.microsoftonline.com/tenant/v2.0',
        sub: 'user_123',
        aud: 'client_456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        email: 'user@company.com',
        groups: ['group1', 'group2', 'admin']
      };
      
      const attrs = extractAttributesFromClaims(claims, undefined, 'microsoft_entra');
      
      expect(attrs.groups).toEqual(['group1', 'group2', 'admin']);
    });
    
    it('should use UPN as email fallback for Microsoft Entra', () => {
      const claims: OIDCIDTokenClaims = {
        iss: 'https://login.microsoftonline.com/tenant/v2.0',
        sub: 'user_123',
        aud: 'client_456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        upn: 'user@company.onmicrosoft.com'
        // No email claim
      };
      
      const attrs = extractAttributesFromClaims(claims, undefined, 'microsoft_entra');
      
      expect(attrs.email).toBe('user@company.onmicrosoft.com');
    });
    
    it('should throw error when email cannot be extracted', () => {
      const claims: OIDCIDTokenClaims = {
        iss: 'https://example.com',
        sub: 'user_123',
        aud: 'client_456',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
        // No email claim
      };
      
      expect(() => extractAttributesFromClaims(claims)).toThrow('Unable to extract email');
    });
  });

  
  describe('Discovery URL Generation', () => {
    it('should generate discovery URL from issuer', () => {
      const config = {
        clientId: 'client_123',
        issuer: 'https://accounts.google.com'
      };
      
      const url = getDiscoveryUrl(config);
      expect(url).toBe('https://accounts.google.com/.well-known/openid-configuration');
    });
    
    it('should handle issuer with trailing slash', () => {
      const config = {
        clientId: 'client_123',
        issuer: 'https://accounts.google.com/'
      };
      
      const url = getDiscoveryUrl(config);
      expect(url).toBe('https://accounts.google.com/.well-known/openid-configuration');
    });
    
    it('should use preset discovery URL for Google Workspace', () => {
      const config = {
        clientId: 'client_123',
        issuer: 'https://accounts.google.com',
        providerPreset: 'google_workspace' as const
      };
      
      const url = getDiscoveryUrl(config);
      expect(url).toBe('https://accounts.google.com/.well-known/openid-configuration');
    });
    
    it('should throw error when issuer is empty', () => {
      const config = {
        clientId: 'client_123',
        issuer: ''
      };
      
      expect(() => getDiscoveryUrl(config)).toThrow('Unable to determine discovery URL');
    });
  });
  
  describe('Provider-Specific Discovery URLs', () => {
    it('should generate Microsoft Entra discovery URL', () => {
      const url = getMicrosoftEntraDiscoveryUrl('tenant-id-123');
      expect(url).toBe('https://login.microsoftonline.com/tenant-id-123/v2.0/.well-known/openid-configuration');
    });
    
    it('should generate Okta discovery URL without auth server', () => {
      const url = getOktaDiscoveryUrl('company.okta.com');
      expect(url).toBe('https://company.okta.com/.well-known/openid-configuration');
    });
    
    it('should generate Okta discovery URL with auth server', () => {
      const url = getOktaDiscoveryUrl('company.okta.com', 'default');
      expect(url).toBe('https://company.okta.com/oauth2/default/.well-known/openid-configuration');
    });
    
    it('should handle Okta domain with https prefix', () => {
      const url = getOktaDiscoveryUrl('https://company.okta.com');
      expect(url).toBe('https://company.okta.com/.well-known/openid-configuration');
    });
    
    it('should generate Auth0 discovery URL', () => {
      const url = getAuth0DiscoveryUrl('company.auth0.com');
      expect(url).toBe('https://company.auth0.com/.well-known/openid-configuration');
    });
    
    it('should generate OneLogin discovery URL', () => {
      const url = getOneLoginDiscoveryUrl('company');
      expect(url).toBe('https://company.onelogin.com/oidc/2/.well-known/openid-configuration');
    });
  });
  
  describe('Default Attribute Mapping', () => {
    it('should return Google Workspace mapping', () => {
      const mapping = getOIDCDefaultAttributeMapping('google_workspace');
      
      expect(mapping.email).toBe('email');
      expect(mapping.firstName).toBe('given_name');
      expect(mapping.lastName).toBe('family_name');
      expect(mapping.displayName).toBe('name');
    });
    
    it('should return Microsoft Entra mapping with groups', () => {
      const mapping = getOIDCDefaultAttributeMapping('microsoft_entra');
      
      expect(mapping.email).toBe('email');
      expect(mapping.groups).toBe('groups');
    });
    
    it('should return Okta mapping with groups', () => {
      const mapping = getOIDCDefaultAttributeMapping('okta');
      
      expect(mapping.email).toBe('email');
      expect(mapping.groups).toBe('groups');
    });
    
    it('should return default mapping for unknown preset', () => {
      const mapping = getOIDCDefaultAttributeMapping(undefined);
      
      expect(mapping.email).toBe('email');
      expect(mapping.firstName).toBe('given_name');
      expect(mapping.lastName).toBe('family_name');
    });
  });

  
  describe('OIDC Configuration Validation', () => {
    beforeEach(() => {
      jest.resetAllMocks();
    });
    
    afterEach(() => {
      jest.restoreAllMocks();
    });
    
    it('should reject config without client ID', async () => {
      const config = {
        issuer: 'https://accounts.google.com',
        clientId: ''
      };
      
      const result = await validateOIDCConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Client ID is required');
    });
    
    it('should reject config without issuer or preset', async () => {
      const config = {
        clientId: 'client_123',
        issuer: ''
      };
      
      const result = await validateOIDCConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Issuer or provider preset is required');
    });
    
    it('should validate config with Google Workspace preset', async () => {
      // Mock fetch for discovery document
      const mockDiscoveryDoc = {
        issuer: 'https://accounts.google.com',
        authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        token_endpoint: 'https://oauth2.googleapis.com/token',
        jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
        code_challenge_methods_supported: ['S256']
      };
      
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockDiscoveryDoc)
      });
      
      const config = {
        clientId: 'client_123',
        issuer: 'https://accounts.google.com',
        providerPreset: 'google_workspace' as const
      };
      
      const result = await validateOIDCConfig(config);
      
      expect(result.valid).toBe(true);
      expect(result.discoveryDocument).toBeDefined();
      expect(result.discoveryDocument?.issuer).toBe('https://accounts.google.com');
    });
    
    it('should reject provider without PKCE S256 support', async () => {
      const mockDiscoveryDoc = {
        issuer: 'https://old-provider.com',
        authorization_endpoint: 'https://old-provider.com/auth',
        token_endpoint: 'https://old-provider.com/token',
        jwks_uri: 'https://old-provider.com/jwks',
        code_challenge_methods_supported: ['plain'] // No S256
      };
      
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockDiscoveryDoc)
      });
      
      const config = {
        clientId: 'client_123',
        issuer: 'https://old-provider.com'
      };
      
      const result = await validateOIDCConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('PKCE');
    });
    
    it('should handle discovery document fetch failure', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found'
      });
      
      const config = {
        clientId: 'client_123',
        issuer: 'https://invalid-provider.com'
      };
      
      const result = await validateOIDCConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Failed to fetch discovery document');
    });
  });
});
