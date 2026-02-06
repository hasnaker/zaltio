/**
 * OAuth Service Unit Tests
 * 
 * Task 4.1: OAuth Service
 * Tests PKCE, state encryption, and token handling
 */

import {
  generatePKCE,
  generateNonce,
  encryptState,
  decryptState,
  generateGoogleAuthorizationURL,
  generateAppleAuthorizationURL,
  decodeJWT,
  verifyIDToken,
  validateCallbackParams,
  OAuthState,
  OAuthProviderConfig,
  OAUTH_PROVIDERS
} from './oauth.service';

describe('OAuth Service', () => {
  const mockGoogleConfig: OAuthProviderConfig = {
    clientId: 'clinisyn-google-client-id',
    clientSecret: 'clinisyn-google-secret',
    redirectUri: 'https://api.zalt.io/v1/auth/social/google/callback',
    scopes: ['openid', 'email', 'profile']
  };

  const mockAppleConfig: OAuthProviderConfig = {
    clientId: 'com.clinisyn.auth',
    clientSecret: 'apple-client-secret',
    redirectUri: 'https://api.zalt.io/v1/auth/social/apple/callback',
    scopes: ['name', 'email']
  };

  describe('generatePKCE', () => {
    it('should generate code verifier and challenge', () => {
      const pkce = generatePKCE();
      
      expect(pkce.codeVerifier).toBeDefined();
      expect(pkce.codeChallenge).toBeDefined();
      expect(pkce.codeChallengeMethod).toBe('S256');
    });

    it('should generate code verifier with correct length', () => {
      const pkce = generatePKCE();
      
      // RFC 7636: 43-128 characters
      expect(pkce.codeVerifier.length).toBeGreaterThanOrEqual(43);
      expect(pkce.codeVerifier.length).toBeLessThanOrEqual(128);
    });

    it('should generate unique values each time', () => {
      const pkce1 = generatePKCE();
      const pkce2 = generatePKCE();
      
      expect(pkce1.codeVerifier).not.toBe(pkce2.codeVerifier);
      expect(pkce1.codeChallenge).not.toBe(pkce2.codeChallenge);
    });

    it('should generate URL-safe characters', () => {
      const pkce = generatePKCE();
      
      // Should only contain alphanumeric characters
      expect(/^[a-zA-Z0-9_-]+$/.test(pkce.codeVerifier)).toBe(true);
      expect(/^[a-zA-Z0-9_-]+$/.test(pkce.codeChallenge)).toBe(true);
    });

    it('should use SHA-256 for code challenge', () => {
      const pkce = generatePKCE();
      
      // SHA-256 base64url encoded is 43 characters
      expect(pkce.codeChallenge.length).toBe(43);
    });
  });

  describe('generateNonce', () => {
    it('should generate 32 character hex string', () => {
      const nonce = generateNonce();
      
      expect(nonce).toHaveLength(32);
      expect(/^[a-f0-9]+$/.test(nonce)).toBe(true);
    });

    it('should generate unique values', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      
      expect(nonce1).not.toBe(nonce2);
    });
  });

  describe('State Encryption', () => {
    const mockState: OAuthState = {
      realmId: 'clinisyn-psychologists',
      nonce: 'test-nonce-123',
      redirectUrl: 'https://clinisyn.com/dashboard',
      timestamp: Date.now()
    };

    it('should encrypt and decrypt state', () => {
      const encrypted = encryptState(mockState);
      const decrypted = decryptState(encrypted);
      
      expect(decrypted).not.toBeNull();
      expect(decrypted?.realmId).toBe(mockState.realmId);
      expect(decrypted?.nonce).toBe(mockState.nonce);
    });

    it('should produce URL-safe encrypted string', () => {
      const encrypted = encryptState(mockState);
      
      // base64url should not contain +, /, or =
      expect(encrypted).not.toContain('+');
      expect(encrypted).not.toContain('/');
    });

    it('should return null for invalid encrypted state', () => {
      const decrypted = decryptState('invalid-state');
      
      expect(decrypted).toBeNull();
    });

    it('should return null for expired state', () => {
      const expiredState: OAuthState = {
        ...mockState,
        timestamp: Date.now() - 15 * 60 * 1000 // 15 minutes ago
      };
      
      const encrypted = encryptState(expiredState);
      const decrypted = decryptState(encrypted);
      
      expect(decrypted).toBeNull();
    });

    it('should include realm_id in state', () => {
      const encrypted = encryptState(mockState);
      const decrypted = decryptState(encrypted);
      
      expect(decrypted?.realmId).toBe('clinisyn-psychologists');
    });
  });

  describe('generateGoogleAuthorizationURL', () => {
    it('should generate valid Google authorization URL', () => {
      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: generateNonce(),
        timestamp: Date.now()
      };
      const pkce = generatePKCE();
      
      const url = generateGoogleAuthorizationURL(mockGoogleConfig, state, pkce);
      
      expect(url).toContain(OAUTH_PROVIDERS.google.authorizationEndpoint);
      expect(url).toContain('client_id=clinisyn-google-client-id');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=openid+email+profile');
    });

    it('should include PKCE parameters', () => {
      const state: OAuthState = {
        realmId: 'test-realm',
        nonce: generateNonce(),
        timestamp: Date.now()
      };
      const pkce = generatePKCE();
      
      const url = generateGoogleAuthorizationURL(mockGoogleConfig, state, pkce);
      
      expect(url).toContain('code_challenge=');
      expect(url).toContain('code_challenge_method=S256');
    });

    it('should include encrypted state', () => {
      const state: OAuthState = {
        realmId: 'test-realm',
        nonce: generateNonce(),
        timestamp: Date.now()
      };
      const pkce = generatePKCE();
      
      const url = generateGoogleAuthorizationURL(mockGoogleConfig, state, pkce);
      
      expect(url).toContain('state=');
    });

    it('should request offline access for refresh token', () => {
      const state: OAuthState = {
        realmId: 'test-realm',
        nonce: generateNonce(),
        timestamp: Date.now()
      };
      const pkce = generatePKCE();
      
      const url = generateGoogleAuthorizationURL(mockGoogleConfig, state, pkce);
      
      expect(url).toContain('access_type=offline');
    });
  });

  describe('generateAppleAuthorizationURL', () => {
    it('should generate valid Apple authorization URL', () => {
      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: generateNonce(),
        timestamp: Date.now()
      };
      
      const url = generateAppleAuthorizationURL(mockAppleConfig, state);
      
      expect(url).toContain(OAUTH_PROVIDERS.apple.authorizationEndpoint);
      expect(url).toContain('client_id=com.clinisyn.auth');
      expect(url).toContain('response_type=code+id_token');
    });

    it('should use form_post response mode', () => {
      const state: OAuthState = {
        realmId: 'test-realm',
        nonce: generateNonce(),
        timestamp: Date.now()
      };
      
      const url = generateAppleAuthorizationURL(mockAppleConfig, state);
      
      expect(url).toContain('response_mode=form_post');
    });
  });

  describe('decodeJWT', () => {
    // Sample JWT (not a real token, just for testing structure)
    const sampleJWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiY2xpbmlzeW4tZ29vZ2xlLWNsaWVudC1pZCIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNjAwMDAwMDAwLCJlbWFpbCI6ImRyLmF5c2VAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkRyLiBBeXNlIFlpbG1heiJ9.signature';

    it('should decode JWT payload', () => {
      const claims = decodeJWT(sampleJWT);
      
      expect(claims).not.toBeNull();
      expect(claims?.iss).toBe('https://accounts.google.com');
      expect(claims?.email).toBe('dr.ayse@example.com');
    });

    it('should return null for invalid JWT', () => {
      const claims = decodeJWT('invalid-token');
      
      expect(claims).toBeNull();
    });

    it('should return null for malformed JWT', () => {
      const claims = decodeJWT('only.two.parts.here.extra');
      
      expect(claims).toBeNull();
    });
  });

  describe('verifyIDToken', () => {
    const validClaims = {
      iss: 'https://accounts.google.com',
      sub: '123456789',
      aud: 'clinisyn-google-client-id',
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      iat: Math.floor(Date.now() / 1000),
      email: 'dr.ayse@example.com',
      email_verified: true,
      nonce: 'test-nonce'
    };

    // Create a test JWT
    const createTestJWT = (claims: object) => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
      return `${header}.${payload}.test-signature`;
    };

    it('should verify valid token', async () => {
      const token = createTestJWT(validClaims);
      
      const result = await verifyIDToken(token, 'google', 'clinisyn-google-client-id', 'test-nonce');
      
      expect(result.valid).toBe(true);
      expect(result.claims?.email).toBe('dr.ayse@example.com');
    });

    it('should reject token with wrong issuer', async () => {
      const token = createTestJWT({ ...validClaims, iss: 'https://evil.com' });
      
      const result = await verifyIDToken(token, 'google', 'clinisyn-google-client-id');
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid issuer');
    });

    it('should reject token with wrong audience', async () => {
      const token = createTestJWT({ ...validClaims, aud: 'wrong-client-id' });
      
      const result = await verifyIDToken(token, 'google', 'clinisyn-google-client-id');
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid audience');
    });

    it('should reject expired token', async () => {
      const token = createTestJWT({ 
        ...validClaims, 
        exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
      });
      
      const result = await verifyIDToken(token, 'google', 'clinisyn-google-client-id');
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should reject token with wrong nonce', async () => {
      const token = createTestJWT({ ...validClaims, nonce: 'wrong-nonce' });
      
      const result = await verifyIDToken(token, 'google', 'clinisyn-google-client-id', 'expected-nonce');
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid nonce');
    });
  });

  describe('validateCallbackParams', () => {
    it('should validate successful callback', () => {
      const state: OAuthState = {
        realmId: 'test-realm',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);
      
      const result = validateCallbackParams({
        code: 'auth-code-123',
        state: encryptedState
      });
      
      expect(result.valid).toBe(true);
      expect(result.state?.realmId).toBe('test-realm');
    });

    it('should return error for OAuth error response', () => {
      const result = validateCallbackParams({
        error: 'access_denied',
        error_description: 'User denied access'
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('User denied access');
    });

    it('should return error for missing code', () => {
      const result = validateCallbackParams({
        state: 'some-state'
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing authorization code');
    });

    it('should return error for missing state', () => {
      const result = validateCallbackParams({
        code: 'auth-code-123'
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Missing state');
    });

    it('should return error for invalid state', () => {
      const result = validateCallbackParams({
        code: 'auth-code-123',
        state: 'invalid-encrypted-state'
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid or expired state');
    });
  });

  describe('OAuth Provider URLs', () => {
    it('should have correct Google endpoints', () => {
      expect(OAUTH_PROVIDERS.google.authorizationEndpoint).toContain('accounts.google.com');
      expect(OAUTH_PROVIDERS.google.tokenEndpoint).toContain('googleapis.com');
      expect(OAUTH_PROVIDERS.google.issuer).toBe('https://accounts.google.com');
    });

    it('should have correct Apple endpoints', () => {
      expect(OAUTH_PROVIDERS.apple.authorizationEndpoint).toContain('appleid.apple.com');
      expect(OAUTH_PROVIDERS.apple.tokenEndpoint).toContain('appleid.apple.com');
      expect(OAUTH_PROVIDERS.apple.issuer).toBe('https://appleid.apple.com');
    });
  });
});
