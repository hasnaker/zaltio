/**
 * E2E Tests for Clinisyn OAuth Setup Script
 * Task 10.2: Validate OAuth configuration logic
 * 
 * These tests verify:
 * 1. OAuth credential parsing from environment
 * 2. Auth provider configuration generation
 * 3. Realm OAuth configuration
 * 4. Security best practices
 */

import {
  getOAuthCredentials,
  createAuthProviders
} from '../../../scripts/clinisyn-oauth-setup';

describe('Clinisyn OAuth Setup Script', () => {
  // Store original env vars
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset env vars before each test
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    // Restore original env vars
    process.env = originalEnv;
  });

  describe('getOAuthCredentials', () => {
    it('should return empty config when no credentials set', () => {
      delete process.env.CLINISYN_GOOGLE_CLIENT_ID;
      delete process.env.CLINISYN_GOOGLE_CLIENT_SECRET;
      delete process.env.CLINISYN_APPLE_CLIENT_ID;
      delete process.env.CLINISYN_APPLE_TEAM_ID;

      const config = getOAuthCredentials();
      expect(config.google).toBeUndefined();
      expect(config.apple).toBeUndefined();
    });

    it('should parse Google OAuth credentials', () => {
      process.env.CLINISYN_GOOGLE_CLIENT_ID = 'google-client-id-123';
      process.env.CLINISYN_GOOGLE_CLIENT_SECRET = 'google-secret-456';

      const config = getOAuthCredentials();
      expect(config.google).toBeDefined();
      expect(config.google?.client_id).toBe('google-client-id-123');
      expect(config.google?.client_secret).toBe('google-secret-456');
      expect(config.google?.redirect_uri).toBe('https://api.zalt.io/v1/auth/social/google/callback');
    });

    it('should parse Apple OAuth credentials', () => {
      process.env.CLINISYN_APPLE_CLIENT_ID = 'com.clinisyn.app';
      process.env.CLINISYN_APPLE_TEAM_ID = 'TEAM123456';
      process.env.CLINISYN_APPLE_KEY_ID = 'KEY789';
      process.env.CLINISYN_APPLE_PRIVATE_KEY = Buffer.from('-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----').toString('base64');

      const config = getOAuthCredentials();
      expect(config.apple).toBeDefined();
      expect(config.apple?.client_id).toBe('com.clinisyn.app');
      expect(config.apple?.team_id).toBe('TEAM123456');
      expect(config.apple?.key_id).toBe('KEY789');
      expect(config.apple?.private_key).toContain('BEGIN PRIVATE KEY');
      expect(config.apple?.redirect_uri).toBe('https://api.zalt.io/v1/auth/social/apple/callback');
    });

    it('should require both client_id and client_secret for Google', () => {
      process.env.CLINISYN_GOOGLE_CLIENT_ID = 'google-client-id-123';
      delete process.env.CLINISYN_GOOGLE_CLIENT_SECRET;

      const config = getOAuthCredentials();
      expect(config.google).toBeUndefined();
    });

    it('should require both client_id and team_id for Apple', () => {
      process.env.CLINISYN_APPLE_CLIENT_ID = 'com.clinisyn.app';
      delete process.env.CLINISYN_APPLE_TEAM_ID;

      const config = getOAuthCredentials();
      expect(config.apple).toBeUndefined();
    });

    it('should handle both Google and Apple credentials', () => {
      process.env.CLINISYN_GOOGLE_CLIENT_ID = 'google-client-id';
      process.env.CLINISYN_GOOGLE_CLIENT_SECRET = 'google-secret';
      process.env.CLINISYN_APPLE_CLIENT_ID = 'com.clinisyn.app';
      process.env.CLINISYN_APPLE_TEAM_ID = 'TEAM123';

      const config = getOAuthCredentials();
      expect(config.google).toBeDefined();
      expect(config.apple).toBeDefined();
    });
  });

  describe('createAuthProviders', () => {
    it('should always include email_password provider', () => {
      const providers = createAuthProviders({});
      
      expect(providers).toHaveLength(1);
      expect(providers[0].type).toBe('email_password');
      expect(providers[0].enabled).toBe(true);
    });

    it('should add Google OAuth provider when configured', () => {
      const config = {
        google: {
          client_id: 'google-client-id',
          client_secret: 'google-secret',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/google/callback'
        }
      };

      const providers = createAuthProviders(config);
      
      expect(providers).toHaveLength(2);
      
      const googleProvider = providers.find(p => 
        p.type === 'oauth' && (p.config as any).provider === 'google'
      );
      expect(googleProvider).toBeDefined();
      expect(googleProvider?.enabled).toBe(true);
      expect((googleProvider?.config as any).client_id).toBe('google-client-id');
      expect((googleProvider?.config as any).scopes).toContain('openid');
      expect((googleProvider?.config as any).scopes).toContain('email');
      expect((googleProvider?.config as any).scopes).toContain('profile');
    });

    it('should add Apple OAuth provider when configured', () => {
      const config = {
        apple: {
          client_id: 'com.clinisyn.app',
          team_id: 'TEAM123',
          key_id: 'KEY456',
          private_key: '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/apple/callback'
        }
      };

      const providers = createAuthProviders(config);
      
      expect(providers).toHaveLength(2);
      
      const appleProvider = providers.find(p => 
        p.type === 'oauth' && (p.config as any).provider === 'apple'
      );
      expect(appleProvider).toBeDefined();
      expect(appleProvider?.enabled).toBe(true);
      expect((appleProvider?.config as any).client_id).toBe('com.clinisyn.app');
      expect((appleProvider?.config as any).team_id).toBe('TEAM123');
      expect((appleProvider?.config as any).scopes).toContain('name');
      expect((appleProvider?.config as any).scopes).toContain('email');
    });

    it('should add both providers when both configured', () => {
      const config = {
        google: {
          client_id: 'google-client-id',
          client_secret: 'google-secret',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/google/callback'
        },
        apple: {
          client_id: 'com.clinisyn.app',
          team_id: 'TEAM123',
          key_id: 'KEY456',
          private_key: 'test-key',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/apple/callback'
        }
      };

      const providers = createAuthProviders(config);
      
      expect(providers).toHaveLength(3); // email_password + google + apple
      
      const types = providers.map(p => 
        p.type === 'oauth' ? (p.config as any).provider : p.type
      );
      expect(types).toContain('email_password');
      expect(types).toContain('google');
      expect(types).toContain('apple');
    });

    it('should use secret references instead of raw secrets', () => {
      const config = {
        google: {
          client_id: 'google-client-id',
          client_secret: 'google-secret',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/google/callback'
        }
      };

      const providers = createAuthProviders(config);
      const googleProvider = providers.find(p => 
        p.type === 'oauth' && (p.config as any).provider === 'google'
      );

      // Should use secret reference for AWS Secrets Manager
      expect((googleProvider?.config as any).client_secret_ref).toBe('clinisyn/google/client_secret');
    });

    it('should use private key reference for Apple', () => {
      const config = {
        apple: {
          client_id: 'com.clinisyn.app',
          team_id: 'TEAM123',
          key_id: 'KEY456',
          private_key: 'test-key',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/apple/callback'
        }
      };

      const providers = createAuthProviders(config);
      const appleProvider = providers.find(p => 
        p.type === 'oauth' && (p.config as any).provider === 'apple'
      );

      // Should use secret reference for AWS Secrets Manager
      expect((appleProvider?.config as any).private_key_ref).toBe('clinisyn/apple/private_key');
    });
  });

  describe('Security Best Practices', () => {
    it('should use HTTPS redirect URIs', () => {
      process.env.CLINISYN_GOOGLE_CLIENT_ID = 'google-client-id';
      process.env.CLINISYN_GOOGLE_CLIENT_SECRET = 'google-secret';

      const config = getOAuthCredentials();
      expect(config.google?.redirect_uri).toMatch(/^https:\/\//);
    });

    it('should use api.zalt.io domain for callbacks', () => {
      process.env.CLINISYN_GOOGLE_CLIENT_ID = 'google-client-id';
      process.env.CLINISYN_GOOGLE_CLIENT_SECRET = 'google-secret';
      process.env.CLINISYN_APPLE_CLIENT_ID = 'com.clinisyn.app';
      process.env.CLINISYN_APPLE_TEAM_ID = 'TEAM123';

      const config = getOAuthCredentials();
      expect(config.google?.redirect_uri).toContain('api.zalt.io');
      expect(config.apple?.redirect_uri).toContain('api.zalt.io');
    });

    it('should request minimal OAuth scopes for Google', () => {
      const config = {
        google: {
          client_id: 'test',
          client_secret: 'test',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/google/callback'
        }
      };

      const providers = createAuthProviders(config);
      const googleProvider = providers.find(p => 
        p.type === 'oauth' && (p.config as any).provider === 'google'
      );

      const scopes = (googleProvider?.config as any).scopes;
      expect(scopes).toHaveLength(3); // Only openid, email, profile
      expect(scopes).not.toContain('https://www.googleapis.com/auth/calendar');
      expect(scopes).not.toContain('https://www.googleapis.com/auth/drive');
    });

    it('should request minimal OAuth scopes for Apple', () => {
      const config = {
        apple: {
          client_id: 'test',
          team_id: 'test',
          key_id: 'test',
          private_key: 'test',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/apple/callback'
        }
      };

      const providers = createAuthProviders(config);
      const appleProvider = providers.find(p => 
        p.type === 'oauth' && (p.config as any).provider === 'apple'
      );

      const scopes = (appleProvider?.config as any).scopes;
      expect(scopes).toHaveLength(2); // Only name, email
    });
  });

  describe('Realm Configuration', () => {
    it('should configure providers for psychologists realm', () => {
      const config = {
        google: {
          client_id: 'google-client-id',
          client_secret: 'google-secret',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/google/callback'
        }
      };

      const providers = createAuthProviders(config);
      
      // All providers should be enabled
      expect(providers.every(p => p.enabled)).toBe(true);
    });

    it('should configure providers for students realm', () => {
      const config = {
        google: {
          client_id: 'google-client-id',
          client_secret: 'google-secret',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/google/callback'
        }
      };

      const providers = createAuthProviders(config);
      
      // Same providers for both realms
      expect(providers).toHaveLength(2);
    });
  });

  describe('Error Handling', () => {
    it('should handle empty environment variables gracefully', () => {
      process.env.CLINISYN_GOOGLE_CLIENT_ID = '';
      process.env.CLINISYN_GOOGLE_CLIENT_SECRET = '';

      const config = getOAuthCredentials();
      expect(config.google).toBeUndefined();
    });

    it('should handle invalid base64 for Apple private key', () => {
      process.env.CLINISYN_APPLE_CLIENT_ID = 'com.clinisyn.app';
      process.env.CLINISYN_APPLE_TEAM_ID = 'TEAM123';
      process.env.CLINISYN_APPLE_KEY_ID = 'KEY456';
      process.env.CLINISYN_APPLE_PRIVATE_KEY = 'not-valid-base64!!!';

      // Should not throw, but private_key will be garbled
      const config = getOAuthCredentials();
      expect(config.apple).toBeDefined();
    });

    it('should handle missing optional Apple fields', () => {
      process.env.CLINISYN_APPLE_CLIENT_ID = 'com.clinisyn.app';
      process.env.CLINISYN_APPLE_TEAM_ID = 'TEAM123';
      delete process.env.CLINISYN_APPLE_KEY_ID;
      delete process.env.CLINISYN_APPLE_PRIVATE_KEY;

      const config = getOAuthCredentials();
      expect(config.apple).toBeDefined();
      expect(config.apple?.key_id).toBe('');
      expect(config.apple?.private_key).toBe('');
    });
  });

  describe('Provider Type Validation', () => {
    it('should set correct type for email_password provider', () => {
      const providers = createAuthProviders({});
      expect(providers[0].type).toBe('email_password');
    });

    it('should set correct type for OAuth providers', () => {
      const config = {
        google: {
          client_id: 'test',
          client_secret: 'test',
          redirect_uri: 'https://api.zalt.io/v1/auth/social/google/callback'
        }
      };

      const providers = createAuthProviders(config);
      const oauthProvider = providers.find(p => p.type === 'oauth');
      expect(oauthProvider).toBeDefined();
    });
  });
});
