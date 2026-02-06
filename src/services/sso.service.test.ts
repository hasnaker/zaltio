/**
 * Property-based tests for SSO functionality
 * Feature: zalt-platform, Property 11: Single Sign-On Continuity
 * Validates: Requirements 6.2
 */

import * as fc from 'fast-check';

// Mock uuid before importing the service
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'test-uuid-' + Math.random().toString(36).substring(7))
}));

import {
  createSSOSession,
  getSSOSession,
  addApplicationToSSOSession,
  generateSSOToken,
  validateSSOToken,
  invalidateSSOSession,
  registerOAuthClient,
  getOAuthClient,
  validateClientCredentials,
  generateAuthorizationCode,
  exchangeAuthorizationCode,
  convertLegacyToken,
  validateLegacyToken,
  getOIDCDiscoveryDocument,
  _testHelpers
} from './sso.service';
import { HSDApplication, OIDCScope } from '../models/sso.model';
import jwt from 'jsonwebtoken';

// Mock the secrets service
jest.mock('./secrets.service', () => ({
  getJWTSecrets: jest.fn().mockResolvedValue({
    access_token_secret: 'test-access-secret-key-for-testing-purposes',
    refresh_token_secret: 'test-refresh-secret-key-for-testing-purposes'
  })
}));

// Mock the user repository
jest.mock('../repositories/user.repository', () => ({
  findUserById: jest.fn().mockResolvedValue({
    id: 'test-user-id',
    email: 'test@example.com',
    email_verified: true,
    profile: {
      first_name: 'Test',
      last_name: 'User',
      avatar_url: 'https://example.com/avatar.png'
    }
  })
}));

// Mock the OAuth client repository
jest.mock('../repositories/oauth-client.repository', () => {
  const clients = new Map<string, unknown>();
  return {
    createOAuthClient: jest.fn().mockImplementation(async (realmId: string, name: string, redirectUris: string[], scopes: string[], application: string) => {
      const clientId = `hsd_${Math.random().toString(36).substring(7)}`;
      const plainSecret = `secret_${Math.random().toString(36).substring(7)}`;
      const client = {
        client_id: clientId,
        client_name: name,
        application,
        realm_id: realmId,
        redirect_uris: redirectUris,
        allowed_scopes: scopes,
        grant_types: ['authorization_code', 'refresh_token'],
        created_at: Date.now(),
        updated_at: Date.now()
      };
      clients.set(clientId, { ...client, client_secret_hash: plainSecret });
      return { client, plainSecret };
    }),
    findOAuthClientById: jest.fn().mockImplementation(async (clientId: string) => {
      return clients.get(clientId) || null;
    }),
    validateOAuthClientCredentials: jest.fn().mockResolvedValue(true)
  };
});

/**
 * Custom generators for realistic test data
 */
const hsdApplicationArb = fc.constantFrom<HSDApplication>(
  'hsd-portal',
  'hsd-chat',
  'hsd-tasks',
  'hsd-docs',
  'hsd-crm'
);

const realmIdArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'),
  { minLength: 3, maxLength: 30 }
).filter(s => /^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(s) && s.length >= 3);

const userIdArb = fc.uuid();

const sessionIdArb = fc.uuid();

const scopeArb = fc.constantFrom<OIDCScope>(
  'openid',
  'profile',
  'email',
  'offline_access'
);

const scopeArrayArb = fc.array(scopeArb, { minLength: 1, maxLength: 4 })
  .map(scopes => [...new Set(scopes)] as OIDCScope[]);

describe('SSO Service - Property Tests', () => {
  beforeEach(() => {
    // Clear all test data before each test
    _testHelpers.clearAuthorizationCodes();
    _testHelpers.clearSSOSessions();
  });

  /**
   * Property 11: Single Sign-On Continuity
   * For any user authenticated in one HSD application, subsequent authentication
   * attempts in other integrated applications should succeed without requiring
   * re-authentication within the session validity period.
   * Validates: Requirements 6.2
   */
  describe('Property 11: Single Sign-On Continuity', () => {
    it('should create SSO session that is retrievable', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          sessionIdArb,
          hsdApplicationArb,
          async (userId, realmId, primarySessionId, application) => {
            const session = await createSSOSession(userId, realmId, primarySessionId, application);
            
            // Session should be created with correct data
            expect(session.user_id).toBe(userId);
            expect(session.realm_id).toBe(realmId);
            expect(session.primary_session_id).toBe(primarySessionId);
            expect(session.authenticated_applications).toContain(application);
            
            // Session should be retrievable
            const retrieved = getSSOSession(session.id);
            expect(retrieved).not.toBeNull();
            expect(retrieved?.id).toBe(session.id);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow adding applications to existing SSO session', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          sessionIdArb,
          hsdApplicationArb,
          fc.array(hsdApplicationArb, { minLength: 1, maxLength: 4 }),
          async (userId, realmId, primarySessionId, initialApp, additionalApps) => {
            const session = await createSSOSession(userId, realmId, primarySessionId, initialApp);
            
            // Add each additional application
            for (const app of additionalApps) {
              const updated = addApplicationToSSOSession(session.id, app);
              expect(updated).not.toBeNull();
            }
            
            // Verify all applications are in the session
            const finalSession = getSSOSession(session.id);
            expect(finalSession).not.toBeNull();
            expect(finalSession?.authenticated_applications).toContain(initialApp);
            
            // All unique additional apps should be present
            const uniqueApps = [...new Set(additionalApps)];
            uniqueApps.forEach(app => {
              expect(finalSession?.authenticated_applications).toContain(app);
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should generate valid SSO tokens that can be validated', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          sessionIdArb,
          fc.array(hsdApplicationArb, { minLength: 1, maxLength: 5 }).map(apps => [...new Set(apps)] as HSDApplication[]),
          async (userId, realmId, sessionId, applications) => {
            // First create a session
            const session = await createSSOSession(userId, realmId, sessionId, applications[0]);
            
            // Generate SSO token
            const token = await generateSSOToken(userId, realmId, session.id, applications);
            expect(token).toBeTruthy();
            expect(typeof token).toBe('string');
            
            // Validate the token
            const result = await validateSSOToken(token);
            expect(result.valid).toBe(true);
            expect(result.user_id).toBe(userId);
            expect(result.realm_id).toBe(realmId);
            expect(result.applications).toEqual(applications);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should invalidate SSO session and reject subsequent token validations', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          sessionIdArb,
          hsdApplicationArb,
          async (userId, realmId, primarySessionId, application) => {
            // Create session and token
            const session = await createSSOSession(userId, realmId, primarySessionId, application);
            const token = await generateSSOToken(userId, realmId, session.id, [application]);
            
            // Token should be valid initially
            const validResult = await validateSSOToken(token);
            expect(validResult.valid).toBe(true);
            
            // Invalidate the session
            const invalidated = invalidateSSOSession(session.id);
            expect(invalidated).toBe(true);
            
            // Token should now be invalid (session not found)
            const invalidResult = await validateSSOToken(token);
            expect(invalidResult.valid).toBe(false);
            expect(invalidResult.error).toBe('Session expired or invalidated');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should maintain session continuity across multiple applications', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          sessionIdArb,
          async (userId, realmId, primarySessionId) => {
            const allApps: HSDApplication[] = ['hsd-portal', 'hsd-chat', 'hsd-tasks', 'hsd-docs', 'hsd-crm'];
            
            // Start with first application
            const session = await createSSOSession(userId, realmId, primarySessionId, allApps[0]);
            
            // Simulate user navigating to each application
            for (let i = 1; i < allApps.length; i++) {
              const app = allApps[i];
              
              // Generate token for current session
              const token = await generateSSOToken(
                userId,
                realmId,
                session.id,
                session.authenticated_applications
              );
              
              // Validate token (simulating new app checking SSO)
              const validation = await validateSSOToken(token);
              expect(validation.valid).toBe(true);
              expect(validation.user_id).toBe(userId);
              
              // Add new application to session
              const updated = addApplicationToSSOSession(session.id, app);
              expect(updated).not.toBeNull();
              
              // Update session reference for next iteration
              Object.assign(session, updated);
            }
            
            // Final session should have all applications
            const finalSession = getSSOSession(session.id);
            expect(finalSession?.authenticated_applications.length).toBe(allApps.length);
            allApps.forEach(app => {
              expect(finalSession?.authenticated_applications).toContain(app);
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not allow duplicate applications in session', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          sessionIdArb,
          hsdApplicationArb,
          fc.integer({ min: 2, max: 10 }),
          async (userId, realmId, primarySessionId, application, repeatCount) => {
            const session = await createSSOSession(userId, realmId, primarySessionId, application);
            
            // Try to add the same application multiple times
            for (let i = 0; i < repeatCount; i++) {
              addApplicationToSSOSession(session.id, application);
            }
            
            // Session should only have the application once
            const finalSession = getSSOSession(session.id);
            const appCount = finalSession?.authenticated_applications.filter(a => a === application).length;
            expect(appCount).toBe(1);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should return null for non-existent session', async () => {
      await fc.assert(
        fc.asyncProperty(sessionIdArb, async (sessionId) => {
          const session = getSSOSession(sessionId);
          expect(session).toBeNull();
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should fail to add application to non-existent session', async () => {
      await fc.assert(
        fc.asyncProperty(
          sessionIdArb,
          hsdApplicationArb,
          async (sessionId, application) => {
            const result = addApplicationToSSOSession(sessionId, application);
            expect(result).toBeNull();
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('OpenID Connect Discovery', () => {
    it('should return valid discovery document', () => {
      const discovery = getOIDCDiscoveryDocument();
      
      expect(discovery.issuer).toBe('https://api.zalt.io');
      expect(discovery.authorization_endpoint).toContain('/oauth/authorize');
      expect(discovery.token_endpoint).toContain('/oauth/token');
      expect(discovery.userinfo_endpoint).toContain('/oauth/userinfo');
      expect(discovery.scopes_supported).toContain('openid');
      expect(discovery.response_types_supported).toContain('code');
      expect(discovery.grant_types_supported).toContain('authorization_code');
    });
  });

  describe('OAuth Client Registration', () => {
    it('should register OAuth clients with unique IDs', async () => {
      await fc.assert(
        fc.asyncProperty(
          hsdApplicationArb,
          realmIdArb,
          async (application, realmId) => {
            const client = await registerOAuthClient(application, realmId, []);
            
            expect(client.client_id).toBeTruthy();
            expect(client.client_id).toContain('hsd_');
            expect(client.application).toBe(application);
            expect(client.realm_id).toBe(realmId);
            
            // Client should be retrievable
            const retrieved = await getOAuthClient(client.client_id);
            expect(retrieved).not.toBeNull();
            expect(retrieved?.client_id).toBe(client.client_id);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  /**
   * Property 12: Backward Compatibility Preservation
   * For any legacy authentication method during transition periods, existing
   * authentication flows should continue to function while new authentication
   * methods are also available.
   * Validates: Requirements 6.4
   */
  describe('Property 12: Backward Compatibility Preservation', () => {
    it('should convert valid legacy tokens to new OAuth format', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          hsdApplicationArb,
          async (userId, realmId, application) => {
            // Create a legacy-style JWT token
            const legacyToken = jwt.sign(
              {
                sub: userId,
                realm_id: realmId,
                application,
                exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
              },
              'legacy-secret-key'
            );
            
            // Convert to new format
            const newTokens = await convertLegacyToken(legacyToken, application);
            
            // Should successfully convert
            expect(newTokens).not.toBeNull();
            expect(newTokens?.access_token).toBeTruthy();
            expect(newTokens?.token_type).toBe('Bearer');
            expect(newTokens?.expires_in).toBeGreaterThan(0);
            expect(newTokens?.refresh_token).toBeTruthy();
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should validate legacy tokens and extract user information', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          hsdApplicationArb,
          async (userId, realmId, application) => {
            // Create a legacy-style JWT token
            const legacyToken = jwt.sign(
              {
                sub: userId,
                realm_id: realmId,
                application,
                exp: Math.floor(Date.now() / 1000) + 3600
              },
              'legacy-secret-key'
            );
            
            // Validate legacy token
            const result = await validateLegacyToken(legacyToken);
            
            // Should extract correct information
            expect(result).not.toBeNull();
            expect(result?.user_id).toBe(userId);
            expect(result?.realm_id).toBe(realmId);
            expect(result?.application).toBe(application);
            expect(result?.legacy_format).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject expired legacy tokens', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          hsdApplicationArb,
          async (userId, realmId, application) => {
            // Create an expired legacy token
            const expiredToken = jwt.sign(
              {
                sub: userId,
                realm_id: realmId,
                application,
                exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
              },
              'legacy-secret-key'
            );
            
            // Should reject expired token
            const result = await validateLegacyToken(expiredToken);
            expect(result).toBeNull();
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle legacy tokens with alternative field names', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          async (userId, realmId) => {
            // Create a legacy token using user_id instead of sub
            const legacyToken = jwt.sign(
              {
                user_id: userId,
                realm_id: realmId,
                exp: Math.floor(Date.now() / 1000) + 3600
              },
              'legacy-secret-key'
            );
            
            // Should still extract user information
            const result = await validateLegacyToken(legacyToken);
            
            expect(result).not.toBeNull();
            expect(result?.user_id).toBe(userId);
            expect(result?.realm_id).toBe(realmId);
            expect(result?.legacy_format).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject malformed legacy tokens', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 10, maxLength: 100 }),
          async (randomString) => {
            // Random string should not be a valid token
            const result = await validateLegacyToken(randomString);
            expect(result).toBeNull();
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should preserve user identity during legacy token conversion', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          hsdApplicationArb,
          async (userId, realmId, application) => {
            // Create legacy token
            const legacyToken = jwt.sign(
              {
                sub: userId,
                realm_id: realmId,
                application,
                exp: Math.floor(Date.now() / 1000) + 3600
              },
              'legacy-secret-key'
            );
            
            // Convert to new format
            const newTokens = await convertLegacyToken(legacyToken, application);
            expect(newTokens).not.toBeNull();
            
            // Decode the new access token to verify user identity is preserved
            const decoded = jwt.decode(newTokens!.access_token) as {
              sub: string;
              realm_id: string;
              application: string;
              legacy_converted: boolean;
            };
            
            expect(decoded.sub).toBe(userId);
            expect(decoded.realm_id).toBe(realmId);
            expect(decoded.application).toBe(application);
            expect(decoded.legacy_converted).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow both legacy and new authentication methods simultaneously', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          sessionIdArb,
          hsdApplicationArb,
          async (userId, realmId, primarySessionId, application) => {
            // Create a new SSO session (new method)
            const ssoSession = await createSSOSession(userId, realmId, primarySessionId, application);
            const ssoToken = await generateSSOToken(userId, realmId, ssoSession.id, [application]);
            
            // Create a legacy token (old method)
            const legacyToken = jwt.sign(
              {
                sub: userId,
                realm_id: realmId,
                application,
                exp: Math.floor(Date.now() / 1000) + 3600
              },
              'legacy-secret-key'
            );
            
            // Both should be valid simultaneously
            const ssoValidation = await validateSSOToken(ssoToken);
            const legacyValidation = await validateLegacyToken(legacyToken);
            
            expect(ssoValidation.valid).toBe(true);
            expect(ssoValidation.user_id).toBe(userId);
            
            expect(legacyValidation).not.toBeNull();
            expect(legacyValidation?.user_id).toBe(userId);
            
            // Both should identify the same user
            expect(ssoValidation.user_id).toBe(legacyValidation?.user_id);
            expect(ssoValidation.realm_id).toBe(legacyValidation?.realm_id);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should mark converted tokens with legacy_converted flag', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          hsdApplicationArb,
          async (userId, realmId, application) => {
            const legacyToken = jwt.sign(
              {
                sub: userId,
                realm_id: realmId,
                application,
                exp: Math.floor(Date.now() / 1000) + 3600
              },
              'legacy-secret-key'
            );
            
            const newTokens = await convertLegacyToken(legacyToken, application);
            expect(newTokens).not.toBeNull();
            
            // Both access and refresh tokens should have legacy_converted flag
            const accessDecoded = jwt.decode(newTokens!.access_token) as { legacy_converted: boolean };
            const refreshDecoded = jwt.decode(newTokens!.refresh_token!) as { legacy_converted: boolean };
            
            expect(accessDecoded.legacy_converted).toBe(true);
            expect(refreshDecoded.legacy_converted).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should return null for tokens missing required fields', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.constantFrom('sub', 'realm_id'),
          userIdArb,
          realmIdArb,
          async (missingField, userId, realmId) => {
            // Create token with missing field
            const payload: Record<string, unknown> = {
              sub: userId,
              realm_id: realmId,
              exp: Math.floor(Date.now() / 1000) + 3600
            };
            
            delete payload[missingField];
            
            const incompleteToken = jwt.sign(payload, 'legacy-secret-key');
            
            // Should return null for incomplete tokens
            const result = await validateLegacyToken(incompleteToken);
            
            // If both sub/user_id and realm_id are missing, should be null
            if (missingField === 'realm_id') {
              expect(result).toBeNull();
            }
            // If only sub is missing but user_id could be used, depends on implementation
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
