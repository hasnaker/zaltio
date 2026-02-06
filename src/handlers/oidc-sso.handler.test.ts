/**
 * OIDC SSO Handler Tests
 * 
 * Tests for OIDC SSO Lambda handler endpoints:
 * - Login initiation
 * - Callback processing
 * - Logout
 * 
 * Validates: Requirements 9.3 (OIDC per organization)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler, loginHandler, callbackHandler, logoutHandler } from './oidc-sso.handler';

// Mock dependencies
jest.mock('../repositories/org-sso.repository');
jest.mock('../repositories/user.repository');
jest.mock('../repositories/session.repository');
jest.mock('../utils/jwt');
jest.mock('../services/audit.service');
jest.mock('../services/oidc.service');

import { getSSOConfig, recordSSOLogin } from '../repositories/org-sso.repository';
import { findUserByEmail, createUser } from '../repositories/user.repository';
import { createSession } from '../repositories/session.repository';
import { generateTokenPair } from '../utils/jwt';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';
import { initiateOIDCSSO, processOIDCCallback } from '../services/oidc.service';

const mockGetSSOConfig = getSSOConfig as jest.MockedFunction<typeof getSSOConfig>;
const mockRecordSSOLogin = recordSSOLogin as jest.MockedFunction<typeof recordSSOLogin>;
const mockFindUserByEmail = findUserByEmail as jest.MockedFunction<typeof findUserByEmail>;
const mockCreateUser = createUser as jest.MockedFunction<typeof createUser>;
const mockCreateSession = createSession as jest.MockedFunction<typeof createSession>;
const mockGenerateTokenPair = generateTokenPair as jest.MockedFunction<typeof generateTokenPair>;
const mockLogAuditEvent = logAuditEvent as jest.MockedFunction<typeof logAuditEvent>;
const mockInitiateOIDCSSO = initiateOIDCSSO as jest.MockedFunction<typeof initiateOIDCSSO>;
const mockProcessOIDCCallback = processOIDCCallback as jest.MockedFunction<typeof processOIDCCallback>;


// Helper to create mock API Gateway event
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/sso/oidc/realm_123/tenant_456/login',
    pathParameters: {
      realmId: 'realm_123',
      tenantId: 'tenant_456'
    },
    queryStringParameters: null,
    headers: {
      'User-Agent': 'Test Browser',
      'Content-Type': 'application/json'
    },
    body: null,
    isBase64Encoded: false,
    requestContext: {
      identity: {
        sourceIp: '192.168.1.1'
      }
    } as any,
    resource: '',
    stageVariables: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    ...overrides
  } as APIGatewayProxyEvent;
}

// Mock SSO config
const mockSSOConfig = {
  id: 'sso_config_123',
  tenantId: 'tenant_456',
  realmId: 'realm_123',
  ssoType: 'oidc' as const,
  enabled: true,
  status: 'active' as const,
  providerName: 'Google Workspace',
  oidcConfig: {
    providerPreset: 'google_workspace' as const,
    clientId: 'google_client_id',
    clientSecretEncrypted: 'encrypted_secret',
    issuer: 'https://accounts.google.com',
    scopes: ['openid', 'email', 'profile']
  },
  spEntityId: 'https://api.zalt.io/v1/sso/oidc/realm_123/tenant_456',
  acsUrl: 'https://api.zalt.io/v1/sso/oidc/realm_123/tenant_456/callback',
  domains: [],
  enforced: false,
  jitProvisioning: {
    enabled: true,
    defaultRole: 'member',
    autoVerifyEmail: true,
    syncGroups: false
  },
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString()
};

describe('OIDC SSO Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  
  describe('Login Handler', () => {
    it('should redirect to IdP authorization URL', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockInitiateOIDCSSO.mockResolvedValue({
        authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=xxx&state=yyy',
        state: 'encrypted-state',
        nonce: 'test-nonce',
        codeVerifier: 'test-verifier'
      });
      
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/login',
        queryStringParameters: {
          redirect_uri: 'https://app.example.com/callback'
        }
      });
      
      const result = await loginHandler(event);
      
      expect(result.statusCode).toBe(302);
      expect(result.headers?.Location).toContain('accounts.google.com');
      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'OIDC SSO initiated'
        })
      );
    });
    
    it('should return 404 when SSO not configured', async () => {
      mockGetSSOConfig.mockResolvedValue(null);
      
      const event = createMockEvent();
      const result = await loginHandler(event);
      
      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error).toBe('not_found');
    });
    
    it('should return 400 when SSO type is not OIDC', async () => {
      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        ssoType: 'saml'
      } as any);
      
      const event = createMockEvent();
      const result = await loginHandler(event);
      
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error).toBe('invalid_request');
      expect(body.error_description).toContain('not OIDC');
    });
    
    it('should return 403 when SSO is disabled', async () => {
      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        enabled: false
      } as any);
      
      const event = createMockEvent();
      const result = await loginHandler(event);
      
      expect(result.statusCode).toBe(403);
      const body = JSON.parse(result.body);
      expect(body.error).toBe('sso_disabled');
    });
    
    it('should return 400 when realm mismatch', async () => {
      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        realmId: 'different_realm'
      } as any);
      
      const event = createMockEvent();
      const result = await loginHandler(event);
      
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error_description).toContain('Realm mismatch');
    });
    
    it('should return 400 when path parameters missing', async () => {
      const event = createMockEvent({
        pathParameters: null
      });
      
      const result = await loginHandler(event);
      
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error).toBe('invalid_request');
    });
    
    it('should pass force_login option to initiateOIDCSSO', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockInitiateOIDCSSO.mockResolvedValue({
        authorizationUrl: 'https://accounts.google.com/auth',
        state: 'state',
        nonce: 'nonce',
        codeVerifier: 'verifier'
      });
      
      const event = createMockEvent({
        queryStringParameters: {
          force_login: 'true',
          login_hint: 'user@example.com'
        }
      });
      
      await loginHandler(event);
      
      expect(mockInitiateOIDCSSO).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          forceLogin: true,
          loginHint: 'user@example.com'
        })
      );
    });
  });

  
  describe('Callback Handler', () => {
    it('should process successful OIDC callback for existing user', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockProcessOIDCCallback.mockResolvedValue({
        success: true,
        user: {
          email: 'user@example.com',
          firstName: 'John',
          lastName: 'Doe',
          emailVerified: true
        },
        idToken: 'id_token_xxx',
        accessToken: 'access_token_xxx'
      });
      mockFindUserByEmail.mockResolvedValue({
        id: 'user_123',
        email: 'user@example.com',
        realm_id: 'realm_123'
      } as any);
      mockGenerateTokenPair.mockResolvedValue({
        access_token: 'zalt_access_token',
        refresh_token: 'zalt_refresh_token',
        expires_in: 900
      });
      mockCreateSession.mockResolvedValue({} as any);
      
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/callback',
        queryStringParameters: {
          code: 'auth_code_123',
          state: 'encrypted_state_xxx'
        }
      });
      
      const result = await callbackHandler(event);
      
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.access_token).toBe('zalt_access_token');
      expect(body.refresh_token).toBe('zalt_refresh_token');
      expect(body.user.email).toBe('user@example.com');
      expect(body.sso.provider).toBe('Google Workspace');
      expect(body.sso.providerType).toBe('oidc');
      
      expect(mockRecordSSOLogin).toHaveBeenCalledWith('tenant_456');
      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'OIDC SSO authentication successful'
        })
      );
    });
    
    it('should create new user with JIT provisioning', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockProcessOIDCCallback.mockResolvedValue({
        success: true,
        user: {
          email: 'newuser@example.com',
          firstName: 'New',
          lastName: 'User',
          emailVerified: true
        }
      });
      mockFindUserByEmail.mockResolvedValue(null);
      mockCreateUser.mockResolvedValue({
        id: 'user_new',
        email: 'newuser@example.com',
        realm_id: 'realm_123'
      } as any);
      mockGenerateTokenPair.mockResolvedValue({
        access_token: 'new_access_token',
        refresh_token: 'new_refresh_token',
        expires_in: 900
      });
      mockCreateSession.mockResolvedValue({} as any);
      
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/callback',
        queryStringParameters: {
          code: 'auth_code_123',
          state: 'encrypted_state_xxx'
        }
      });
      
      const result = await callbackHandler(event);
      
      expect(result.statusCode).toBe(200);
      expect(mockCreateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          realm_id: 'realm_123',
          email: 'newuser@example.com'
        })
      );
      
      // Verify JIT provisioning is logged
      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          details: expect.objectContaining({
            jitProvisioned: true
          })
        })
      );
    });
    
    it('should return error when IdP returns error', async () => {
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/callback',
        queryStringParameters: {
          error: 'access_denied',
          error_description: 'User denied access'
        }
      });
      
      const result = await callbackHandler(event);
      
      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error).toBe('access_denied');
      expect(body.error_description).toBe('User denied access');
      
      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'OIDC SSO authentication failed at IdP'
        })
      );
    });
    
    it('should return 400 when code is missing', async () => {
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/callback',
        queryStringParameters: {
          state: 'encrypted_state'
        }
      });
      
      const result = await callbackHandler(event);
      
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error_description).toContain('Missing authorization code');
    });
    
    it('should return 400 when state is missing', async () => {
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/callback',
        queryStringParameters: {
          code: 'auth_code'
        }
      });
      
      const result = await callbackHandler(event);
      
      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error_description).toContain('Missing state');
    });
    
    it('should return 401 when OIDC callback processing fails', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockProcessOIDCCallback.mockResolvedValue({
        success: false,
        error: 'Invalid state parameter'
      });
      
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/callback',
        queryStringParameters: {
          code: 'auth_code',
          state: 'invalid_state'
        }
      });
      
      const result = await callbackHandler(event);
      
      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error).toBe('authentication_failed');
    });
    
    it('should fail JIT provisioning when disabled', async () => {
      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        jitProvisioning: {
          enabled: false,
          defaultRole: 'member',
          autoVerifyEmail: true,
          syncGroups: false
        }
      } as any);
      mockProcessOIDCCallback.mockResolvedValue({
        success: true,
        user: {
          email: 'newuser@example.com',
          firstName: 'New',
          lastName: 'User'
        }
      });
      mockFindUserByEmail.mockResolvedValue(null);
      
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/callback',
        queryStringParameters: {
          code: 'auth_code',
          state: 'state'
        }
      });
      
      const result = await callbackHandler(event);
      
      expect(result.statusCode).toBe(500);
      const body = JSON.parse(result.body);
      expect(body.error).toBe('user_creation_failed');
      expect(body.error_description).toContain('JIT provisioning is disabled');
    });
  });

  
  describe('Logout Handler', () => {
    it('should process logout successfully', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/logout'
      });
      
      const result = await logoutHandler(event);
      
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.success).toBe(true);
      
      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'OIDC SSO logout'
        })
      );
    });
    
    it('should redirect to post_logout_redirect_uri', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/logout',
        queryStringParameters: {
          post_logout_redirect_uri: 'https://app.example.com/logged-out'
        }
      });
      
      const result = await logoutHandler(event);
      
      expect(result.statusCode).toBe(302);
      expect(result.headers?.Location).toBe('https://app.example.com/logged-out');
    });
    
    it('should return 404 when SSO not configured', async () => {
      mockGetSSOConfig.mockResolvedValue(null);
      
      const event = createMockEvent({
        path: '/sso/oidc/realm_123/tenant_456/logout'
      });
      
      const result = await logoutHandler(event);
      
      expect(result.statusCode).toBe(404);
    });
  });
  
  describe('Main Handler Router', () => {
    it('should route to login handler', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockInitiateOIDCSSO.mockResolvedValue({
        authorizationUrl: 'https://idp.example.com/auth',
        state: 'state',
        nonce: 'nonce',
        codeVerifier: 'verifier'
      });
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/sso/oidc/realm_123/tenant_456/login'
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(302);
    });
    
    it('should route to callback handler', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockProcessOIDCCallback.mockResolvedValue({
        success: true,
        user: { email: 'user@example.com' }
      });
      mockFindUserByEmail.mockResolvedValue({
        id: 'user_123',
        email: 'user@example.com'
      } as any);
      mockGenerateTokenPair.mockResolvedValue({
        access_token: 'token',
        refresh_token: 'refresh',
        expires_in: 900
      });
      mockCreateSession.mockResolvedValue({} as any);
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/sso/oidc/realm_123/tenant_456/callback',
        queryStringParameters: {
          code: 'code',
          state: 'state'
        }
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
    });
    
    it('should route to logout handler', async () => {
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/sso/oidc/realm_123/tenant_456/logout'
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
    });
    
    it('should return 404 for unknown path', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/sso/oidc/realm_123/tenant_456/unknown'
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(404);
    });
    
    it('should handle CORS preflight', async () => {
      const event = createMockEvent({
        httpMethod: 'OPTIONS',
        path: '/sso/oidc/realm_123/tenant_456/login'
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      expect(result.headers?.['Access-Control-Allow-Origin']).toBe('*');
      expect(result.headers?.['Access-Control-Allow-Methods']).toContain('GET');
    });
  });
});
