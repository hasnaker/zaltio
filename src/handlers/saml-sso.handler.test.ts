/**
 * SAML SSO Handler Tests
 * 
 * Tests for SAML 2.0 SSO endpoints:
 * - GET /sso/saml/{realmId}/{tenantId}/login
 * - POST /sso/saml/{realmId}/{tenantId}/acs
 * - GET /sso/saml/{realmId}/{tenantId}/metadata
 * - POST /sso/saml/{realmId}/{tenantId}/slo
 * 
 * Validates: Requirements 9.2 (SAML 2.0 per organization)
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

// Mock dependencies
jest.mock('../repositories/org-sso.repository', () => ({
  getSSOConfig: jest.fn(),
  recordSSOLogin: jest.fn()
}));

jest.mock('../repositories/user.repository', () => ({
  findUserByEmail: jest.fn(),
  createUser: jest.fn()
}));

jest.mock('../repositories/session.repository', () => ({
  createSession: jest.fn()
}));

jest.mock('../repositories/realm.repository', () => ({
  findRealmById: jest.fn()
}));

jest.mock('../utils/jwt', () => ({
  generateTokenPair: jest.fn()
}));

jest.mock('../services/audit.service', () => ({
  logAuditEvent: jest.fn(),
  AuditEventType: {
    OAUTH_LOGIN: 'oauth_login',
    LOGOUT: 'logout'
  },
  AuditResult: {
    SUCCESS: 'success',
    FAILURE: 'failure',
    PENDING: 'pending'
  }
}));

jest.mock('../services/saml.service', () => ({
  initiateSAMLSSO: jest.fn(),
  processSAMLResponse: jest.fn(),
  generateTenantSPMetadata: jest.fn(),
  generateLogoutRequest: jest.fn()
}));

import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  handler,
  loginHandler,
  acsHandler,
  metadataHandler,
  sloHandler
} from './saml-sso.handler';

import { getSSOConfig, recordSSOLogin } from '../repositories/org-sso.repository';
import { findUserByEmail, createUser } from '../repositories/user.repository';
import { createSession } from '../repositories/session.repository';
import { findRealmById } from '../repositories/realm.repository';
import { generateTokenPair } from '../utils/jwt';
import { logAuditEvent } from '../services/audit.service';
import {
  initiateSAMLSSO,
  processSAMLResponse,
  generateTenantSPMetadata,
  generateLogoutRequest
} from '../services/saml.service';

const mockedGetSSOConfig = getSSOConfig as jest.MockedFunction<typeof getSSOConfig>;
const mockedRecordSSOLogin = recordSSOLogin as jest.MockedFunction<typeof recordSSOLogin>;
const mockedFindUserByEmail = findUserByEmail as jest.MockedFunction<typeof findUserByEmail>;
const mockedCreateUser = createUser as jest.MockedFunction<typeof createUser>;
const mockedCreateSession = createSession as jest.MockedFunction<typeof createSession>;
const mockedFindRealmById = findRealmById as jest.MockedFunction<typeof findRealmById>;
const mockedGenerateTokenPair = generateTokenPair as jest.MockedFunction<typeof generateTokenPair>;
const mockedLogAuditEvent = logAuditEvent as jest.MockedFunction<typeof logAuditEvent>;
const mockedInitiateSAMLSSO = initiateSAMLSSO as jest.MockedFunction<typeof initiateSAMLSSO>;
const mockedProcessSAMLResponse = processSAMLResponse as jest.MockedFunction<typeof processSAMLResponse>;
const mockedGenerateTenantSPMetadata = generateTenantSPMetadata as jest.MockedFunction<typeof generateTenantSPMetadata>;

// ============================================================================
// TEST HELPERS
// ============================================================================

function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/sso/saml/realm_123/tenant_456/login',
    pathParameters: {
      realmId: 'realm_123',
      tenantId: 'tenant_456'
    },
    queryStringParameters: null,
    headers: {
      'User-Agent': 'Mozilla/5.0 Test Browser'
    },
    body: null,
    isBase64Encoded: false,
    requestContext: {
      identity: {
        sourceIp: '192.168.1.1'
      }
    } as any,
    ...overrides
  } as APIGatewayProxyEvent;
}

const mockSSOConfig = {
  id: 'sso_config_123',
  tenantId: 'tenant_456',
  realmId: 'realm_123',
  ssoType: 'saml' as const,
  enabled: true,
  status: 'active' as const,
  providerName: 'Okta',
  samlConfig: {
    idpEntityId: 'https://idp.example.com',
    idpSsoUrl: 'https://idp.example.com/sso',
    idpCertificate: '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----'
  },
  spEntityId: 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456',
  acsUrl: 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456/acs',
  sloUrl: 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456/slo',
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

// ============================================================================
// TESTS
// ============================================================================

describe('SAML SSO Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Login Handler (SP-initiated SSO)', () => {
    it('should redirect to IdP for valid SSO config', async () => {
      mockedGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockedInitiateSAMLSSO.mockResolvedValue({
        redirectUrl: 'https://idp.example.com/sso?SAMLRequest=encoded',
        requestId: '_request_123'
      });
      mockedLogAuditEvent.mockResolvedValue({} as any);

      const event = createMockEvent({
        path: '/sso/saml/realm_123/tenant_456/login'
      });

      const response = await loginHandler(event);

      expect(response.statusCode).toBe(302);
      expect(response.headers?.Location).toContain('https://idp.example.com/sso');
      expect(mockedGetSSOConfig).toHaveBeenCalledWith('tenant_456');
      expect(mockedLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'oauth_login',
          result: 'pending',
          realmId: 'realm_123',
          action: 'SAML SSO initiated'
        })
      );
    });

    it('should return 404 when SSO not configured', async () => {
      mockedGetSSOConfig.mockResolvedValue(null);

      const event = createMockEvent();
      const response = await loginHandler(event);

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('not_found');
    });

    it('should return 403 when SSO is disabled', async () => {
      mockedGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        enabled: false
      } as any);

      const event = createMockEvent();
      const response = await loginHandler(event);

      expect(response.statusCode).toBe(403);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('sso_disabled');
    });

    it('should return 400 for realm mismatch', async () => {
      mockedGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        realmId: 'different_realm'
      } as any);

      const event = createMockEvent();
      const response = await loginHandler(event);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('invalid_request');
    });

    it('should return 400 for missing path parameters', async () => {
      const event = createMockEvent({
        pathParameters: null
      });

      const response = await loginHandler(event);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('invalid_request');
    });
  });

  describe('ACS Handler (Assertion Consumer Service)', () => {
    it('should process valid SAML response and return tokens', async () => {
      mockedGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockedProcessSAMLResponse.mockResolvedValue({
        success: true,
        user: {
          email: 'user@example.com',
          firstName: 'John',
          lastName: 'Doe'
        },
        sessionIndex: '_session_123'
      });
      mockedFindUserByEmail.mockResolvedValue({
        id: 'user_123',
        email: 'user@example.com'
      } as any);
      mockedCreateSession.mockResolvedValue({
        id: 'session_123'
      } as any);
      mockedGenerateTokenPair.mockResolvedValue({
        access_token: 'access_token_123',
        refresh_token: 'refresh_token_123',
        expires_in: 900
      });
      mockedRecordSSOLogin.mockResolvedValue(undefined);
      mockedLogAuditEvent.mockResolvedValue({} as any);

      const samlResponse = Buffer.from('<samlp:Response>test</samlp:Response>').toString('base64');
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/sso/saml/realm_123/tenant_456/acs',
        body: `SAMLResponse=${encodeURIComponent(samlResponse)}`,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      const response = await acsHandler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.access_token).toBe('access_token_123');
      expect(body.refresh_token).toBe('refresh_token_123');
      expect(body.user.email).toBe('user@example.com');
      expect(body.sso.provider).toBe('Okta');
    });

    it('should create new user with JIT provisioning', async () => {
      mockedGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockedProcessSAMLResponse.mockResolvedValue({
        success: true,
        user: {
          email: 'newuser@example.com',
          firstName: 'Jane',
          lastName: 'Smith'
        }
      });
      mockedFindUserByEmail.mockResolvedValue(null);
      mockedCreateUser.mockResolvedValue({
        id: 'user_new',
        email: 'newuser@example.com'
      } as any);
      mockedCreateSession.mockResolvedValue({ id: 'session_new' } as any);
      mockedGenerateTokenPair.mockResolvedValue({
        access_token: 'access_token_new',
        refresh_token: 'refresh_token_new',
        expires_in: 900
      });
      mockedRecordSSOLogin.mockResolvedValue(undefined);
      mockedLogAuditEvent.mockResolvedValue({} as any);

      const samlResponse = Buffer.from('<samlp:Response>test</samlp:Response>').toString('base64');
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/sso/saml/realm_123/tenant_456/acs',
        body: `SAMLResponse=${encodeURIComponent(samlResponse)}`
      });

      const response = await acsHandler(event);

      expect(response.statusCode).toBe(200);
      expect(mockedCreateUser).toHaveBeenCalled();
      expect(mockedLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'oauth_login',
          result: 'success',
          action: 'SAML SSO authentication successful',
          details: expect.objectContaining({
            jitProvisioned: true
          })
        })
      );
    });

    it('should return 401 for failed SAML validation', async () => {
      mockedGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockedProcessSAMLResponse.mockResolvedValue({
        success: false,
        error: 'Invalid signature'
      });
      mockedLogAuditEvent.mockResolvedValue({} as any);

      const samlResponse = Buffer.from('<samlp:Response>invalid</samlp:Response>').toString('base64');
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/sso/saml/realm_123/tenant_456/acs',
        body: `SAMLResponse=${encodeURIComponent(samlResponse)}`
      });

      const response = await acsHandler(event);

      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('authentication_failed');
      expect(mockedLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'oauth_login',
          result: 'failure',
          action: 'SAML SSO authentication failed'
        })
      );
    });

    it('should return 400 for missing SAMLResponse', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/sso/saml/realm_123/tenant_456/acs',
        body: ''
      });

      const response = await acsHandler(event);

      expect(response.statusCode).toBe(400);
    });
  });

  describe('Metadata Handler', () => {
    it('should return SP metadata XML', async () => {
      mockedFindRealmById.mockResolvedValue({
        id: 'realm_123',
        name: 'Test Realm'
      } as any);
      mockedGenerateTenantSPMetadata.mockReturnValue(
        '<?xml version="1.0"?><EntityDescriptor>test</EntityDescriptor>'
      );

      const event = createMockEvent({
        path: '/sso/saml/realm_123/tenant_456/metadata'
      });

      const response = await metadataHandler(event);

      expect(response.statusCode).toBe(200);
      expect(response.headers?.['Content-Type']).toBe('application/xml');
      expect(response.body).toContain('EntityDescriptor');
      expect(mockedGenerateTenantSPMetadata).toHaveBeenCalledWith(
        'realm_123',
        'tenant_456',
        expect.objectContaining({
          organizationName: 'Test Realm'
        })
      );
    });

    it('should return 400 for missing path parameters', async () => {
      const event = createMockEvent({
        pathParameters: null,
        path: '/sso/saml/metadata'
      });

      const response = await metadataHandler(event);

      expect(response.statusCode).toBe(400);
    });
  });

  describe('SLO Handler (Single Logout)', () => {
    it('should process IdP-initiated logout', async () => {
      mockedGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockedLogAuditEvent.mockResolvedValue({} as any);

      const samlRequest = Buffer.from('<samlp:LogoutRequest>test</samlp:LogoutRequest>').toString('base64');
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/sso/saml/realm_123/tenant_456/slo',
        body: `SAMLRequest=${encodeURIComponent(samlRequest)}`
      });

      const response = await sloHandler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(mockedLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'logout',
          result: 'success',
          action: 'SAML SSO IdP-initiated logout'
        })
      );
    });

    it('should process SP-initiated logout response', async () => {
      mockedGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockedLogAuditEvent.mockResolvedValue({} as any);

      const samlResponse = Buffer.from('<samlp:LogoutResponse>test</samlp:LogoutResponse>').toString('base64');
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/sso/saml/realm_123/tenant_456/slo',
        body: `SAMLResponse=${encodeURIComponent(samlResponse)}`
      });

      const response = await sloHandler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(mockedLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'logout',
          result: 'success',
          action: 'SAML SSO logout completed'
        })
      );
    });

    it('should return 400 for missing SAML request/response', async () => {
      mockedGetSSOConfig.mockResolvedValue(mockSSOConfig as any);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/sso/saml/realm_123/tenant_456/slo',
        body: ''
      });

      const response = await sloHandler(event);

      expect(response.statusCode).toBe(400);
    });
  });

  describe('Main Handler Router', () => {
    it('should route to login handler', async () => {
      mockedGetSSOConfig.mockResolvedValue(mockSSOConfig as any);
      mockedInitiateSAMLSSO.mockResolvedValue({
        redirectUrl: 'https://idp.example.com/sso',
        requestId: '_req_123'
      });
      mockedLogAuditEvent.mockResolvedValue({} as any);

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/sso/saml/realm_123/tenant_456/login'
      });

      const response = await handler(event);
      expect(response.statusCode).toBe(302);
    });

    it('should route to metadata handler', async () => {
      mockedFindRealmById.mockResolvedValue({ id: 'realm_123' } as any);
      mockedGenerateTenantSPMetadata.mockReturnValue('<EntityDescriptor/>');

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/sso/saml/realm_123/tenant_456/metadata'
      });

      const response = await handler(event);
      expect(response.statusCode).toBe(200);
      expect(response.headers?.['Content-Type']).toBe('application/xml');
    });

    it('should return 404 for unknown endpoint', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/sso/saml/realm_123/tenant_456/unknown'
      });

      const response = await handler(event);
      expect(response.statusCode).toBe(404);
    });

    it('should handle CORS preflight', async () => {
      const event = createMockEvent({
        httpMethod: 'OPTIONS',
        path: '/sso/saml/realm_123/tenant_456/login'
      });

      const response = await handler(event);
      expect(response.statusCode).toBe(200);
      expect(response.headers?.['Access-Control-Allow-Origin']).toBe('*');
      expect(response.headers?.['Access-Control-Allow-Methods']).toContain('GET');
    });
  });
});
