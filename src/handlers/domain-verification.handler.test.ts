/**
 * Domain Verification Handler Tests
 * 
 * Tests for domain verification Lambda handler endpoints.
 * Validates: Requirements 9.5 (Domain verification for SSO enforcement)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock functions
const mockAddDomain = jest.fn();
const mockVerifyDomain = jest.fn();
const mockRemoveDomain = jest.fn();
const mockGetDomainStatus = jest.fn();
const mockListDomains = jest.fn();
const mockRegenerateVerificationToken = jest.fn();
const mockEnableSSOEnforcement = jest.fn();
const mockDisableSSOEnforcement = jest.fn();
const mockValidateDomainForTenant = jest.fn();

// Mock dependencies
jest.mock('../models/org-sso.model', () => ({
  isValidDomain: (domain: string) => /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(domain)
}));

jest.mock('../services/domain-verification.service', () => ({
  addDomain: (...args: unknown[]) => mockAddDomain(...args),
  verifyDomain: (...args: unknown[]) => mockVerifyDomain(...args),
  removeDomain: (...args: unknown[]) => mockRemoveDomain(...args),
  getDomainStatus: (...args: unknown[]) => mockGetDomainStatus(...args),
  listDomains: (...args: unknown[]) => mockListDomains(...args),
  regenerateVerificationToken: (...args: unknown[]) => mockRegenerateVerificationToken(...args),
  enableSSOEnforcement: (...args: unknown[]) => mockEnableSSOEnforcement(...args),
  disableSSOEnforcement: (...args: unknown[]) => mockDisableSSOEnforcement(...args),
  validateDomainForTenant: (...args: unknown[]) => mockValidateDomainForTenant(...args),
  getDnsRecordName: (d: string) => '_zalt-verify.' + d
}));

import {
  handler,
  addDomainHandler,
  listDomainsHandler,
  getDomainStatusHandler,
  verifyDomainHandler,
  removeDomainHandler,
  regenerateTokenHandler,
  enableEnforcementHandler,
  disableEnforcementHandler
} from './domain-verification.handler';

// Helper to create mock API Gateway event
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/tenants/tenant_123/sso/domains',
    pathParameters: { tenantId: 'tenant_123' },
    queryStringParameters: null,
    headers: { 'Content-Type': 'application/json' },
    body: null,
    isBase64Encoded: false,
    requestContext: {
      accountId: '123456789',
      apiId: 'api123',
      authorizer: { claims: { sub: 'user_123' } },
      httpMethod: 'GET',
      identity: { sourceIp: '192.168.1.1', userAgent: 'test-agent' },
      path: '/tenants/tenant_123/sso/domains',
      protocol: 'HTTP/1.1',
      requestId: 'req123',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource123',
      resourcePath: '/tenants/{tenantId}/sso/domains',
      stage: 'test'
    },
    resource: '/tenants/{tenantId}/sso/domains',
    stageVariables: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    ...overrides
  } as APIGatewayProxyEvent;
}

describe('Domain Verification Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('handler routing', () => {
    it('should handle CORS preflight requests', async () => {
      const event = createMockEvent({ httpMethod: 'OPTIONS' });
      const result = await handler(event);
      expect(result.statusCode).toBe(200);
      expect(result.headers?.['Access-Control-Allow-Origin']).toBe('*');
    });

    it('should return 404 for unknown endpoints', async () => {
      const event = createMockEvent({ path: '/unknown/endpoint', httpMethod: 'GET' });
      const result = await handler(event);
      expect(result.statusCode).toBe(404);
    });
  });

  describe('addDomainHandler', () => {
    it('should add domain successfully', async () => {
      mockValidateDomainForTenant.mockResolvedValue({ valid: true });
      mockAddDomain.mockResolvedValue({
        domain: 'acme.com',
        verificationStatus: 'pending',
        verificationToken: 'zalt-verify=abc123',
        verificationMethod: 'dns_txt',
        dnsRecordName: '_zalt-verify.acme.com',
        dnsRecordValue: 'zalt-verify=abc123'
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains',
        body: JSON.stringify({ domain: 'acme.com' })
      });

      const result = await addDomainHandler(event);
      expect(result.statusCode).toBe(201);
      const body = JSON.parse(result.body);
      expect(body.success).toBe(true);
      expect(body.domain.domain).toBe('acme.com');
    });

    it('should return 400 for missing tenantId', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants//sso/domains',
        pathParameters: {},
        body: JSON.stringify({ domain: 'acme.com' })
      });
      const result = await addDomainHandler(event);
      expect(result.statusCode).toBe(400);
    });

    it('should return 400 for missing domain in body', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains',
        body: JSON.stringify({})
      });
      const result = await addDomainHandler(event);
      expect(result.statusCode).toBe(400);
    });

    it('should return 400 for invalid domain format', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains',
        body: JSON.stringify({ domain: 'invalid' })
      });
      const result = await addDomainHandler(event);
      expect(result.statusCode).toBe(400);
    });

    it('should return 409 for domain conflict', async () => {
      mockValidateDomainForTenant.mockResolvedValue({
        valid: false,
        error: 'Domain acme.com is already claimed'
      });
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains',
        body: JSON.stringify({ domain: 'acme.com' })
      });
      const result = await addDomainHandler(event);
      expect(result.statusCode).toBe(409);
    });
  });

  describe('listDomainsHandler', () => {
    it('should list domains successfully', async () => {
      mockListDomains.mockResolvedValue([
        { domain: 'acme.com', verificationStatus: 'pending', verificationMethod: 'dns_txt', dnsRecordName: '_zalt-verify.acme.com' },
        { domain: 'verified.com', verificationStatus: 'verified', verificationMethod: 'dns_txt', dnsRecordName: '_zalt-verify.verified.com' }
      ]);
      const event = createMockEvent({ httpMethod: 'GET', path: '/tenants/tenant_123/sso/domains' });
      const result = await listDomainsHandler(event);
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.domains).toHaveLength(2);
    });

    it('should return 400 for missing tenantId', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants//sso/domains',
        pathParameters: {}
      });
      const result = await listDomainsHandler(event);
      expect(result.statusCode).toBe(400);
    });
  });

  describe('getDomainStatusHandler', () => {
    it('should return domain status', async () => {
      mockGetDomainStatus.mockResolvedValue({
        domain: 'acme.com',
        verificationStatus: 'pending',
        verificationMethod: 'dns_txt',
        dnsRecordName: '_zalt-verify.acme.com'
      });
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants/tenant_123/sso/domains/acme.com',
        pathParameters: { tenantId: 'tenant_123', domain: 'acme.com' }
      });
      const result = await getDomainStatusHandler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should return 404 for non-existent domain', async () => {
      mockGetDomainStatus.mockResolvedValue(null);
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants/tenant_123/sso/domains/unknown.com',
        pathParameters: { tenantId: 'tenant_123', domain: 'unknown.com' }
      });
      const result = await getDomainStatusHandler(event);
      expect(result.statusCode).toBe(404);
    });
  });

  describe('verifyDomainHandler', () => {
    it('should verify domain successfully', async () => {
      mockVerifyDomain.mockResolvedValue({ success: true, domain: 'acme.com', status: 'verified' });
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains/acme.com/verify',
        pathParameters: { tenantId: 'tenant_123', domain: 'acme.com' }
      });
      const result = await verifyDomainHandler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should return 400 when verification fails', async () => {
      mockVerifyDomain.mockResolvedValue({ success: false, domain: 'acme.com', status: 'failed', error: 'DNS not found' });
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains/acme.com/verify',
        pathParameters: { tenantId: 'tenant_123', domain: 'acme.com' }
      });
      const result = await verifyDomainHandler(event);
      expect(result.statusCode).toBe(400);
    });
  });

  describe('removeDomainHandler', () => {
    it('should remove domain successfully', async () => {
      mockRemoveDomain.mockResolvedValue(true);
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/tenants/tenant_123/sso/domains/acme.com',
        pathParameters: { tenantId: 'tenant_123', domain: 'acme.com' }
      });
      const result = await removeDomainHandler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should return 400 when removal is blocked', async () => {
      mockRemoveDomain.mockRejectedValue(new Error('Cannot remove the only verified domain'));
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/tenants/tenant_123/sso/domains/acme.com',
        pathParameters: { tenantId: 'tenant_123', domain: 'acme.com' }
      });
      const result = await removeDomainHandler(event);
      expect(result.statusCode).toBe(400);
    });
  });

  describe('regenerateTokenHandler', () => {
    it('should regenerate token successfully', async () => {
      mockRegenerateVerificationToken.mockResolvedValue({
        domain: 'acme.com',
        verificationStatus: 'pending',
        verificationMethod: 'dns_txt',
        dnsRecordName: '_zalt-verify.acme.com'
      });
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains/acme.com/regenerate',
        pathParameters: { tenantId: 'tenant_123', domain: 'acme.com' }
      });
      const result = await regenerateTokenHandler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should return 400 for already verified domain', async () => {
      mockRegenerateVerificationToken.mockRejectedValue(new Error('Cannot regenerate token for already verified domain'));
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains/verified.com/regenerate',
        pathParameters: { tenantId: 'tenant_123', domain: 'verified.com' }
      });
      const result = await regenerateTokenHandler(event);
      expect(result.statusCode).toBe(400);
    });
  });

  describe('enableEnforcementHandler', () => {
    it('should enable enforcement successfully', async () => {
      mockEnableSSOEnforcement.mockResolvedValue(true);
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/enforcement/enable',
        pathParameters: { tenantId: 'tenant_123' }
      });
      const result = await enableEnforcementHandler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should return 400 when preconditions not met', async () => {
      mockEnableSSOEnforcement.mockRejectedValue(new Error('At least one verified domain is required'));
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/enforcement/enable',
        pathParameters: { tenantId: 'tenant_123' }
      });
      const result = await enableEnforcementHandler(event);
      expect(result.statusCode).toBe(400);
    });
  });

  describe('disableEnforcementHandler', () => {
    it('should disable enforcement successfully', async () => {
      mockDisableSSOEnforcement.mockResolvedValue(true);
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/enforcement/disable',
        pathParameters: { tenantId: 'tenant_123' }
      });
      const result = await disableEnforcementHandler(event);
      expect(result.statusCode).toBe(200);
    });
  });

  describe('main handler routing', () => {
    it('should route POST /tenants/{tenantId}/sso/domains', async () => {
      mockValidateDomainForTenant.mockResolvedValue({ valid: true });
      mockAddDomain.mockResolvedValue({ domain: 'test.com', verificationStatus: 'pending', verificationMethod: 'dns_txt', dnsRecordName: '_zalt-verify.test.com' });
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains',
        body: JSON.stringify({ domain: 'test.com' })
      });
      const result = await handler(event);
      expect(result.statusCode).toBe(201);
    });

    it('should route GET /tenants/{tenantId}/sso/domains', async () => {
      mockListDomains.mockResolvedValue([]);
      const event = createMockEvent({ httpMethod: 'GET', path: '/tenants/tenant_123/sso/domains' });
      const result = await handler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should route POST verify endpoint', async () => {
      mockVerifyDomain.mockResolvedValue({ success: true, domain: 'test.com', status: 'verified' });
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/domains/test.com/verify',
        pathParameters: { tenantId: 'tenant_123', domain: 'test.com' }
      });
      const result = await handler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should route DELETE domain endpoint', async () => {
      mockRemoveDomain.mockResolvedValue(true);
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/tenants/tenant_123/sso/domains/test.com',
        pathParameters: { tenantId: 'tenant_123', domain: 'test.com' }
      });
      const result = await handler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should route enable enforcement endpoint', async () => {
      mockEnableSSOEnforcement.mockResolvedValue(true);
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/enforcement/enable',
        pathParameters: { tenantId: 'tenant_123' }
      });
      const result = await handler(event);
      expect(result.statusCode).toBe(200);
    });

    it('should route disable enforcement endpoint', async () => {
      mockDisableSSOEnforcement.mockResolvedValue(true);
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/sso/enforcement/disable',
        pathParameters: { tenantId: 'tenant_123' }
      });
      const result = await handler(event);
      expect(result.statusCode).toBe(200);
    });
  });
});
