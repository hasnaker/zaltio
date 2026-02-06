/**
 * Entitlement Middleware Tests
 * Tests for entitlement enforcement middleware
 * 
 * Validates: Requirements 7.6 (Entitlement Enforcement)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (Services mocked for unit tests)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock billing service
const mockCheckEntitlementDetailed = jest.fn();
const mockCheckLimit = jest.fn();
jest.mock('../services/billing.service', () => ({
  billingService: {
    checkEntitlementDetailed: (...args: unknown[]) => mockCheckEntitlementDetailed(...args),
    checkLimit: (...args: unknown[]) => mockCheckLimit(...args)
  },
  BillingServiceError: class BillingServiceError extends Error {
    constructor(public code: string, message: string) {
      super(message);
    }
  },
  BillingErrorCode: {
    NO_ACTIVE_SUBSCRIPTION: 'NO_ACTIVE_SUBSCRIPTION',
    FEATURE_NOT_AVAILABLE: 'FEATURE_NOT_AVAILABLE',
    LIMIT_EXCEEDED: 'LIMIT_EXCEEDED'
  }
}));

// Mock audit service
jest.mock('../services/audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue(undefined),
  AuditEventType: { RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded' },
  AuditResult: { FAILURE: 'failure' }
}));

import {
  extractTenantId,
  checkFeatureEntitlement,
  checkLimitEntitlement,
  withEntitlement,
  requireFeature,
  requireLimit,
  getEndpointEntitlement,
  withAutoEntitlement,
  ENDPOINT_ENTITLEMENTS
} from './entitlement.middleware';

describe('Entitlement Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('extractTenantId', () => {
    it('should extract tenant ID from authorizer context', () => {
      const event = {
        requestContext: {
          authorizer: {
            tenantId: 'tenant_123'
          }
        }
      } as unknown as APIGatewayProxyEvent;

      expect(extractTenantId(event)).toBe('tenant_123');
    });

    it('should extract tenant_id from authorizer context', () => {
      const event = {
        requestContext: {
          authorizer: {
            tenant_id: 'tenant_456'
          }
        }
      } as unknown as APIGatewayProxyEvent;

      expect(extractTenantId(event)).toBe('tenant_456');
    });

    it('should extract tenant ID from path parameters', () => {
      const event = {
        pathParameters: {
          tenantId: 'tenant_789'
        },
        requestContext: {}
      } as unknown as APIGatewayProxyEvent;

      expect(extractTenantId(event)).toBe('tenant_789');
    });

    it('should extract tenant ID from query string', () => {
      const event = {
        queryStringParameters: {
          tenantId: 'tenant_abc'
        },
        requestContext: {}
      } as unknown as APIGatewayProxyEvent;

      expect(extractTenantId(event)).toBe('tenant_abc');
    });

    it('should extract tenant ID from request body', () => {
      const event = {
        body: JSON.stringify({ tenantId: 'tenant_def' }),
        requestContext: {}
      } as unknown as APIGatewayProxyEvent;

      expect(extractTenantId(event)).toBe('tenant_def');
    });

    it('should return null when tenant ID not found', () => {
      const event = {
        requestContext: {}
      } as unknown as APIGatewayProxyEvent;

      expect(extractTenantId(event)).toBeNull();
    });

    it('should handle invalid JSON body gracefully', () => {
      const event = {
        body: 'invalid json',
        requestContext: {}
      } as unknown as APIGatewayProxyEvent;

      expect(extractTenantId(event)).toBeNull();
    });
  });

  describe('checkFeatureEntitlement', () => {
    it('should return allowed when feature is available', async () => {
      mockCheckEntitlementDetailed.mockResolvedValue({
        has_access: true
      });

      const result = await checkFeatureEntitlement('tenant_123', 'sso');

      expect(result.allowed).toBe(true);
      expect(result.feature).toBe('sso');
    });

    it('should return denied when feature is not available', async () => {
      mockCheckEntitlementDetailed.mockResolvedValue({
        has_access: false,
        reason: 'Feature not included in plan',
        upgrade_required: true
      });

      const result = await checkFeatureEntitlement('tenant_123', 'sso');

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Feature not included in plan');
      expect(result.upgradeRequired).toBe(true);
    });
  });

  describe('checkLimitEntitlement', () => {
    it('should return allowed when within limit', async () => {
      mockCheckLimit.mockResolvedValue({
        has_access: true,
        limit: 100,
        current_usage: 50
      });

      const result = await checkLimitEntitlement('tenant_123', 'users', 50);

      expect(result.allowed).toBe(true);
      expect(result.limit).toBe(100);
      expect(result.currentUsage).toBe(50);
    });

    it('should return denied when limit exceeded', async () => {
      mockCheckLimit.mockResolvedValue({
        has_access: false,
        reason: 'users limit exceeded (150/100)',
        limit: 100,
        current_usage: 150,
        upgrade_required: true
      });

      const result = await checkLimitEntitlement('tenant_123', 'users', 150);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('limit exceeded');
      expect(result.upgradeRequired).toBe(true);
    });
  });

  describe('withEntitlement', () => {
    const mockHandler = jest.fn().mockResolvedValue({
      statusCode: 200,
      body: JSON.stringify({ success: true })
    });

    const createEvent = (tenantId?: string): APIGatewayProxyEvent => ({
      requestContext: {
        requestId: 'req_123',
        authorizer: tenantId ? { tenantId } : undefined,
        identity: { sourceIp: '127.0.0.1' }
      } as unknown as APIGatewayProxyEvent['requestContext'],
      path: '/test',
      httpMethod: 'GET'
    } as APIGatewayProxyEvent);

    beforeEach(() => {
      mockHandler.mockClear();
    });

    it('should pass through when skip is true', async () => {
      const wrappedHandler = withEntitlement(mockHandler, { skip: true });
      const event = createEvent();

      const result = await wrappedHandler(event);

      expect(result.statusCode).toBe(200);
      expect(mockHandler).toHaveBeenCalled();
    });

    it('should return 400 when tenant ID is missing', async () => {
      const wrappedHandler = withEntitlement(mockHandler, { feature: 'sso' });
      const event = createEvent();

      const result = await wrappedHandler(event);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).error.code).toBe('TENANT_ID_REQUIRED');
      expect(mockHandler).not.toHaveBeenCalled();
    });

    it('should return 403 when feature check fails', async () => {
      mockCheckEntitlementDetailed.mockResolvedValue({
        has_access: false,
        reason: 'Feature not available',
        upgrade_required: true
      });

      const wrappedHandler = withEntitlement(mockHandler, { feature: 'sso' });
      const event = createEvent('tenant_123');

      const result = await wrappedHandler(event);

      expect(result.statusCode).toBe(403);
      expect(JSON.parse(result.body).error.code).toBe('FEATURE_NOT_AVAILABLE');
      expect(mockHandler).not.toHaveBeenCalled();
    });

    it('should return 403 when limit check fails', async () => {
      mockCheckLimit.mockResolvedValue({
        has_access: false,
        reason: 'Limit exceeded',
        limit: 10,
        current_usage: 15,
        upgrade_required: true
      });

      const getUsage = jest.fn().mockResolvedValue(15);
      const wrappedHandler = withEntitlement(mockHandler, {
        limitKey: 'users',
        getUsage
      });
      const event = createEvent('tenant_123');

      const result = await wrappedHandler(event);

      expect(result.statusCode).toBe(403);
      expect(JSON.parse(result.body).error.code).toBe('PLAN_LIMIT_EXCEEDED');
      expect(mockHandler).not.toHaveBeenCalled();
    });

    it('should call handler when all checks pass', async () => {
      mockCheckEntitlementDetailed.mockResolvedValue({ has_access: true });

      const wrappedHandler = withEntitlement(mockHandler, { feature: 'sso' });
      const event = createEvent('tenant_123');

      const result = await wrappedHandler(event);

      expect(result.statusCode).toBe(200);
      expect(mockHandler).toHaveBeenCalled();
    });

    it('should check both feature and limit when configured', async () => {
      mockCheckEntitlementDetailed.mockResolvedValue({ has_access: true });
      mockCheckLimit.mockResolvedValue({ has_access: true, limit: 100, current_usage: 50 });

      const getUsage = jest.fn().mockResolvedValue(50);
      const wrappedHandler = withEntitlement(mockHandler, {
        feature: 'sso',
        limitKey: 'users',
        getUsage
      });
      const event = createEvent('tenant_123');

      const result = await wrappedHandler(event);

      expect(result.statusCode).toBe(200);
      expect(mockCheckEntitlementDetailed).toHaveBeenCalled();
      expect(mockCheckLimit).toHaveBeenCalled();
      expect(mockHandler).toHaveBeenCalled();
    });
  });

  describe('requireFeature', () => {
    it('should create middleware that checks feature', async () => {
      mockCheckEntitlementDetailed.mockResolvedValue({ has_access: true });

      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: '{}'
      });

      const wrappedHandler = requireFeature('sso')(mockHandler);
      const event = {
        requestContext: {
          authorizer: { tenantId: 'tenant_123' }
        }
      } as unknown as APIGatewayProxyEvent;

      await wrappedHandler(event);

      expect(mockCheckEntitlementDetailed).toHaveBeenCalledWith('tenant_123', 'sso');
    });
  });

  describe('requireLimit', () => {
    it('should create middleware that checks limit', async () => {
      mockCheckLimit.mockResolvedValue({ has_access: true, limit: 100, current_usage: 50 });

      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: '{}'
      });

      const getUsage = jest.fn().mockResolvedValue(50);
      const wrappedHandler = requireLimit('users', getUsage)(mockHandler);
      const event = {
        requestContext: {
          authorizer: { tenantId: 'tenant_123' }
        }
      } as unknown as APIGatewayProxyEvent;

      await wrappedHandler(event);

      expect(getUsage).toHaveBeenCalledWith('tenant_123');
      expect(mockCheckLimit).toHaveBeenCalledWith('tenant_123', 'users', 50);
    });
  });

  describe('getEndpointEntitlement', () => {
    it('should return config for SSO endpoints', () => {
      const config = getEndpointEntitlement('/sso/login');
      expect(config?.feature).toBe('sso');
    });

    it('should return config for SAML endpoints', () => {
      const config = getEndpointEntitlement('/saml/callback');
      expect(config?.feature).toBe('sso');
    });

    it('should return config for API key endpoints', () => {
      const config = getEndpointEntitlement('/api-keys/create');
      expect(config?.feature).toBe('api_keys');
    });

    it('should return config for webhook endpoints', () => {
      const config = getEndpointEntitlement('/webhooks/list');
      expect(config?.feature).toBe('webhooks');
    });

    it('should return null for unprotected endpoints', () => {
      const config = getEndpointEntitlement('/login');
      expect(config).toBeNull();
    });
  });

  describe('withAutoEntitlement', () => {
    it('should apply entitlement check for protected endpoints', async () => {
      mockCheckEntitlementDetailed.mockResolvedValue({ has_access: true });

      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: '{}'
      });

      const wrappedHandler = withAutoEntitlement(mockHandler);
      const event = {
        path: '/sso/login',
        requestContext: {
          authorizer: { tenantId: 'tenant_123' }
        }
      } as unknown as APIGatewayProxyEvent;

      await wrappedHandler(event);

      expect(mockCheckEntitlementDetailed).toHaveBeenCalledWith('tenant_123', 'sso');
    });

    it('should skip entitlement check for unprotected endpoints', async () => {
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: '{}'
      });

      const wrappedHandler = withAutoEntitlement(mockHandler);
      const event = {
        path: '/login',
        requestContext: {}
      } as unknown as APIGatewayProxyEvent;

      await wrappedHandler(event);

      expect(mockCheckEntitlementDetailed).not.toHaveBeenCalled();
      expect(mockHandler).toHaveBeenCalled();
    });
  });

  describe('ENDPOINT_ENTITLEMENTS', () => {
    it('should have SSO endpoints configured', () => {
      expect(ENDPOINT_ENTITLEMENTS['/sso/*']).toBeDefined();
      expect(ENDPOINT_ENTITLEMENTS['/saml/*']).toBeDefined();
    });

    it('should have API key endpoints configured', () => {
      expect(ENDPOINT_ENTITLEMENTS['/api-keys/*']).toBeDefined();
    });

    it('should have webhook endpoints configured', () => {
      expect(ENDPOINT_ENTITLEMENTS['/webhooks/*']).toBeDefined();
    });

    it('should have SCIM endpoints configured', () => {
      expect(ENDPOINT_ENTITLEMENTS['/scim/*']).toBeDefined();
    });
  });
});
