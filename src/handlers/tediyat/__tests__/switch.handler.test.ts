/**
 * Tediyat Tenant Switch Handler Tests
 * Property 16: Tenant Switch Authorization
 * 
 * Validates: Requirements 11.1-11.4
 */

// Mock dependencies before importing handler
jest.mock('../../../utils/jwt');
jest.mock('../../../services/security-logger.service');
jest.mock('../../../services/tediyat/tenant.service');
jest.mock('../../../services/tediyat/membership.service');

import { handler } from '../switch.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as jwtUtils from '../../../utils/jwt';
import * as securityLogger from '../../../services/security-logger.service';
import * as tenantService from '../../../services/tediyat/tenant.service';
import * as membershipService from '../../../services/tediyat/membership.service';

const mockVerifyAccessToken = jwtUtils.verifyAccessToken as jest.Mock;
const mockGenerateTokenPair = jwtUtils.generateTokenPair as jest.Mock;
const mockLogSecurityEvent = securityLogger.logSecurityEvent as jest.Mock;
const mockGetTenant = tenantService.getTenant as jest.Mock;
const mockGetMembership = membershipService.getMembership as jest.Mock;
const mockSetDefaultTenant = membershipService.setDefaultTenant as jest.Mock;

function createMockEvent(body: unknown, token?: string): APIGatewayProxyEvent {
  return {
    body: typeof body === 'string' ? body : JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : undefined,
    } as any,
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/tediyat/switch',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '127.0.0.1' },
    } as any,
    resource: '',
    multiValueHeaders: {},
  };
}

describe('Tediyat Tenant Switch Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    mockVerifyAccessToken.mockResolvedValue({
      sub: 'user_xxx',
      email: 'test@example.com',
      realm_id: 'tediyat',
      org_id: 'ten_current',
    });

    mockGetMembership.mockResolvedValue({
      success: true,
      data: {
        user_id: 'user_xxx',
        tenant_id: 'ten_target',
        role_id: 'role_admin',
        role_name: 'Yönetici',
        status: 'active',
      },
    });

    mockGetTenant.mockResolvedValue({
      success: true,
      data: {
        id: 'ten_target',
        name: 'Target Company',
        slug: 'target-company',
        status: 'active',
      },
    });

    mockGenerateTokenPair.mockResolvedValue({
      access_token: 'new_access_token',
      refresh_token: 'new_refresh_token',
      expires_in: 3600,
    });

    mockSetDefaultTenant.mockResolvedValue({ success: true });
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Property 16: Tenant Switch Authorization', () => {
    it('should allow switch when user has membership', async () => {
      const event = createMockEvent(
        { tenant_id: 'ten_target' },
        'valid_token'
      );

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.tenant.id).toBe('ten_target');
      expect(body.data.accessToken).toBeDefined();
    });

    it('should deny switch when user has no membership', async () => {
      mockGetMembership.mockResolvedValue({
        success: false,
        error: 'Membership not found',
        code: 'MEMBERSHIP_NOT_FOUND',
      });

      const event = createMockEvent(
        { tenant_id: 'ten_unauthorized' },
        'valid_token'
      );

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('should return new token with tenant context', async () => {
      const event = createMockEvent(
        { tenant_id: 'ten_target' },
        'valid_token'
      );

      await handler(event);

      expect(mockGenerateTokenPair).toHaveBeenCalledWith(
        'user_xxx',
        'tediyat',
        'test@example.com',
        expect.objectContaining({
          orgId: 'ten_target',
          roles: ['role_admin'],
        })
      );
    });

    it('should include role and permissions in response', async () => {
      const event = createMockEvent(
        { tenant_id: 'ten_target' },
        'valid_token'
      );

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.role).toBe('role_admin');
      expect(body.data.role_name).toBeDefined();
      expect(body.data.permissions).toBeDefined();
      expect(Array.isArray(body.data.permissions)).toBe(true);
    });
  });

  describe('Authentication', () => {
    it('should reject request without token', async () => {
      const event = createMockEvent({ tenant_id: 'ten_target' });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject invalid token', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent(
        { tenant_id: 'ten_target' },
        'invalid_token'
      );

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });

    it('should reject token from different realm', async () => {
      mockVerifyAccessToken.mockResolvedValue({
        sub: 'user_xxx',
        email: 'test@example.com',
        realm_id: 'other_realm',
      });

      const event = createMockEvent(
        { tenant_id: 'ten_target' },
        'valid_token'
      );

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  describe('Input Validation', () => {
    it('should reject missing tenant_id', async () => {
      const event = createMockEvent({}, 'valid_token');

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_TENANT_ID');
    });

    it('should reject invalid JSON', async () => {
      const event = createMockEvent('invalid json', 'valid_token');
      event.body = 'invalid json';

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });
  });

  describe('Tenant Validation', () => {
    it('should return 404 for non-existent tenant', async () => {
      mockGetTenant.mockResolvedValue({
        success: false,
        error: 'Tenant not found',
        code: 'TENANT_NOT_FOUND',
      });

      const event = createMockEvent(
        { tenant_id: 'ten_nonexistent' },
        'valid_token'
      );

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('TENANT_NOT_FOUND');
    });
  });

  describe('Security Logging', () => {
    it('should log successful switch', async () => {
      const event = createMockEvent(
        { tenant_id: 'ten_target' },
        'valid_token'
      );

      await handler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'tenant_switch_success',
          realm_id: 'tediyat',
        })
      );
    });

    it('should log denied switch', async () => {
      mockGetMembership.mockResolvedValue({
        success: false,
        code: 'MEMBERSHIP_NOT_FOUND',
      });

      const event = createMockEvent(
        { tenant_id: 'ten_unauthorized' },
        'valid_token'
      );

      await handler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'tenant_switch_denied',
        })
      );
    });
  });

  describe('Default Tenant Update', () => {
    it('should update default tenant on switch', async () => {
      const event = createMockEvent(
        { tenant_id: 'ten_target' },
        'valid_token'
      );

      await handler(event);

      expect(mockSetDefaultTenant).toHaveBeenCalledWith('user_xxx', 'ten_target');
    });
  });
});
