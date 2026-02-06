/**
 * Tediyat Tenant Handlers Tests
 * Property 14: Tenant Creation with Ownership
 * Property 15: Tenant List Completeness
 * 
 * Validates: Requirements 9.1-9.5, 10.1-10.3
 */

jest.mock('../../../utils/jwt');
jest.mock('../../../services/security-logger.service');
jest.mock('../../../services/tediyat/tenant.service');
jest.mock('../../../services/tediyat/membership.service');

import { handler as createHandler } from '../tenant-create.handler';
import { handler as listHandler } from '../tenant-list.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as jwtUtils from '../../../utils/jwt';
import * as securityLogger from '../../../services/security-logger.service';
import * as tenantService from '../../../services/tediyat/tenant.service';
import * as membershipService from '../../../services/tediyat/membership.service';

const mockVerifyAccessToken = jwtUtils.verifyAccessToken as jest.Mock;
const mockLogSecurityEvent = securityLogger.logSecurityEvent as jest.Mock;
const mockCreateTenant = tenantService.createTenant as jest.Mock;
const mockListUserTenants = tenantService.listUserTenants as jest.Mock;
const mockCreateMembership = membershipService.createMembership as jest.Mock;
const mockListUserMemberships = membershipService.listUserMemberships as jest.Mock;

function createMockEvent(body: unknown, token?: string, method = 'POST'): APIGatewayProxyEvent {
  return {
    body: body ? JSON.stringify(body) : null,
    headers: { 'Authorization': token ? `Bearer ${token}` : undefined } as any,
    httpMethod: method,
    isBase64Encoded: false,
    path: '/v1/tediyat/tenants',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: { requestId: 'test', identity: { sourceIp: '127.0.0.1' } } as any,
    resource: '',
    multiValueHeaders: {},
  };
}

describe('Tediyat Tenant Handlers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'user_xxx',
      email: 'test@example.com',
      realm_id: 'tediyat',
    });
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Tenant Create Handler', () => {
    beforeEach(() => {
      mockCreateTenant.mockResolvedValue({
        success: true,
        data: { id: 'ten_new', name: 'New Company', slug: 'new-company', status: 'active' },
      });
      mockCreateMembership.mockResolvedValue({ success: true });
    });

    it('should create tenant with owner membership', async () => {
      const event = createMockEvent({ name: 'New Company' }, 'valid_token');
      const response = await createHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(201);
      expect(body.success).toBe(true);
      expect(body.data.tenant.id).toBe('ten_new');
      expect(body.data.membership.role).toBe('role_owner');
    });

    it('should reject without token', async () => {
      const event = createMockEvent({ name: 'New Company' });
      const response = await createHandler(event);
      expect(response.statusCode).toBe(401);
    });

    it('should reject invalid name', async () => {
      const event = createMockEvent({ name: 'A' }, 'valid_token');
      const response = await createHandler(event);
      expect(response.statusCode).toBe(400);
    });

    it('should handle slug conflict', async () => {
      mockCreateTenant.mockResolvedValue({
        success: false,
        code: 'SLUG_EXISTS',
        error: 'Slug already exists',
      });

      const event = createMockEvent({ name: 'Existing Company' }, 'valid_token');
      const response = await createHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(409);
      expect(body.error.code).toBe('SLUG_EXISTS');
    });
  });

  describe('Tenant List Handler', () => {
    beforeEach(() => {
      mockListUserMemberships.mockResolvedValue({
        success: true,
        data: [
          { user_id: 'user_xxx', tenant_id: 'ten_1', role_id: 'role_owner', status: 'active' },
          { user_id: 'user_xxx', tenant_id: 'ten_2', role_id: 'role_admin', status: 'active' },
        ],
      });
      mockListUserTenants.mockResolvedValue({
        success: true,
        data: [
          { id: 'ten_1', name: 'Company 1', slug: 'company-1', role: 'role_owner', role_name: 'Şirket Sahibi', is_default: true },
          { id: 'ten_2', name: 'Company 2', slug: 'company-2', role: 'role_admin', role_name: 'Yönetici', is_default: false },
        ],
      });
    });

    it('should return all user tenants', async () => {
      const event = createMockEvent(null, 'valid_token', 'GET');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.tenants).toHaveLength(2);
      expect(body.data.total).toBe(2);
    });

    it('should include role info for each tenant', async () => {
      const event = createMockEvent(null, 'valid_token', 'GET');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      body.data.tenants.forEach((tenant: any) => {
        expect(tenant).toHaveProperty('id');
        expect(tenant).toHaveProperty('name');
        expect(tenant).toHaveProperty('slug');
        expect(tenant).toHaveProperty('role');
        expect(tenant).toHaveProperty('role_name');
        expect(tenant).toHaveProperty('is_default');
      });
    });

    it('should reject without token', async () => {
      const event = createMockEvent(null, undefined, 'GET');
      const response = await listHandler(event);
      expect(response.statusCode).toBe(401);
    });
  });
});
