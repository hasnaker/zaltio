/**
 * Tediyat Role Handlers Tests
 * Property 20: Role Permission Mapping
 * Property 21: Custom Role Uniqueness
 * 
 * Validates: Requirements 16.1-16.6, 17.1-17.4
 */

jest.mock('../../../utils/jwt');
jest.mock('../../../services/security-logger.service');
jest.mock('../../../services/tediyat/membership.service');
jest.mock('../../../services/tediyat/role.service');

import { handler as listHandler } from '../role-list.handler';
import { handler as createHandler } from '../role-create.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as jwtUtils from '../../../utils/jwt';
import * as securityLogger from '../../../services/security-logger.service';
import * as membershipService from '../../../services/tediyat/membership.service';
import * as roleService from '../../../services/tediyat/role.service';

const mockVerifyAccessToken = jwtUtils.verifyAccessToken as jest.Mock;
const mockLogSecurityEvent = securityLogger.logSecurityEvent as jest.Mock;
const mockGetMembership = membershipService.getMembership as jest.Mock;
const mockGetSystemRoles = roleService.getSystemRoles as jest.Mock;
const mockListTenantRoles = roleService.listTenantRoles as jest.Mock;
const mockCreateCustomRole = roleService.createCustomRole as jest.Mock;

function createMockEvent(method: string, pathParams: Record<string, string>, body?: unknown, token?: string): APIGatewayProxyEvent {
  return {
    body: body ? JSON.stringify(body) : null,
    headers: { 'Authorization': token ? `Bearer ${token}` : undefined } as any,
    httpMethod: method,
    isBase64Encoded: false,
    path: '/v1/tediyat/tenants/ten_xxx/roles',
    pathParameters: pathParams,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: { requestId: 'test', identity: { sourceIp: '127.0.0.1' } } as any,
    resource: '',
    multiValueHeaders: {},
  };
}

describe('Tediyat Role Handlers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockVerifyAccessToken.mockResolvedValue({ sub: 'user_owner', email: 'owner@test.com', realm_id: 'tediyat' });
    mockGetMembership.mockResolvedValue({ success: true, data: { role_id: 'role_owner' } });
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Role List Handler', () => {
    beforeEach(() => {
      mockGetSystemRoles.mockReturnValue([
        { id: 'role_owner', name: 'Şirket Sahibi', permissions: ['*'] },
        { id: 'role_admin', name: 'Yönetici', permissions: ['invoices:*', 'accounts:*'] },
        { id: 'role_accountant', name: 'Muhasebeci', permissions: ['invoices:read', 'invoices:create'] },
      ]);
      mockListTenantRoles.mockResolvedValue
({
        success: true,
        data: [{ id: 'role_custom_1', name: 'Custom Role', permissions: ['reports:read'] }],
      });
    });

    it('should return system and custom roles', async () => {
      const event = createMockEvent('GET', { tenantId: 'ten_xxx' }, null, 'valid_token');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.systemRoles).toHaveLength(3);
      expect(body.data.customRoles).toHaveLength(1);
    });

    it('should mark system roles correctly', async () => {
      const event = createMockEvent('GET', { tenantId: 'ten_xxx' }, null, 'valid_token');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      body.data.systemRoles.forEach((role: any) => {
        expect(role.isSystem).toBe(true);
      });
      body.data.customRoles.forEach((role: any) => {
        expect(role.isSystem).toBe(false);
      });
    });

    it('should reject non-members', async () => {
      mockGetMembership.mockResolvedValue({ success: false });

      const event = createMockEvent('GET', { tenantId: 'ten_xxx' }, null, 'valid_token');
      const response = await listHandler(event);

      expect(response.statusCode).toBe(403);
    });
  });

  describe('Role Create Handler', () => {
    beforeEach(() => {
      mockCreateCustomRole.mockResolvedValue({
        success: true,
        data: { id: 'role_custom_new', name: 'New Custom Role', permissions: ['reports:read'] },
      });
    });

    it('should create custom role', async () => {
      const event = createMockEvent(
        'POST',
        { tenantId: 'ten_xxx' },
        { name: 'New Custom Role', permissions: ['reports:read'] },
        'valid_token'
      );
      const response = await createHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(201);
      expect(body.success).toBe(true);
      expect(body.data.role.name).toBe('New Custom Role');
    });

    it('should reject duplicate role name', async () => {
      mockCreateCustomRole.mockResolvedValue({
        success: false,
        code: 'ROLE_EXISTS',
        error: 'Role with this name already exists',
      });

      const event = createMockEvent(
        'POST',
        { tenantId: 'ten_xxx' },
        { name: 'Existing Role', permissions: ['reports:read'] },
        'valid_token'
      );
      const response = await createHandler(event);

      expect(response.statusCode).toBe(409);
    });

    it('should reject non-owner/admin', async () => {
      mockGetMembership.mockResolvedValue({ success: true, data: { role_id: 'role_viewer' } });

      const event = createMockEvent(
        'POST',
        { tenantId: 'ten_xxx' },
        { name: 'New Role', permissions: ['reports:read'] },
        'valid_token'
      );
      const response = await createHandler(event);

      expect(response.statusCode).toBe(403);
    });

    it('should reject invalid name', async () => {
      const event = createMockEvent(
        'POST',
        { tenantId: 'ten_xxx' },
        { name: 'A', permissions: ['reports:read'] },
        'valid_token'
      );
      const response = await createHandler(event);

      expect(response.statusCode).toBe(400);
    });

    it('should reject missing permissions', async () => {
      const event = createMockEvent(
        'POST',
        { tenantId: 'ten_xxx' },
        { name: 'New Role' },
        'valid_token'
      );
      const response = await createHandler(event);

      expect(response.statusCode).toBe(400);
    });
  });
});
