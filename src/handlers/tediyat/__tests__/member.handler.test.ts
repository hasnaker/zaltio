/**
 * Tediyat Member Handlers Tests
 * Property 18: Member List Authorization
 * Property 19: Owner Protection on Removal
 * 
 * Validates: Requirements 14.1-14.4, 15.1-15.4, 19.1-19.4
 */

jest.mock('../../../utils/jwt');
jest.mock('../../../services/security-logger.service');
jest.mock('../../../services/tediyat/membership.service');

import { handler as listHandler } from '../member-list.handler';
import { handler as updateHandler } from '../member-update.handler';
import { handler as removeHandler } from '../member-remove.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as jwtUtils from '../../../utils/jwt';
import * as securityLogger from '../../../services/security-logger.service';
import * as membershipService from '../../../services/tediyat/membership.service';

const mockVerifyAccessToken = jwtUtils.verifyAccessToken as jest.Mock;
const mockLogSecurityEvent = securityLogger.logSecurityEvent as jest.Mock;
const mockGetMembership = membershipService.getMembership as jest.Mock;
const mockListTenantMembers = membershipService.listTenantMembers as jest.Mock;
const mockUpdateMembership = membershipService.updateMembership as jest.Mock;
const mockDeleteMembership = membershipService.deleteMembership as jest.Mock;

function createMockEvent(
  method: string,
  pathParams: Record<string, string>,
  body?: unknown,
  token?: string
): APIGatewayProxyEvent {
  return {
    body: body ? JSON.stringify(body) : null,
    headers: { 'Authorization': token ? `Bearer ${token}` : undefined } as any,
    httpMethod: method,
    isBase64Encoded: false,
    path: '/v1/tediyat/tenants/ten_xxx/members',
    pathParameters: pathParams,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: { requestId: 'test', identity: { sourceIp: '127.0.0.1' } } as any,
    resource: '',
    multiValueHeaders: {},
  };
}

describe('Tediyat Member Handlers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'user_owner',
      email: 'owner@example.com',
      realm_id: 'tediyat',
    });
    mockGetMembership.mockResolvedValue({
      success: true,
      data: { user_id: 'user_owner', tenant_id: 'ten_xxx', role_id: 'role_owner', status: 'active' },
    });
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Member List Handler', () => {
    beforeEach(() => {
      mockListTenantMembers.mockResolvedValue({
        success: true,
        data: {
          members: [
            { user_id: 'user_1', role_id: 'role_owner', user: { email: 'owner@test.com' } },
            { user_id: 'user_2', role_id: 'role_admin', user: { email: 'admin@test.com' } },
          ],
          total: 2,
          page: 1,
          page_size: 50,
        },
      });
    });

    it('should return member list for owner/admin', async () => {
      const event = createMockEvent('GET', { tenantId: 'ten_xxx' }, null, 'valid_token');
      const response = await listHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.members).toHaveLength(2);
    });

    it('should deny access for non-members', async () => {
      mockGetMembership.mockResolvedValue({ success: false, code: 'MEMBERSHIP_NOT_FOUND' });

      const event = createMockEvent('GET', { tenantId: 'ten_xxx' }, null, 'valid_token');
      const response = await listHandler(event);

      expect(response.statusCode).toBe(403);
    });

    it('should deny access for viewer role', async () => {
      mockGetMembership.mockResolvedValue({
        success: true,
        data: { role_id: 'role_viewer' },
      });
      mockListTenantMembers.mockResolvedValue({
        success: false,
        code: 'FORBIDDEN',
        error: 'Only owners and admins can view members',
      });

      const event = createMockEvent('GET', { tenantId: 'ten_xxx' }, null, 'valid_token');
      const response = await listHandler(event);

      expect(response.statusCode).toBe(403);
    });
  });

  describe('Member Update Handler', () => {
    beforeEach(() => {
      mockUpdateMembership.mockResolvedValue({
        success: true,
        data: { user_id: 'user_target', role_id: 'role_accountant' },
      });
    });

    it('should update member role', async () => {
      const event = createMockEvent(
        'PATCH',
        { tenantId: 'ten_xxx', userId: 'user_target' },
        { role_id: 'role_accountant' },
        'valid_token'
      );
      const response = await updateHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
    });

    it('should prevent changing owner role', async () => {
      mockUpdateMembership.mockResolvedValue({
        success: false,
        code: 'CANNOT_CHANGE_OWNER',
        error: 'Cannot change owner role',
      });

      const event = createMockEvent(
        'PATCH',
        { tenantId: 'ten_xxx', userId: 'user_owner' },
        { role_id: 'role_admin' },
        'valid_token'
      );
      const response = await updateHandler(event);

      expect(response.statusCode).toBe(400);
    });
  });

  describe('Member Remove Handler', () => {
    beforeEach(() => {
      mockDeleteMembership.mockResolvedValue({ success: true });
    });

    it('should remove member', async () => {
      const event = createMockEvent(
        'DELETE',
        { tenantId: 'ten_xxx', userId: 'user_target' },
        null,
        'valid_token'
      );
      const response = await removeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
    });

    it('should prevent removing only owner', async () => {
      mockDeleteMembership.mockResolvedValue({
        success: false,
        code: 'CANNOT_REMOVE_OWNER',
        error: 'Cannot remove the only owner',
      });

      const event = createMockEvent(
        'DELETE',
        { tenantId: 'ten_xxx', userId: 'user_owner' },
        null,
        'valid_token'
      );
      const response = await removeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('CANNOT_REMOVE_OWNER');
    });
  });
});
