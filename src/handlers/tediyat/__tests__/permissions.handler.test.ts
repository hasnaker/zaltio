/**
 * Tediyat Permissions Handler Tests
 * Property 26: JWT Claims Completeness
 * 
 * Validates: Requirements 23.1-23.5
 */

jest.mock('../../../utils/jwt');
jest.mock('../../../services/tediyat/membership.service');
jest.mock('../../../services/tediyat/role.service');

import { handler } from '../permissions.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as jwtUtils from '../../../utils/jwt';
import * as membershipService from '../../../services/tediyat/membership.service';
import * as roleService from '../../../services/tediyat/role.service';

const mockVerifyAccessToken = jwtUtils.verifyAccessToken as jest.Mock;
const mockGetMembership = membershipService.getMembership as jest.Mock;
const mockGetEffectivePermissions = roleService.getEffectivePermissions as jest.Mock;

function createMockEvent(
  queryParams?: Record<string, string> | null,
  token?: string
): APIGatewayProxyEvent {
  return {
    body: null,
    headers: { 'Authorization': token ? `Bearer ${token}` : undefined } as any,
    httpMethod: 'GET',
    isBase64Encoded: false,
    path: '/v1/tediyat/auth/permissions',
    pathParameters: null,
    queryStringParameters: queryParams || null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: { requestId: 'test', identity: { sourceIp: '127.0.0.1' } } as any,
    resource: '',
    multiValueHeaders: {},
  };
}

describe('Tediyat Permissions Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'user_xxx',
      email: 'test@example.com',
      realm_id: 'tediyat',
    });
  });

  it('should return permissions for valid tenant membership', async () => {
    mockGetMembership.mockResolvedValue({
      success: true,
      data: {
        tenant_id: 'tenant_xxx',
        user_id: 'user_xxx',
        role_id: 'admin',
      },
    });
    mockGetEffectivePermissions.mockResolvedValue([
      'users:read',
      'users:write',
      'invoices:read',
      'invoices:write',
      'reports:read',
    ]);

    const event = createMockEvent({ tenant_id: 'tenant_xxx' }, 'valid_token');
    const response = await handler(event);
    const body = JSON.parse(response.body);

    expect(response.statusCode).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.tenant_id).toBe('tenant_xxx');
    expect(body.data.role_id).toBe('admin');
    expect(body.data.permissions).toHaveLength(5);
    expect(body.data.total).toBe(5);
  });

  it('should return 400 when tenant_id is missing', async () => {
    const event = createMockEvent(null, 'valid_token');
    const response = await handler(event);
    const body = JSON.parse(response.body);

    expect(response.statusCode).toBe(400);
    expect(body.error.code).toBe('TENANT_ID_REQUIRED');
  });

  it('should return 403 when user is not a member', async () => {
    mockGetMembership.mockResolvedValue({ success: false, error: 'NOT_FOUND' });

    const event = createMockEvent({ tenant_id: 'tenant_xxx' }, 'valid_token');
    const response = await handler(event);
    const body = JSON.parse(response.body);

    expect(response.statusCode).toBe(403);
    expect(body.error.code).toBe('NOT_A_MEMBER');
  });

  it('should return 401 without token', async () => {
    const event = createMockEvent({ tenant_id: 'tenant_xxx' });
    const response = await handler(event);

    expect(response.statusCode).toBe(401);
  });

  it('should return 403 for non-tediyat realm', async () => {
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'user_xxx',
      realm_id: 'other_realm',
    });

    const event = createMockEvent({ tenant_id: 'tenant_xxx' }, 'valid_token');
    const response = await handler(event);

    expect(response.statusCode).toBe(403);
  });

  it('should handle large permission sets (>50)', async () => {
    mockGetMembership.mockResolvedValue({
      success: true,
      data: {
        tenant_id: 'tenant_xxx',
        user_id: 'user_xxx',
        role_id: 'owner',
      },
    });
    
    // Generate 60 permissions
    const largePermissions = Array.from({ length: 60 }, (_, i) => `resource${i}:action`);
    mockGetEffectivePermissions.mockResolvedValue(largePermissions);

    const event = createMockEvent({ tenant_id: 'tenant_xxx' }, 'valid_token');
    const response = await handler(event);
    const body = JSON.parse(response.body);

    expect(response.statusCode).toBe(200);
    expect(body.data.permissions).toHaveLength(60);
    expect(body.data.total).toBe(60);
  });
});
