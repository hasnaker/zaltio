/**
 * Tediyat Invitation Handlers Tests
 * Property 17: Invitation Flow Integrity
 * 
 * Validates: Requirements 12.1-12.7, 13.1-13.4
 */

jest.mock('../../../utils/jwt');
jest.mock('../../../utils/password');
jest.mock('../../../utils/validation');
jest.mock('../../../repositories/user.repository');
jest.mock('../../../repositories/session.repository');
jest.mock('../../../services/security-logger.service');
jest.mock('../../../services/tediyat/invitation.service');
jest.mock('../../../services/tediyat/membership.service');
jest.mock('../../../services/tediyat/tenant.service');

import { handler as createHandler } from '../invitation-create.handler';
import { handler as acceptHandler } from '../invitation-accept.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as jwtUtils from '../../../utils/jwt';
import * as passwordUtils from '../../../utils/password';
import * as validation from '../../../utils/validation';
import * as userRepo from '../../../repositories/user.repository';
import * as sessionRepo from '../../../repositories/session.repository';
import * as securityLogger from '../../../services/security-logger.service';
import * as invitationService from '../../../services/tediyat/invitation.service';
import * as membershipService from '../../../services/tediyat/membership.service';
import * as tenantService from '../../../services/tediyat/tenant.service';

const mockVerifyAccessToken = jwtUtils.verifyAccessToken as jest.Mock;
const mockGenerateTokenPair = jwtUtils.generateTokenPair as jest.Mock;
const mockValidateEmail = validation.validateEmail as jest.Mock;
const mockValidatePasswordPolicy = passwordUtils.validatePasswordPolicy as jest.Mock;
const mockCheckPasswordPwned = passwordUtils.checkPasswordPwned as jest.Mock;
const mockFindUserByEmail = userRepo.findUserByEmail as jest.Mock;
const mockCreateUser = userRepo.createUser as jest.Mock;
const mockCreateSession = sessionRepo.createSession as jest.Mock;
const mockLogSecurityEvent = securityLogger.logSecurityEvent as jest.Mock;
const mockGetMembership = membershipService.getMembership as jest.Mock;
const mockCreateInvitation = invitationService.createInvitation as jest.Mock;
const mockGetInvitationByToken = invitationService.getInvitationByToken as jest.Mock;
const mockCanAcceptInvitation = invitationService.canAcceptInvitation as jest.Mock;
const mockAcceptInvitation = invitationService.acceptInvitation as jest.Mock;
const mockGetTenant = tenantService.getTenant as jest.Mock;

function createMockEvent(pathParams: Record<string, string>, body?: unknown, token?: string): APIGatewayProxyEvent {
  return {
    body: body ? JSON.stringify(body) : null,
    headers: { 'Authorization': token ? `Bearer ${token}` : undefined } as any,
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/tediyat/invitations',
    pathParameters: pathParams,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: { requestId: 'test', identity: { sourceIp: '127.0.0.1' } } as any,
    resource: '',
    multiValueHeaders: {},
  };
}

describe('Tediyat Invitation Handlers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockVerifyAccessToken.mockResolvedValue({ sub: 'user_owner', email: 'owner@test.com', realm_id: 'tediyat' });
    mockValidateEmail.mockReturnValue({ valid: true });
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Invitation Create Handler', () => {
    beforeEach(() => {
      mockGetMembership.mockResolvedValue({
        success: true,
        data: { role_id: 'role_owner' },
      });
      mockCreateInvitation.mockResolvedValue({
        success: true,
        data: {
          invitation: { id: 'inv_xxx', email: 'new@test.com', role_id: 'role_accountant', status: 'pending', expires_at: new Date().toISOString() },
          inviteUrl: 'https://app.tediyat.com/invite/xxx',
        },
      });
    });

    it('should create invitation', async () => {
      const event = createMockEvent(
        { tenantId: 'ten_xxx' },
        { email: 'new@test.com', role_id: 'role_accountant' },
        'valid_token'
      );
      const response = await createHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(201);
      expect(body.success).toBe(true);
      expect(body.data.invitation.id).toBe('inv_xxx');
    });

    it('should reject invalid email', async () => {
      mockValidateEmail.mockReturnValue({ valid: false });

      const event = createMockEvent(
        { tenantId: 'ten_xxx' },
        { email: 'invalid', role_id: 'role_accountant' },
        'valid_token'
      );
      const response = await createHandler(event);

      expect(response.statusCode).toBe(400);
    });

    it('should reject non-owner/admin', async () => {
      mockGetMembership.mockResolvedValue({
        success: true,
        data: { role_id: 'role_viewer' },
      });

      const event = createMockEvent(
        { tenantId: 'ten_xxx' },
        { email: 'new@test.com', role_id: 'role_accountant' },
        'valid_token'
      );
      const response = await createHandler(event);

      expect(response.statusCode).toBe(403);
    });
  });

  describe('Invitation Accept Handler', () => {
    beforeEach(() => {
      mockGetInvitationByToken.mockResolvedValue({
        success: true,
        data: {
          id: 'inv_xxx',
          tenant_id: 'ten_xxx',
          email: 'new@test.com',
          role_id: 'role_accountant',
          role_name: 'Muhasebeci',
          status: 'pending',
        },
      });
      mockCanAcceptInvitation.mockReturnValue(true);
      mockAcceptInvitation.mockResolvedValue({ success: true });
      mockGetTenant.mockResolvedValue({
        success: true,
        data: { id: 'ten_xxx', name: 'Test Company', slug: 'test-company' },
      });
      mockGenerateTokenPair.mockResolvedValue({
        access_token: 'access_xxx',
        refresh_token: 'refresh_xxx',
        expires_in: 3600,
      });
      mockCreateSession.mockResolvedValue({});
    });

    it('should accept invitation for existing user', async () => {
      mockFindUserByEmail.mockResolvedValue({
        id: 'user_existing',
        email: 'new@test.com',
      });

      const event = createMockEvent({ token: 'valid_invitation_token' }, {});
      const response = await acceptHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.user.isNewUser).toBe(false);
      expect(body.data.tokens.accessToken).toBeDefined();
    });

    it('should accept invitation for new user with password', async () => {
      mockFindUserByEmail.mockResolvedValue(null);
      mockValidatePasswordPolicy.mockReturnValue({ valid: true, errors: [] });
      mockCheckPasswordPwned.mockResolvedValue(0);
      mockCreateUser.mockResolvedValue({
        id: 'user_new',
        email: 'new@test.com',
      });

      const event = createMockEvent(
        { token: 'valid_invitation_token' },
        { password: 'SecurePass123!', firstName: 'Test', lastName: 'User' }
      );
      const response = await acceptHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.user.isNewUser).toBe(true);
    });

    it('should require password for new user', async () => {
      mockFindUserByEmail.mockResolvedValue(null);

      const event = createMockEvent({ token: 'valid_invitation_token' }, {});
      const response = await acceptHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('PASSWORD_REQUIRED');
    });

    it('should reject expired invitation', async () => {
      mockCanAcceptInvitation.mockReturnValue(false);

      const event = createMockEvent({ token: 'expired_token' }, {});
      const response = await acceptHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVITATION_EXPIRED');
    });

    it('should reject invalid invitation token', async () => {
      mockGetInvitationByToken.mockResolvedValue({ success: false });

      const event = createMockEvent({ token: 'invalid_token' }, {});
      const response = await acceptHandler(event);

      expect(response.statusCode).toBe(404);
    });
  });
});
