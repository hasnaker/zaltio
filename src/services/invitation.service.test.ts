/**
 * Invitation Service Tests
 * 
 * Tests for the InvitationService covering:
 * - Creating invitations
 * - Accepting invitations (existing and new users)
 * - Revoking invitations
 * - Listing invitations
 * - Resending invitations
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (using proper mocks for external dependencies)
 * 
 * Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6
 */

// Mock dependencies before imports
const mockInvitationRepository = {
  hasPendingInvitation: jest.fn(),
  createInvitation: jest.fn(),
  validateInvitationToken: jest.fn(),
  acceptInvitation: jest.fn(),
  getInvitationById: jest.fn(),
  revokeInvitation: jest.fn(),
  listInvitationsByTenant: jest.fn(),
  resendInvitation: jest.fn(),
  countInvitationsByStatus: jest.fn()
};

const mockMembershipRepository = {
  getMembership: jest.fn(),
  createMembership: jest.fn()
};

const mockUserRepository = {
  findUserById: jest.fn(),
  findUserByEmail: jest.fn(),
  createUser: jest.fn()
};

const mockOrganizationRepository = {
  getOrganization: jest.fn()
};

const mockEmailService = {
  sendEmail: jest.fn(),
  sendInvitationEmail: jest.fn()
};

const mockAuditService = {
  logAuditEvent: jest.fn(),
  AuditEventType: {
    ADMIN_ACTION: 'admin_action',
    LOGIN_SUCCESS: 'login_success',
    LOGIN_FAILURE: 'login_failure'
  },
  AuditResult: {
    SUCCESS: 'success',
    FAILURE: 'failure'
  },
  AuditSeverity: {
    INFO: 'info',
    WARNING: 'warning',
    ERROR: 'error'
  }
};

jest.mock('../repositories/invitation.repository', () => mockInvitationRepository);
jest.mock('../repositories/membership.repository', () => mockMembershipRepository);
jest.mock('../repositories/user.repository', () => mockUserRepository);
jest.mock('../repositories/organization.repository', () => mockOrganizationRepository);
jest.mock('./email.service', () => mockEmailService);
jest.mock('./audit.service', () => mockAuditService);


import {
  InvitationService,
  InvitationServiceError,
  InvitationErrorCode,
  CreateInvitationServiceInput,
  AcceptInvitationServiceInput,
  WebhookDispatcher
} from './invitation.service';
import { Organization } from '../models/organization.model';
import { User, UserResponse, UserStatus } from '../models/user.model';

// ============================================================================
// Test Data Factories
// ============================================================================

function createMockInvitation(overrides: Partial<any> = {}) {
  return {
    id: 'inv_test123',
    tenant_id: 'tenant_123',
    email: 'test@example.com',
    role: 'member',
    permissions: [],
    invited_by: 'user_admin',
    token_hash: 'hashed_token_123',
    status: 'pending' as const,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date().toISOString(),
    metadata: {
      tenant_name: 'Test Organization',
      inviter_name: 'Admin User',
      resend_count: 0
    },
    ...overrides
  };
}

function createMockInvitationResponse(overrides: Partial<any> = {}) {
  const invitation = createMockInvitation(overrides);
  return {
    id: invitation.id,
    tenant_id: invitation.tenant_id,
    email: invitation.email,
    role: invitation.role,
    permissions: invitation.permissions,
    invited_by: invitation.invited_by,
    status: invitation.status,
    expires_at: invitation.expires_at,
    created_at: invitation.created_at,
    metadata: invitation.metadata
  };
}

function createMockOrganization(overrides: Partial<Organization> = {}): Organization {
  return {
    id: 'tenant_123',
    realm_id: 'realm_test',
    name: 'Test Organization',
    slug: 'test-organization',
    status: 'active',
    member_count: 5,
    settings: {},
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides
  };
}

function createMockUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user_123',
    realm_id: 'realm_test',
    email: 'test@example.com',
    email_verified: true,
    password_hash: 'hashed_password_123',
    profile: {
      first_name: 'Test',
      last_name: 'User',
      metadata: {}
    },
    status: 'active' as UserStatus,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_login: new Date().toISOString(),
    ...overrides
  };
}

function createMockUserResponse(overrides: Partial<UserResponse> = {}): UserResponse {
  return {
    id: 'user_123',
    realm_id: 'realm_test',
    email: 'test@example.com',
    email_verified: true,
    profile: {
      first_name: 'Test',
      last_name: 'User',
      metadata: {}
    },
    status: 'active' as UserStatus,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_login: new Date().toISOString(),
    ...overrides
  };
}

// ============================================================================
// Test Suite
// ============================================================================

describe('InvitationService', () => {
  let service: InvitationService;
  let mockWebhookDispatcher: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    mockWebhookDispatcher = jest.fn().mockResolvedValue(undefined);
    service = new InvitationService(mockWebhookDispatcher);
    
    // Default mock implementations
    mockAuditService.logAuditEvent.mockResolvedValue({});
    mockEmailService.sendEmail.mockResolvedValue({ success: true });
    mockEmailService.sendInvitationEmail.mockResolvedValue({ success: true, messageId: 'test-message-id' });
  });

  // ==========================================================================
  // create() Tests
  // ==========================================================================

  describe('create()', () => {
    const validInput: CreateInvitationServiceInput = {
      tenant_id: 'tenant_123',
      email: 'newuser@example.com',
      role: 'member',
      invited_by: 'user_admin',
      inviter_name: 'Admin User',
      realm_id: 'realm_test'
    };

    it('should create an invitation successfully', async () => {
      // Arrange
      mockInvitationRepository.hasPendingInvitation.mockResolvedValue(false);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.createInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse({ email: 'newuser@example.com' }),
        token: 'raw_token_123'
      });

      // Act
      const result = await service.create(validInput);

      // Assert
      expect(result.invitation.email).toBe('newuser@example.com');
      expect(result.token).toBe('raw_token_123');
      expect(mockInvitationRepository.createInvitation).toHaveBeenCalledWith(
        expect.objectContaining({
          tenant_id: 'tenant_123',
          email: 'newuser@example.com',
          role: 'member'
        })
      );
    });

    it('should send invitation email after creation', async () => {
      // Arrange
      mockInvitationRepository.hasPendingInvitation.mockResolvedValue(false);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.createInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse({ email: 'newuser@example.com' }),
        token: 'raw_token_123'
      });

      // Act
      await service.create(validInput);

      // Assert - now uses sendInvitationEmail from email service
      expect(mockEmailService.sendInvitationEmail).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'newuser@example.com',
          token: 'raw_token_123',
          tenantName: 'Test Organization',
          inviterName: 'Admin User',
          role: 'member'
        })
      );
    });

    it('should trigger member.invited webhook', async () => {
      // Arrange
      mockInvitationRepository.hasPendingInvitation.mockResolvedValue(false);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.createInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse({ email: 'newuser@example.com' }),
        token: 'raw_token_123'
      });

      // Act
      await service.create(validInput);

      // Assert
      expect(mockWebhookDispatcher).toHaveBeenCalledWith(
        'realm_test',
        'member.invited',
        expect.objectContaining({
          tenant_id: 'tenant_123',
          email: 'newuser@example.com',
          role: 'member'
        })
      );
    });

    it('should reject invalid email format', async () => {
      // Arrange
      const invalidInput = { ...validInput, email: 'invalid-email' };

      // Act & Assert
      await expect(service.create(invalidInput)).rejects.toThrow(InvitationServiceError);
      await expect(service.create(invalidInput)).rejects.toMatchObject({
        code: InvitationErrorCode.INVALID_EMAIL
      });
    });

    it('should reject duplicate pending invitation', async () => {
      // Arrange
      mockInvitationRepository.hasPendingInvitation.mockResolvedValue(true);

      // Act & Assert
      await expect(service.create(validInput)).rejects.toThrow(InvitationServiceError);
      await expect(service.create(validInput)).rejects.toMatchObject({
        code: InvitationErrorCode.DUPLICATE_INVITATION
      });
    });

    it('should normalize email to lowercase', async () => {
      // Arrange
      const inputWithUppercase = { ...validInput, email: 'NewUser@EXAMPLE.COM' };
      mockInvitationRepository.hasPendingInvitation.mockResolvedValue(false);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.createInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse({ email: 'newuser@example.com' }),
        token: 'raw_token_123'
      });

      // Act
      await service.create(inputWithUppercase);

      // Assert
      expect(mockInvitationRepository.createInvitation).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'newuser@example.com'
        })
      );
    });

    it('should audit log invitation creation', async () => {
      // Arrange
      mockInvitationRepository.hasPendingInvitation.mockResolvedValue(false);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.createInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse(),
        token: 'raw_token_123'
      });

      // Act
      await service.create(validInput);

      // Assert
      expect(mockAuditService.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'invitation_created',
          realmId: 'realm_test'
        })
      );
    });
  });


  // ==========================================================================
  // accept() Tests
  // ==========================================================================

  describe('accept()', () => {
    const validToken = 'valid_invitation_token_123';

    it('should accept invitation for existing user', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: true,
        invitation: mockInvitation
      });
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockUserRepository.findUserById.mockResolvedValue(createMockUser());
      mockMembershipRepository.getMembership.mockResolvedValue(null);
      mockInvitationRepository.acceptInvitation.mockResolvedValue(
        createMockInvitation({ status: 'accepted' })
      );
      mockMembershipRepository.createMembership.mockResolvedValue({});

      const input: AcceptInvitationServiceInput = {
        token: validToken,
        user_id: 'user_123',
        ip_address: '192.168.1.1'
      };

      // Act
      const result = await service.accept(input);

      // Assert
      expect(result.user_id).toBe('user_123');
      expect(result.tenant_id).toBe('tenant_123');
      expect(result.role).toBe('member');
      expect(result.is_new_user).toBe(false);
    });

    it('should accept invitation and create new user', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: true,
        invitation: mockInvitation
      });
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockUserRepository.findUserByEmail.mockResolvedValue(null);
      mockUserRepository.createUser.mockResolvedValue(createMockUserResponse({ id: 'new_user_456' }));
      mockInvitationRepository.acceptInvitation.mockResolvedValue(
        createMockInvitation({ status: 'accepted' })
      );
      mockMembershipRepository.createMembership.mockResolvedValue({});

      const input: AcceptInvitationServiceInput = {
        token: validToken,
        new_user_data: {
          first_name: 'New',
          last_name: 'User',
          password: 'SecurePassword123!'
        },
        ip_address: '192.168.1.1'
      };

      // Act
      const result = await service.accept(input);

      // Assert
      expect(result.user_id).toBe('new_user_456');
      expect(result.is_new_user).toBe(true);
      expect(mockUserRepository.createUser).toHaveBeenCalled();
    });

    it('should trigger member.joined webhook on acceptance', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: true,
        invitation: mockInvitation
      });
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockUserRepository.findUserById.mockResolvedValue(createMockUser());
      mockMembershipRepository.getMembership.mockResolvedValue(null);
      mockInvitationRepository.acceptInvitation.mockResolvedValue(
        createMockInvitation({ status: 'accepted' })
      );
      mockMembershipRepository.createMembership.mockResolvedValue({});

      const input: AcceptInvitationServiceInput = {
        token: validToken,
        user_id: 'user_123',
        ip_address: '192.168.1.1'
      };

      // Act
      await service.accept(input);

      // Assert
      expect(mockWebhookDispatcher).toHaveBeenCalledWith(
        'realm_test',
        'member.joined',
        expect.objectContaining({
          tenant_id: 'tenant_123',
          user_id: 'user_123'
        })
      );
    });

    it('should reject invalid token', async () => {
      // Arrange
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: false,
        error: 'Invalid invitation token',
        error_code: 'INVITATION_NOT_FOUND'
      });

      const input: AcceptInvitationServiceInput = {
        token: 'invalid_token',
        user_id: 'user_123',
        ip_address: '192.168.1.1'
      };

      // Act & Assert
      await expect(service.accept(input)).rejects.toMatchObject({
        code: InvitationErrorCode.INVALID_TOKEN
      });
    });

    it('should reject expired invitation', async () => {
      // Arrange
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: false,
        error: 'Invitation has expired',
        error_code: 'INVITATION_EXPIRED'
      });

      const input: AcceptInvitationServiceInput = {
        token: validToken,
        user_id: 'user_123',
        ip_address: '192.168.1.1'
      };

      // Act & Assert
      await expect(service.accept(input)).rejects.toMatchObject({
        code: InvitationErrorCode.INVITATION_EXPIRED
      });
    });

    it('should reject already used invitation', async () => {
      // Arrange
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: false,
        error: 'Invitation has already been accepted',
        error_code: 'INVITATION_ALREADY_USED'
      });

      const input: AcceptInvitationServiceInput = {
        token: validToken,
        user_id: 'user_123',
        ip_address: '192.168.1.1'
      };

      // Act & Assert
      await expect(service.accept(input)).rejects.toMatchObject({
        code: InvitationErrorCode.INVITATION_ALREADY_USED
      });
    });

    it('should reject if user is already a member', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: true,
        invitation: mockInvitation
      });
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockUserRepository.findUserById.mockResolvedValue(createMockUser());
      mockMembershipRepository.getMembership.mockResolvedValue({}); // Already a member

      const input: AcceptInvitationServiceInput = {
        token: validToken,
        user_id: 'user_123',
        ip_address: '192.168.1.1'
      };

      // Act & Assert
      await expect(service.accept(input)).rejects.toMatchObject({
        code: InvitationErrorCode.USER_ALREADY_MEMBER
      });
    });

    it('should create membership with correct role', async () => {
      // Arrange
      const mockInvitation = createMockInvitation({ role: 'admin', permissions: ['read', 'write'] });
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: true,
        invitation: mockInvitation
      });
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockUserRepository.findUserById.mockResolvedValue(createMockUser());
      mockMembershipRepository.getMembership.mockResolvedValue(null);
      mockInvitationRepository.acceptInvitation.mockResolvedValue(
        createMockInvitation({ status: 'accepted' })
      );
      mockMembershipRepository.createMembership.mockResolvedValue({});

      const input: AcceptInvitationServiceInput = {
        token: validToken,
        user_id: 'user_123',
        ip_address: '192.168.1.1'
      };

      // Act
      await service.accept(input);

      // Assert
      expect(mockMembershipRepository.createMembership).toHaveBeenCalledWith(
        expect.objectContaining({
          user_id: 'user_123',
          org_id: 'tenant_123',
          role_ids: ['admin'],
          direct_permissions: ['read', 'write']
        })
      );
    });
  });


  // ==========================================================================
  // revoke() Tests
  // ==========================================================================

  describe('revoke()', () => {
    it('should revoke a pending invitation', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.getInvitationById.mockResolvedValue(mockInvitation);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.revokeInvitation.mockResolvedValue(
        createMockInvitation({ status: 'revoked' })
      );

      // Act
      const result = await service.revoke({
        invitation_id: 'inv_test123',
        tenant_id: 'tenant_123',
        revoked_by: 'user_admin',
        ip_address: '192.168.1.1'
      });

      // Assert
      expect(result.status).toBe('revoked');
      expect(mockInvitationRepository.revokeInvitation).toHaveBeenCalledWith(
        'tenant_123',
        'inv_test123',
        'user_admin'
      );
    });

    it('should reject revoking non-existent invitation', async () => {
      // Arrange
      mockInvitationRepository.getInvitationById.mockResolvedValue(null);

      // Act & Assert
      await expect(service.revoke({
        invitation_id: 'inv_nonexistent',
        tenant_id: 'tenant_123',
        revoked_by: 'user_admin',
        ip_address: '192.168.1.1'
      })).rejects.toMatchObject({
        code: InvitationErrorCode.INVITATION_NOT_FOUND
      });
    });

    it('should reject revoking already accepted invitation', async () => {
      // Arrange
      const acceptedInvitation = createMockInvitation({ status: 'accepted' });
      mockInvitationRepository.getInvitationById.mockResolvedValue(acceptedInvitation);

      // Act & Assert
      await expect(service.revoke({
        invitation_id: 'inv_test123',
        tenant_id: 'tenant_123',
        revoked_by: 'user_admin',
        ip_address: '192.168.1.1'
      })).rejects.toMatchObject({
        code: InvitationErrorCode.CANNOT_REVOKE
      });
    });

    it('should audit log revocation', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.getInvitationById.mockResolvedValue(mockInvitation);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.revokeInvitation.mockResolvedValue(
        createMockInvitation({ status: 'revoked' })
      );

      // Act
      await service.revoke({
        invitation_id: 'inv_test123',
        tenant_id: 'tenant_123',
        revoked_by: 'user_admin',
        ip_address: '192.168.1.1'
      });

      // Assert
      expect(mockAuditService.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'invitation_revoked'
        })
      );
    });
  });

  // ==========================================================================
  // list() Tests
  // ==========================================================================

  describe('list()', () => {
    it('should list all invitations for a tenant', async () => {
      // Arrange
      const mockInvitations = [
        createMockInvitationResponse({ id: 'inv_1', status: 'pending' }),
        createMockInvitationResponse({ id: 'inv_2', status: 'accepted' }),
        createMockInvitationResponse({ id: 'inv_3', status: 'expired' })
      ];
      mockInvitationRepository.listInvitationsByTenant.mockResolvedValue({
        invitations: mockInvitations,
        nextCursor: undefined
      });

      // Act
      const result = await service.list({ tenant_id: 'tenant_123' });

      // Assert
      expect(result.invitations).toHaveLength(3);
      expect(result.next_cursor).toBeUndefined();
    });

    it('should filter by status', async () => {
      // Arrange
      const pendingInvitations = [
        createMockInvitationResponse({ id: 'inv_1', status: 'pending' })
      ];
      mockInvitationRepository.listInvitationsByTenant.mockResolvedValue({
        invitations: pendingInvitations,
        nextCursor: undefined
      });

      // Act
      const result = await service.list({ tenant_id: 'tenant_123', status: 'pending' });

      // Assert
      expect(mockInvitationRepository.listInvitationsByTenant).toHaveBeenCalledWith(
        'tenant_123',
        expect.objectContaining({ status: 'pending' })
      );
      expect(result.invitations).toHaveLength(1);
    });

    it('should support pagination', async () => {
      // Arrange
      const mockInvitations = [createMockInvitationResponse()];
      mockInvitationRepository.listInvitationsByTenant.mockResolvedValue({
        invitations: mockInvitations,
        nextCursor: 'next_page_cursor'
      });

      // Act
      const result = await service.list({
        tenant_id: 'tenant_123',
        limit: 10,
        cursor: 'current_cursor'
      });

      // Assert
      expect(mockInvitationRepository.listInvitationsByTenant).toHaveBeenCalledWith(
        'tenant_123',
        expect.objectContaining({ limit: 10, cursor: 'current_cursor' })
      );
      expect(result.next_cursor).toBe('next_page_cursor');
    });
  });

  // ==========================================================================
  // resend() Tests
  // ==========================================================================

  describe('resend()', () => {
    it('should resend invitation with new token', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.getInvitationById.mockResolvedValue(mockInvitation);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.resendInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse(),
        token: 'new_token_456'
      });

      // Act
      const result = await service.resend({
        invitation_id: 'inv_test123',
        tenant_id: 'tenant_123',
        resent_by: 'user_admin',
        ip_address: '192.168.1.1'
      });

      // Assert
      expect(result.token).toBe('new_token_456');
      expect(mockEmailService.sendInvitationEmail).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'test@example.com',
          token: 'new_token_456'
        })
      );
    });

    it('should reject resending non-pending invitation', async () => {
      // Arrange
      const acceptedInvitation = createMockInvitation({ status: 'accepted' });
      mockInvitationRepository.getInvitationById.mockResolvedValue(acceptedInvitation);

      // Act & Assert
      await expect(service.resend({
        invitation_id: 'inv_test123',
        tenant_id: 'tenant_123',
        resent_by: 'user_admin',
        ip_address: '192.168.1.1'
      })).rejects.toMatchObject({
        code: InvitationErrorCode.CANNOT_RESEND
      });
    });

    it('should reject resending non-existent invitation', async () => {
      // Arrange
      mockInvitationRepository.getInvitationById.mockResolvedValue(null);

      // Act & Assert
      await expect(service.resend({
        invitation_id: 'inv_nonexistent',
        tenant_id: 'tenant_123',
        resent_by: 'user_admin',
        ip_address: '192.168.1.1'
      })).rejects.toMatchObject({
        code: InvitationErrorCode.INVITATION_NOT_FOUND
      });
    });

    it('should audit log resend', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.getInvitationById.mockResolvedValue(mockInvitation);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.resendInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse(),
        token: 'new_token_456'
      });

      // Act
      await service.resend({
        invitation_id: 'inv_test123',
        tenant_id: 'tenant_123',
        resent_by: 'user_admin',
        ip_address: '192.168.1.1'
      });

      // Assert
      expect(mockAuditService.logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'invitation_resent'
        })
      );
    });
  });

  // ==========================================================================
  // validateToken() Tests
  // ==========================================================================

  describe('validateToken()', () => {
    it('should return valid result for valid token', async () => {
      // Arrange
      const mockInvitation = createMockInvitation();
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: true,
        invitation: mockInvitation
      });

      // Act
      const result = await service.validateToken('valid_token');

      // Assert
      expect(result.valid).toBe(true);
      expect(result.invitation_details).toBeDefined();
      expect(result.invitation_details?.email).toBe('test@example.com');
    });

    it('should return invalid result for invalid token', async () => {
      // Arrange
      mockInvitationRepository.validateInvitationToken.mockResolvedValue({
        valid: false,
        error: 'Invalid token',
        error_code: 'INVITATION_NOT_FOUND'
      });

      // Act
      const result = await service.validateToken('invalid_token');

      // Assert
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token');
    });
  });

  // ==========================================================================
  // getStatistics() Tests
  // ==========================================================================

  describe('getStatistics()', () => {
    it('should return invitation statistics', async () => {
      // Arrange
      mockInvitationRepository.countInvitationsByStatus.mockResolvedValue({
        pending: 5,
        accepted: 10,
        expired: 3,
        revoked: 2
      });

      // Act
      const result = await service.getStatistics('tenant_123');

      // Assert
      expect(result.pending).toBe(5);
      expect(result.accepted).toBe(10);
      expect(result.expired).toBe(3);
      expect(result.revoked).toBe(2);
    });
  });

  // ==========================================================================
  // Webhook Dispatcher Tests
  // ==========================================================================

  describe('webhook dispatcher', () => {
    it('should not fail if webhook dispatcher throws', async () => {
      // Arrange
      const failingDispatcher = jest.fn().mockRejectedValue(new Error('Webhook failed'));
      const serviceWithFailingWebhook = new InvitationService(failingDispatcher);
      
      mockInvitationRepository.hasPendingInvitation.mockResolvedValue(false);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.createInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse(),
        token: 'raw_token_123'
      });

      // Act & Assert - should not throw
      await expect(serviceWithFailingWebhook.create({
        tenant_id: 'tenant_123',
        email: 'test@example.com',
        role: 'member',
        invited_by: 'user_admin',
        realm_id: 'realm_test'
      })).resolves.toBeDefined();
    });

    it('should work without webhook dispatcher', async () => {
      // Arrange
      const serviceWithoutWebhook = new InvitationService();
      
      mockInvitationRepository.hasPendingInvitation.mockResolvedValue(false);
      mockOrganizationRepository.getOrganization.mockResolvedValue(createMockOrganization());
      mockInvitationRepository.createInvitation.mockResolvedValue({
        invitation: createMockInvitationResponse(),
        token: 'raw_token_123'
      });

      // Act & Assert - should not throw
      await expect(serviceWithoutWebhook.create({
        tenant_id: 'tenant_123',
        email: 'test@example.com',
        role: 'member',
        invited_by: 'user_admin',
        realm_id: 'realm_test'
      })).resolves.toBeDefined();
    });
  });
});
