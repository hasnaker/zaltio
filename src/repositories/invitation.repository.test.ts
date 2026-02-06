/**
 * Invitation Repository Tests
 * Tests for invitation CRUD operations
 * 
 * Validates: Requirements 11.1 (Invitation System)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 * 
 * Security Requirements Tested:
 * - Token must be cryptographically secure (32 bytes, hex encoded)
 * - Token must be hashed before storage (SHA-256)
 * - No email enumeration
 */

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  }
}));

// Import after mocks
import {
  createInvitation,
  getInvitationById,
  getInvitationByTokenHash,
  validateInvitationToken,
  listInvitationsByTenant,
  listInvitationsByEmail,
  hasPendingInvitation,
  acceptInvitation,
  revokeInvitation,
  expireInvitation,
  resendInvitation,
  deleteInvitation,
  deleteAllTenantInvitations,
  countInvitationsByStatus
} from './invitation.repository';

import {
  hashInvitationToken,
  generateInvitationToken,
  INVITATION_TOKEN_BYTES
} from '../models/invitation.model';

describe('Invitation Repository', () => {
  const mockTenantId = 'tenant_test123';
  const mockInvitationId = 'inv_abc123def456';
  const mockEmail = 'test@example.com';
  const mockUserId = 'user_inviter123';
  const mockRole = 'member';
  
  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createInvitation', () => {
    it('should create a new invitation with generated ID and token', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        metadata: {
          tenant_name: 'Test Tenant',
          inviter_name: 'John Doe'
        }
      };
      
      const result = await createInvitation(input);
      
      // Verify invitation was created
      expect(result).toBeDefined();
      expect(result.invitation.id).toMatch(/^inv_[a-f0-9]{24}$/);
      expect(result.invitation.tenant_id).toBe(mockTenantId);
      expect(result.invitation.email).toBe(mockEmail.toLowerCase());
      expect(result.invitation.role).toBe(mockRole);
      expect(result.invitation.invited_by).toBe(mockUserId);
      expect(result.invitation.status).toBe('pending');
      
      // Verify token is returned (64 hex chars = 32 bytes)
      expect(result.token).toMatch(/^[a-f0-9]{64}$/);
      expect(result.token.length).toBe(INVITATION_TOKEN_BYTES * 2);
      
      // Verify DynamoDB put was called
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should normalize email to lowercase', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        tenant_id: mockTenantId,
        email: 'TEST@EXAMPLE.COM',
        role: mockRole,
        invited_by: mockUserId
      };
      
      const result = await createInvitation(input);
      
      expect(result.invitation.email).toBe('test@example.com');
    });
    
    it('should set default 7-day expiry', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId
      };
      
      const result = await createInvitation(input);
      
      const expiresAt = new Date(result.invitation.expires_at);
      const now = new Date();
      const diffDays = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      
      // Should be approximately 7 days
      expect(diffDays).toBeGreaterThan(6.9);
      expect(diffDays).toBeLessThan(7.1);
    });
    
    it('should allow custom expiry days', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        expires_in_days: 14
      };
      
      const result = await createInvitation(input);
      
      const expiresAt = new Date(result.invitation.expires_at);
      const now = new Date();
      const diffDays = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      
      expect(diffDays).toBeGreaterThan(13.9);
      expect(diffDays).toBeLessThan(14.1);
    });
    
    it('should include permissions if provided', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        permissions: ['read:reports', 'write:comments'],
        invited_by: mockUserId
      };
      
      const result = await createInvitation(input);
      
      expect(result.invitation.permissions).toEqual(['read:reports', 'write:comments']);
    });
  });

  describe('getInvitationById', () => {
    it('should return invitation when found', async () => {
      const mockInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: 'hashed_token_123',
        status: 'pending',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Item: mockInvitation
      });
      
      const result = await getInvitationById(mockTenantId, mockInvitationId);
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockInvitationId);
      expect(result?.email).toBe(mockEmail);
      expect(result?.status).toBe('pending');
    });
    
    it('should return null when invitation not found', async () => {
      mockSend.mockResolvedValueOnce({
        Item: undefined
      });
      
      const result = await getInvitationById(mockTenantId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });

  describe('getInvitationByTokenHash', () => {
    it('should return invitation when token hash matches', async () => {
      const tokenHash = 'hashed_token_abc123';
      const mockInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: tokenHash,
        status: 'pending',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockInvitation]
      });
      
      const result = await getInvitationByTokenHash(tokenHash);
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockInvitationId);
    });
    
    it('should return null when token hash not found', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getInvitationByTokenHash('nonexistent_hash');
      
      expect(result).toBeNull();
    });
  });

  describe('validateInvitationToken', () => {
    it('should return valid result for valid pending invitation', async () => {
      const rawToken = generateInvitationToken();
      const tokenHash = hashInvitationToken(rawToken);
      
      const mockInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: tokenHash,
        status: 'pending',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockInvitation]
      });
      
      const result = await validateInvitationToken(rawToken);
      
      expect(result.valid).toBe(true);
      expect(result.invitation).toBeDefined();
      expect(result.error).toBeUndefined();
    });
    
    it('should return invalid for non-existent token', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await validateInvitationToken('invalid_token');
      
      expect(result.valid).toBe(false);
      expect(result.error_code).toBe('INVITATION_NOT_FOUND');
    });
    
    it('should return invalid for already accepted invitation', async () => {
      const rawToken = generateInvitationToken();
      const tokenHash = hashInvitationToken(rawToken);
      
      const mockInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: tokenHash,
        status: 'accepted',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: '2026-01-01T00:00:00Z',
        accepted_at: '2026-01-02T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockInvitation]
      });
      
      const result = await validateInvitationToken(rawToken);
      
      expect(result.valid).toBe(false);
      expect(result.error_code).toBe('INVITATION_ALREADY_USED');
    });
    
    it('should return invalid for expired invitation', async () => {
      const rawToken = generateInvitationToken();
      const tokenHash = hashInvitationToken(rawToken);
      
      const mockInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: tokenHash,
        status: 'pending',
        expires_at: '2020-01-01T00:00:00Z', // Past date
        created_at: '2019-12-25T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockInvitation]
      });
      
      const result = await validateInvitationToken(rawToken);
      
      expect(result.valid).toBe(false);
      expect(result.error_code).toBe('INVITATION_EXPIRED');
    });
    
    it('should return invalid for revoked invitation', async () => {
      const rawToken = generateInvitationToken();
      const tokenHash = hashInvitationToken(rawToken);
      
      const mockInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: tokenHash,
        status: 'revoked',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: '2026-01-01T00:00:00Z',
        revoked_at: '2026-01-02T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockInvitation]
      });
      
      const result = await validateInvitationToken(rawToken);
      
      expect(result.valid).toBe(false);
      expect(result.error_code).toBe('INVITATION_REVOKED');
    });
  });

  describe('listInvitationsByTenant', () => {
    it('should return all invitations for a tenant', async () => {
      const mockInvitations = [
        {
          id: 'inv_1',
          tenant_id: mockTenantId,
          email: 'user1@example.com',
          role: 'member',
          invited_by: mockUserId,
          token_hash: 'hash1',
          status: 'pending',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          created_at: '2026-01-01T00:00:00Z'
        },
        {
          id: 'inv_2',
          tenant_id: mockTenantId,
          email: 'user2@example.com',
          role: 'admin',
          invited_by: mockUserId,
          token_hash: 'hash2',
          status: 'accepted',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          created_at: '2026-01-02T00:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockInvitations
      });
      
      const result = await listInvitationsByTenant(mockTenantId);
      
      expect(result.invitations).toHaveLength(2);
      expect(result.invitations[0].email).toBe('user1@example.com');
      expect(result.invitations[1].email).toBe('user2@example.com');
    });
    
    it('should filter by status when provided', async () => {
      const mockInvitations = [
        {
          id: 'inv_1',
          tenant_id: mockTenantId,
          email: 'user1@example.com',
          role: 'member',
          invited_by: mockUserId,
          token_hash: 'hash1',
          status: 'pending',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          created_at: '2026-01-01T00:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockInvitations
      });
      
      const result = await listInvitationsByTenant(mockTenantId, { status: 'pending' });
      
      expect(result.invitations).toHaveLength(1);
      expect(result.invitations[0].status).toBe('pending');
    });
    
    it('should return empty array when no invitations', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await listInvitationsByTenant(mockTenantId);
      
      expect(result.invitations).toEqual([]);
    });
    
    it('should handle pagination cursor', async () => {
      const mockInvitations = [
        {
          id: 'inv_1',
          tenant_id: mockTenantId,
          email: 'user1@example.com',
          role: 'member',
          invited_by: mockUserId,
          token_hash: 'hash1',
          status: 'pending',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          created_at: '2026-01-01T00:00:00Z'
        }
      ];
      
      const lastKey = { pk: 'TENANT#test#INVITATION#inv_1', sk: 'INVITATION' };
      
      mockSend.mockResolvedValueOnce({
        Items: mockInvitations,
        LastEvaluatedKey: lastKey
      });
      
      const result = await listInvitationsByTenant(mockTenantId, { limit: 1 });
      
      expect(result.invitations).toHaveLength(1);
      expect(result.nextCursor).toBeDefined();
    });
  });

  describe('listInvitationsByEmail', () => {
    it('should return invitations for an email', async () => {
      const mockInvitations = [
        {
          id: 'inv_1',
          tenant_id: 'tenant_1',
          email: mockEmail,
          role: 'member',
          invited_by: mockUserId,
          token_hash: 'hash1',
          status: 'pending',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          created_at: '2026-01-01T00:00:00Z'
        },
        {
          id: 'inv_2',
          tenant_id: 'tenant_2',
          email: mockEmail,
          role: 'admin',
          invited_by: 'user_other',
          token_hash: 'hash2',
          status: 'pending',
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          created_at: '2026-01-02T00:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockInvitations
      });
      
      const result = await listInvitationsByEmail(mockEmail);
      
      expect(result).toHaveLength(2);
    });
    
    it('should normalize email for lookup', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      await listInvitationsByEmail('TEST@EXAMPLE.COM');
      
      // Verify the query used lowercase email
      expect(mockSend).toHaveBeenCalledTimes(1);
      const callArgs = mockSend.mock.calls[0][0];
      expect(callArgs.input.ExpressionAttributeValues[':email']).toBe('test@example.com');
    });
  });

  describe('hasPendingInvitation', () => {
    it('should return true when pending invitation exists', async () => {
      mockSend.mockResolvedValueOnce({
        Items: [{ id: 'inv_1' }]
      });
      
      const result = await hasPendingInvitation(mockTenantId, mockEmail);
      
      expect(result).toBe(true);
    });
    
    it('should return false when no pending invitation', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await hasPendingInvitation(mockTenantId, mockEmail);
      
      expect(result).toBe(false);
    });
  });

  describe('acceptInvitation', () => {
    it('should accept a pending invitation', async () => {
      const acceptedInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: 'hash123',
        status: 'accepted',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: '2026-01-01T00:00:00Z',
        accepted_at: '2026-01-02T00:00:00Z',
        accepted_by_user_id: 'user_accepter123'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: acceptedInvitation
      });
      
      const result = await acceptInvitation(mockTenantId, mockInvitationId, 'user_accepter123');
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('accepted');
      expect(result?.accepted_at).toBeDefined();
      expect(result?.accepted_by_user_id).toBe('user_accepter123');
    });
    
    it('should return null when invitation not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await acceptInvitation(mockTenantId, 'nonexistent', 'user_123');
      
      expect(result).toBeNull();
    });
    
    it('should return null when invitation already accepted', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await acceptInvitation(mockTenantId, mockInvitationId, 'user_123');
      
      expect(result).toBeNull();
    });
  });

  describe('revokeInvitation', () => {
    it('should revoke a pending invitation', async () => {
      const revokedInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: 'hash123',
        status: 'revoked',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: '2026-01-01T00:00:00Z',
        revoked_at: '2026-01-02T00:00:00Z',
        revoked_by: 'admin_user123'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: revokedInvitation
      });
      
      const result = await revokeInvitation(mockTenantId, mockInvitationId, 'admin_user123');
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('revoked');
      expect(result?.revoked_at).toBeDefined();
      expect(result?.revoked_by).toBe('admin_user123');
    });
    
    it('should return null when invitation not pending', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await revokeInvitation(mockTenantId, mockInvitationId, 'admin_user123');
      
      expect(result).toBeNull();
    });
  });

  describe('expireInvitation', () => {
    it('should expire a pending invitation', async () => {
      const expiredInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: 'hash123',
        status: 'expired',
        expires_at: '2026-01-01T00:00:00Z',
        created_at: '2025-12-25T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: expiredInvitation
      });
      
      const result = await expireInvitation(mockTenantId, mockInvitationId);
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('expired');
    });
    
    it('should return null when invitation not pending', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await expireInvitation(mockTenantId, mockInvitationId);
      
      expect(result).toBeNull();
    });
  });

  describe('resendInvitation', () => {
    it('should generate new token and extend expiry', async () => {
      // First call: getInvitationById
      const existingInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: 'old_hash',
        status: 'pending',
        expires_at: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000).toISOString(), // 1 day left
        created_at: '2026-01-01T00:00:00Z',
        metadata: { resend_count: 1 }
      };
      
      mockSend.mockResolvedValueOnce({
        Item: existingInvitation
      });
      
      // Second call: UpdateCommand
      const updatedInvitation = {
        ...existingInvitation,
        token_hash: 'new_hash',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        metadata: { resend_count: 2, last_resent_at: '2026-01-03T00:00:00Z' }
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedInvitation
      });
      
      const result = await resendInvitation(mockTenantId, mockInvitationId);
      
      expect(result).toBeDefined();
      expect(result?.token).toMatch(/^[a-f0-9]{64}$/);
      expect(result?.invitation.id).toBe(mockInvitationId);
    });
    
    it('should return null when invitation not found', async () => {
      mockSend.mockResolvedValueOnce({
        Item: undefined
      });
      
      const result = await resendInvitation(mockTenantId, 'nonexistent');
      
      expect(result).toBeNull();
    });
    
    it('should return null when invitation not pending', async () => {
      const acceptedInvitation = {
        id: mockInvitationId,
        tenant_id: mockTenantId,
        email: mockEmail,
        role: mockRole,
        invited_by: mockUserId,
        token_hash: 'hash',
        status: 'accepted',
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Item: acceptedInvitation
      });
      
      const result = await resendInvitation(mockTenantId, mockInvitationId);
      
      expect(result).toBeNull();
    });
  });

  describe('deleteInvitation', () => {
    it('should delete an invitation', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const result = await deleteInvitation(mockTenantId, mockInvitationId);
      
      expect(result).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
      
      const result = await deleteInvitation(mockTenantId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });

  describe('deleteAllTenantInvitations', () => {
    it('should delete all invitations for a tenant', async () => {
      const mockInvitations = [
        { id: 'inv_1', tenant_id: mockTenantId, email: 'user1@example.com', role: 'member', invited_by: mockUserId, token_hash: 'h1', status: 'pending', expires_at: '2026-01-08T00:00:00Z', created_at: '2026-01-01T00:00:00Z' },
        { id: 'inv_2', tenant_id: mockTenantId, email: 'user2@example.com', role: 'admin', invited_by: mockUserId, token_hash: 'h2', status: 'accepted', expires_at: '2026-01-08T00:00:00Z', created_at: '2026-01-02T00:00:00Z' }
      ];
      
      mockSend
        .mockResolvedValueOnce({ Items: mockInvitations }) // listInvitationsByTenant
        .mockResolvedValueOnce({}); // BatchWriteCommand
      
      const result = await deleteAllTenantInvitations(mockTenantId);
      
      expect(result).toBe(2);
    });
    
    it('should return 0 when no invitations', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await deleteAllTenantInvitations(mockTenantId);
      
      expect(result).toBe(0);
    });
  });

  describe('countInvitationsByStatus', () => {
    it('should count invitations by status', async () => {
      const mockInvitations = [
        { id: 'inv_1', status: 'pending', expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() },
        { id: 'inv_2', status: 'pending', expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() },
        { id: 'inv_3', status: 'accepted', expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() },
        { id: 'inv_4', status: 'revoked', expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockInvitations });
      
      const result = await countInvitationsByStatus(mockTenantId);
      
      expect(result.pending).toBe(2);
      expect(result.accepted).toBe(1);
      expect(result.revoked).toBe(1);
      expect(result.expired).toBe(0);
    });
    
    it('should count expired pending invitations as expired', async () => {
      const mockInvitations = [
        { id: 'inv_1', status: 'pending', expires_at: '2020-01-01T00:00:00Z' }, // Expired
        { id: 'inv_2', status: 'pending', expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockInvitations });
      
      const result = await countInvitationsByStatus(mockTenantId);
      
      expect(result.pending).toBe(1);
      expect(result.expired).toBe(1);
    });
  });
});

describe('Invitation Model Utilities', () => {
  const {
    generateInvitationId,
    generateInvitationToken,
    hashInvitationToken,
    calculateExpiryDate,
    calculateTTL,
    isInvitationExpired,
    isValidInvitationStatus,
    canAcceptInvitation,
    normalizeEmail,
    toInvitationResponse,
    isValidEmail,
    maskEmail,
    INVITATION_TOKEN_BYTES,
    DEFAULT_INVITATION_EXPIRY_DAYS,
    MAX_INVITATION_EXPIRY_DAYS
  } = require('../models/invitation.model');
  
  describe('generateInvitationId', () => {
    it('should generate ID with inv_ prefix', () => {
      const id = generateInvitationId();
      expect(id).toMatch(/^inv_[a-f0-9]{24}$/);
    });
    
    it('should generate unique IDs', () => {
      const ids = new Set();
      for (let i = 0; i < 100; i++) {
        ids.add(generateInvitationId());
      }
      expect(ids.size).toBe(100);
    });
  });
  
  describe('generateInvitationToken', () => {
    it('should generate 64 character hex token', () => {
      const token = generateInvitationToken();
      expect(token).toMatch(/^[a-f0-9]{64}$/);
      expect(token.length).toBe(INVITATION_TOKEN_BYTES * 2);
    });
    
    it('should generate unique tokens', () => {
      const tokens = new Set();
      for (let i = 0; i < 100; i++) {
        tokens.add(generateInvitationToken());
      }
      expect(tokens.size).toBe(100);
    });
  });
  
  describe('hashInvitationToken', () => {
    it('should hash token with SHA-256', () => {
      const token = 'test_token_123';
      const hash = hashInvitationToken(token);
      
      // SHA-256 produces 64 character hex string
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });
    
    it('should produce consistent hash for same input', () => {
      const token = 'consistent_token';
      const hash1 = hashInvitationToken(token);
      const hash2 = hashInvitationToken(token);
      
      expect(hash1).toBe(hash2);
    });
    
    it('should produce different hash for different input', () => {
      const hash1 = hashInvitationToken('token1');
      const hash2 = hashInvitationToken('token2');
      
      expect(hash1).not.toBe(hash2);
    });
  });
  
  describe('calculateExpiryDate', () => {
    it('should default to 7 days', () => {
      const expiryDate = new Date(calculateExpiryDate());
      const now = new Date();
      const diffDays = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      
      expect(diffDays).toBeGreaterThan(6.9);
      expect(diffDays).toBeLessThan(7.1);
    });
    
    it('should respect custom days', () => {
      const expiryDate = new Date(calculateExpiryDate(14));
      const now = new Date();
      const diffDays = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      
      expect(diffDays).toBeGreaterThan(13.9);
      expect(diffDays).toBeLessThan(14.1);
    });
    
    it('should cap at maximum days', () => {
      const expiryDate = new Date(calculateExpiryDate(100));
      const now = new Date();
      const diffDays = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      
      expect(diffDays).toBeLessThanOrEqual(MAX_INVITATION_EXPIRY_DAYS + 0.1);
    });
  });
  
  describe('isValidInvitationStatus', () => {
    it('should return true for valid statuses', () => {
      expect(isValidInvitationStatus('pending')).toBe(true);
      expect(isValidInvitationStatus('accepted')).toBe(true);
      expect(isValidInvitationStatus('expired')).toBe(true);
      expect(isValidInvitationStatus('revoked')).toBe(true);
    });
    
    it('should return false for invalid statuses', () => {
      expect(isValidInvitationStatus('invalid')).toBe(false);
      expect(isValidInvitationStatus('PENDING')).toBe(false);
      expect(isValidInvitationStatus('')).toBe(false);
    });
  });
  
  describe('normalizeEmail', () => {
    it('should lowercase email', () => {
      expect(normalizeEmail('TEST@EXAMPLE.COM')).toBe('test@example.com');
    });
    
    it('should trim whitespace', () => {
      expect(normalizeEmail('  test@example.com  ')).toBe('test@example.com');
    });
  });
  
  describe('isValidEmail', () => {
    it('should return true for valid emails', () => {
      expect(isValidEmail('test@example.com')).toBe(true);
      expect(isValidEmail('user.name@domain.co.uk')).toBe(true);
    });
    
    it('should return false for invalid emails', () => {
      expect(isValidEmail('invalid')).toBe(false);
      expect(isValidEmail('test@')).toBe(false);
      expect(isValidEmail('@example.com')).toBe(false);
    });
  });
  
  describe('maskEmail', () => {
    it('should mask email local part', () => {
      expect(maskEmail('john@example.com')).toBe('j***@example.com');
      expect(maskEmail('ab@example.com')).toBe('a*@example.com');
    });
  });
});
