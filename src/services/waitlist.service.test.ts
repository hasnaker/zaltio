/**
 * Waitlist Service Tests
 * 
 * Tests for waitlist business logic.
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (Dependencies mocked for unit tests)
 * 
 * Validates: Requirements 5.3, 5.4, 5.5, 5.6, 5.8, 5.9 (Waitlist Mode)
 */

// Mock dependencies - must be before imports
const mockJoinWaitlist = jest.fn();
const mockGetEntryById = jest.fn();
const mockGetEntryByEmail = jest.fn();
const mockGetEntryByReferralCode = jest.fn();
const mockListEntries = jest.fn();
const mockGetPosition = jest.fn();
const mockGetWaitlistStats = jest.fn();
const mockApproveEntry = jest.fn();
const mockRejectEntry = jest.fn();
const mockMarkAsInvited = jest.fn();
const mockBulkApprove = jest.fn();
const mockDeleteEntry = jest.fn();

jest.mock('../repositories/waitlist.repository', () => ({
  joinWaitlist: (...args: unknown[]) => mockJoinWaitlist(...args),
  getEntryById: (...args: unknown[]) => mockGetEntryById(...args),
  getEntryByEmail: (...args: unknown[]) => mockGetEntryByEmail(...args),
  getEntryByReferralCode: (...args: unknown[]) => mockGetEntryByReferralCode(...args),
  listEntries: (...args: unknown[]) => mockListEntries(...args),
  getPosition: (...args: unknown[]) => mockGetPosition(...args),
  getWaitlistStats: (...args: unknown[]) => mockGetWaitlistStats(...args),
  approveEntry: (...args: unknown[]) => mockApproveEntry(...args),
  rejectEntry: (...args: unknown[]) => mockRejectEntry(...args),
  markAsInvited: (...args: unknown[]) => mockMarkAsInvited(...args),
  bulkApprove: (...args: unknown[]) => mockBulkApprove(...args),
  deleteEntry: (...args: unknown[]) => mockDeleteEntry(...args)
}));

const mockFindRealmById = jest.fn();
jest.mock('../repositories/realm.repository', () => ({
  findRealmById: (...args: unknown[]) => mockFindRealmById(...args)
}));

const mockCreateInvitation = jest.fn();
jest.mock('../repositories/invitation.repository', () => ({
  createInvitation: (...args: unknown[]) => mockCreateInvitation(...args)
}));

const mockSendEmail = jest.fn();
jest.mock('./email.service', () => ({
  sendEmail: (...args: unknown[]) => mockSendEmail(...args)
}));

// Import after mocks
import { WaitlistService, WaitlistError, createWaitlistService } from './waitlist.service';

describe('WaitlistService', () => {
  let service: WaitlistService;
  const realmId = 'realm_test123';

  beforeEach(() => {
    jest.clearAllMocks();
    service = new WaitlistService({ realmId });
    
    // Default realm with waitlist enabled
    mockFindRealmById.mockResolvedValue({
      id: realmId,
      name: 'Test Realm',
      settings: {
        waitlist_mode_enabled: true,
        app_url: 'https://app.example.com'
      }
    });
  });

  describe('isWaitlistModeEnabled', () => {
    it('should return true when waitlist mode is enabled', async () => {
      mockFindRealmById.mockResolvedValueOnce({
        id: realmId,
        settings: { waitlist_mode_enabled: true }
      });

      const result = await service.isWaitlistModeEnabled();

      expect(result).toBe(true);
    });

    it('should return false when waitlist mode is disabled', async () => {
      mockFindRealmById.mockResolvedValueOnce({
        id: realmId,
        settings: { waitlist_mode_enabled: false }
      });

      const result = await service.isWaitlistModeEnabled();

      expect(result).toBe(false);
    });

    it('should return false when realm not found', async () => {
      mockFindRealmById.mockResolvedValueOnce(null);

      const result = await service.isWaitlistModeEnabled();

      expect(result).toBe(false);
    });

    it('should return false on error', async () => {
      mockFindRealmById.mockRejectedValueOnce(new Error('DB error'));

      const result = await service.isWaitlistModeEnabled();

      expect(result).toBe(false);
    });
  });

  describe('join', () => {
    it('should join waitlist successfully', async () => {
      const joinResult = {
        entry: {
          id: 'wl_123',
          realm_id: realmId,
          email: 'test@example.com',
          status: 'pending',
          position: 1,
          referral_code: 'ABC12345',
          referral_count: 0,
          created_at: '2026-01-01T00:00:00Z'
        },
        already_exists: false,
        position: 1,
        referral_code: 'ABC12345'
      };

      mockJoinWaitlist.mockResolvedValueOnce(joinResult);
      mockSendEmail.mockResolvedValueOnce(undefined);

      const result = await service.join({
        email: 'test@example.com',
        metadata: { firstName: 'Test' }
      });

      expect(result.already_exists).toBe(false);
      expect(result.entry.email).toBe('test@example.com');
      expect(result.position).toBe(1);
      expect(mockSendEmail).toHaveBeenCalled();
    });

    it('should return existing entry without sending email', async () => {
      const joinResult = {
        entry: {
          id: 'wl_existing',
          realm_id: realmId,
          email: 'test@example.com',
          status: 'pending',
          position: 5,
          referral_code: 'EXISTING',
          referral_count: 2,
          created_at: '2026-01-01T00:00:00Z'
        },
        already_exists: true,
        position: 5,
        referral_code: 'EXISTING'
      };

      mockJoinWaitlist.mockResolvedValueOnce(joinResult);

      const result = await service.join({ email: 'test@example.com' });

      expect(result.already_exists).toBe(true);
      // Should not send confirmation email for existing entries
      expect(mockSendEmail).not.toHaveBeenCalled();
    });

    it('should throw error for invalid email', async () => {
      await expect(service.join({ email: 'invalid' }))
        .rejects.toThrow(WaitlistError);
      
      await expect(service.join({ email: 'invalid' }))
        .rejects.toThrow('Invalid email format');
    });

    it('should throw error when waitlist mode is disabled', async () => {
      mockFindRealmById.mockResolvedValueOnce({
        id: realmId,
        settings: { waitlist_mode_enabled: false }
      });

      await expect(service.join({ email: 'test@example.com' }))
        .rejects.toThrow('Waitlist mode is not enabled');
    });

    it('should handle referral code', async () => {
      const joinResult = {
        entry: {
          id: 'wl_123',
          realm_id: realmId,
          email: 'test@example.com',
          status: 'pending',
          position: 2,
          referral_code: 'NEWCODE1',
          referral_count: 0,
          created_at: '2026-01-01T00:00:00Z'
        },
        already_exists: false,
        position: 2,
        referral_code: 'NEWCODE1'
      };

      mockJoinWaitlist.mockResolvedValueOnce(joinResult);
      mockSendEmail.mockResolvedValueOnce(undefined);

      await service.join({
        email: 'test@example.com',
        referralCode: 'REFCODE1'
      });

      expect(mockJoinWaitlist).toHaveBeenCalledWith(
        expect.objectContaining({
          referral_code: 'REFCODE1'
        })
      );
    });

    it('should mask IP address in metadata', async () => {
      const joinResult = {
        entry: {
          id: 'wl_123',
          realm_id: realmId,
          email: 'test@example.com',
          status: 'pending',
          position: 1,
          referral_code: 'ABC12345',
          referral_count: 0,
          created_at: '2026-01-01T00:00:00Z'
        },
        already_exists: false,
        position: 1,
        referral_code: 'ABC12345'
      };

      mockJoinWaitlist.mockResolvedValueOnce(joinResult);
      mockSendEmail.mockResolvedValueOnce(undefined);

      await service.join({
        email: 'test@example.com',
        ipAddress: '192.168.1.100'
      });

      expect(mockJoinWaitlist).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({
            ip_address: '192.168.xxx.xxx'
          })
        })
      );
    });
  });

  describe('approve', () => {
    it('should approve entry and send invitation', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: realmId,
        email: 'test@example.com',
        status: 'approved',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z',
        approved_at: '2026-01-02T00:00:00Z',
        approved_by: 'admin_123'
      };

      mockApproveEntry.mockResolvedValueOnce(entry);
      mockCreateInvitation.mockResolvedValueOnce({
        invitation: { id: 'inv_123' },
        token: 'invitation_token_123'
      });
      mockMarkAsInvited.mockResolvedValueOnce(entry);
      mockSendEmail.mockResolvedValueOnce(undefined);

      const result = await service.approve('wl_123', 'admin_123');

      expect(result).not.toBeNull();
      expect(result?.status).toBe('approved');
      expect(mockCreateInvitation).toHaveBeenCalled();
      expect(mockMarkAsInvited).toHaveBeenCalled();
      expect(mockSendEmail).toHaveBeenCalled();
    });

    it('should approve without sending invitation when disabled', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: realmId,
        email: 'test@example.com',
        status: 'approved',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      };

      mockApproveEntry.mockResolvedValueOnce(entry);

      const result = await service.approve('wl_123', 'admin_123', {
        sendInvitation: false
      });

      expect(result).not.toBeNull();
      expect(mockCreateInvitation).not.toHaveBeenCalled();
      expect(mockSendEmail).not.toHaveBeenCalled();
    });

    it('should return null if entry not found', async () => {
      mockApproveEntry.mockResolvedValueOnce(null);

      const result = await service.approve('wl_nonexistent', 'admin_123');

      expect(result).toBeNull();
    });

    it('should use custom role for invitation', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: realmId,
        email: 'test@example.com',
        status: 'approved',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      };

      mockApproveEntry.mockResolvedValueOnce(entry);
      mockCreateInvitation.mockResolvedValueOnce({
        invitation: { id: 'inv_123' },
        token: 'token'
      });
      mockMarkAsInvited.mockResolvedValueOnce(entry);
      mockSendEmail.mockResolvedValueOnce(undefined);

      await service.approve('wl_123', 'admin_123', {
        invitationRole: 'admin'
      });

      expect(mockCreateInvitation).toHaveBeenCalledWith(
        expect.objectContaining({
          role: 'admin'
        })
      );
    });
  });

  describe('reject', () => {
    it('should reject entry', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: realmId,
        email: 'test@example.com',
        status: 'rejected',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z',
        rejected_at: '2026-01-02T00:00:00Z',
        rejected_by: 'admin_123',
        rejection_reason: 'Spam'
      };

      mockRejectEntry.mockResolvedValueOnce(entry);

      const result = await service.reject('wl_123', 'admin_123', {
        reason: 'Spam'
      });

      expect(result).not.toBeNull();
      expect(result?.status).toBe('rejected');
    });

    it('should send notification when requested', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: realmId,
        email: 'test@example.com',
        status: 'rejected',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      };

      mockRejectEntry.mockResolvedValueOnce(entry);
      mockSendEmail.mockResolvedValueOnce(undefined);

      await service.reject('wl_123', 'admin_123', {
        sendNotification: true,
        reason: 'Not a good fit'
      });

      expect(mockSendEmail).toHaveBeenCalled();
    });

    it('should not send notification by default', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: realmId,
        email: 'test@example.com',
        status: 'rejected',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z'
      };

      mockRejectEntry.mockResolvedValueOnce(entry);

      await service.reject('wl_123', 'admin_123');

      expect(mockSendEmail).not.toHaveBeenCalled();
    });

    it('should return null if entry not found', async () => {
      mockRejectEntry.mockResolvedValueOnce(null);

      const result = await service.reject('wl_nonexistent', 'admin_123');

      expect(result).toBeNull();
    });
  });

  describe('bulkApprove', () => {
    it('should bulk approve entries', async () => {
      const bulkResult = {
        approved: ['wl_1', 'wl_2'],
        failed: []
      };

      mockBulkApprove.mockResolvedValueOnce(bulkResult);

      // Mock for invitation sending
      mockGetEntryById.mockResolvedValue({
        id: 'wl_1',
        email: 'test@example.com',
        status: 'approved'
      });
      mockCreateInvitation.mockResolvedValue({
        invitation: { id: 'inv_123' },
        token: 'token'
      });
      mockMarkAsInvited.mockResolvedValue({});
      mockSendEmail.mockResolvedValue(undefined);

      const result = await service.bulkApprove(['wl_1', 'wl_2'], 'admin_123');

      expect(result.approved).toHaveLength(2);
      expect(result.failed).toHaveLength(0);
    });

    it('should handle partial failures', async () => {
      const bulkResult = {
        approved: ['wl_1'],
        failed: [{ id: 'wl_2', error: 'Already approved' }]
      };

      mockBulkApprove.mockResolvedValueOnce(bulkResult);
      mockGetEntryById.mockResolvedValue({
        id: 'wl_1',
        email: 'test@example.com',
        status: 'approved'
      });
      mockCreateInvitation.mockResolvedValue({
        invitation: { id: 'inv_123' },
        token: 'token'
      });
      mockMarkAsInvited.mockResolvedValue({});
      mockSendEmail.mockResolvedValue(undefined);

      const result = await service.bulkApprove(['wl_1', 'wl_2'], 'admin_123');

      expect(result.approved).toHaveLength(1);
      expect(result.failed).toHaveLength(1);
    });

    it('should skip invitations when disabled', async () => {
      const bulkResult = {
        approved: ['wl_1'],
        failed: []
      };

      mockBulkApprove.mockResolvedValueOnce(bulkResult);

      await service.bulkApprove(['wl_1'], 'admin_123', {
        sendInvitation: false
      });

      expect(mockCreateInvitation).not.toHaveBeenCalled();
    });
  });

  describe('getPosition', () => {
    it('should return position and total', async () => {
      mockGetPosition.mockResolvedValueOnce({
        position: 5,
        total: 100
      });

      const result = await service.getPosition('wl_123');

      expect(result).toEqual({ position: 5, total: 100 });
    });

    it('should return null if entry not found', async () => {
      mockGetPosition.mockResolvedValueOnce(null);

      const result = await service.getPosition('wl_nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('list', () => {
    it('should list entries', async () => {
      const entries = [
        { id: 'wl_1', email: 'test1@example.com', status: 'pending', position: 1 },
        { id: 'wl_2', email: 'test2@example.com', status: 'pending', position: 2 }
      ];

      mockListEntries.mockResolvedValueOnce({
        entries,
        nextCursor: undefined
      });

      const result = await service.list();

      expect(result.entries).toHaveLength(2);
    });

    it('should filter by status', async () => {
      mockListEntries.mockResolvedValueOnce({
        entries: [],
        nextCursor: undefined
      });

      await service.list({ status: 'pending' });

      expect(mockListEntries).toHaveBeenCalledWith(
        realmId,
        expect.objectContaining({ status: 'pending' })
      );
    });
  });

  describe('getStats', () => {
    it('should return statistics', async () => {
      const stats = {
        total: 100,
        pending: 50,
        approved: 30,
        rejected: 10,
        invited: 10,
        referral_signups: 25
      };

      mockGetWaitlistStats.mockResolvedValueOnce(stats);

      const result = await service.getStats();

      expect(result).toEqual(stats);
    });
  });

  describe('deleteEntry', () => {
    it('should delete entry', async () => {
      mockGetEntryById.mockResolvedValueOnce({
        id: 'wl_123',
        email: 'test@example.com'
      });
      mockDeleteEntry.mockResolvedValueOnce(true);

      const result = await service.deleteEntry('wl_123', 'admin_123');

      expect(result).toBe(true);
    });

    it('should return false if entry not found', async () => {
      mockGetEntryById.mockResolvedValueOnce(null);

      const result = await service.deleteEntry('wl_nonexistent', 'admin_123');

      expect(result).toBe(false);
      expect(mockDeleteEntry).not.toHaveBeenCalled();
    });
  });

  describe('createWaitlistService', () => {
    it('should create service instance', () => {
      const svc = createWaitlistService('realm_123');
      expect(svc).toBeInstanceOf(WaitlistService);
    });
  });
});
