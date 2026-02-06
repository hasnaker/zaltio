/**
 * Waitlist Repository Tests
 * 
 * Tests for DynamoDB operations for waitlist entries.
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 * 
 * Validates: Requirements 5.1, 5.2 (Waitlist Mode)
 */

// Mock DynamoDB - must be before imports
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  }
}));

// Import after mocks
import {
  joinWaitlist,
  getEntryById,
  getEntryByEmail,
  getEntryByReferralCode,
  listEntries,
  getPosition,
  getWaitlistStats,
  approveEntry,
  rejectEntry,
  markAsInvited,
  bulkApprove,
  deleteEntry
} from './waitlist.repository';

import {
  generateWaitlistId,
  generateReferralCode,
  normalizeEmail,
  isValidEmail,
  toWaitlistResponse,
  WaitlistEntry
} from '../models/waitlist.model';

describe('Waitlist Repository', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('Model Helper Functions', () => {
    describe('generateWaitlistId', () => {
      it('should generate ID with wl_ prefix', () => {
        const id = generateWaitlistId();
        expect(id).toMatch(/^wl_[a-f0-9]{24}$/);
      });

      it('should generate unique IDs', () => {
        const ids = new Set<string>();
        for (let i = 0; i < 100; i++) {
          ids.add(generateWaitlistId());
        }
        expect(ids.size).toBe(100);
      });
    });

    describe('generateReferralCode', () => {
      it('should generate 8 character code', () => {
        const code = generateReferralCode();
        expect(code).toHaveLength(8);
      });

      it('should only contain allowed characters', () => {
        const code = generateReferralCode();
        expect(code).toMatch(/^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/);
      });

      it('should not contain confusing characters (0, O, 1, I)', () => {
        for (let i = 0; i < 100; i++) {
          const code = generateReferralCode();
          expect(code).not.toMatch(/[0O1I]/);
        }
      });

      it('should generate unique codes', () => {
        const codes = new Set<string>();
        for (let i = 0; i < 100; i++) {
          codes.add(generateReferralCode());
        }
        expect(codes.size).toBe(100);
      });
    });

    describe('normalizeEmail', () => {
      it('should lowercase email', () => {
        expect(normalizeEmail('Test@Example.COM')).toBe('test@example.com');
      });

      it('should trim whitespace', () => {
        expect(normalizeEmail('  test@example.com  ')).toBe('test@example.com');
      });
    });

    describe('isValidEmail', () => {
      it('should accept valid emails', () => {
        expect(isValidEmail('test@example.com')).toBe(true);
        expect(isValidEmail('user.name@domain.co.uk')).toBe(true);
        expect(isValidEmail('user+tag@example.org')).toBe(true);
      });

      it('should reject invalid emails', () => {
        expect(isValidEmail('invalid')).toBe(false);
        expect(isValidEmail('invalid@')).toBe(false);
        expect(isValidEmail('@domain.com')).toBe(false);
        expect(isValidEmail('test @example.com')).toBe(false);
      });
    });

    describe('toWaitlistResponse', () => {
      it('should exclude sensitive metadata', () => {
        const entry: WaitlistEntry = {
          id: 'wl_123',
          realm_id: 'realm_123',
          email: 'test@example.com',
          status: 'pending',
          position: 1,
          referral_code: 'ABC12345',
          referral_count: 0,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          metadata: {
            first_name: 'Test',
            ip_address: '192.168.1.1',
            user_agent: 'Mozilla/5.0'
          }
        };

        const response = toWaitlistResponse(entry);
        
        expect(response.metadata?.first_name).toBe('Test');
        expect((response.metadata as Record<string, unknown>)?.ip_address).toBeUndefined();
        expect((response.metadata as Record<string, unknown>)?.user_agent).toBeUndefined();
      });
    });
  });

  describe('joinWaitlist', () => {
    it('should create new waitlist entry', async () => {
      // Mock: No existing entry
      mockSend.mockResolvedValueOnce({ Items: [] }); // getEntryByEmail
      mockSend.mockResolvedValueOnce({ Count: 0 }); // getNextPosition
      mockSend.mockResolvedValueOnce({}); // PutCommand

      const result = await joinWaitlist({
        realm_id: 'realm_123',
        email: 'test@example.com',
        metadata: { first_name: 'Test' }
      });

      expect(result.already_exists).toBe(false);
      expect(result.entry.email).toBe('test@example.com');
      expect(result.entry.status).toBe('pending');
      expect(result.position).toBe(1);
      expect(result.referral_code).toHaveLength(8);
    });

    it('should return existing entry if email already exists', async () => {
      const existingEntry = {
        id: 'wl_existing',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'pending',
        position: 5,
        referral_code: 'EXISTING',
        referral_count: 2,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Items: [existingEntry] });

      const result = await joinWaitlist({
        realm_id: 'realm_123',
        email: 'test@example.com'
      });

      expect(result.already_exists).toBe(true);
      expect(result.entry.id).toBe('wl_existing');
      expect(result.position).toBe(5);
      expect(result.referral_code).toBe('EXISTING');
    });

    it('should handle referral code', async () => {
      const referrer = {
        id: 'wl_referrer',
        realm_id: 'realm_123',
        email: 'referrer@example.com',
        status: 'pending',
        position: 1,
        referral_code: 'REFCODE1',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Items: [] }); // getEntryByEmail
      mockSend.mockResolvedValueOnce({ Count: 1 }); // getNextPosition
      mockSend.mockResolvedValueOnce({ Items: [referrer] }); // getEntryByReferralCode
      mockSend.mockResolvedValueOnce({}); // incrementReferralCount
      mockSend.mockResolvedValueOnce({}); // PutCommand

      const result = await joinWaitlist({
        realm_id: 'realm_123',
        email: 'new@example.com',
        referral_code: 'REFCODE1'
      });

      expect(result.already_exists).toBe(false);
      expect(result.position).toBe(2);
    });

    it('should normalize email to lowercase', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      mockSend.mockResolvedValueOnce({ Count: 0 });
      mockSend.mockResolvedValueOnce({});

      const result = await joinWaitlist({
        realm_id: 'realm_123',
        email: 'TEST@EXAMPLE.COM'
      });

      expect(result.entry.email).toBe('test@example.com');
    });
  });

  describe('getEntryById', () => {
    it('should return entry if found', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'pending',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Item: entry });

      const result = await getEntryById('realm_123', 'wl_123');

      expect(result).not.toBeNull();
      expect(result?.id).toBe('wl_123');
    });

    it('should return null if not found', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const result = await getEntryById('realm_123', 'wl_nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('getEntryByEmail', () => {
    it('should find entry by email', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'pending',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Items: [entry] });

      const result = await getEntryByEmail('realm_123', 'test@example.com');

      expect(result).not.toBeNull();
      expect(result?.email).toBe('test@example.com');
    });

    it('should return null if not found', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const result = await getEntryByEmail('realm_123', 'notfound@example.com');

      expect(result).toBeNull();
    });
  });

  describe('getEntryByReferralCode', () => {
    it('should find entry by referral code', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'pending',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Items: [entry] });

      const result = await getEntryByReferralCode('realm_123', 'ABC12345');

      expect(result).not.toBeNull();
      expect(result?.referral_code).toBe('ABC12345');
    });

    it('should return null if not found', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const result = await getEntryByReferralCode('realm_123', 'NOTFOUND');

      expect(result).toBeNull();
    });
  });

  describe('listEntries', () => {
    it('should list entries for realm', async () => {
      const entries = [
        {
          id: 'wl_1',
          realm_id: 'realm_123',
          email: 'test1@example.com',
          status: 'pending',
          position: 1,
          referral_code: 'CODE1111',
          referral_count: 0,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z'
        },
        {
          id: 'wl_2',
          realm_id: 'realm_123',
          email: 'test2@example.com',
          status: 'approved',
          position: 2,
          referral_code: 'CODE2222',
          referral_count: 1,
          created_at: '2026-01-02T00:00:00Z',
          updated_at: '2026-01-02T00:00:00Z'
        }
      ];

      mockSend.mockResolvedValueOnce({ Items: entries });

      const result = await listEntries('realm_123');

      expect(result.entries).toHaveLength(2);
      expect(result.entries[0].id).toBe('wl_1');
    });

    it('should handle pagination', async () => {
      const lastKey = { pk: 'REALM#realm_123#WAITLIST#wl_50', sk: 'WAITLIST' };
      mockSend.mockResolvedValueOnce({ 
        Items: [],
        LastEvaluatedKey: lastKey
      });

      const result = await listEntries('realm_123', { limit: 50 });

      expect(result.nextCursor).toBeDefined();
    });
  });

  describe('getPosition', () => {
    it('should return position and total', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'pending',
        position: 5,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Item: entry }); // getEntryById
      mockSend.mockResolvedValueOnce({ Items: [] }); // getWaitlistStats

      const result = await getPosition('realm_123', 'wl_123');

      expect(result).not.toBeNull();
      expect(result?.position).toBe(5);
    });

    it('should return null if entry not found', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const result = await getPosition('realm_123', 'wl_nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('getWaitlistStats', () => {
    it('should calculate statistics', async () => {
      const entries = [
        { status: 'pending', referred_by: undefined },
        { status: 'pending', referred_by: 'CODE1111' },
        { status: 'approved', referred_by: undefined },
        { status: 'rejected', referred_by: undefined },
        { status: 'invited', referred_by: 'CODE2222' }
      ];

      mockSend.mockResolvedValueOnce({ Items: entries });

      const stats = await getWaitlistStats('realm_123');

      expect(stats.total).toBe(5);
      expect(stats.pending).toBe(2);
      expect(stats.approved).toBe(1);
      expect(stats.rejected).toBe(1);
      expect(stats.invited).toBe(1);
      expect(stats.referral_signups).toBe(2);
    });
  });

  describe('approveEntry', () => {
    it('should approve pending entry', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'pending',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      const approvedEntry = {
        ...entry,
        status: 'approved',
        approved_at: '2026-01-02T00:00:00Z',
        approved_by: 'admin_123'
      };

      mockSend.mockResolvedValueOnce({ Item: entry }); // getEntryById
      mockSend.mockResolvedValueOnce({ Attributes: approvedEntry }); // UpdateCommand

      const result = await approveEntry('realm_123', 'wl_123', 'admin_123');

      expect(result).not.toBeNull();
      expect(result?.status).toBe('approved');
      expect(result?.approved_by).toBe('admin_123');
    });

    it('should throw error if entry already approved', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'approved',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Item: entry });

      await expect(approveEntry('realm_123', 'wl_123', 'admin_123'))
        .rejects.toThrow('Entry is already approved');
    });

    it('should return null if entry not found', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const result = await approveEntry('realm_123', 'wl_nonexistent', 'admin_123');

      expect(result).toBeNull();
    });
  });

  describe('rejectEntry', () => {
    it('should reject pending entry', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'pending',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      const rejectedEntry = {
        ...entry,
        status: 'rejected',
        rejected_at: '2026-01-02T00:00:00Z',
        rejected_by: 'admin_123',
        rejection_reason: 'Spam'
      };

      mockSend.mockResolvedValueOnce({ Item: entry });
      mockSend.mockResolvedValueOnce({ Attributes: rejectedEntry });

      const result = await rejectEntry('realm_123', 'wl_123', 'admin_123', 'Spam');

      expect(result).not.toBeNull();
      expect(result?.status).toBe('rejected');
      expect(result?.rejection_reason).toBe('Spam');
    });

    it('should throw error if entry already rejected', async () => {
      const entry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'rejected',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Item: entry });

      await expect(rejectEntry('realm_123', 'wl_123', 'admin_123'))
        .rejects.toThrow('Entry is already rejected');
    });
  });

  describe('markAsInvited', () => {
    it('should mark approved entry as invited', async () => {
      const invitedEntry = {
        id: 'wl_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        status: 'invited',
        position: 1,
        referral_code: 'ABC12345',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-02T00:00:00Z',
        invitation_sent_at: '2026-01-02T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Attributes: invitedEntry });

      const result = await markAsInvited('realm_123', 'wl_123');

      expect(result).not.toBeNull();
      expect(result?.status).toBe('invited');
      expect(result?.invitation_sent_at).toBeDefined();
    });

    it('should return null if entry not approved', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);

      const result = await markAsInvited('realm_123', 'wl_123');

      expect(result).toBeNull();
    });
  });

  describe('bulkApprove', () => {
    it('should approve multiple entries', async () => {
      const entry1 = {
        id: 'wl_1',
        realm_id: 'realm_123',
        email: 'test1@example.com',
        status: 'pending',
        position: 1,
        referral_code: 'CODE1111',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      const entry2 = {
        id: 'wl_2',
        realm_id: 'realm_123',
        email: 'test2@example.com',
        status: 'pending',
        position: 2,
        referral_code: 'CODE2222',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      // First entry
      mockSend.mockResolvedValueOnce({ Item: entry1 });
      mockSend.mockResolvedValueOnce({ Attributes: { ...entry1, status: 'approved' } });
      
      // Second entry
      mockSend.mockResolvedValueOnce({ Item: entry2 });
      mockSend.mockResolvedValueOnce({ Attributes: { ...entry2, status: 'approved' } });

      const result = await bulkApprove('realm_123', ['wl_1', 'wl_2'], 'admin_123');

      expect(result.approved).toHaveLength(2);
      expect(result.failed).toHaveLength(0);
    });

    it('should handle partial failures', async () => {
      const entry1 = {
        id: 'wl_1',
        realm_id: 'realm_123',
        email: 'test1@example.com',
        status: 'pending',
        position: 1,
        referral_code: 'CODE1111',
        referral_count: 0,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };

      // First entry succeeds
      mockSend.mockResolvedValueOnce({ Item: entry1 });
      mockSend.mockResolvedValueOnce({ Attributes: { ...entry1, status: 'approved' } });
      
      // Second entry not found
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const result = await bulkApprove('realm_123', ['wl_1', 'wl_nonexistent'], 'admin_123');

      expect(result.approved).toHaveLength(1);
      expect(result.failed).toHaveLength(1);
      expect(result.failed[0].id).toBe('wl_nonexistent');
    });

    it('should limit bulk operations to MAX_BULK_ENTRIES', async () => {
      const entryIds = Array.from({ length: 150 }, (_, i) => `wl_${i}`);
      
      // Mock all entries as not found (simplest case)
      for (let i = 0; i < 100; i++) {
        mockSend.mockResolvedValueOnce({ Item: undefined });
      }

      const result = await bulkApprove('realm_123', entryIds, 'admin_123');

      // Should only process first 100
      expect(result.failed).toHaveLength(100);
    });
  });

  describe('deleteEntry', () => {
    it('should delete entry', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await deleteEntry('realm_123', 'wl_123');

      expect(result).toBe(true);
    });

    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));

      const result = await deleteEntry('realm_123', 'wl_123');

      expect(result).toBe(false);
    });
  });
});
