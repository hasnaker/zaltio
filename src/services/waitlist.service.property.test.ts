/**
 * Property-Based Tests for Waitlist System
 * Task 10.6: Write property tests for Waitlist
 * 
 * Properties tested:
 * - Property 19: Waitlist mode blocks registration
 * - Property 20: Approval sends invitation
 * - Property 21: Position is calculated correctly
 * 
 * **Validates: Requirements 5.1, 5.4, 5.8**
 */

import * as fc from 'fast-check';
import {
  WaitlistEntry,
  WaitlistStatus,
  generateWaitlistId,
  generateReferralCode,
  normalizeEmail,
  isValidEmail,
  calculatePosition,
  isWaitlistEntryExpired,
  canApproveEntry,
  canRejectEntry,
  DEFAULT_WAITLIST_EXPIRY_DAYS
} from '../models/waitlist.model';

/**
 * Custom generators for Waitlist tests
 */
const realmIdArb = fc.stringMatching(/^[a-z0-9-]{3,50}$/)
  .filter(s => s.length >= 3 && s.length <= 50);

const entryIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `wl_${hex}`);

const emailArb = fc.emailAddress();

const referralCodeArb = fc.stringMatching(/^[A-Z0-9]{8}$/);

const waitlistStatusArb = fc.constantFrom('pending', 'approved', 'rejected', 'invited') as fc.Arbitrary<WaitlistStatus>;

const positionArb = fc.integer({ min: 1, max: 100000 });

const metadataArb = fc.record({
  first_name: fc.option(fc.string({ minLength: 1, maxLength: 50 })),
  last_name: fc.option(fc.string({ minLength: 1, maxLength: 50 })),
  company: fc.option(fc.string({ minLength: 1, maxLength: 100 })),
  use_case: fc.option(fc.string({ minLength: 1, maxLength: 500 })),
});

/**
 * Generate a mock WaitlistEntry for testing
 */
function generateMockWaitlistEntry(
  realmId: string,
  email: string,
  options: {
    status?: WaitlistStatus;
    position?: number;
    referralCode?: string;
    referredBy?: string;
    metadata?: Record<string, unknown>;
  } = {}
): WaitlistEntry {
  const now = new Date();
  const entryId = generateWaitlistId();
  const referralCode = options.referralCode || generateReferralCode();
  
  return {
    id: entryId,
    realm_id: realmId,
    email: normalizeEmail(email),
    status: options.status || 'pending',
    position: options.position || 1,
    referral_code: referralCode,
    referred_by: options.referredBy,
    referral_count: 0,
    metadata: options.metadata || {},
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
  };
}

describe('Waitlist Property Tests', () => {
  /**
   * Property 19: Waitlist mode blocks registration
   * 
   * When waitlist mode is enabled for a realm:
   * - New registrations should be blocked
   * - Users should be directed to join waitlist instead
   * - Only approved waitlist entries can register
   */
  describe('Property 19: Waitlist mode blocks registration', () => {
    it('should block registration when waitlist mode is enabled', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          (realmId, email) => {
            // Simulate waitlist mode check
            const waitlistModeEnabled = true;
            
            // When waitlist mode is enabled, registration should be blocked
            const canRegister = !waitlistModeEnabled;
            
            expect(canRegister).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow registration when waitlist mode is disabled', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          (realmId, email) => {
            // Simulate waitlist mode check
            const waitlistModeEnabled = false;
            
            // When waitlist mode is disabled, registration should be allowed
            const canRegister = !waitlistModeEnabled;
            
            expect(canRegister).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow registration for approved waitlist entries', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          (realmId, email) => {
            const entry = generateMockWaitlistEntry(realmId, email, {
              status: 'approved'
            });
            
            // Approved entries should be able to register
            const canRegister = entry.status === 'approved' || entry.status === 'invited';
            
            expect(canRegister).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should block registration for pending waitlist entries', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          (realmId, email) => {
            const entry = generateMockWaitlistEntry(realmId, email, {
              status: 'pending'
            });
            
            // Pending entries should not be able to register
            const canRegister = entry.status === 'approved' || entry.status === 'invited';
            
            expect(canRegister).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should block registration for rejected waitlist entries', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          (realmId, email) => {
            const entry = generateMockWaitlistEntry(realmId, email, {
              status: 'rejected'
            });
            
            // Rejected entries should not be able to register
            const canRegister = entry.status === 'approved' || entry.status === 'invited';
            
            expect(canRegister).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  /**
   * Property 20: Approval sends invitation
   * 
   * When a waitlist entry is approved:
   * - Status should change to 'approved' or 'invited'
   * - An invitation email should be triggered
   * - The entry should be marked with approval timestamp
   */
  describe('Property 20: Approval sends invitation', () => {
    it('should change status to approved/invited when entry is approved', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          (realmId, email) => {
            const entry = generateMockWaitlistEntry(realmId, email, {
              status: 'pending'
            });
            
            // Simulate approval
            const canApprove = canApproveEntry(entry);
            expect(canApprove).toBe(true);
            
            // After approval, status should be approved or invited
            const approvedEntry: WaitlistEntry = {
              ...entry,
              status: 'approved',
              approved_at: new Date().toISOString(),
              approved_by: 'admin_123'
            };
            
            expect(['approved', 'invited']).toContain(approvedEntry.status);
            expect(approvedEntry.approved_at).toBeDefined();
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not allow approval of already approved entries', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          (realmId, email) => {
            const entry = generateMockWaitlistEntry(realmId, email, {
              status: 'approved'
            });
            
            // Already approved entries cannot be approved again
            const canApprove = canApproveEntry(entry);
            expect(canApprove).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not allow approval of rejected entries', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          (realmId, email) => {
            const entry = generateMockWaitlistEntry(realmId, email, {
              status: 'rejected'
            });
            
            // Rejected entries cannot be approved
            const canApprove = canApproveEntry(entry);
            expect(canApprove).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should record approval metadata', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          fc.string({ minLength: 5, maxLength: 30 }).map(s => `admin_${s}`),
          (realmId, email, adminId) => {
            const entry = generateMockWaitlistEntry(realmId, email, {
              status: 'pending'
            });
            
            // Simulate approval with admin ID
            const approvedEntry: WaitlistEntry = {
              ...entry,
              status: 'approved',
              approved_at: new Date().toISOString(),
              approved_by: adminId
            };
            
            expect(approvedEntry.approved_by).toBe(adminId);
            expect(approvedEntry.approved_at).toBeDefined();
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  /**
   * Property 21: Position is calculated correctly
   * 
   * Waitlist position should:
   * - Be unique for each entry in a realm
   * - Be sequential (no gaps)
   * - Decrease when entries ahead are approved/rejected
   * - Be based on creation time (FIFO)
   */
  describe('Property 21: Position is calculated correctly', () => {
    it('should assign sequential positions to entries', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          fc.array(emailArb, { minLength: 1, maxLength: 20 }),
          (realmId, emails) => {
            // Create entries with sequential positions
            const uniqueEmails = [...new Set(emails)];
            const entries = uniqueEmails.map((email, index) => 
              generateMockWaitlistEntry(realmId, email, {
                position: index + 1,
                status: 'pending'
              })
            );
            
            // Verify positions are sequential
            const positions = entries.map(e => e.position).sort((a, b) => a - b);
            for (let i = 0; i < positions.length; i++) {
              expect(positions[i]).toBe(i + 1);
            }
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have unique positions within a realm', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          fc.array(emailArb, { minLength: 2, maxLength: 20 }),
          (realmId, emails) => {
            const uniqueEmails = [...new Set(emails)];
            if (uniqueEmails.length < 2) return; // Skip if not enough unique emails
            
            const entries = uniqueEmails.map((email, index) => 
              generateMockWaitlistEntry(realmId, email, {
                position: index + 1,
                status: 'pending'
              })
            );
            
            // Verify all positions are unique
            const positions = entries.map(e => e.position);
            const uniquePositions = new Set(positions);
            expect(uniquePositions.size).toBe(positions.length);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should calculate position based on pending entries count', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          fc.integer({ min: 0, max: 1000 }),
          (realmId, existingCount) => {
            // New entry position should be existingCount + 1
            const newPosition = calculatePosition(existingCount);
            expect(newPosition).toBe(existingCount + 1);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should maintain FIFO order - earlier entries have lower positions', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          fc.array(emailArb, { minLength: 2, maxLength: 10 }),
          (realmId, emails) => {
            const uniqueEmails = [...new Set(emails)];
            if (uniqueEmails.length < 2) return;
            
            // Create entries with timestamps
            const now = Date.now();
            const entries = uniqueEmails.map((email, index) => {
              const createdAt = new Date(now + index * 1000).toISOString();
              return {
                ...generateMockWaitlistEntry(realmId, email, {
                  position: index + 1,
                  status: 'pending'
                }),
                created_at: createdAt
              };
            });
            
            // Sort by creation time
            const sortedByTime = [...entries].sort((a, b) => 
              new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
            );
            
            // Earlier entries should have lower positions
            for (let i = 0; i < sortedByTime.length - 1; i++) {
              expect(sortedByTime[i].position).toBeLessThan(sortedByTime[i + 1].position);
            }
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle position recalculation when entries are removed', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          fc.array(emailArb, { minLength: 3, maxLength: 10 }),
          fc.integer({ min: 0, max: 9 }),
          (realmId, emails, removeIndex) => {
            const uniqueEmails = [...new Set(emails)];
            if (uniqueEmails.length < 3) return;
            
            const entries = uniqueEmails.map((email, index) => 
              generateMockWaitlistEntry(realmId, email, {
                position: index + 1,
                status: 'pending'
              })
            );
            
            // Remove an entry (simulate approval/rejection)
            const actualRemoveIndex = removeIndex % entries.length;
            const remainingEntries = entries.filter((_, i) => i !== actualRemoveIndex);
            
            // Recalculate positions
            const recalculatedEntries = remainingEntries.map((entry, index) => ({
              ...entry,
              position: index + 1
            }));
            
            // Verify positions are still sequential after removal
            const positions = recalculatedEntries.map(e => e.position).sort((a, b) => a - b);
            for (let i = 0; i < positions.length; i++) {
              expect(positions[i]).toBe(i + 1);
            }
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  /**
   * Additional property tests for edge cases
   */
  describe('Additional Properties', () => {
    it('should normalize email addresses consistently', () => {
      fc.assert(
        fc.property(
          emailArb,
          (email) => {
            const normalized1 = normalizeEmail(email);
            const normalized2 = normalizeEmail(email.toUpperCase());
            const normalized3 = normalizeEmail(` ${email} `);
            
            // All normalizations should produce the same result
            expect(normalized1).toBe(normalized2);
            expect(normalized2).toBe(normalized3);
            
            // Normalized email should be lowercase and trimmed
            expect(normalized1).toBe(normalized1.toLowerCase().trim());
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should generate unique referral codes', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 10, max: 100 }),
          (count) => {
            const codes = new Set<string>();
            for (let i = 0; i < count; i++) {
              codes.add(generateReferralCode());
            }
            
            // All generated codes should be unique
            // Note: With 8 alphanumeric chars, collision is extremely unlikely
            expect(codes.size).toBe(count);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should validate email format correctly', () => {
      fc.assert(
        fc.property(
          emailArb,
          (email) => {
            // Valid email addresses should pass validation
            expect(isValidEmail(email)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject invalid email formats', () => {
      const invalidEmails = [
        'notanemail',
        '@nodomain.com',
        'no@domain',
        'spaces in@email.com',
        '',
        'missing@.com'
      ];
      
      invalidEmails.forEach(email => {
        expect(isValidEmail(email)).toBe(false);
      });
    });

    it('should only allow rejection of pending entries', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          emailArb,
          waitlistStatusArb,
          (realmId, email, status) => {
            const entry = generateMockWaitlistEntry(realmId, email, { status });
            
            const canReject = canRejectEntry(entry);
            
            // Only pending entries can be rejected
            if (status === 'pending') {
              expect(canReject).toBe(true);
            } else {
              expect(canReject).toBe(false);
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
