/**
 * Property-Based Tests for Invitation System
 * Task 7.6: Write property tests for Invitations
 * 
 * Properties tested:
 * - Property 13: Invitation token single use
 * - Property 14: Invitation expiry rejects acceptance
 * - Property 15: Revoked invitation cannot be accepted
 * 
 * **Validates: Requirements 11.3, 11.4, 11.5, 11.6**
 */

import * as fc from 'fast-check';
import {
  Invitation,
  InvitationStatus,
  InvitationValidationResult,
  generateInvitationId,
  generateInvitationToken,
  hashInvitationToken,
  calculateExpiryDate,
  isInvitationExpired,
  canAcceptInvitation,
  normalizeEmail,
  isValidEmail,
  DEFAULT_INVITATION_EXPIRY_DAYS
} from '../models/invitation.model';

/**
 * Custom generators for Invitation tests
 */
const tenantIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `tenant_${hex}`);

const userIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `user_${hex}`);

const invitationIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `inv_${hex}`);

const emailArb = fc.emailAddress();

const roleArb = fc.constantFrom('owner', 'admin', 'member', 'viewer');

const invitationStatusArb = fc.constantFrom('pending', 'accepted', 'expired', 'revoked') as fc.Arbitrary<InvitationStatus>;

const tokenArb = fc.hexaString({ minLength: 64, maxLength: 64 });

const expiryDaysArb = fc.integer({ min: 1, max: 30 });


/**
 * Generate a mock Invitation for testing
 */
function generateMockInvitation(
  tenantId: string,
  email: string,
  role: string,
  invitedBy: string,
  options: {
    status?: InvitationStatus;
    expired?: boolean;
    expiryDays?: number;
    acceptedByUserId?: string;
    revokedBy?: string;
  } = {}
): Invitation {
  const now = new Date();
  const invitationId = generateInvitationId();
  const token = generateInvitationToken();
  const tokenHash = hashInvitationToken(token);
  
  let expiresAt: string;
  if (options.expired) {
    // Set expiry in the past
    const pastDate = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 1 day ago
    expiresAt = pastDate.toISOString();
  } else {
    expiresAt = calculateExpiryDate(options.expiryDays || DEFAULT_INVITATION_EXPIRY_DAYS);
  }
  
  const invitation: Invitation = {
    id: invitationId,
    tenant_id: tenantId,
    email: normalizeEmail(email),
    role,
    invited_by: invitedBy,
    token_hash: tokenHash,
    status: options.status || 'pending',
    expires_at: expiresAt,
    created_at: now.toISOString(),
    metadata: {
      tenant_name: 'Test Organization',
      inviter_name: 'Test Inviter',
      resend_count: 0
    }
  };
  
  if (options.status === 'accepted' && options.acceptedByUserId) {
    invitation.accepted_at = now.toISOString();
    invitation.accepted_by_user_id = options.acceptedByUserId;
  }
  
  if (options.status === 'revoked' && options.revokedBy) {
    invitation.revoked_at = now.toISOString();
    invitation.revoked_by = options.revokedBy;
  }
  
  return invitation;
}

/**
 * Mock Invitation Repository for property testing
 * Simulates real behavior without database dependencies
 */
class MockInvitationRepository {
  private invitations: Map<string, Invitation> = new Map();
  private tokenIndex: Map<string, string> = new Map(); // tokenHash -> invitationId
  
  reset(): void {
    this.invitations.clear();
    this.tokenIndex.clear();
  }
  
  addInvitation(invitation: Invitation, rawToken?: string): void {
    this.invitations.set(invitation.id, invitation);
    if (rawToken) {
      const tokenHash = hashInvitationToken(rawToken);
      this.tokenIndex.set(tokenHash, invitation.id);
    }
  }
  
  getInvitationById(invitationId: string): Invitation | null {
    return this.invitations.get(invitationId) || null;
  }
  
  getInvitationByTokenHash(tokenHash: string): Invitation | null {
    const invitationId = this.tokenIndex.get(tokenHash);
    if (!invitationId) return null;
    return this.invitations.get(invitationId) || null;
  }

  
  validateInvitationToken(rawToken: string): InvitationValidationResult {
    const tokenHash = hashInvitationToken(rawToken);
    const invitation = this.getInvitationByTokenHash(tokenHash);
    
    if (!invitation) {
      return {
        valid: false,
        error: 'Invalid invitation token',
        error_code: 'INVITATION_NOT_FOUND'
      };
    }
    
    return canAcceptInvitation(invitation);
  }
  
  acceptInvitation(invitationId: string, acceptedByUserId: string): Invitation | null {
    const invitation = this.invitations.get(invitationId);
    if (!invitation) return null;
    
    // Can only accept pending invitations
    if (invitation.status !== 'pending') return null;
    
    // Check if expired
    if (isInvitationExpired(invitation)) return null;
    
    // Update invitation
    invitation.status = 'accepted';
    invitation.accepted_at = new Date().toISOString();
    invitation.accepted_by_user_id = acceptedByUserId;
    this.invitations.set(invitationId, invitation);
    
    return invitation;
  }
  
  revokeInvitation(invitationId: string, revokedBy: string): Invitation | null {
    const invitation = this.invitations.get(invitationId);
    if (!invitation) return null;
    
    // Can only revoke pending invitations
    if (invitation.status !== 'pending') return null;
    
    // Update invitation
    invitation.status = 'revoked';
    invitation.revoked_at = new Date().toISOString();
    invitation.revoked_by = revokedBy;
    this.invitations.set(invitationId, invitation);
    
    return invitation;
  }
  
  expireInvitation(invitationId: string): Invitation | null {
    const invitation = this.invitations.get(invitationId);
    if (!invitation) return null;
    
    // Can only expire pending invitations
    if (invitation.status !== 'pending') return null;
    
    // Update invitation
    invitation.status = 'expired';
    this.invitations.set(invitationId, invitation);
    
    return invitation;
  }
}

describe('Invitation Property-Based Tests', () => {
  let mockRepo: MockInvitationRepository;

  beforeEach(() => {
    mockRepo = new MockInvitationRepository();
  });

  afterEach(() => {
    mockRepo.reset();
  });


  /**
   * Property 13: Invitation token single use
   * 
   * Once an invitation token is used, it cannot be used again.
   * For any invitation token, acceptance SHALL succeed exactly once
   * and subsequent attempts SHALL fail.
   * 
   * Properties:
   * - First acceptance of valid token succeeds
   * - Second acceptance of same token fails with INVITATION_ALREADY_USED
   * - Multiple acceptance attempts all fail after first success
   * - Token remains invalid even with different user IDs
   * 
   * **Validates: Requirements 11.3, 11.4**
   */
  describe('Property 13: Invitation token single use', () => {
    it('should accept invitation token exactly once', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, acceptingUserId) => {
            mockRepo.reset();
            
            // Create a valid pending invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // First validation should succeed
            const firstValidation = mockRepo.validateInvitationToken(rawToken);
            expect(firstValidation.valid).toBe(true);
            expect(firstValidation.invitation).toBeDefined();
            
            // Accept the invitation
            const acceptedInvitation = mockRepo.acceptInvitation(invitation.id, acceptingUserId);
            expect(acceptedInvitation).not.toBeNull();
            expect(acceptedInvitation?.status).toBe('accepted');
            
            // Second validation should fail with INVITATION_ALREADY_USED
            const secondValidation = mockRepo.validateInvitationToken(rawToken);
            expect(secondValidation.valid).toBe(false);
            expect(secondValidation.error_code).toBe('INVITATION_ALREADY_USED');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject multiple acceptance attempts after first success', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          fc.array(userIdArb, { minLength: 2, maxLength: 5 }),
          (tenantId, email, role, invitedBy, acceptingUserIds) => {
            mockRepo.reset();
            
            // Create a valid pending invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // First acceptance should succeed
            const firstAccept = mockRepo.acceptInvitation(invitation.id, acceptingUserIds[0]);
            expect(firstAccept).not.toBeNull();
            expect(firstAccept?.status).toBe('accepted');
            
            // All subsequent acceptance attempts should fail
            for (let i = 1; i < acceptingUserIds.length; i++) {
              const subsequentAccept = mockRepo.acceptInvitation(invitation.id, acceptingUserIds[i]);
              expect(subsequentAccept).toBeNull();
            }
            
            // Verify invitation remains in accepted state
            const finalInvitation = mockRepo.getInvitationById(invitation.id);
            expect(finalInvitation?.status).toBe('accepted');
            expect(finalInvitation?.accepted_by_user_id).toBe(acceptingUserIds[0]);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });


    it('should maintain single-use property across different user IDs', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, firstUserId, secondUserId) => {
            // Ensure different user IDs
            fc.pre(firstUserId !== secondUserId);
            mockRepo.reset();
            
            // Create a valid pending invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // First user accepts
            const firstAccept = mockRepo.acceptInvitation(invitation.id, firstUserId);
            expect(firstAccept).not.toBeNull();
            
            // Second user cannot accept the same invitation
            const secondAccept = mockRepo.acceptInvitation(invitation.id, secondUserId);
            expect(secondAccept).toBeNull();
            
            // Verify the invitation was accepted by first user only
            const finalInvitation = mockRepo.getInvitationById(invitation.id);
            expect(finalInvitation?.accepted_by_user_id).toBe(firstUserId);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should validate token returns INVITATION_ALREADY_USED for accepted invitations', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          fc.integer({ min: 1, max: 10 }),
          (tenantId, email, role, invitedBy, acceptingUserId, validationAttempts) => {
            mockRepo.reset();
            
            // Create and accept an invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            mockRepo.acceptInvitation(invitation.id, acceptingUserId);
            
            // All validation attempts should return INVITATION_ALREADY_USED
            for (let i = 0; i < validationAttempts; i++) {
              const validation = mockRepo.validateInvitationToken(rawToken);
              expect(validation.valid).toBe(false);
              expect(validation.error_code).toBe('INVITATION_ALREADY_USED');
            }
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should preserve acceptance timestamp and user ID', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, acceptingUserId) => {
            mockRepo.reset();
            
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            const beforeAccept = new Date();
            const acceptedInvitation = mockRepo.acceptInvitation(invitation.id, acceptingUserId);
            const afterAccept = new Date();
            
            expect(acceptedInvitation).not.toBeNull();
            expect(acceptedInvitation?.accepted_by_user_id).toBe(acceptingUserId);
            expect(acceptedInvitation?.accepted_at).toBeDefined();
            
            // Verify timestamp is within expected range
            const acceptedAt = new Date(acceptedInvitation!.accepted_at!);
            expect(acceptedAt.getTime()).toBeGreaterThanOrEqual(beforeAccept.getTime());
            expect(acceptedAt.getTime()).toBeLessThanOrEqual(afterAccept.getTime());
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });


  /**
   * Property 14: Invitation expiry rejects acceptance
   * 
   * Expired invitations cannot be accepted.
   * When invitation expires, the Zalt Platform SHALL reject acceptance attempts.
   * 
   * Properties:
   * - Expired invitations return INVITATION_EXPIRED on validation
   * - Acceptance of expired invitation fails
   * - Expiry is determined by expires_at timestamp
   * - Non-expired invitations can be accepted
   * 
   * **Validates: Requirements 11.5**
   */
  describe('Property 14: Invitation expiry rejects acceptance', () => {
    it('should reject acceptance of expired invitations', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, acceptingUserId) => {
            mockRepo.reset();
            
            // Create an expired invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: true // This sets expires_at in the past
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // Validation should fail with INVITATION_EXPIRED
            const validation = mockRepo.validateInvitationToken(rawToken);
            expect(validation.valid).toBe(false);
            expect(validation.error_code).toBe('INVITATION_EXPIRED');
            
            // Acceptance should also fail
            const acceptResult = mockRepo.acceptInvitation(invitation.id, acceptingUserId);
            expect(acceptResult).toBeNull();
            
            // Invitation status should remain pending (not changed to accepted)
            const finalInvitation = mockRepo.getInvitationById(invitation.id);
            expect(finalInvitation?.status).toBe('pending');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept non-expired invitations', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          expiryDaysArb,
          (tenantId, email, role, invitedBy, acceptingUserId, expiryDays) => {
            mockRepo.reset();
            
            // Create a non-expired invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false,
              expiryDays
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // Validation should succeed
            const validation = mockRepo.validateInvitationToken(rawToken);
            expect(validation.valid).toBe(true);
            
            // Acceptance should succeed
            const acceptResult = mockRepo.acceptInvitation(invitation.id, acceptingUserId);
            expect(acceptResult).not.toBeNull();
            expect(acceptResult?.status).toBe('accepted');
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should correctly identify expired invitations using isInvitationExpired', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          fc.boolean(),
          (tenantId, email, role, invitedBy, shouldBeExpired) => {
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: shouldBeExpired
            });
            
            const isExpired = isInvitationExpired(invitation);
            expect(isExpired).toBe(shouldBeExpired);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should use canAcceptInvitation to check expiry correctly', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          (tenantId, email, role, invitedBy) => {
            // Test expired invitation
            const expiredInvitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: true
            });
            
            const expiredResult = canAcceptInvitation(expiredInvitation);
            expect(expiredResult.valid).toBe(false);
            expect(expiredResult.error_code).toBe('INVITATION_EXPIRED');
            
            // Test non-expired invitation
            const validInvitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            
            const validResult = canAcceptInvitation(validInvitation);
            expect(validResult.valid).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject expired invitations regardless of other valid properties', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          fc.array(fc.string(), { minLength: 0, maxLength: 3 }),
          (tenantId, email, role, invitedBy, permissions) => {
            mockRepo.reset();
            
            // Create expired invitation with valid permissions
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: true
            });
            invitation.permissions = permissions;
            mockRepo.addInvitation(invitation, rawToken);
            
            // Should still be rejected due to expiry
            const validation = mockRepo.validateInvitationToken(rawToken);
            expect(validation.valid).toBe(false);
            expect(validation.error_code).toBe('INVITATION_EXPIRED');
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle edge case of invitation expiring exactly at current time', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          (tenantId, email, role, invitedBy) => {
            // Create invitation that expires "now" (slightly in the past to ensure expiry)
            const invitation: Invitation = {
              id: generateInvitationId(),
              tenant_id: tenantId,
              email: normalizeEmail(email),
              role,
              invited_by: invitedBy,
              token_hash: hashInvitationToken(generateInvitationToken()),
              status: 'pending',
              expires_at: new Date(Date.now() - 1000).toISOString(), // 1 second ago
              created_at: new Date().toISOString()
            };
            
            expect(isInvitationExpired(invitation)).toBe(true);
            
            const result = canAcceptInvitation(invitation);
            expect(result.valid).toBe(false);
            expect(result.error_code).toBe('INVITATION_EXPIRED');
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });
  });


  /**
   * Property 15: Revoked invitation cannot be accepted
   * 
   * Revoked invitations cannot be accepted.
   * When admin revokes invitation, the Zalt Platform SHALL invalidate immediately.
   * 
   * Properties:
   * - Revoked invitations return INVITATION_REVOKED on validation
   * - Acceptance of revoked invitation fails
   * - Revocation is immediate and permanent
   * - Cannot revoke already accepted invitations
   * 
   * **Validates: Requirements 11.6**
   */
  describe('Property 15: Revoked invitation cannot be accepted', () => {
    it('should reject acceptance of revoked invitations', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, revokedBy, acceptingUserId) => {
            mockRepo.reset();
            
            // Create a pending invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // Revoke the invitation
            const revokedInvitation = mockRepo.revokeInvitation(invitation.id, revokedBy);
            expect(revokedInvitation).not.toBeNull();
            expect(revokedInvitation?.status).toBe('revoked');
            
            // Validation should fail with INVITATION_REVOKED
            const validation = mockRepo.validateInvitationToken(rawToken);
            expect(validation.valid).toBe(false);
            expect(validation.error_code).toBe('INVITATION_REVOKED');
            
            // Acceptance should also fail
            const acceptResult = mockRepo.acceptInvitation(invitation.id, acceptingUserId);
            expect(acceptResult).toBeNull();
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should immediately invalidate invitation upon revocation', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, revokedBy) => {
            mockRepo.reset();
            
            // Create a pending invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // Verify invitation is valid before revocation
            const beforeRevoke = mockRepo.validateInvitationToken(rawToken);
            expect(beforeRevoke.valid).toBe(true);
            
            // Revoke the invitation
            mockRepo.revokeInvitation(invitation.id, revokedBy);
            
            // Verify invitation is immediately invalid after revocation
            const afterRevoke = mockRepo.validateInvitationToken(rawToken);
            expect(afterRevoke.valid).toBe(false);
            expect(afterRevoke.error_code).toBe('INVITATION_REVOKED');
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });


    it('should not allow revoking already accepted invitations', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, acceptingUserId, revokedBy) => {
            mockRepo.reset();
            
            // Create and accept an invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            mockRepo.acceptInvitation(invitation.id, acceptingUserId);
            
            // Attempt to revoke should fail
            const revokeResult = mockRepo.revokeInvitation(invitation.id, revokedBy);
            expect(revokeResult).toBeNull();
            
            // Invitation should remain accepted
            const finalInvitation = mockRepo.getInvitationById(invitation.id);
            expect(finalInvitation?.status).toBe('accepted');
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should preserve revocation metadata', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, revokedBy) => {
            mockRepo.reset();
            
            // Create a pending invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            const beforeRevoke = new Date();
            const revokedInvitation = mockRepo.revokeInvitation(invitation.id, revokedBy);
            const afterRevoke = new Date();
            
            expect(revokedInvitation).not.toBeNull();
            expect(revokedInvitation?.revoked_by).toBe(revokedBy);
            expect(revokedInvitation?.revoked_at).toBeDefined();
            
            // Verify timestamp is within expected range
            const revokedAt = new Date(revokedInvitation!.revoked_at!);
            expect(revokedAt.getTime()).toBeGreaterThanOrEqual(beforeRevoke.getTime());
            expect(revokedAt.getTime()).toBeLessThanOrEqual(afterRevoke.getTime());
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should use canAcceptInvitation to check revoked status correctly', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          (tenantId, email, role, invitedBy, revokedBy) => {
            // Test revoked invitation
            const revokedInvitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'revoked',
              expired: false,
              revokedBy
            });
            
            const revokedResult = canAcceptInvitation(revokedInvitation);
            expect(revokedResult.valid).toBe(false);
            expect(revokedResult.error_code).toBe('INVITATION_REVOKED');
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });


    it('should reject revoked invitations regardless of expiry status', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          userIdArb,
          fc.boolean(),
          (tenantId, email, role, invitedBy, revokedBy, isExpired) => {
            mockRepo.reset();
            
            // Create invitation (may or may not be expired)
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: isExpired
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // Revoke the invitation (only works if pending)
            if (!isExpired) {
              mockRepo.revokeInvitation(invitation.id, revokedBy);
            } else {
              // Manually set to revoked for expired case
              const inv = mockRepo.getInvitationById(invitation.id);
              if (inv) {
                inv.status = 'revoked';
                inv.revoked_by = revokedBy;
                inv.revoked_at = new Date().toISOString();
              }
            }
            
            // Validation should fail with INVITATION_REVOKED
            const validation = mockRepo.validateInvitationToken(rawToken);
            expect(validation.valid).toBe(false);
            // Note: The error code depends on which check happens first
            // Both INVITATION_REVOKED and INVITATION_EXPIRED are valid rejections
            expect(['INVITATION_REVOKED', 'INVITATION_EXPIRED']).toContain(validation.error_code);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should not allow multiple revocations', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          fc.array(userIdArb, { minLength: 2, maxLength: 5 }),
          (tenantId, email, role, invitedBy, revokers) => {
            mockRepo.reset();
            
            // Create a pending invitation
            const rawToken = generateInvitationToken();
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: 'pending',
              expired: false
            });
            mockRepo.addInvitation(invitation, rawToken);
            
            // First revocation should succeed
            const firstRevoke = mockRepo.revokeInvitation(invitation.id, revokers[0]);
            expect(firstRevoke).not.toBeNull();
            expect(firstRevoke?.status).toBe('revoked');
            expect(firstRevoke?.revoked_by).toBe(revokers[0]);
            
            // Subsequent revocations should fail
            for (let i = 1; i < revokers.length; i++) {
              const subsequentRevoke = mockRepo.revokeInvitation(invitation.id, revokers[i]);
              expect(subsequentRevoke).toBeNull();
            }
            
            // Verify original revoker is preserved
            const finalInvitation = mockRepo.getInvitationById(invitation.id);
            expect(finalInvitation?.revoked_by).toBe(revokers[0]);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });
  });


  /**
   * Additional property tests for invitation model validation
   */
  describe('Invitation model validation properties', () => {
    it('should generate unique invitation IDs', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 10, max: 100 }),
          (count) => {
            const ids = new Set<string>();
            for (let i = 0; i < count; i++) {
              ids.add(generateInvitationId());
            }
            // All IDs should be unique
            expect(ids.size).toBe(count);
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should generate unique invitation tokens', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 10, max: 100 }),
          (count) => {
            const tokens = new Set<string>();
            for (let i = 0; i < count; i++) {
              tokens.add(generateInvitationToken());
            }
            // All tokens should be unique
            expect(tokens.size).toBe(count);
            return true;
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should hash tokens consistently', () => {
      fc.assert(
        fc.property(
          tokenArb,
          (token) => {
            const hash1 = hashInvitationToken(token);
            const hash2 = hashInvitationToken(token);
            
            // Same token should produce same hash
            expect(hash1).toBe(hash2);
            
            // Hash should be different from original token
            expect(hash1).not.toBe(token);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should normalize emails consistently', () => {
      fc.assert(
        fc.property(
          emailArb,
          (email) => {
            const normalized1 = normalizeEmail(email);
            const normalized2 = normalizeEmail(email.toUpperCase());
            const normalized3 = normalizeEmail('  ' + email + '  ');
            
            // All normalizations should produce same result
            expect(normalized1).toBe(normalized2);
            expect(normalized1).toBe(normalized3);
            
            // Normalized email should be lowercase and trimmed
            expect(normalized1).toBe(normalized1.toLowerCase().trim());
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should validate email format correctly', () => {
      fc.assert(
        fc.property(
          emailArb,
          (email) => {
            // Valid emails from fast-check should pass validation
            expect(isValidEmail(email)).toBe(true);
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject invalid email formats', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.constant('invalid'),
            fc.constant('no-at-sign'),
            fc.constant('@nodomain'),
            fc.constant('no@domain'),
            fc.constant('spaces in@email.com'),
            fc.constant('')
          ),
          (invalidEmail) => {
            expect(isValidEmail(invalidEmail)).toBe(false);
            return true;
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should calculate expiry date correctly', () => {
      fc.assert(
        fc.property(
          expiryDaysArb,
          (days) => {
            const beforeCalc = new Date();
            const expiryDate = calculateExpiryDate(days);
            const afterCalc = new Date();
            
            const expiry = new Date(expiryDate);
            const expectedMinExpiry = new Date(beforeCalc.getTime() + days * 24 * 60 * 60 * 1000);
            const expectedMaxExpiry = new Date(afterCalc.getTime() + days * 24 * 60 * 60 * 1000);
            
            // Expiry should be within expected range
            expect(expiry.getTime()).toBeGreaterThanOrEqual(expectedMinExpiry.getTime() - 1000);
            expect(expiry.getTime()).toBeLessThanOrEqual(expectedMaxExpiry.getTime() + 1000);
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  /**
   * State transition properties
   */
  describe('Invitation state transition properties', () => {
    it('should only allow valid state transitions', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          (tenantId, email, role, invitedBy) => {
            // Valid transitions from pending:
            // pending -> accepted (via accept)
            // pending -> revoked (via revoke)
            // pending -> expired (via time or explicit expire)
            
            // Test pending -> accepted
            mockRepo.reset();
            const inv1 = generateMockInvitation(tenantId, email, role, invitedBy, { status: 'pending' });
            mockRepo.addInvitation(inv1, generateInvitationToken());
            const accepted = mockRepo.acceptInvitation(inv1.id, 'user_123');
            expect(accepted?.status).toBe('accepted');
            
            // Test pending -> revoked
            mockRepo.reset();
            const inv2 = generateMockInvitation(tenantId, email, role, invitedBy, { status: 'pending' });
            mockRepo.addInvitation(inv2, generateInvitationToken());
            const revoked = mockRepo.revokeInvitation(inv2.id, 'admin_123');
            expect(revoked?.status).toBe('revoked');
            
            // Test pending -> expired
            mockRepo.reset();
            const inv3 = generateMockInvitation(tenantId, email, role, invitedBy, { status: 'pending' });
            mockRepo.addInvitation(inv3, generateInvitationToken());
            const expired = mockRepo.expireInvitation(inv3.id);
            expect(expired?.status).toBe('expired');
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should not allow transitions from terminal states', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          emailArb,
          roleArb,
          userIdArb,
          fc.constantFrom('accepted', 'revoked', 'expired') as fc.Arbitrary<InvitationStatus>,
          (tenantId, email, role, invitedBy, terminalStatus) => {
            mockRepo.reset();
            
            const invitation = generateMockInvitation(tenantId, email, role, invitedBy, {
              status: terminalStatus
            });
            mockRepo.addInvitation(invitation, generateInvitationToken());
            
            // Cannot accept from terminal state
            const acceptResult = mockRepo.acceptInvitation(invitation.id, 'user_123');
            expect(acceptResult).toBeNull();
            
            // Cannot revoke from terminal state
            const revokeResult = mockRepo.revokeInvitation(invitation.id, 'admin_123');
            expect(revokeResult).toBeNull();
            
            // Cannot expire from terminal state
            const expireResult = mockRepo.expireInvitation(invitation.id);
            expect(expireResult).toBeNull();
            
            return true;
          }
        ),
        { numRuns: 30 }
      );
    });
  });
});
