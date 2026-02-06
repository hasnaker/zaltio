/**
 * Tediyat Invitation Service Tests
 * Property-based tests for invitation flow
 * 
 * Feature: tediyat-integration
 * Property 17: Invitation Flow Integrity
 * Validates: Requirements 12.3-12.7, 13.3
 */

import * as fc from 'fast-check';
import {
  generateInvitationId,
  generateInvitationToken,
  hashInvitationToken,
  calculateExpiryDate,
  calculateTTL,
  isInvitationExpired,
  canAcceptInvitation,
  Invitation,
} from '../../../models/tediyat/invitation.model';
import {
  getInvitationEmailSubject,
  getInvitationEmailHtml,
  getInvitationEmailText,
} from '../invitation-email.service';

describe('Tediyat Invitation Service', () => {
  describe('Property 17: Invitation Flow Integrity', () => {
    /**
     * Property 17: Invitation Flow Integrity
     * For any invitation, the system should track status (pending/accepted/expired),
     * support both existing and new users, and create membership with specified role.
     * 
     * Validates: Requirements 12.3, 12.4, 12.5, 12.6, 12.7, 13.3
     */
    it('should generate unique invitation IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        const id = generateInvitationId();
        expect(id).toMatch(/^inv_[a-z0-9]+$/);
        expect(ids.has(id)).toBe(false);
        ids.add(id);
      }
    });

    it('should generate secure invitation tokens', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 100 }),
          () => {
            const { rawToken, hashedToken } = generateInvitationToken();
            
            // Raw token should be 64 hex chars (32 bytes)
            expect(rawToken).toMatch(/^[a-f0-9]{64}$/);
            
            // Hashed token should be different from raw
            expect(hashedToken).not.toBe(rawToken);
            
            // Same raw token should produce same hash
            expect(hashInvitationToken(rawToken)).toBe(hashedToken);
            
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should calculate expiry date 7 days in future', () => {
      const now = new Date();
      const expiryDate = new Date(calculateExpiryDate());
      
      // Should be approximately 7 days in future
      const diffDays = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      expect(diffDays).toBeGreaterThan(6.9);
      expect(diffDays).toBeLessThan(7.1);
    });

    it('should calculate TTL as Unix timestamp', () => {
      const ttl = calculateTTL();
      const now = Math.floor(Date.now() / 1000);
      
      // TTL should be approximately 7 days from now
      const diffSeconds = ttl - now;
      const diffDays = diffSeconds / (60 * 60 * 24);
      expect(diffDays).toBeGreaterThan(6.9);
      expect(diffDays).toBeLessThan(7.1);
    });
  });

  describe('Invitation Status Checking', () => {
    const createMockInvitation = (overrides: Partial<Invitation> = {}): Invitation => ({
      id: 'inv_test123',
      tenant_id: 'ten_test123',
      tenant_name: 'Test Şirketi',
      email: 'test@example.com',
      role_id: 'role_accountant',
      role_name: 'Muhasebeci',
      token: 'hashed_token',
      status: 'pending',
      invited_by: 'user_123',
      invited_by_name: 'Test User',
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      created_at: new Date().toISOString(),
      ...overrides,
    });

    it('should correctly identify expired invitations', () => {
      // Not expired
      const validInvitation = createMockInvitation();
      expect(isInvitationExpired(validInvitation)).toBe(false);

      // Expired
      const expiredInvitation = createMockInvitation({
        expires_at: new Date(Date.now() - 1000).toISOString(),
      });
      expect(isInvitationExpired(expiredInvitation)).toBe(true);
    });

    it('should correctly check if invitation can be accepted', () => {
      // Pending invitation can be accepted
      const pendingInvitation = createMockInvitation({ status: 'pending' });
      expect(canAcceptInvitation(pendingInvitation).canAccept).toBe(true);

      // Already accepted
      const acceptedInvitation = createMockInvitation({ status: 'accepted' });
      const acceptedResult = canAcceptInvitation(acceptedInvitation);
      expect(acceptedResult.canAccept).toBe(false);
      expect(acceptedResult.reason).toContain('already accepted');

      // Cancelled
      const cancelledInvitation = createMockInvitation({ status: 'cancelled' });
      const cancelledResult = canAcceptInvitation(cancelledInvitation);
      expect(cancelledResult.canAccept).toBe(false);
      expect(cancelledResult.reason).toContain('cancelled');

      // Expired status
      const expiredStatusInvitation = createMockInvitation({ status: 'expired' });
      const expiredStatusResult = canAcceptInvitation(expiredStatusInvitation);
      expect(expiredStatusResult.canAccept).toBe(false);
      expect(expiredStatusResult.reason).toContain('expired');

      // Expired by date
      const expiredDateInvitation = createMockInvitation({
        status: 'pending',
        expires_at: new Date(Date.now() - 1000).toISOString(),
      });
      const expiredDateResult = canAcceptInvitation(expiredDateInvitation);
      expect(expiredDateResult.canAccept).toBe(false);
      expect(expiredDateResult.reason).toContain('expired');
    });
  });

  describe('Email Templates', () => {
    const emailData = {
      inviteeName: 'Ahmet',
      inviterName: 'Mehmet Yılmaz',
      tenantName: 'ABC Şirketi',
      roleName: 'Muhasebeci',
      inviteUrl: 'https://app.tediyat.com/invite/abc123',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    };

    it('should generate correct email subject', () => {
      const subject = getInvitationEmailSubject('ABC Şirketi');
      expect(subject).toContain('ABC Şirketi');
      expect(subject).toContain('davet');
      expect(subject).toContain('Tediyat');
    });

    it('should generate HTML email with all required data', () => {
      const html = getInvitationEmailHtml(emailData);
      
      expect(html).toContain(emailData.inviteeName);
      expect(html).toContain(emailData.inviterName);
      expect(html).toContain(emailData.tenantName);
      expect(html).toContain(emailData.roleName);
      expect(html).toContain(emailData.inviteUrl);
      expect(html).toContain('Daveti Kabul Et');
    });

    it('should generate plain text email with all required data', () => {
      const text = getInvitationEmailText(emailData);
      
      expect(text).toContain(emailData.inviteeName);
      expect(text).toContain(emailData.inviterName);
      expect(text).toContain(emailData.tenantName);
      expect(text).toContain(emailData.roleName);
      expect(text).toContain(emailData.inviteUrl);
    });

    it('should handle missing invitee name', () => {
      const dataWithoutName = { ...emailData, inviteeName: '' };
      
      const html = getInvitationEmailHtml(dataWithoutName);
      const text = getInvitationEmailText(dataWithoutName);
      
      expect(html).toContain('Merhaba,');
      expect(text).toContain('Merhaba,');
    });
  });
});
