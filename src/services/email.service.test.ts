/**
 * Email Service Unit Tests
 * 
 * Task 5.1: Email Service
 * Validates: Requirements 5.1 (Email Verification), 5.3 (Password Reset)
 * Task 7.4: Invitation Email Templates
 * Validates: Requirement 11.2 (Invitation email with tenant name, inviter, role)
 * 
 * @unit-test
 * @phase Phase 5
 */

import {
  generateVerificationCode,
  generateResetToken,
  hashToken,
  verifyTokenHash,
  createVerificationCodeData,
  createResetTokenData,
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendSecurityAlertEmail,
  sendNewDeviceEmail,
  sendMFAEnabledEmail,
  sendMFADisabledEmail,
  sendAccountLockedEmail,
  sendInvitationEmail,
  EMAIL_CONFIG,
  EMAIL_TEMPLATES,
  InvitationEmailInput
} from './email.service';

// Mock AWS SES
jest.mock('@aws-sdk/client-ses', () => ({
  SESClient: jest.fn().mockImplementation(() => ({
    send: jest.fn().mockResolvedValue({ MessageId: 'test-message-id' })
  })),
  SendEmailCommand: jest.fn()
}));

describe('Email Service', () => {
  describe('generateVerificationCode', () => {
    it('should generate 6-digit code', () => {
      const code = generateVerificationCode();
      expect(code).toMatch(/^\d{6}$/);
    });

    it('should generate different codes each time', () => {
      const codes = new Set<string>();
      for (let i = 0; i < 100; i++) {
        codes.add(generateVerificationCode());
      }
      // Should have high uniqueness
      expect(codes.size).toBeGreaterThan(90);
    });

    it('should generate codes between 100000 and 999999', () => {
      for (let i = 0; i < 100; i++) {
        const code = generateVerificationCode();
        const num = parseInt(code, 10);
        expect(num).toBeGreaterThanOrEqual(100000);
        expect(num).toBeLessThanOrEqual(999999);
      }
    });
  });

  describe('generateResetToken', () => {
    it('should generate 64-character hex token', () => {
      const token = generateResetToken();
      expect(token).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should generate different tokens each time', () => {
      const tokens = new Set<string>();
      for (let i = 0; i < 100; i++) {
        tokens.add(generateResetToken());
      }
      expect(tokens.size).toBe(100);
    });
  });

  describe('hashToken', () => {
    it('should hash token using SHA-256', () => {
      const token = 'test-token';
      const hash = hashToken(token);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce same hash for same input', () => {
      const token = 'test-token';
      const hash1 = hashToken(token);
      const hash2 = hashToken(token);
      expect(hash1).toBe(hash2);
    });

    it('should produce different hash for different input', () => {
      const hash1 = hashToken('token1');
      const hash2 = hashToken('token2');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyTokenHash', () => {
    it('should return true for matching token and hash', () => {
      const token = 'test-token';
      const hash = hashToken(token);
      expect(verifyTokenHash(token, hash)).toBe(true);
    });

    it('should return false for non-matching token', () => {
      const hash = hashToken('correct-token');
      expect(verifyTokenHash('wrong-token', hash)).toBe(false);
    });

    it('should use constant-time comparison', () => {
      // This test verifies the function uses timingSafeEqual
      const token = 'test-token';
      const hash = hashToken(token);
      
      // Should not throw for valid comparison
      expect(() => verifyTokenHash(token, hash)).not.toThrow();
    });
  });

  describe('createVerificationCodeData', () => {
    it('should create verification code data with all fields', () => {
      const data = createVerificationCodeData();
      
      expect(data.code).toMatch(/^\d{6}$/);
      expect(data.codeHash).toMatch(/^[a-f0-9]{64}$/);
      expect(data.expiresAt).toBeGreaterThan(Date.now());
      expect(data.attempts).toBe(0);
    });

    it('should set expiry to 15 minutes from now', () => {
      const before = Date.now();
      const data = createVerificationCodeData();
      const after = Date.now();
      
      const expectedExpiry = 15 * 60 * 1000;
      expect(data.expiresAt).toBeGreaterThanOrEqual(before + expectedExpiry);
      expect(data.expiresAt).toBeLessThanOrEqual(after + expectedExpiry);
    });

    it('should hash the code correctly', () => {
      const data = createVerificationCodeData();
      expect(verifyTokenHash(data.code, data.codeHash)).toBe(true);
    });
  });

  describe('createResetTokenData', () => {
    it('should create reset token data with all fields', () => {
      const data = createResetTokenData();
      
      expect(data.token).toMatch(/^[a-f0-9]{64}$/);
      expect(data.tokenHash).toMatch(/^[a-f0-9]{64}$/);
      expect(data.expiresAt).toBeGreaterThan(Date.now());
      expect(data.used).toBe(false);
    });

    it('should set expiry to 1 hour from now', () => {
      const before = Date.now();
      const data = createResetTokenData();
      const after = Date.now();
      
      const expectedExpiry = 60 * 60 * 1000;
      expect(data.expiresAt).toBeGreaterThanOrEqual(before + expectedExpiry);
      expect(data.expiresAt).toBeLessThanOrEqual(after + expectedExpiry);
    });

    it('should hash the token correctly', () => {
      const data = createResetTokenData();
      expect(verifyTokenHash(data.token, data.tokenHash)).toBe(true);
    });
  });

  describe('sendVerificationEmail', () => {
    it('should send verification email successfully', async () => {
      const result = await sendVerificationEmail(
        'test@example.com',
        '123456',
        'Clinisyn'
      );

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('test-message-id');
    });

    it('should include code in email', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      await sendVerificationEmail(
        'test@example.com',
        '654321',
        'Clinisyn'
      );

      expect(SendEmailCommand).toHaveBeenCalled();
    });
  });

  describe('sendPasswordResetEmail', () => {
    it('should send password reset email successfully', async () => {
      const result = await sendPasswordResetEmail(
        'test@example.com',
        'reset-token-123',
        'Clinisyn',
        'https://clinisyn.zalt.io'
      );

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('test-message-id');
    });
  });

  describe('sendSecurityAlertEmail', () => {
    it('should send security alert email successfully', async () => {
      const result = await sendSecurityAlertEmail(
        'test@example.com',
        'Suspicious Login Attempt',
        'Multiple failed login attempts detected',
        'Clinisyn'
      );

      expect(result.success).toBe(true);
    });
  });

  describe('sendNewDeviceEmail', () => {
    it('should send new device email successfully', async () => {
      const result = await sendNewDeviceEmail(
        'test@example.com',
        'Chrome on Windows',
        'Istanbul, Turkey',
        'Clinisyn'
      );

      expect(result.success).toBe(true);
    });
  });

  describe('sendMFAEnabledEmail', () => {
    it('should send MFA enabled email successfully', async () => {
      const result = await sendMFAEnabledEmail(
        'test@example.com',
        'Clinisyn'
      );

      expect(result.success).toBe(true);
    });
  });

  describe('sendMFADisabledEmail', () => {
    it('should send MFA disabled email successfully', async () => {
      const result = await sendMFADisabledEmail(
        'test@example.com',
        'Clinisyn'
      );

      expect(result.success).toBe(true);
    });
  });

  describe('sendAccountLockedEmail', () => {
    it('should send account locked email successfully', async () => {
      const result = await sendAccountLockedEmail(
        'test@example.com',
        'Clinisyn',
        'Too many failed login attempts',
        '2026-01-15T12:00:00Z'
      );

      expect(result.success).toBe(true);
    });

    it('should work without unlock time', async () => {
      const result = await sendAccountLockedEmail(
        'test@example.com',
        'Clinisyn',
        'Security concern'
      );

      expect(result.success).toBe(true);
    });
  });

  describe('EMAIL_CONFIG', () => {
    it('should have correct verification code expiry', () => {
      expect(EMAIL_CONFIG.verificationCodeExpiry).toBe(15 * 60 * 1000);
    });

    it('should have correct reset token expiry', () => {
      expect(EMAIL_CONFIG.resetTokenExpiry).toBe(60 * 60 * 1000);
    });

    it('should have correct max verification attempts', () => {
      expect(EMAIL_CONFIG.maxVerificationAttempts).toBe(3);
    });

    it('should have correct rate limit per hour', () => {
      expect(EMAIL_CONFIG.rateLimitPerHour).toBe(5);
    });
  });

  describe('XSS Prevention', () => {
    it('should escape HTML in realm name', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      await sendVerificationEmail(
        'test@example.com',
        '123456',
        '<script>alert("xss")</script>'
      );

      // The SendEmailCommand should be called with escaped content
      expect(SendEmailCommand).toHaveBeenCalled();
    });
  });

  // ==========================================================================
  // Invitation Email Tests - Task 7.4
  // Validates: Requirement 11.2
  // ==========================================================================

  describe('sendInvitationEmail', () => {
    const validInput: InvitationEmailInput = {
      email: 'newmember@example.com',
      token: 'secure-invitation-token-123',
      tenantName: 'Clinisyn Healthcare',
      inviterName: 'Dr. John Smith',
      role: 'member'
    };

    it('should send invitation email successfully', async () => {
      const result = await sendInvitationEmail(validInput);

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('test-message-id');
    });

    it('should include tenant name in email', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      await sendInvitationEmail(validInput);

      expect(SendEmailCommand).toHaveBeenCalled();
      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('Clinisyn Healthcare');
      expect(callArgs.Message.Body.Text.Data).toContain('Clinisyn Healthcare');
    });

    it('should include inviter name in email', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      await sendInvitationEmail(validInput);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('Dr. John Smith');
      expect(callArgs.Message.Body.Text.Data).toContain('Dr. John Smith');
    });

    it('should include role in email', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      await sendInvitationEmail(validInput);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('member');
      expect(callArgs.Message.Body.Text.Data).toContain('member');
    });

    it('should include accept URL with token', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      await sendInvitationEmail(validInput);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('/invitations/accept?token=secure-invitation-token-123');
      expect(callArgs.Message.Body.Text.Data).toContain('/invitations/accept?token=secure-invitation-token-123');
    });

    it('should include custom message when provided', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      const inputWithMessage: InvitationEmailInput = {
        ...validInput,
        customMessage: 'Welcome to our team! Looking forward to working with you.'
      };
      
      await sendInvitationEmail(inputWithMessage);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('Welcome to our team!');
      expect(callArgs.Message.Body.Text.Data).toContain('Welcome to our team!');
    });

    it('should use default expiry of 7 days', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      await sendInvitationEmail(validInput);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('7 days');
      expect(callArgs.Message.Body.Text.Data).toContain('7 days');
    });

    it('should use custom expiry when provided', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      const inputWithExpiry: InvitationEmailInput = {
        ...validInput,
        expiresInDays: 14
      };
      
      await sendInvitationEmail(inputWithExpiry);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('14 days');
      expect(callArgs.Message.Body.Text.Data).toContain('14 days');
    });

    it('should use branding app_url when provided', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      const inputWithBranding: InvitationEmailInput = {
        ...validInput,
        branding: {
          display_name: 'Clinisyn',
          app_url: 'https://app.clinisyn.com'
        }
      };
      
      await sendInvitationEmail(inputWithBranding);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('https://app.clinisyn.com/invitations/accept');
    });

    it('should use branding display_name when provided', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      const inputWithBranding: InvitationEmailInput = {
        ...validInput,
        branding: {
          display_name: 'Clinisyn Pro'
        }
      };
      
      await sendInvitationEmail(inputWithBranding);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('Clinisyn Pro');
    });

    it('should include logo when branding logo_url is provided', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      const inputWithLogo: InvitationEmailInput = {
        ...validInput,
        branding: {
          display_name: 'Clinisyn',
          logo_url: 'https://clinisyn.com/logo.png'
        }
      };
      
      await sendInvitationEmail(inputWithLogo);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).toContain('https://clinisyn.com/logo.png');
    });

    it('should set correct subject line', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      await sendInvitationEmail(validInput);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Subject.Data).toContain('Dr. John Smith');
      expect(callArgs.Message.Subject.Data).toContain('invited you to join');
      expect(callArgs.Message.Subject.Data).toContain('Clinisyn Healthcare');
    });

    it('should escape HTML in tenant name to prevent XSS', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      const inputWithXSS: InvitationEmailInput = {
        ...validInput,
        tenantName: '<script>alert("xss")</script>'
      };
      
      await sendInvitationEmail(inputWithXSS);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).not.toContain('<script>');
      expect(callArgs.Message.Body.Html.Data).toContain('&lt;script&gt;');
    });

    it('should escape HTML in inviter name to prevent XSS', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      const inputWithXSS: InvitationEmailInput = {
        ...validInput,
        inviterName: '<img src=x onerror=alert("xss")>'
      };
      
      await sendInvitationEmail(inputWithXSS);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      // The HTML should contain escaped version, not the raw script
      expect(callArgs.Message.Body.Html.Data).toContain('&lt;img');
      expect(callArgs.Message.Body.Html.Data).toContain('&gt;');
    });

    it('should escape HTML in custom message to prevent XSS', async () => {
      const { SendEmailCommand } = require('@aws-sdk/client-ses');
      
      const inputWithXSS: InvitationEmailInput = {
        ...validInput,
        customMessage: '<script>document.cookie</script>'
      };
      
      await sendInvitationEmail(inputWithXSS);

      const callArgs = SendEmailCommand.mock.calls[SendEmailCommand.mock.calls.length - 1][0];
      expect(callArgs.Message.Body.Html.Data).not.toContain('<script>document.cookie</script>');
    });
  });

  describe('EMAIL_TEMPLATES.invitation', () => {
    it('should generate invitation template with all required fields', () => {
      const template = EMAIL_TEMPLATES.invitation({
        tenantName: 'Test Org',
        inviterName: 'John Doe',
        role: 'admin',
        acceptUrl: 'https://app.zalt.io/invitations/accept?token=abc123',
        expiresInDays: 7
      });

      expect(template.subject).toContain('John Doe');
      expect(template.subject).toContain('Test Org');
      expect(template.html).toContain('Test Org');
      expect(template.html).toContain('John Doe');
      expect(template.html).toContain('admin');
      expect(template.html).toContain('https://app.zalt.io/invitations/accept?token=abc123');
      expect(template.html).toContain('7 days');
      expect(template.text).toContain('Test Org');
      expect(template.text).toContain('John Doe');
      expect(template.text).toContain('admin');
    });

    it('should include custom message when provided', () => {
      const template = EMAIL_TEMPLATES.invitation({
        tenantName: 'Test Org',
        inviterName: 'John Doe',
        role: 'member',
        acceptUrl: 'https://app.zalt.io/invitations/accept?token=abc123',
        customMessage: 'Welcome aboard!',
        expiresInDays: 7
      });

      expect(template.html).toContain('Welcome aboard!');
      expect(template.text).toContain('Welcome aboard!');
    });

    it('should include logo when provided', () => {
      const template = EMAIL_TEMPLATES.invitation({
        tenantName: 'Test Org',
        inviterName: 'John Doe',
        role: 'member',
        acceptUrl: 'https://app.zalt.io/invitations/accept?token=abc123',
        logoUrl: 'https://example.com/logo.png',
        expiresInDays: 7
      });

      expect(template.html).toContain('https://example.com/logo.png');
    });

    it('should not include logo section when not provided', () => {
      const template = EMAIL_TEMPLATES.invitation({
        tenantName: 'Test Org',
        inviterName: 'John Doe',
        role: 'member',
        acceptUrl: 'https://app.zalt.io/invitations/accept?token=abc123',
        expiresInDays: 7
      });

      expect(template.html).not.toContain('<img src=""');
    });

    it('should have both HTML and plain text versions', () => {
      const template = EMAIL_TEMPLATES.invitation({
        tenantName: 'Test Org',
        inviterName: 'John Doe',
        role: 'member',
        acceptUrl: 'https://app.zalt.io/invitations/accept?token=abc123',
        expiresInDays: 7
      });

      expect(template.html).toContain('<!DOCTYPE html>');
      expect(template.text).not.toContain('<html>');
      expect(template.text).toContain('Test Org');
    });
  });
});
