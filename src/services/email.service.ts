/**
 * Email Service - AWS SES + Gmail SMTP Integration
 * Validates: Requirements 5.1 (Email Verification), 5.3 (Password Reset)
 * 
 * SECURITY:
 * - Rate limiting per user
 * - No email enumeration (same response for valid/invalid)
 * - Secure token generation
 * - Template injection prevention
 * 
 * PROVIDERS:
 * - AWS SES (production, scalable)
 * - Gmail SMTP (Google Workspace, immediate)
 * 
 * @healthcare HIPAA compliant - no PHI in emails
 */

import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import crypto from 'crypto';
import * as nodemailer from 'nodemailer';

// Email Provider Type
export type EmailProvider = 'ses' | 'gmail' | 'smtp';

// Get current provider from env
const EMAIL_PROVIDER: EmailProvider = (process.env.EMAIL_PROVIDER as EmailProvider) || 'ses';

// SES Client (lazy init)
let sesClient: SESClient | null = null;
function getSESClient(): SESClient {
  if (!sesClient) {
    sesClient = new SESClient({
      region: process.env.SES_REGION || process.env.AWS_REGION || 'eu-central-1'
    });
  }
  return sesClient;
}

// Gmail/SMTP Transporter (lazy init)
let smtpTransporter: nodemailer.Transporter | null = null;
function getSMTPTransporter(): nodemailer.Transporter {
  if (!smtpTransporter) {
    if (EMAIL_PROVIDER === 'gmail') {
      // Gmail SMTP (Google Workspace)
      smtpTransporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.GMAIL_USER || process.env.SMTP_USER,
          pass: process.env.GMAIL_APP_PASSWORD || process.env.SMTP_PASSWORD
        }
      });
    } else {
      // Generic SMTP
      smtpTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD
        }
      });
    }
  }
  return smtpTransporter;
}

// Default Configuration (fallback when no realm branding)
const EMAIL_CONFIG = {
  fromAddress: process.env.EMAIL_FROM_ADDRESS || 'noreply@zalt.io',
  fromName: process.env.EMAIL_FROM_NAME || 'Zalt.io',
  replyTo: process.env.EMAIL_REPLY_TO || 'support@zalt.io',
  verificationCodeExpiry: 15 * 60 * 1000, // 15 minutes
  resetTokenExpiry: 60 * 60 * 1000, // 1 hour
  maxVerificationAttempts: 3,
  rateLimitPerHour: 5
};

/**
 * Realm Branding for emails
 * Allows each customer to show their own brand
 */
export interface RealmBranding {
  display_name: string;           // "Clinisyn" instead of "Zalt.io"
  email_from_address?: string;    // "noreply@clinisyn.com" (requires SES verification)
  email_from_name?: string;       // "Clinisyn"
  support_email?: string;         // "support@clinisyn.com"
  logo_url?: string;              // For email headers
  primary_color?: string;         // Brand color
  app_url?: string;               // "https://app.clinisyn.com"
}

/**
 * Email Template Types
 */
export type EmailTemplateType = 
  | 'verification'
  | 'password_reset'
  | 'security_alert'
  | 'new_device'
  | 'mfa_enabled'
  | 'mfa_disabled'
  | 'account_locked'
  | 'invitation';

/**
 * Email Send Result
 */
export interface EmailSendResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

/**
 * Verification Code Data
 */
export interface VerificationCodeData {
  code: string;
  codeHash: string;
  expiresAt: number;
  attempts: number;
}

/**
 * Password Reset Token Data
 */
export interface ResetTokenData {
  token: string;
  tokenHash: string;
  expiresAt: number;
  used: boolean;
}

/**
 * Generate 6-digit verification code
 */
export function generateVerificationCode(): string {
  // Generate cryptographically secure 6-digit code
  const buffer = crypto.randomBytes(4);
  const num = buffer.readUInt32BE(0);
  const code = (num % 900000 + 100000).toString();
  return code;
}

/**
 * Generate secure password reset token
 */
export function generateResetToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Hash verification code or reset token for storage
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Verify token against hash
 */
export function verifyTokenHash(token: string, hash: string): boolean {
  const tokenHash = hashToken(token);
  return crypto.timingSafeEqual(
    Buffer.from(tokenHash, 'hex'),
    Buffer.from(hash, 'hex')
  );
}

/**
 * Create verification code data
 */
export function createVerificationCodeData(): VerificationCodeData {
  const code = generateVerificationCode();
  return {
    code,
    codeHash: hashToken(code),
    expiresAt: Date.now() + EMAIL_CONFIG.verificationCodeExpiry,
    attempts: 0
  };
}

/**
 * Create password reset token data
 */
export function createResetTokenData(): ResetTokenData {
  const token = generateResetToken();
  return {
    token,
    tokenHash: hashToken(token),
    expiresAt: Date.now() + EMAIL_CONFIG.resetTokenExpiry,
    used: false
  };
}

/**
 * Email Templates
 */
const EMAIL_TEMPLATES = {
  verification: (data: { code: string; realmName: string; expiresMinutes: number }) => ({
    subject: `${data.realmName} - Email Verification Code`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .code { font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #2563eb; text-align: center; padding: 20px; background: #f3f4f6; border-radius: 8px; margin: 20px 0; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Email Verification</h2>
          <p>Your verification code for ${escapeHtml(data.realmName)} is:</p>
          <div class="code">${escapeHtml(data.code)}</div>
          <p>This code will expire in ${data.expiresMinutes} minutes.</p>
          <p>If you didn't request this code, please ignore this email.</p>
          <div class="footer">
            <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.realmName)}.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `Your verification code for ${data.realmName} is: ${data.code}\n\nThis code will expire in ${data.expiresMinutes} minutes.\n\nIf you didn't request this code, please ignore this email.`
  }),

  password_reset: (data: { resetUrl: string; realmName: string; expiresMinutes: number }) => ({
    subject: `${data.realmName} - Password Reset Request`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .button { display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 30px; }
          .warning { background: #fef3c7; border: 1px solid #f59e0b; padding: 12px; border-radius: 6px; margin: 20px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Password Reset Request</h2>
          <p>We received a request to reset your password for ${escapeHtml(data.realmName)}.</p>
          <p><a href="${escapeHtml(data.resetUrl)}" class="button">Reset Password</a></p>
          <p>Or copy this link: ${escapeHtml(data.resetUrl)}</p>
          <p>This link will expire in ${data.expiresMinutes} minutes.</p>
          <div class="warning">
            <strong>Security Notice:</strong> If you didn't request this password reset, please ignore this email. Your password will remain unchanged.
          </div>
          <div class="footer">
            <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.realmName)}.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `Password Reset Request\n\nWe received a request to reset your password for ${data.realmName}.\n\nClick here to reset: ${data.resetUrl}\n\nThis link will expire in ${data.expiresMinutes} minutes.\n\nIf you didn't request this, please ignore this email.`
  }),

  security_alert: (data: { alertType: string; details: string; realmName: string; timestamp: string }) => ({
    subject: `${data.realmName} - Security Alert`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .alert { background: #fef2f2; border: 1px solid #ef4444; padding: 16px; border-radius: 6px; margin: 20px 0; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>🔒 Security Alert</h2>
          <div class="alert">
            <strong>${escapeHtml(data.alertType)}</strong>
            <p>${escapeHtml(data.details)}</p>
            <p><small>Time: ${escapeHtml(data.timestamp)}</small></p>
          </div>
          <p>If this was you, no action is needed. If you don't recognize this activity, please secure your account immediately.</p>
          <div class="footer">
            <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.realmName)}.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `Security Alert\n\n${data.alertType}\n${data.details}\nTime: ${data.timestamp}\n\nIf this was you, no action is needed. If you don't recognize this activity, please secure your account immediately.`
  }),

  new_device: (data: { deviceInfo: string; location: string; realmName: string; timestamp: string }) => ({
    subject: `${data.realmName} - New Device Login`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .device-info { background: #f3f4f6; padding: 16px; border-radius: 6px; margin: 20px 0; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>New Device Login</h2>
          <p>A new device was used to sign in to your ${escapeHtml(data.realmName)} account.</p>
          <div class="device-info">
            <p><strong>Device:</strong> ${escapeHtml(data.deviceInfo)}</p>
            <p><strong>Location:</strong> ${escapeHtml(data.location)}</p>
            <p><strong>Time:</strong> ${escapeHtml(data.timestamp)}</p>
          </div>
          <p>If this was you, no action is needed. If you don't recognize this device, please change your password immediately.</p>
          <div class="footer">
            <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.realmName)}.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `New Device Login\n\nA new device was used to sign in to your ${data.realmName} account.\n\nDevice: ${data.deviceInfo}\nLocation: ${data.location}\nTime: ${data.timestamp}\n\nIf this was you, no action is needed. If you don't recognize this device, please change your password immediately.`
  }),

  mfa_enabled: (data: { realmName: string }) => ({
    subject: `${data.realmName} - Two-Factor Authentication Enabled`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .success { background: #ecfdf5; border: 1px solid #10b981; padding: 16px; border-radius: 6px; margin: 20px 0; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>✅ Two-Factor Authentication Enabled</h2>
          <div class="success">
            <p>Two-factor authentication has been successfully enabled on your ${escapeHtml(data.realmName)} account.</p>
          </div>
          <p>Your account is now more secure. You'll need to enter a verification code from your authenticator app when signing in.</p>
          <p>Make sure to save your backup codes in a safe place.</p>
          <div class="footer">
            <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.realmName)}.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `Two-Factor Authentication Enabled\n\nTwo-factor authentication has been successfully enabled on your ${data.realmName} account.\n\nYour account is now more secure. Make sure to save your backup codes in a safe place.`
  }),

  mfa_disabled: (data: { realmName: string }) => ({
    subject: `${data.realmName} - Two-Factor Authentication Disabled`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .warning { background: #fef3c7; border: 1px solid #f59e0b; padding: 16px; border-radius: 6px; margin: 20px 0; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>⚠️ Two-Factor Authentication Disabled</h2>
          <div class="warning">
            <p>Two-factor authentication has been disabled on your ${escapeHtml(data.realmName)} account.</p>
          </div>
          <p>Your account is now less secure. We recommend re-enabling two-factor authentication.</p>
          <p>If you didn't make this change, please secure your account immediately.</p>
          <div class="footer">
            <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.realmName)}.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `Two-Factor Authentication Disabled\n\nTwo-factor authentication has been disabled on your ${data.realmName} account.\n\nYour account is now less secure. We recommend re-enabling two-factor authentication.\n\nIf you didn't make this change, please secure your account immediately.`
  }),

  account_locked: (data: { realmName: string; reason: string; unlockTime?: string }) => ({
    subject: `${data.realmName} - Account Temporarily Locked`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .alert { background: #fef2f2; border: 1px solid #ef4444; padding: 16px; border-radius: 6px; margin: 20px 0; }
          .footer { font-size: 12px; color: #6b7280; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>🔒 Account Temporarily Locked</h2>
          <div class="alert">
            <p>Your ${escapeHtml(data.realmName)} account has been temporarily locked.</p>
            <p><strong>Reason:</strong> ${escapeHtml(data.reason)}</p>
            ${data.unlockTime ? `<p><strong>Unlock time:</strong> ${escapeHtml(data.unlockTime)}</p>` : ''}
          </div>
          <p>If you believe this is an error, please contact support.</p>
          <div class="footer">
            <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.realmName)}.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `Account Temporarily Locked\n\nYour ${data.realmName} account has been temporarily locked.\n\nReason: ${data.reason}\n${data.unlockTime ? `Unlock time: ${data.unlockTime}\n` : ''}\nIf you believe this is an error, please contact support.`
  }),

  invitation: (data: { 
    tenantName: string; 
    inviterName: string; 
    role: string; 
    acceptUrl: string;
    customMessage?: string;
    logoUrl?: string;
    expiresInDays: number;
  }) => ({
    subject: `${escapeHtml(data.inviterName)} invited you to join ${escapeHtml(data.tenantName)}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
          }
          .wrapper {
            background-color: #f5f5f5;
            padding: 40px 20px;
          }
          .container { 
            max-width: 600px; 
            margin: 0 auto; 
            padding: 40px; 
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
          }
          .header { 
            text-align: center; 
            margin-bottom: 30px; 
          }
          .logo { 
            max-height: 50px; 
            margin-bottom: 20px;
          }
          h1 {
            color: #1a1a1a;
            font-size: 24px;
            font-weight: 600;
            margin: 0 0 8px 0;
          }
          .subtitle {
            color: #666;
            font-size: 16px;
            margin: 0;
          }
          .invitation-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            padding: 24px;
            margin: 24px 0;
            color: white;
          }
          .invitation-card h2 {
            margin: 0 0 16px 0;
            font-size: 18px;
            font-weight: 500;
          }
          .invitation-details {
            background: rgba(255, 255, 255, 0.15);
            border-radius: 8px;
            padding: 16px;
          }
          .invitation-details p {
            margin: 8px 0;
            font-size: 14px;
          }
          .invitation-details strong {
            color: rgba(255, 255, 255, 0.8);
          }
          .custom-message {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 16px;
            margin: 24px 0;
            border-radius: 0 8px 8px 0;
          }
          .custom-message p {
            margin: 0;
            font-style: italic;
            color: #92400e;
          }
          .button-container {
            text-align: center;
            margin: 32px 0;
          }
          .button { 
            display: inline-block; 
            padding: 16px 32px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white !important; 
            text-decoration: none; 
            border-radius: 8px; 
            font-weight: 600;
            font-size: 16px;
            box-shadow: 0 4px 14px rgba(102, 126, 234, 0.4);
            transition: transform 0.2s, box-shadow 0.2s;
          }
          .button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
          }
          .link-fallback {
            text-align: center;
            margin: 16px 0;
            font-size: 13px;
            color: #666;
          }
          .link-fallback code {
            display: block;
            background: #f3f4f6;
            padding: 12px;
            border-radius: 6px;
            font-size: 12px;
            word-break: break-all;
            margin-top: 8px;
            color: #374151;
          }
          .expiry-notice {
            text-align: center;
            padding: 12px;
            background: #fef2f2;
            border-radius: 8px;
            margin: 24px 0;
          }
          .expiry-notice p {
            margin: 0;
            color: #dc2626;
            font-weight: 500;
            font-size: 14px;
          }
          .footer { 
            font-size: 12px; 
            color: #9ca3af; 
            margin-top: 32px; 
            text-align: center;
            padding-top: 24px;
            border-top: 1px solid #e5e7eb;
          }
          .footer p {
            margin: 4px 0;
          }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="container">
            ${data.logoUrl ? `<div class="header"><img src="${escapeHtml(data.logoUrl)}" alt="${escapeHtml(data.tenantName)}" class="logo" /></div>` : ''}
            
            <div class="header">
              <h1>You're Invited! 🎉</h1>
              <p class="subtitle">Join ${escapeHtml(data.tenantName)} on Zalt</p>
            </div>
            
            <div class="invitation-card">
              <h2>Invitation Details</h2>
              <div class="invitation-details">
                <p><strong>Organization:</strong> ${escapeHtml(data.tenantName)}</p>
                <p><strong>Role:</strong> ${escapeHtml(data.role)}</p>
                <p><strong>Invited by:</strong> ${escapeHtml(data.inviterName)}</p>
              </div>
            </div>
            
            ${data.customMessage ? `
            <div class="custom-message">
              <p>"${escapeHtml(data.customMessage)}"</p>
            </div>
            ` : ''}
            
            <div class="button-container">
              <a href="${escapeHtml(data.acceptUrl)}" class="button">Accept Invitation</a>
            </div>
            
            <div class="link-fallback">
              Or copy and paste this link into your browser:
              <code>${escapeHtml(data.acceptUrl)}</code>
            </div>
            
            <div class="expiry-notice">
              <p>⏰ This invitation expires in ${data.expiresInDays} days</p>
            </div>
            
            <div class="footer">
              <p>If you didn't expect this invitation, you can safely ignore this email.</p>
              <p>This email was sent by Zalt.io on behalf of ${escapeHtml(data.tenantName)}.</p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `You're Invited to ${data.tenantName}!

${data.inviterName} has invited you to join ${data.tenantName} as a ${data.role}.

${data.customMessage ? `Message from ${data.inviterName}: "${data.customMessage}"\n` : ''}
Invitation Details:
- Organization: ${data.tenantName}
- Role: ${data.role}
- Invited by: ${data.inviterName}

Accept the invitation by clicking this link:
${data.acceptUrl}

This invitation expires in ${data.expiresInDays} days.

If you didn't expect this invitation, you can safely ignore this email.

---
This email was sent by Zalt.io on behalf of ${data.tenantName}.`
  })
};

/**
 * Escape HTML to prevent XSS in email templates
 */
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

/**
 * Send email via AWS SES with optional realm branding
 */
async function sendEmailViaSES(
  to: string,
  subject: string,
  htmlBody: string,
  textBody: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  try {
    // Use realm branding if provided, otherwise use defaults
    const fromAddress = branding?.email_from_address || EMAIL_CONFIG.fromAddress;
    const fromName = branding?.email_from_name || branding?.display_name || EMAIL_CONFIG.fromName;
    const replyTo = branding?.support_email || EMAIL_CONFIG.replyTo;

    const command = new SendEmailCommand({
      Source: `${fromName} <${fromAddress}>`,
      Destination: {
        ToAddresses: [to]
      },
      Message: {
        Subject: {
          Data: subject,
          Charset: 'UTF-8'
        },
        Body: {
          Html: {
            Data: htmlBody,
            Charset: 'UTF-8'
          },
          Text: {
            Data: textBody,
            Charset: 'UTF-8'
          }
        }
      },
      ReplyToAddresses: [replyTo]
    });

    const result = await getSESClient().send(command);

    return {
      success: true,
      messageId: result.MessageId
    };
  } catch (error) {
    console.error('SES email send error:', error);
    return {
      success: false,
      error: (error as Error).message
    };
  }
}

/**
 * Send email via Gmail/SMTP with optional realm branding
 */
async function sendEmailViaSMTP(
  to: string,
  subject: string,
  htmlBody: string,
  textBody: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  try {
    const transporter = getSMTPTransporter();
    
    // Use realm branding if provided, otherwise use defaults
    const fromAddress = branding?.email_from_address || EMAIL_CONFIG.fromAddress;
    const fromName = branding?.email_from_name || branding?.display_name || EMAIL_CONFIG.fromName;
    const replyTo = branding?.support_email || EMAIL_CONFIG.replyTo;
    
    const result = await transporter.sendMail({
      from: `${fromName} <${fromAddress}>`,
      to,
      subject,
      html: htmlBody,
      text: textBody,
      replyTo: replyTo
    });

    return {
      success: true,
      messageId: result.messageId
    };
  } catch (error) {
    console.error('SMTP email send error:', error);
    return {
      success: false,
      error: (error as Error).message
    };
  }
}

/**
 * Send email - automatically selects provider based on EMAIL_PROVIDER env
 * Supports realm branding for white-label emails
 */
export async function sendEmail(
  to: string,
  subject: string,
  htmlBody: string,
  textBody: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  // Select provider based on config
  if (EMAIL_PROVIDER === 'ses') {
    return sendEmailViaSES(to, subject, htmlBody, textBody, branding);
  } else {
    // gmail or smtp
    return sendEmailViaSMTP(to, subject, htmlBody, textBody, branding);
  }
}

/**
 * Send verification email with realm branding
 */
export async function sendVerificationEmail(
  to: string,
  code: string,
  realmName: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  const displayName = branding?.display_name || realmName;
  const template = EMAIL_TEMPLATES.verification({
    code,
    realmName: displayName,
    expiresMinutes: 15
  });

  return sendEmail(to, template.subject, template.html, template.text, branding);
}

/**
 * Send password reset email with realm branding
 */
export async function sendPasswordResetEmail(
  to: string,
  resetToken: string,
  realmName: string,
  baseUrl: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  // Use realm's app_url if available, otherwise use provided baseUrl
  const appUrl = branding?.app_url || baseUrl;
  const displayName = branding?.display_name || realmName;
  const resetUrl = `${appUrl}/reset-password?token=${resetToken}`;
  
  const template = EMAIL_TEMPLATES.password_reset({
    resetUrl,
    realmName: displayName,
    expiresMinutes: 60
  });

  return sendEmail(to, template.subject, template.html, template.text, branding);
}

/**
 * Send security alert email with realm branding
 */
export async function sendSecurityAlertEmail(
  to: string,
  alertType: string,
  details: string,
  realmName: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  const displayName = branding?.display_name || realmName;
  const template = EMAIL_TEMPLATES.security_alert({
    alertType,
    details,
    realmName: displayName,
    timestamp: new Date().toISOString()
  });

  return sendEmail(to, template.subject, template.html, template.text, branding);
}

/**
 * Send new device login email with realm branding
 */
export async function sendNewDeviceEmail(
  to: string,
  deviceInfo: string,
  location: string,
  realmName: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  const displayName = branding?.display_name || realmName;
  const template = EMAIL_TEMPLATES.new_device({
    deviceInfo,
    location,
    realmName: displayName,
    timestamp: new Date().toISOString()
  });

  return sendEmail(to, template.subject, template.html, template.text, branding);
}

/**
 * Send MFA enabled notification with realm branding
 */
export async function sendMFAEnabledEmail(
  to: string,
  realmName: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  const displayName = branding?.display_name || realmName;
  const template = EMAIL_TEMPLATES.mfa_enabled({ realmName: displayName });
  return sendEmail(to, template.subject, template.html, template.text, branding);
}

/**
 * Send MFA disabled notification with realm branding
 */
export async function sendMFADisabledEmail(
  to: string,
  realmName: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  const displayName = branding?.display_name || realmName;
  const template = EMAIL_TEMPLATES.mfa_disabled({ realmName: displayName });
  return sendEmail(to, template.subject, template.html, template.text, branding);
}

/**
 * Send account locked notification with realm branding
 */
export async function sendAccountLockedEmail(
  to: string,
  realmName: string,
  reason: string,
  unlockTime?: string,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  const displayName = branding?.display_name || realmName;
  const template = EMAIL_TEMPLATES.account_locked({ realmName: displayName, reason, unlockTime });
  return sendEmail(to, template.subject, template.html, template.text, branding);
}

/**
 * Invitation Email Input
 * Contains all data needed to send an invitation email
 * Validates: Requirement 11.2
 */
export interface InvitationEmailInput {
  /** Email address of the invitee */
  email: string;
  /** Invitation token for the accept URL */
  token: string;
  /** Name of the tenant/organization */
  tenantName: string;
  /** Name of the person who sent the invitation */
  inviterName: string;
  /** Role being assigned to the invitee */
  role: string;
  /** Optional custom message from the inviter */
  customMessage?: string;
  /** Number of days until invitation expires (default: 7) */
  expiresInDays?: number;
  /** Optional realm branding for white-label emails */
  branding?: RealmBranding;
}

/**
 * Send invitation email with tenant name, inviter, role, and accept link
 * 
 * This function sends a professional invitation email that includes:
 * - Tenant/organization name
 * - Inviter name
 * - Assigned role
 * - Accept link with token: {baseUrl}/invitations/accept?token={token}
 * - Optional custom message
 * - Expiry notice
 * 
 * Uses AWS SES for sending with support for realm branding.
 * 
 * @security
 * - Token is included in URL, not in email body directly
 * - HTML is escaped to prevent XSS
 * - No sensitive data logged
 * 
 * Validates: Requirement 11.2
 */
export async function sendInvitationEmail(
  input: InvitationEmailInput
): Promise<EmailSendResult> {
  const {
    email,
    token,
    tenantName,
    inviterName,
    role,
    customMessage,
    expiresInDays = 7,
    branding
  } = input;

  // Build accept URL using branding app_url or default
  const appUrl = branding?.app_url || process.env.APP_URL || 'https://app.zalt.io';
  const acceptUrl = `${appUrl}/invitations/accept?token=${token}`;
  
  // Use branding display name if available
  const displayName = branding?.display_name || tenantName;

  // Generate email from template
  const template = EMAIL_TEMPLATES.invitation({
    tenantName: displayName,
    inviterName,
    role,
    acceptUrl,
    customMessage,
    logoUrl: branding?.logo_url,
    expiresInDays
  });

  return sendEmail(email, template.subject, template.html, template.text, branding);
}

// Export config and templates for testing
export { EMAIL_CONFIG, EMAIL_TEMPLATES };

/**
 * Breach Notification Email Data
 * Task 17.4: Background breach check job notification
 * _Requirements: 8.8_
 */
export interface BreachNotificationData {
  /** Number of times password was found in breaches */
  breachCount: number;
  /** When the breach was detected */
  detectedAt: string;
  /** Optional custom message */
  message?: string;
}

/**
 * Send breach notification email to user
 * Called by background breach check job when compromised password is detected
 * 
 * SECURITY:
 * - Does NOT include password or hash in email
 * - Provides actionable steps for user
 * - Links to password reset
 * 
 * Task 17.4: Implement background breach check job
 * _Requirements: 8.8_
 */
export async function sendBreachNotificationEmail(
  to: string,
  realmId: string,
  data: BreachNotificationData,
  branding?: RealmBranding
): Promise<EmailSendResult> {
  const displayName = branding?.display_name || 'Zalt.io';
  const appUrl = branding?.app_url || process.env.APP_URL || 'https://app.zalt.io';
  const resetUrl = `${appUrl}/reset-password`;
  const supportEmail = branding?.support_email || 'support@zalt.io';

  const subject = `${displayName} - Security Alert: Password Found in Data Breach`;
  
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
          line-height: 1.6; 
          color: #333; 
          margin: 0;
          padding: 0;
          background-color: #f5f5f5;
        }
        .wrapper {
          background-color: #f5f5f5;
          padding: 40px 20px;
        }
        .container { 
          max-width: 600px; 
          margin: 0 auto; 
          padding: 40px; 
          background: #ffffff;
          border-radius: 12px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }
        .alert-header {
          background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
          color: white;
          padding: 20px;
          border-radius: 8px;
          margin-bottom: 24px;
          text-align: center;
        }
        .alert-header h1 {
          margin: 0;
          font-size: 24px;
        }
        .alert-header .icon {
          font-size: 48px;
          margin-bottom: 12px;
        }
        .info-box {
          background: #fef2f2;
          border: 1px solid #fecaca;
          border-radius: 8px;
          padding: 16px;
          margin: 20px 0;
        }
        .info-box h3 {
          color: #dc2626;
          margin: 0 0 8px 0;
        }
        .steps {
          background: #f0fdf4;
          border: 1px solid #bbf7d0;
          border-radius: 8px;
          padding: 16px;
          margin: 20px 0;
        }
        .steps h3 {
          color: #16a34a;
          margin: 0 0 12px 0;
        }
        .steps ol {
          margin: 0;
          padding-left: 20px;
        }
        .steps li {
          margin: 8px 0;
        }
        .button-container {
          text-align: center;
          margin: 32px 0;
        }
        .button { 
          display: inline-block; 
          padding: 16px 32px; 
          background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
          color: white !important; 
          text-decoration: none; 
          border-radius: 8px; 
          font-weight: 600;
          font-size: 16px;
        }
        .footer { 
          font-size: 12px; 
          color: #9ca3af; 
          margin-top: 32px; 
          text-align: center;
          padding-top: 24px;
          border-top: 1px solid #e5e7eb;
        }
      </style>
    </head>
    <body>
      <div class="wrapper">
        <div class="container">
          <div class="alert-header">
            <div class="icon">🔐</div>
            <h1>Security Alert</h1>
          </div>
          
          <p>We detected that your password for <strong>${escapeHtml(displayName)}</strong> has been found in a known data breach.</p>
          
          <div class="info-box">
            <h3>⚠️ What This Means</h3>
            <p>Your password was found in <strong>${data.breachCount.toLocaleString()}</strong> data breach${data.breachCount > 1 ? 'es' : ''}. This means attackers may have access to this password and could try to use it to access your account.</p>
            <p><small>Detected: ${new Date(data.detectedAt).toLocaleString()}</small></p>
          </div>
          
          <div class="steps">
            <h3>✅ What You Should Do</h3>
            <ol>
              <li><strong>Reset your password immediately</strong> using the button below</li>
              <li>Choose a <strong>unique password</strong> that you don't use anywhere else</li>
              <li>Consider using a <strong>password manager</strong> to generate and store strong passwords</li>
              <li>Enable <strong>two-factor authentication</strong> for additional security</li>
              <li>If you used this password on other sites, <strong>change it there too</strong></li>
            </ol>
          </div>
          
          <div class="button-container">
            <a href="${escapeHtml(resetUrl)}" class="button">Reset Password Now</a>
          </div>
          
          <p style="text-align: center; color: #666; font-size: 14px;">
            If you have any questions, please contact us at <a href="mailto:${escapeHtml(supportEmail)}">${escapeHtml(supportEmail)}</a>
          </p>
          
          <div class="footer">
            <p>This is an automated security notification from ${escapeHtml(displayName)}.</p>
            <p>We regularly check passwords against known data breaches to help keep your account secure.</p>
          </div>
        </div>
      </div>
    </body>
    </html>
  `;

  const text = `SECURITY ALERT: Password Found in Data Breach

We detected that your password for ${displayName} has been found in a known data breach.

WHAT THIS MEANS:
Your password was found in ${data.breachCount.toLocaleString()} data breach${data.breachCount > 1 ? 'es' : ''}. This means attackers may have access to this password and could try to use it to access your account.

Detected: ${new Date(data.detectedAt).toLocaleString()}

WHAT YOU SHOULD DO:
1. Reset your password immediately: ${resetUrl}
2. Choose a unique password that you don't use anywhere else
3. Consider using a password manager to generate and store strong passwords
4. Enable two-factor authentication for additional security
5. If you used this password on other sites, change it there too

If you have any questions, please contact us at ${supportEmail}

---
This is an automated security notification from ${displayName}.
We regularly check passwords against known data breaches to help keep your account secure.
`;

  return sendEmail(to, subject, html, text, branding);
}
