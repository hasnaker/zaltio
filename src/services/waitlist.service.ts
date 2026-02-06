/**
 * Waitlist Service - Business logic for waitlist mode
 * Validates: Requirements 5.3, 5.4, 5.5, 5.6, 5.8, 5.9 (Waitlist Mode)
 */

import {
  joinWaitlist as repoJoinWaitlist,
  getEntryById,
  getEntryByEmail,
  getEntryByReferralCode,
  listEntries,
  getPosition as repoGetPosition,
  getWaitlistStats,
  approveEntry as repoApproveEntry,
  rejectEntry as repoRejectEntry,
  markAsInvited,
  bulkApprove as repoBulkApprove,
  deleteEntry
} from '../repositories/waitlist.repository';
import { findRealmById } from '../repositories/realm.repository';
import { createInvitation } from '../repositories/invitation.repository';
import { sendEmail } from './email.service';
import {
  WaitlistEntry,
  WaitlistResponse,
  WaitlistJoinResult,
  WaitlistStats,
  BulkApprovalResult,
  JoinWaitlistInput,
  isValidEmail
} from '../models/waitlist.model';

export interface WaitlistServiceConfig {
  realmId: string;
}

export interface JoinWaitlistOptions {
  email: string;
  referralCode?: string;
  metadata?: {
    firstName?: string;
    lastName?: string;
    company?: string;
    useCase?: string;
    source?: string;
    utmSource?: string;
    utmMedium?: string;
    utmCampaign?: string;
    customFields?: Record<string, string>;
  };
  ipAddress?: string;
  userAgent?: string;
}

export interface ApproveOptions {
  sendInvitation?: boolean;
  invitationRole?: string;
  customMessage?: string;
}

export interface RejectOptions {
  reason?: string;
  sendNotification?: boolean;
}

export interface ListOptions {
  status?: 'pending' | 'approved' | 'rejected' | 'invited';
  limit?: number;
  cursor?: string;
  sortBy?: 'position' | 'created_at';
  sortOrder?: 'asc' | 'desc';
}

export class WaitlistService {
  private realmId: string;

  constructor(config: WaitlistServiceConfig) {
    this.realmId = config.realmId;
  }

  async isWaitlistModeEnabled(): Promise<boolean> {
    try {
      const realm = await findRealmById(this.realmId);
      // Cast to any to access dynamic property that may be added to realm settings
      const settings = realm?.settings as Record<string, unknown> | undefined;
      return settings?.waitlist_mode_enabled === true;
    } catch {
      return false;
    }
  }

  async join(options: JoinWaitlistOptions): Promise<WaitlistJoinResult> {
    if (!isValidEmail(options.email)) {
      throw new WaitlistError('INVALID_EMAIL', 'Invalid email format');
    }

    const isEnabled = await this.isWaitlistModeEnabled();
    if (!isEnabled) {
      throw new WaitlistError('WAITLIST_NOT_ENABLED', 'Waitlist mode is not enabled for this realm');
    }

    const input: JoinWaitlistInput = {
      realm_id: this.realmId,
      email: options.email,
      referral_code: options.referralCode,
      metadata: {
        first_name: options.metadata?.firstName,
        last_name: options.metadata?.lastName,
        company: options.metadata?.company,
        use_case: options.metadata?.useCase,
        source: options.metadata?.source,
        utm_source: options.metadata?.utmSource,
        utm_medium: options.metadata?.utmMedium,
        utm_campaign: options.metadata?.utmCampaign,
        custom_fields: options.metadata?.customFields,
        ip_address: options.ipAddress ? maskIpAddress(options.ipAddress) : undefined,
        user_agent: options.userAgent
      }
    };

    const result = await repoJoinWaitlist(input);

    if (!result.already_exists) {
      await this.sendWaitlistConfirmationEmail(result.entry, result.referral_code);
    }

    return result;
  }

  async approve(
    entryId: string,
    approvedBy: string,
    options: ApproveOptions = {}
  ): Promise<WaitlistEntry | null> {
    const { sendInvitation = true, invitationRole = 'member', customMessage } = options;

    const entry = await repoApproveEntry(this.realmId, entryId, approvedBy);
    if (!entry) {
      return null;
    }

    if (sendInvitation) {
      try {
        const invitation = await createInvitation({
          tenant_id: this.realmId,
          email: entry.email,
          role: invitationRole,
          invited_by: approvedBy,
          metadata: { custom_message: customMessage }
        });

        await markAsInvited(this.realmId, entryId);
        await this.sendWaitlistApprovalEmail(entry, invitation.token);
      } catch (error) {
        console.error('Failed to send invitation:', error);
      }
    }

    return entry;
  }

  async reject(
    entryId: string,
    rejectedBy: string,
    options: RejectOptions = {}
  ): Promise<WaitlistEntry | null> {
    const { reason, sendNotification = false } = options;

    const entry = await repoRejectEntry(this.realmId, entryId, rejectedBy, reason);
    if (!entry) {
      return null;
    }

    if (sendNotification) {
      await this.sendWaitlistRejectionEmail(entry, reason);
    }

    return entry;
  }

  async bulkApprove(
    entryIds: string[],
    approvedBy: string,
    options: ApproveOptions = {}
  ): Promise<BulkApprovalResult> {
    const result = await repoBulkApprove(this.realmId, entryIds, approvedBy);

    if (options.sendInvitation !== false) {
      for (const entryId of result.approved) {
        try {
          const entry = await getEntryById(this.realmId, entryId);
          if (entry) {
            const invitation = await createInvitation({
              tenant_id: this.realmId,
              email: entry.email,
              role: options.invitationRole || 'member',
              invited_by: approvedBy,
              metadata: { custom_message: options.customMessage }
            });

            await markAsInvited(this.realmId, entryId);
            await this.sendWaitlistApprovalEmail(entry, invitation.token);
          }
        } catch (error) {
          console.error('Failed to send invitation:', error);
        }
      }
    }

    return result;
  }

  async getPosition(entryId: string): Promise<{ position: number; total: number } | null> {
    return repoGetPosition(this.realmId, entryId);
  }

  async list(options: ListOptions = {}): Promise<{ entries: WaitlistResponse[]; nextCursor?: string }> {
    return listEntries(this.realmId, options);
  }

  async getStats(): Promise<WaitlistStats> {
    return getWaitlistStats(this.realmId);
  }

  async getEntry(entryId: string): Promise<WaitlistEntry | null> {
    return getEntryById(this.realmId, entryId);
  }

  async getEntryByEmail(email: string): Promise<WaitlistEntry | null> {
    return getEntryByEmail(this.realmId, email);
  }

  async getEntryByReferralCode(referralCode: string): Promise<WaitlistEntry | null> {
    return getEntryByReferralCode(this.realmId, referralCode);
  }

  async deleteEntry(entryId: string, _deletedBy: string): Promise<boolean> {
    const entry = await getEntryById(this.realmId, entryId);
    if (!entry) {
      return false;
    }
    return deleteEntry(this.realmId, entryId);
  }

  private async sendWaitlistConfirmationEmail(
    entry: WaitlistResponse,
    referralCode: string
  ): Promise<void> {
    try {
      const realm = await findRealmById(this.realmId);
      const realmName = realm?.name || 'Our Platform';
      const appUrl = realm?.settings?.branding?.app_url || '';

      const htmlBody = '<h1>You are on the waitlist!</h1><p>Position: ' + entry.position + '</p><p>Referral code: ' + referralCode + '</p>';
      const textBody = 'You are on the waitlist! Position: ' + entry.position + '. Referral code: ' + referralCode;

      await sendEmail(entry.email, 'You are on the waitlist for ' + realmName + '!', htmlBody, textBody);
    } catch (error) {
      console.error('Failed to send waitlist confirmation email:', error);
    }
  }

  private async sendWaitlistApprovalEmail(
    entry: WaitlistEntry,
    invitationToken: string
  ): Promise<void> {
    try {
      const realm = await findRealmById(this.realmId);
      const realmName = realm?.name || 'Our Platform';
      const appUrl = realm?.settings?.branding?.app_url || '';

      const htmlBody = '<h1>You are in!</h1><p><a href="' + appUrl + '/invite/' + invitationToken + '">Complete Registration</a></p>';
      const textBody = 'You are in! Complete registration: ' + appUrl + '/invite/' + invitationToken;

      await sendEmail(entry.email, 'You are in! Welcome to ' + realmName, htmlBody, textBody);
    } catch (error) {
      console.error('Failed to send waitlist approval email:', error);
    }
  }

  private async sendWaitlistRejectionEmail(
    entry: WaitlistEntry,
    reason?: string
  ): Promise<void> {
    try {
      const realm = await findRealmById(this.realmId);
      const realmName = realm?.name || 'Our Platform';

      const htmlBody = '<h1>Update on your application</h1><p>Unfortunately, we cannot approve your application.</p>' + (reason ? '<p>Reason: ' + reason + '</p>' : '');
      const textBody = 'Update on your application. Unfortunately, we cannot approve your application.' + (reason ? ' Reason: ' + reason : '');

      await sendEmail(entry.email, 'Update on your ' + realmName + ' waitlist application', htmlBody, textBody);
    } catch (error) {
      console.error('Failed to send waitlist rejection email:', error);
    }
  }
}

export class WaitlistError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'WaitlistError';
    this.code = code;
  }
}

function maskIpAddress(ip: string): string {
  const parts = ip.split('.');
  if (parts.length === 4) {
    return parts[0] + '.' + parts[1] + '.xxx.xxx';
  }
  return ip.substring(0, 10) + '::xxxx';
}

export function createWaitlistService(realmId: string): WaitlistService {
  return new WaitlistService({ realmId });
}
