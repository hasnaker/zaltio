/**
 * Waitlist Model - Waitlist Mode for Zalt.io
 * 
 * Waitlist mode allows realms to collect signups before launch.
 * Users join the waitlist and are approved/rejected by admins.
 * 
 * DynamoDB Schema:
 * - Table: zalt-waitlist
 * - pk: REALM#{realmId}#WAITLIST#{entryId}
 * - sk: WAITLIST
 * - GSI: email-index (email -> entryId)
 * - GSI: realm-index (realmId -> entries)
 * - GSI: referral-index (referralCode -> entries)
 * 
 * Security Requirements:
 * - Email must be normalized (lowercase, trimmed)
 * - No email enumeration (same response for existing/new)
 * - Audit logging for all operations
 * - Rate limiting on join endpoint
 * 
 * Validates: Requirements 5.1, 5.2 (Waitlist Mode)
 */

import { randomBytes } from 'crypto';

/**
 * Waitlist entry status types
 */
export type WaitlistStatus = 'pending' | 'approved' | 'rejected' | 'invited';

/**
 * Waitlist entry entity
 */
export interface WaitlistEntry {
  id: string;                    // wl_xxx format
  realm_id: string;              // Target realm
  email: string;                 // Waitlisted email (lowercase)
  status: WaitlistStatus;        // Current status
  position: number;              // Position in waitlist (1-based)
  referral_code: string;         // Unique referral code for this entry
  referred_by?: string;          // Referral code used to join
  referral_count: number;        // Number of successful referrals
  metadata?: WaitlistMetadata;   // Additional metadata
  created_at: string;            // Join timestamp
  updated_at: string;            // Last update timestamp
  approved_at?: string;          // When approved
  approved_by?: string;          // Admin who approved
  rejected_at?: string;          // When rejected
  rejected_by?: string;          // Admin who rejected
  rejection_reason?: string;     // Reason for rejection
  invitation_sent_at?: string;   // When invitation was sent
}

/**
 * Waitlist metadata for additional context
 */
export interface WaitlistMetadata {
  first_name?: string;           // Optional first name
  last_name?: string;            // Optional last name
  company?: string;              // Company name
  use_case?: string;             // Intended use case
  source?: string;               // How they found us
  ip_address?: string;           // IP address (masked for privacy)
  user_agent?: string;           // Browser user agent
  utm_source?: string;           // UTM tracking
  utm_medium?: string;
  utm_campaign?: string;
  custom_fields?: Record<string, string>; // Custom fields defined by realm
}

/**
 * Input for joining the waitlist
 */
export interface JoinWaitlistInput {
  realm_id: string;
  email: string;
  referral_code?: string;        // Referral code used to join
  metadata?: WaitlistMetadata;
}

/**
 * Waitlist response (API response format)
 */
export interface WaitlistResponse {
  id: string;
  realm_id: string;
  email: string;
  status: WaitlistStatus;
  position: number;
  referral_code: string;
  referral_count: number;
  created_at: string;
  metadata?: Omit<WaitlistMetadata, 'ip_address' | 'user_agent'>;
}

/**
 * Waitlist join result
 */
export interface WaitlistJoinResult {
  entry: WaitlistResponse;
  already_exists: boolean;       // True if email was already on waitlist
  position: number;              // Current position
  referral_code: string;         // Referral code to share
}

/**
 * Waitlist statistics
 */
export interface WaitlistStats {
  total: number;
  pending: number;
  approved: number;
  rejected: number;
  invited: number;
  referral_signups: number;      // Signups via referral
}

/**
 * Bulk approval result
 */
export interface BulkApprovalResult {
  approved: string[];            // Entry IDs that were approved
  failed: Array<{
    id: string;
    error: string;
  }>;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Waitlist entry ID prefix
 */
export const WAITLIST_ID_PREFIX = 'wl_';

/**
 * Referral code length (8 characters)
 */
export const REFERRAL_CODE_LENGTH = 8;

/**
 * Maximum entries per bulk operation
 */
export const MAX_BULK_ENTRIES = 100;

/**
 * Default waitlist expiry in days (for cleanup)
 */
export const DEFAULT_WAITLIST_EXPIRY_DAYS = 365;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate unique waitlist entry ID
 */
export function generateWaitlistId(): string {
  return `${WAITLIST_ID_PREFIX}${randomBytes(12).toString('hex')}`;
}

/**
 * Generate unique referral code
 * 8 character alphanumeric code (uppercase)
 */
export function generateReferralCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude confusing chars (0, O, 1, I)
  let code = '';
  const bytes = randomBytes(REFERRAL_CODE_LENGTH);
  for (let i = 0; i < REFERRAL_CODE_LENGTH; i++) {
    code += chars[bytes[i] % chars.length];
  }
  return code;
}

/**
 * Normalize email for consistent storage and lookup
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  if (!email || typeof email !== 'string') return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.trim());
}

/**
 * Validate waitlist status
 */
export function isValidWaitlistStatus(status: string): status is WaitlistStatus {
  return ['pending', 'approved', 'rejected', 'invited'].includes(status);
}

/**
 * Calculate position for new waitlist entry
 * Position is 1-based (first entry is position 1)
 */
export function calculatePosition(existingPendingCount: number): number {
  return existingPendingCount + 1;
}

/**
 * Check if waitlist entry is expired
 */
export function isWaitlistEntryExpired(entry: WaitlistEntry, expiryDays: number = DEFAULT_WAITLIST_EXPIRY_DAYS): boolean {
  const createdAt = new Date(entry.created_at);
  const expiryDate = new Date(createdAt.getTime() + expiryDays * 24 * 60 * 60 * 1000);
  return new Date() > expiryDate;
}

/**
 * Check if entry can be approved
 * Returns boolean for simple checks, or object with error for detailed validation
 */
export function canApproveEntry(entry: WaitlistEntry): boolean {
  return entry.status === 'pending';
}

/**
 * Check if entry can be approved (detailed version)
 */
export function canApproveEntryDetailed(entry: WaitlistEntry): { valid: boolean; error?: string } {
  if (entry.status === 'approved') {
    return { valid: false, error: 'Entry is already approved' };
  }
  if (entry.status === 'invited') {
    return { valid: false, error: 'Entry has already been invited' };
  }
  if (entry.status === 'rejected') {
    return { valid: false, error: 'Entry has been rejected' };
  }
  return { valid: true };
}

/**
 * Check if entry can be rejected
 * Returns boolean for simple checks
 */
export function canRejectEntry(entry: WaitlistEntry): boolean {
  return entry.status === 'pending';
}

/**
 * Check if entry can be rejected (detailed version)
 */
export function canRejectEntryDetailed(entry: WaitlistEntry): { valid: boolean; error?: string } {
  if (entry.status === 'rejected') {
    return { valid: false, error: 'Entry is already rejected' };
  }
  if (entry.status === 'invited') {
    return { valid: false, error: 'Entry has already been invited' };
  }
  if (entry.status === 'approved') {
    return { valid: false, error: 'Entry has already been approved' };
  }
  return { valid: true };
}

/**
 * Convert WaitlistEntry to API response format (excludes sensitive data)
 */
export function toWaitlistResponse(entry: WaitlistEntry): WaitlistResponse {
  const { ip_address, user_agent, ...safeMetadata } = entry.metadata || {};
  
  return {
    id: entry.id,
    realm_id: entry.realm_id,
    email: entry.email,
    status: entry.status,
    position: entry.position,
    referral_code: entry.referral_code,
    referral_count: entry.referral_count,
    created_at: entry.created_at,
    metadata: Object.keys(safeMetadata).length > 0 ? safeMetadata : undefined
  };
}

/**
 * Mask email for display (e.g., j***@example.com)
 */
export function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!local || !domain) return '***@***';
  
  const maskedLocal = local.length > 2 
    ? `${local[0]}${'*'.repeat(Math.min(local.length - 1, 3))}` 
    : local[0] + '*';
  
  return `${maskedLocal}@${domain}`;
}

/**
 * Calculate TTL for DynamoDB (Unix timestamp in seconds)
 * Waitlist entries are kept for 1 year after creation
 */
export function calculateTTL(createdAt: string): number {
  const date = new Date(createdAt);
  date.setFullYear(date.getFullYear() + 1);
  return Math.floor(date.getTime() / 1000);
}
