/**
 * MFA (Multi-Factor Authentication) Service
 * Validates: Requirements 2.2 (MFA support)
 * 
 * Implements TOTP (Time-based One-Time Password) per RFC 6238
 * 
 * SECURITY NOTES:
 * - NO SMS MFA (SS7 vulnerability)
 * - TOTP + WebAuthn only
 * - Backup codes are hashed (SHA-256)
 * - Secrets are encrypted at rest
 */

import crypto from 'crypto';

// TOTP Configuration per RFC 6238
export const TOTP_CONFIG = {
  issuer: 'Zalt.io',
  algorithm: 'sha1',
  digits: 6,
  period: 30,
  window: 1,  // Allow 1 step before/after for clock drift
  secretLength: 20  // 160 bits
};

export const BACKUP_CODES_CONFIG = {
  count: 8,
  length: 8,  // 8 character codes
  warningThreshold: 2  // Warn when 2 codes remaining
};

/**
 * Generate TOTP secret (20 bytes = 160 bits)
 * Returns base32 encoded string
 */
export function generateTOTPSecret(): string {
  const buffer = crypto.randomBytes(TOTP_CONFIG.secretLength);
  return base32Encode(buffer);
}

/**
 * Base32 encoding for TOTP secret
 * RFC 4648 compliant
 */
export function base32Encode(buffer: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  let bits = 0;
  let value = 0;

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 31];
  }

  return result;
}

/**
 * Base32 decoding
 * RFC 4648 compliant
 */
export function base32Decode(encoded: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleanedInput = encoded.toUpperCase().replace(/[^A-Z2-7]/g, '');
  
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of cleanedInput) {
    const index = alphabet.indexOf(char);
    if (index === -1) continue;
    
    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

/**
 * Generate TOTP code for a given timestamp
 * Implements RFC 6238
 */
export function generateTOTP(secret: string, timestamp?: number): string {
  const time = timestamp || Math.floor(Date.now() / 1000);
  const counter = Math.floor(time / TOTP_CONFIG.period);
  
  // Decode base32 secret
  const key = base32Decode(secret);
  
  // Create counter buffer (8 bytes, big-endian)
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(counter));
  
  // HMAC-SHA1
  const hmac = crypto.createHmac('sha1', key);
  hmac.update(counterBuffer);
  const hash = hmac.digest();
  
  // Dynamic truncation per RFC 4226
  const offset = hash[hash.length - 1] & 0x0f;
  const binary = 
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
  
  const otp = binary % Math.pow(10, TOTP_CONFIG.digits);
  return otp.toString().padStart(TOTP_CONFIG.digits, '0');
}

/**
 * Verify TOTP code with window tolerance for clock drift
 * Uses constant-time comparison to prevent timing attacks
 */
export function verifyTOTPCode(secret: string, code: string): boolean {
  // Validate code format
  if (!code || code.length !== TOTP_CONFIG.digits || !/^\d+$/.test(code)) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);
  
  // Check current and adjacent time windows
  for (let i = -TOTP_CONFIG.window; i <= TOTP_CONFIG.window; i++) {
    const timestamp = now + (i * TOTP_CONFIG.period);
    const expectedCode = generateTOTP(secret, timestamp);
    
    // Constant-time comparison to prevent timing attacks
    if (crypto.timingSafeEqual(Buffer.from(code), Buffer.from(expectedCode))) {
      return true;
    }
  }
  
  return false;
}

/**
 * Generate otpauth:// URL for QR code
 * Compatible with Google Authenticator, Authy, etc.
 */
export function generateQRCodeURL(secret: string, email: string, realmName?: string): string {
  const issuer = realmName 
    ? encodeURIComponent(`${TOTP_CONFIG.issuer} (${realmName})`)
    : encodeURIComponent(TOTP_CONFIG.issuer);
  const account = encodeURIComponent(email);
  
  return `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=${TOTP_CONFIG.digits}&period=${TOTP_CONFIG.period}`;
}

/**
 * Generate backup codes
 * 8 codes, 8 characters each, alphanumeric uppercase
 */
export function generateBackupCodes(): string[] {
  const codes: string[] = [];
  for (let i = 0; i < BACKUP_CODES_CONFIG.count; i++) {
    // 8 character alphanumeric code (4 bytes = 8 hex chars)
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(code);
  }
  return codes;
}

/**
 * Hash backup codes for secure storage
 * Uses SHA-256 - codes are never stored in plaintext
 */
export function hashBackupCodes(codes: string[]): string[] {
  return codes.map(code => 
    crypto.createHash('sha256').update(code.toUpperCase()).digest('hex')
  );
}

/**
 * Verify a backup code against hashed codes
 * Returns the index of the matched code, or -1 if not found
 */
export function verifyBackupCode(code: string, hashedCodes: string[]): number {
  const codeHash = crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
  
  // Use constant-time comparison for each code
  for (let i = 0; i < hashedCodes.length; i++) {
    try {
      if (crypto.timingSafeEqual(Buffer.from(codeHash, 'hex'), Buffer.from(hashedCodes[i], 'hex'))) {
        return i;
      }
    } catch {
      // Length mismatch, continue
    }
  }
  
  return -1;
}

/**
 * Check if backup codes are running low
 */
export function shouldWarnLowBackupCodes(remainingCodes: number): boolean {
  return remainingCodes <= BACKUP_CODES_CONFIG.warningThreshold;
}

/**
 * Validate TOTP secret format
 */
export function isValidTOTPSecret(secret: string): boolean {
  // Must be base32 encoded, 32 characters (20 bytes)
  const base32Regex = /^[A-Z2-7]{32}$/;
  return base32Regex.test(secret.toUpperCase());
}


// ============================================
// KMS Encryption for TOTP Secrets
// ============================================

import { encryptSensitiveData, decryptSensitiveData, isKMSConfigured } from './kms.service';

/**
 * Encrypted TOTP secret structure
 */
export interface EncryptedTOTPSecret {
  encryptedData: string;
  encryptedKey: string;
  iv: string;
  version: 'kms-v1';
}

/**
 * Encrypt TOTP secret using KMS envelope encryption
 * Falls back to plaintext if KMS is not configured (dev mode)
 */
export async function encryptTOTPSecret(secret: string): Promise<string | EncryptedTOTPSecret> {
  const kmsEnabled = await isKMSConfigured();
  
  if (!kmsEnabled) {
    console.warn('⚠️ KMS not configured, storing TOTP secret without envelope encryption');
    return secret;
  }
  
  const encrypted = await encryptSensitiveData(secret);
  
  return {
    ...encrypted,
    version: 'kms-v1'
  };
}

/**
 * Decrypt TOTP secret
 * Handles both encrypted (KMS) and plaintext (legacy/dev) formats
 */
export async function decryptTOTPSecret(data: string | EncryptedTOTPSecret): Promise<string> {
  // Plaintext format (legacy or dev mode)
  if (typeof data === 'string') {
    return data;
  }
  
  // KMS encrypted format
  if (data.version === 'kms-v1') {
    return decryptSensitiveData(data.encryptedData, data.encryptedKey, data.iv);
  }
  
  throw new Error('Unknown TOTP secret format');
}

/**
 * Check if a TOTP secret is encrypted
 */
export function isTOTPSecretEncrypted(data: unknown): data is EncryptedTOTPSecret {
  return (
    typeof data === 'object' &&
    data !== null &&
    'version' in data &&
    (data as EncryptedTOTPSecret).version === 'kms-v1'
  );
}
