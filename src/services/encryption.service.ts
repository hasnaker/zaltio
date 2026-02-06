/**
 * Data Encryption Service for HSD Auth Platform
 * Validates: Requirements 8.2, 9.2
 * 
 * Implements encryption at rest for sensitive data in DynamoDB
 * Uses AES-256-GCM for field-level encryption
 */

import crypto from 'crypto';
import { ENCRYPTION_CONFIG } from '../config/security.config';

/**
 * Encrypted data structure
 */
export interface EncryptedData {
  ciphertext: string;
  iv: string;
  authTag: string;
  version: number;
}

/**
 * Encryption result with metadata
 */
export interface EncryptionResult {
  encrypted: EncryptedData;
  fieldName: string;
  timestamp: string;
}

/**
 * Get encryption key from environment or Secrets Manager
 * In production, this should be fetched from AWS Secrets Manager
 */
async function getEncryptionKey(): Promise<Buffer> {
  const keyBase64 = process.env.HSD_ENCRYPTION_KEY;
  
  if (!keyBase64) {
    // For development/testing, derive a key from a passphrase
    // In production, this should ALWAYS come from Secrets Manager
    const devPassphrase = process.env.HSD_DEV_PASSPHRASE || 'zalt-dev-key-do-not-use-in-prod';
    return deriveKeyFromPassphrase(devPassphrase);
  }
  
  return Buffer.from(keyBase64, 'base64');
}

/**
 * Derive encryption key from passphrase using PBKDF2
 */
function deriveKeyFromPassphrase(passphrase: string, salt?: Buffer): Buffer {
  const derivedSalt = salt || Buffer.from('zalt-platform-salt', 'utf8');
  
  return crypto.pbkdf2Sync(
    passphrase,
    derivedSalt,
    ENCRYPTION_CONFIG.keyDerivation.iterations,
    ENCRYPTION_CONFIG.keyLength,
    ENCRYPTION_CONFIG.keyDerivation.digest
  );
}

/**
 * Encrypt sensitive data using AES-256-GCM
 * Validates: Requirements 8.2 (encryption at rest)
 */
export async function encryptData(plaintext: string): Promise<EncryptedData> {
  const key = await getEncryptionKey();
  const iv = crypto.randomBytes(ENCRYPTION_CONFIG.ivLength);
  
  const cipher = crypto.createCipheriv(
    ENCRYPTION_CONFIG.algorithm,
    key,
    iv,
    { authTagLength: ENCRYPTION_CONFIG.authTagLength }
  );
  
  let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
  ciphertext += cipher.final('base64');
  
  const authTag = cipher.getAuthTag();
  
  return {
    ciphertext,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    version: 1
  };
}

/**
 * Decrypt data encrypted with AES-256-GCM
 */
export async function decryptData(encryptedData: EncryptedData): Promise<string> {
  const key = await getEncryptionKey();
  const iv = Buffer.from(encryptedData.iv, 'base64');
  const authTag = Buffer.from(encryptedData.authTag, 'base64');
  
  const decipher = crypto.createDecipheriv(
    ENCRYPTION_CONFIG.algorithm,
    key,
    iv,
    { authTagLength: ENCRYPTION_CONFIG.authTagLength }
  );
  
  decipher.setAuthTag(authTag);
  
  let plaintext = decipher.update(encryptedData.ciphertext, 'base64', 'utf8');
  plaintext += decipher.final('utf8');
  
  return plaintext;
}

/**
 * Check if a field should be encrypted
 */
export function isSensitiveField(fieldName: string): boolean {
  return (ENCRYPTION_CONFIG.sensitiveFields as readonly string[]).includes(fieldName);
}

/**
 * Encrypt sensitive fields in an object
 */
export async function encryptSensitiveFields<T extends Record<string, unknown>>(
  data: T
): Promise<T> {
  const result = { ...data };
  
  for (const [key, value] of Object.entries(data)) {
    if (isSensitiveField(key) && typeof value === 'string' && value.length > 0) {
      const encrypted = await encryptData(value);
      (result as Record<string, unknown>)[key] = JSON.stringify(encrypted);
    }
  }
  
  return result;
}

/**
 * Decrypt sensitive fields in an object
 */
export async function decryptSensitiveFields<T extends Record<string, unknown>>(
  data: T
): Promise<T> {
  const result = { ...data };
  
  for (const [key, value] of Object.entries(data)) {
    if (isSensitiveField(key) && typeof value === 'string') {
      try {
        const encrypted = JSON.parse(value) as EncryptedData;
        if (encrypted.ciphertext && encrypted.iv && encrypted.authTag) {
          (result as Record<string, unknown>)[key] = await decryptData(encrypted);
        }
      } catch {
        // Value is not encrypted or invalid format, keep as-is
      }
    }
  }
  
  return result;
}

/**
 * Generate a secure random token
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('base64url');
}

/**
 * Hash data with SHA-256 (for non-reversible hashing)
 */
export function hashData(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Create HMAC signature for data integrity
 */
export async function createHmacSignature(data: string): Promise<string> {
  const key = await getEncryptionKey();
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

/**
 * Verify HMAC signature
 */
export async function verifyHmacSignature(
  data: string,
  signature: string
): Promise<boolean> {
  const expectedSignature = await createHmacSignature(data);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );
}

/**
 * Mask sensitive data for logging (show only last 4 chars)
 */
export function maskSensitiveData(data: string, visibleChars: number = 4): string {
  if (data.length <= visibleChars) {
    return '*'.repeat(data.length);
  }
  return '*'.repeat(data.length - visibleChars) + data.slice(-visibleChars);
}

/**
 * Validate encryption key strength
 */
export function validateEncryptionKey(key: Buffer): boolean {
  return key.length >= ENCRYPTION_CONFIG.keyLength;
}
