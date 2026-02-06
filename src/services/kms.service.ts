/**
 * AWS KMS Service - Key Management for Zalt.io
 * 
 * HIPAA/FIPS Compliant Key Management:
 * - JWT signing keys managed by KMS
 * - Automatic key rotation (30 days)
 * - Envelope encryption for sensitive data
 * 
 * KMS Key: alias/zalt-master (created by user)
 */

import {
  KMSClient,
  SignCommand,
  VerifyCommand,
  GenerateDataKeyCommand,
  DecryptCommand,
  DescribeKeyCommand,
  SigningAlgorithmSpec,
  DataKeySpec
} from '@aws-sdk/client-kms';
import { AWS_CONFIG } from '../config/aws.config';

const kmsClient = new KMSClient({ region: AWS_CONFIG.region });

// KMS Key Alias from config
const KMS_KEY_ALIAS = AWS_CONFIG.kms.masterKeyAlias;

/**
 * KMS Key Info
 */
export interface KMSKeyInfo {
  keyId: string;
  keyArn: string;
  keyState: string;
  creationDate: Date;
  enabled: boolean;
}

/**
 * Data Key for envelope encryption
 */
export interface DataKey {
  plaintext: Buffer;
  ciphertext: Buffer;
}

/**
 * Get KMS key information
 */
export async function getKeyInfo(): Promise<KMSKeyInfo> {
  const command = new DescribeKeyCommand({
    KeyId: KMS_KEY_ALIAS
  });

  const response = await kmsClient.send(command);
  
  if (!response.KeyMetadata) {
    throw new Error('KMS key not found');
  }

  return {
    keyId: response.KeyMetadata.KeyId!,
    keyArn: response.KeyMetadata.Arn!,
    keyState: response.KeyMetadata.KeyState!,
    creationDate: response.KeyMetadata.CreationDate!,
    enabled: response.KeyMetadata.Enabled!
  };
}

/**
 * Sign data using KMS (for JWT signing)
 * Uses RSASSA_PKCS1_V1_5_SHA_256 (RS256 equivalent)
 * 
 * @param message - Data to sign (should be SHA-256 hash)
 * @returns Base64 encoded signature
 */
export async function signWithKMS(message: Buffer): Promise<string> {
  const command = new SignCommand({
    KeyId: KMS_KEY_ALIAS,
    Message: message,
    MessageType: 'DIGEST', // We're passing a pre-hashed message
    SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256
  });

  const response = await kmsClient.send(command);
  
  if (!response.Signature) {
    throw new Error('KMS signing failed');
  }

  return Buffer.from(response.Signature).toString('base64');
}

/**
 * Verify signature using KMS
 * 
 * @param message - Original data (should be SHA-256 hash)
 * @param signature - Base64 encoded signature
 * @returns true if valid
 */
export async function verifyWithKMS(message: Buffer, signature: string): Promise<boolean> {
  const command = new VerifyCommand({
    KeyId: KMS_KEY_ALIAS,
    Message: message,
    MessageType: 'DIGEST',
    Signature: Buffer.from(signature, 'base64'),
    SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256
  });

  try {
    const response = await kmsClient.send(command);
    return response.SignatureValid === true;
  } catch {
    return false;
  }
}

/**
 * Generate a data key for envelope encryption
 * Used for encrypting sensitive data (TOTP secrets, etc.)
 * 
 * @returns Plaintext key (for encryption) and encrypted key (for storage)
 */
export async function generateDataKey(): Promise<DataKey> {
  const command = new GenerateDataKeyCommand({
    KeyId: KMS_KEY_ALIAS,
    KeySpec: DataKeySpec.AES_256
  });

  const response = await kmsClient.send(command);
  
  if (!response.Plaintext || !response.CiphertextBlob) {
    throw new Error('Failed to generate data key');
  }

  return {
    plaintext: Buffer.from(response.Plaintext),
    ciphertext: Buffer.from(response.CiphertextBlob)
  };
}

/**
 * Decrypt a data key
 * 
 * @param encryptedKey - Encrypted data key from generateDataKey
 * @returns Decrypted key
 */
export async function decryptDataKey(encryptedKey: Buffer): Promise<Buffer> {
  const command = new DecryptCommand({
    KeyId: KMS_KEY_ALIAS,
    CiphertextBlob: encryptedKey
  });

  const response = await kmsClient.send(command);
  
  if (!response.Plaintext) {
    throw new Error('Failed to decrypt data key');
  }

  return Buffer.from(response.Plaintext);
}

/**
 * Encrypt sensitive data using envelope encryption
 * 
 * @param data - Data to encrypt
 * @returns Encrypted data with encrypted key
 */
export async function encryptSensitiveData(data: string): Promise<{
  encryptedData: string;
  encryptedKey: string;
  iv: string;
}> {
  const crypto = await import('crypto');
  
  // Generate data key
  const dataKey = await generateDataKey();
  
  // Generate IV
  const iv = crypto.randomBytes(16);
  
  // Encrypt data with AES-256-GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', dataKey.plaintext, iv);
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();
  
  // Clear plaintext key from memory
  dataKey.plaintext.fill(0);
  
  return {
    encryptedData: encrypted + ':' + authTag.toString('base64'),
    encryptedKey: dataKey.ciphertext.toString('base64'),
    iv: iv.toString('base64')
  };
}

/**
 * Decrypt sensitive data using envelope encryption
 * 
 * @param encryptedData - Encrypted data from encryptSensitiveData
 * @param encryptedKey - Encrypted key from encryptSensitiveData
 * @param iv - IV from encryptSensitiveData
 * @returns Decrypted data
 */
export async function decryptSensitiveData(
  encryptedData: string,
  encryptedKey: string,
  iv: string
): Promise<string> {
  const crypto = await import('crypto');
  
  // Decrypt data key
  const dataKey = await decryptDataKey(Buffer.from(encryptedKey, 'base64'));
  
  // Parse encrypted data and auth tag
  const [encrypted, authTagBase64] = encryptedData.split(':');
  const authTag = Buffer.from(authTagBase64, 'base64');
  
  // Decrypt data
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    dataKey,
    Buffer.from(iv, 'base64')
  );
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  
  // Clear key from memory
  dataKey.fill(0);
  
  return decrypted;
}

/**
 * Check if KMS is properly configured
 */
export async function isKMSConfigured(): Promise<boolean> {
  try {
    const keyInfo = await getKeyInfo();
    return keyInfo.enabled;
  } catch {
    return false;
  }
}
