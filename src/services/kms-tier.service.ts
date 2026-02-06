/**
 * KMS Tier Integration Service for Zalt.io
 * 
 * Implements tier-specific KMS configurations:
 * - Shared KMS: Basic/Standard tiers share a common KMS key
 * - Dedicated KMS: Pro tier gets a dedicated KMS key per customer
 * - Customer-Managed KMS: Enterprise tier uses customer's own KMS
 * - HIPAA-Compliant KMS: Healthcare tier with audit logging
 * - FIPS 140-3 HSM: Sovereign tier with hardware security module
 * 
 * Security Requirements:
 * - All keys are managed by AWS KMS
 * - Key rotation is automatic (configurable per tier)
 * - Audit logging for all key operations
 * - Cross-region replication for disaster recovery
 */

import {
  KMSClient,
  CreateKeyCommand,
  DescribeKeyCommand,
  EnableKeyRotationCommand,
  GetKeyRotationStatusCommand,
  ScheduleKeyDeletionCommand,
  CreateAliasCommand,
  DeleteAliasCommand,
  ListAliasesCommand,
  GenerateDataKeyCommand,
  DecryptCommand,
  EncryptCommand,
  SignCommand,
  VerifyCommand,
  KeyUsageType,
  KeySpec,
  OriginType,
  SigningAlgorithmSpec,
  DataKeySpec
} from '@aws-sdk/client-kms';
import { SecurityTierLevel, KMSConfigType, getSecurityTier } from './security-tier.service';
import { AWS_CONFIG } from '../config/aws.config';

const kmsClient = new KMSClient({ region: AWS_CONFIG.region });

/**
 * KMS Key configuration for a tier
 */
export interface KMSKeyConfig {
  keyId: string;
  keyArn: string;
  alias: string;
  kmsType: KMSConfigType;
  rotationEnabled: boolean;
  rotationPeriodDays: number;
  createdAt: Date;
  customerId?: string;
  realmId?: string;
}

/**
 * KMS operation result
 */
export interface KMSOperationResult {
  success: boolean;
  keyId?: string;
  error?: string;
}

/**
 * Encrypted data with KMS metadata
 */
export interface KMSEncryptedData {
  ciphertext: string;
  keyId: string;
  encryptionContext: Record<string, string>;
  algorithm: string;
}

/**
 * Get the KMS key alias for a tier/customer combination
 */
export function getKMSKeyAlias(
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string
): string {
  const config = getSecurityTier(tier);
  
  switch (config.kmsType) {
    case 'shared':
      return `alias/zalt-shared-${tier}`;
    
    case 'dedicated':
      if (!customerId) throw new Error('Customer ID required for dedicated KMS');
      return `alias/zalt-dedicated-${customerId}`;
    
    case 'customer_managed':
      if (!customerId) throw new Error('Customer ID required for customer-managed KMS');
      return `alias/zalt-customer-${customerId}`;
    
    case 'hipaa_compliant':
      if (!realmId) throw new Error('Realm ID required for HIPAA-compliant KMS');
      return `alias/zalt-hipaa-${realmId}`;
    
    case 'fips_140_3':
      if (!customerId) throw new Error('Customer ID required for FIPS KMS');
      return `alias/zalt-fips-${customerId}`;
    
    default:
      return `alias/zalt-default`;
  }
}

/**
 * Get KMS key configuration for a tier
 */
export function getKMSConfig(tier: SecurityTierLevel): {
  keySpec: KeySpec;
  keyUsage: KeyUsageType;
  origin: OriginType;
  rotationPeriodDays: number;
  multiRegion: boolean;
} {
  const tierConfig = getSecurityTier(tier);
  
  // Tier-specific configurations
  switch (tierConfig.kmsType) {
    case 'shared':
      // Shared key for basic/standard tiers
      return {
        keySpec: KeySpec.SYMMETRIC_DEFAULT,
        keyUsage: KeyUsageType.ENCRYPT_DECRYPT,
        origin: OriginType.AWS_KMS,
        rotationPeriodDays: tierConfig.jwtKeyRotationDays,
        multiRegion: false
      };
    
    case 'dedicated':
      // Dedicated key per customer
      return {
        keySpec: KeySpec.SYMMETRIC_DEFAULT,
        keyUsage: KeyUsageType.ENCRYPT_DECRYPT,
        origin: OriginType.AWS_KMS,
        rotationPeriodDays: tierConfig.jwtKeyRotationDays,
        multiRegion: true
      };
    
    case 'customer_managed':
      // Customer provides their own key
      return {
        keySpec: KeySpec.SYMMETRIC_DEFAULT,
        keyUsage: KeyUsageType.ENCRYPT_DECRYPT,
        origin: OriginType.EXTERNAL,
        rotationPeriodDays: tierConfig.jwtKeyRotationDays,
        multiRegion: true
      };
    
    case 'hipaa_compliant':
      // HIPAA requires specific configurations
      return {
        keySpec: KeySpec.SYMMETRIC_DEFAULT,
        keyUsage: KeyUsageType.ENCRYPT_DECRYPT,
        origin: OriginType.AWS_KMS,
        rotationPeriodDays: 30, // More frequent rotation
        multiRegion: true
      };
    
    case 'fips_140_3':
      // FIPS 140-3 Level 3 HSM
      return {
        keySpec: KeySpec.SYMMETRIC_DEFAULT,
        keyUsage: KeyUsageType.ENCRYPT_DECRYPT,
        origin: OriginType.AWS_CLOUDHSM,
        rotationPeriodDays: 14, // Most frequent rotation
        multiRegion: true
      };
    
    default:
      // Default configuration
      return {
        keySpec: KeySpec.SYMMETRIC_DEFAULT,
        keyUsage: KeyUsageType.ENCRYPT_DECRYPT,
        origin: OriginType.AWS_KMS,
        rotationPeriodDays: tierConfig.jwtKeyRotationDays,
        multiRegion: false
      };
  }
}

/**
 * Create a new KMS key for a tier/customer
 */
export async function createKMSKey(
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string,
  description?: string
): Promise<KMSOperationResult> {
  try {
    const alias = getKMSKeyAlias(tier, customerId, realmId);
    const config = getKMSConfig(tier);
    const tierConfig = getSecurityTier(tier);
    
    // Check if key already exists
    const existingKey = await getKMSKeyByAlias(alias);
    if (existingKey) {
      return {
        success: true,
        keyId: existingKey.keyId
      };
    }
    
    // Create the key
    const createCommand = new CreateKeyCommand({
      Description: description || `Zalt.io ${tier} tier key for ${customerId || 'shared'}`,
      KeySpec: config.keySpec,
      KeyUsage: config.keyUsage,
      Origin: config.origin,
      MultiRegion: config.multiRegion,
      Tags: [
        { TagKey: 'Tier', TagValue: tier },
        { TagKey: 'CustomerId', TagValue: customerId || 'shared' },
        { TagKey: 'RealmId', TagValue: realmId || 'default' },
        { TagKey: 'ManagedBy', TagValue: 'zalt.io' },
        { TagKey: 'KMSType', TagValue: tierConfig.kmsType }
      ]
    });
    
    const createResponse = await kmsClient.send(createCommand);
    const keyId = createResponse.KeyMetadata?.KeyId;
    
    if (!keyId) {
      return { success: false, error: 'Failed to create KMS key' };
    }
    
    // Enable automatic key rotation
    if (config.origin === OriginType.AWS_KMS) {
      await kmsClient.send(new EnableKeyRotationCommand({ KeyId: keyId }));
    }
    
    // Create alias
    await kmsClient.send(new CreateAliasCommand({
      AliasName: alias,
      TargetKeyId: keyId
    }));
    
    return { success: true, keyId };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Get KMS key by alias
 */
export async function getKMSKeyByAlias(alias: string): Promise<KMSKeyConfig | null> {
  try {
    const listCommand = new ListAliasesCommand({});
    const response = await kmsClient.send(listCommand);
    
    const aliasEntry = response.Aliases?.find(a => a.AliasName === alias);
    if (!aliasEntry?.TargetKeyId) {
      return null;
    }
    
    const describeCommand = new DescribeKeyCommand({
      KeyId: aliasEntry.TargetKeyId
    });
    const keyResponse = await kmsClient.send(describeCommand);
    
    if (!keyResponse.KeyMetadata) {
      return null;
    }
    
    // Get rotation status
    let rotationEnabled = false;
    try {
      const rotationCommand = new GetKeyRotationStatusCommand({
        KeyId: aliasEntry.TargetKeyId
      });
      const rotationResponse = await kmsClient.send(rotationCommand);
      rotationEnabled = rotationResponse.KeyRotationEnabled || false;
    } catch {
      // Rotation status not available for some key types
    }
    
    return {
      keyId: keyResponse.KeyMetadata.KeyId!,
      keyArn: keyResponse.KeyMetadata.Arn!,
      alias,
      kmsType: 'shared', // Would need to parse from tags
      rotationEnabled,
      rotationPeriodDays: 30, // Default
      createdAt: keyResponse.KeyMetadata.CreationDate!
    };
  } catch {
    return null;
  }
}

/**
 * Get or create KMS key for a tier/customer
 */
export async function getOrCreateKMSKey(
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string
): Promise<KMSKeyConfig> {
  const alias = getKMSKeyAlias(tier, customerId, realmId);
  
  // Try to get existing key
  const existingKey = await getKMSKeyByAlias(alias);
  if (existingKey) {
    return existingKey;
  }
  
  // Create new key
  const result = await createKMSKey(tier, customerId, realmId);
  if (!result.success || !result.keyId) {
    throw new Error(result.error || 'Failed to create KMS key');
  }
  
  // Fetch and return the new key config
  const newKey = await getKMSKeyByAlias(alias);
  if (!newKey) {
    throw new Error('Failed to retrieve created KMS key');
  }
  
  return newKey;
}

/**
 * Encrypt data using tier-specific KMS key
 */
export async function encryptWithTierKMS(
  data: string,
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string,
  context?: Record<string, string>
): Promise<KMSEncryptedData> {
  const keyConfig = await getOrCreateKMSKey(tier, customerId, realmId);
  
  const encryptionContext = {
    tier,
    customerId: customerId || 'shared',
    realmId: realmId || 'default',
    ...context
  };
  
  const command = new EncryptCommand({
    KeyId: keyConfig.keyId,
    Plaintext: Buffer.from(data, 'utf8'),
    EncryptionContext: encryptionContext
  });
  
  const response = await kmsClient.send(command);
  
  if (!response.CiphertextBlob) {
    throw new Error('Encryption failed');
  }
  
  return {
    ciphertext: Buffer.from(response.CiphertextBlob).toString('base64'),
    keyId: keyConfig.keyId,
    encryptionContext,
    algorithm: 'SYMMETRIC_DEFAULT'
  };
}

/**
 * Decrypt data using tier-specific KMS key
 */
export async function decryptWithTierKMS(
  encryptedData: KMSEncryptedData
): Promise<string> {
  const command = new DecryptCommand({
    CiphertextBlob: Buffer.from(encryptedData.ciphertext, 'base64'),
    KeyId: encryptedData.keyId,
    EncryptionContext: encryptedData.encryptionContext
  });
  
  const response = await kmsClient.send(command);
  
  if (!response.Plaintext) {
    throw new Error('Decryption failed');
  }
  
  return Buffer.from(response.Plaintext).toString('utf8');
}

/**
 * Generate a data key for envelope encryption
 */
export async function generateDataKeyForTier(
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string,
  context?: Record<string, string>
): Promise<{
  plaintext: Buffer;
  ciphertext: Buffer;
  keyId: string;
}> {
  const keyConfig = await getOrCreateKMSKey(tier, customerId, realmId);
  
  const encryptionContext = {
    tier,
    customerId: customerId || 'shared',
    realmId: realmId || 'default',
    purpose: 'data_key',
    ...context
  };
  
  const command = new GenerateDataKeyCommand({
    KeyId: keyConfig.keyId,
    KeySpec: DataKeySpec.AES_256,
    EncryptionContext: encryptionContext
  });
  
  const response = await kmsClient.send(command);
  
  if (!response.Plaintext || !response.CiphertextBlob) {
    throw new Error('Failed to generate data key');
  }
  
  return {
    plaintext: Buffer.from(response.Plaintext),
    ciphertext: Buffer.from(response.CiphertextBlob),
    keyId: keyConfig.keyId
  };
}

/**
 * Sign data using tier-specific KMS key (for JWT signing)
 */
export async function signWithTierKMS(
  message: Buffer,
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string
): Promise<string> {
  const keyConfig = await getOrCreateKMSKey(tier, customerId, realmId);
  const tierConfig = getSecurityTier(tier);
  
  // Map JWT algorithm to KMS signing algorithm
  let signingAlgorithm: SigningAlgorithmSpec;
  switch (tierConfig.jwtAlgorithm) {
    case 'RS256':
      signingAlgorithm = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;
      break;
    case 'ES256':
      signingAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_256;
      break;
    case 'EdDSA':
      // Note: KMS doesn't directly support EdDSA, would need CloudHSM
      // Fallback to ECDSA for now
      signingAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_256;
      break;
    default:
      // HS256 uses symmetric key, not KMS signing
      throw new Error(`JWT algorithm ${tierConfig.jwtAlgorithm} not supported for KMS signing`);
  }
  
  const command = new SignCommand({
    KeyId: keyConfig.keyId,
    Message: message,
    MessageType: 'DIGEST',
    SigningAlgorithm: signingAlgorithm
  });
  
  const response = await kmsClient.send(command);
  
  if (!response.Signature) {
    throw new Error('Signing failed');
  }
  
  return Buffer.from(response.Signature).toString('base64');
}

/**
 * Verify signature using tier-specific KMS key
 */
export async function verifyWithTierKMS(
  message: Buffer,
  signature: string,
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string
): Promise<boolean> {
  const keyConfig = await getOrCreateKMSKey(tier, customerId, realmId);
  const tierConfig = getSecurityTier(tier);
  
  let signingAlgorithm: SigningAlgorithmSpec;
  switch (tierConfig.jwtAlgorithm) {
    case 'RS256':
      signingAlgorithm = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;
      break;
    case 'ES256':
      signingAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_256;
      break;
    case 'EdDSA':
      signingAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_256;
      break;
    default:
      throw new Error(`JWT algorithm ${tierConfig.jwtAlgorithm} not supported for KMS verification`);
  }
  
  const command = new VerifyCommand({
    KeyId: keyConfig.keyId,
    Message: message,
    MessageType: 'DIGEST',
    Signature: Buffer.from(signature, 'base64'),
    SigningAlgorithm: signingAlgorithm
  });
  
  try {
    const response = await kmsClient.send(command);
    return response.SignatureValid === true;
  } catch {
    return false;
  }
}

/**
 * Schedule key deletion (for customer offboarding)
 */
export async function scheduleKeyDeletion(
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string,
  pendingWindowInDays: number = 30
): Promise<KMSOperationResult> {
  try {
    const alias = getKMSKeyAlias(tier, customerId, realmId);
    const keyConfig = await getKMSKeyByAlias(alias);
    
    if (!keyConfig) {
      return { success: false, error: 'Key not found' };
    }
    
    // Delete alias first
    await kmsClient.send(new DeleteAliasCommand({ AliasName: alias }));
    
    // Schedule key deletion
    await kmsClient.send(new ScheduleKeyDeletionCommand({
      KeyId: keyConfig.keyId,
      PendingWindowInDays: pendingWindowInDays
    }));
    
    return { success: true, keyId: keyConfig.keyId };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Check if KMS is properly configured for a tier
 */
export async function isKMSConfiguredForTier(
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string
): Promise<boolean> {
  try {
    const alias = getKMSKeyAlias(tier, customerId, realmId);
    const keyConfig = await getKMSKeyByAlias(alias);
    return keyConfig !== null;
  } catch {
    return false;
  }
}

/**
 * Get KMS key rotation status
 */
export async function getKeyRotationStatus(
  tier: SecurityTierLevel,
  customerId?: string,
  realmId?: string
): Promise<{
  enabled: boolean;
  lastRotationDate?: Date;
  nextRotationDate?: Date;
}> {
  const alias = getKMSKeyAlias(tier, customerId, realmId);
  const keyConfig = await getKMSKeyByAlias(alias);
  
  if (!keyConfig) {
    throw new Error('Key not found');
  }
  
  const command = new GetKeyRotationStatusCommand({
    KeyId: keyConfig.keyId
  });
  
  const response = await kmsClient.send(command);
  
  return {
    enabled: response.KeyRotationEnabled || false,
    // Note: AWS KMS doesn't expose exact rotation dates via API
    // These would need to be tracked separately
    lastRotationDate: undefined,
    nextRotationDate: undefined
  };
}

/**
 * Migrate customer to a new tier (re-encrypt data with new key)
 */
export async function migrateToNewTier(
  encryptedData: KMSEncryptedData,
  newTier: SecurityTierLevel,
  customerId?: string,
  realmId?: string
): Promise<KMSEncryptedData> {
  // Decrypt with old key
  const plaintext = await decryptWithTierKMS(encryptedData);
  
  // Re-encrypt with new tier's key
  return encryptWithTierKMS(plaintext, newTier, customerId, realmId);
}
