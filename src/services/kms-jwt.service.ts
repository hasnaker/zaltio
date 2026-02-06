/**
 * KMS-based JWT Signing Service
 * 
 * ENTERPRISE SECURITY (January 2026):
 * - Private key NEVER leaves AWS KMS HSM (FIPS 140-2 Level 3)
 * - RSA 4096-bit key for healthcare-grade security
 * - RS256 algorithm (RSASSA_PKCS1_V1_5_SHA_256)
 * - Siberci approved configuration
 * 
 * @see Auth-Security-Research/CLIENT-QUESTIONS-ANSWERS.md
 */

import { KMSClient, SignCommand, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { AWS_CONFIG } from '../config/aws.config';

const kmsClient = new KMSClient({ region: AWS_CONFIG.region });
const secretsClient = new SecretsManagerClient({ region: AWS_CONFIG.region });

/**
 * KMS JWT Configuration from Secrets Manager
 */
export interface KMSJWTConfig {
  kmsKeyId: string;
  kmsKeyAlias: string;
  algorithm: string;
  kid: string;
}

let cachedConfig: KMSJWTConfig | null = null;
let cachedPublicKey: string | null = null;

/**
 * Get KMS JWT configuration from Secrets Manager
 */
export async function getKMSJWTConfig(): Promise<KMSJWTConfig> {
  if (cachedConfig) {
    return cachedConfig;
  }

  const command = new GetSecretValueCommand({
    SecretId: AWS_CONFIG.secretsManager.jwtSecrets
  });

  const response = await secretsClient.send(command);
  
  if (!response.SecretString) {
    throw new Error('KMS JWT config not found in Secrets Manager');
  }

  const secrets = JSON.parse(response.SecretString);
  
  // Validate KMS config
  if (!secrets.kmsKeyId || !secrets.kmsKeyAlias) {
    throw new Error('Invalid KMS JWT config: missing kmsKeyId or kmsKeyAlias');
  }

  cachedConfig = {
    kmsKeyId: secrets.kmsKeyId,
    kmsKeyAlias: secrets.kmsKeyAlias,
    algorithm: secrets.algorithm || 'RS256',
    kid: secrets.kid || 'zalt-kms-default'
  };
  
  return cachedConfig;
}

/**
 * Get public key from KMS for token verification
 * Public key is safe to cache and distribute
 */
export async function getKMSPublicKey(): Promise<string> {
  if (cachedPublicKey) {
    return cachedPublicKey;
  }

  const config = await getKMSJWTConfig();
  
  const command = new GetPublicKeyCommand({
    KeyId: config.kmsKeyAlias
  });

  const response = await kmsClient.send(command);
  
  if (!response.PublicKey) {
    throw new Error('Failed to get public key from KMS');
  }

  // Convert DER to PEM format
  const publicKeyDer = Buffer.from(response.PublicKey);
  const publicKeyPem = derToPem(publicKeyDer, 'PUBLIC KEY');
  
  cachedPublicKey = publicKeyPem;
  return cachedPublicKey;
}

/**
 * Sign JWT using AWS KMS
 * Private key NEVER leaves the HSM!
 */
export async function signWithKMS(message: string): Promise<string> {
  const config = await getKMSJWTConfig();
  
  const command = new SignCommand({
    KeyId: config.kmsKeyAlias,
    Message: Buffer.from(message),
    MessageType: 'RAW',
    SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256' // RS256 equivalent
  });

  const response = await kmsClient.send(command);
  
  if (!response.Signature) {
    throw new Error('KMS signing failed');
  }

  // Convert signature to base64url
  return base64urlEncode(Buffer.from(response.Signature));
}

/**
 * Create JWT header with KMS key ID
 */
export async function createJWTHeader(): Promise<string> {
  const config = await getKMSJWTConfig();
  
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: config.kid
  };
  
  return base64urlEncode(Buffer.from(JSON.stringify(header)));
}

/**
 * Sign complete JWT using KMS
 * This is the main function to use for JWT creation
 */
export async function signJWTWithKMS(payload: object): Promise<string> {
  const header = await createJWTHeader();
  const payloadEncoded = base64urlEncode(Buffer.from(JSON.stringify(payload)));
  
  const message = `${header}.${payloadEncoded}`;
  const signature = await signWithKMS(message);
  
  return `${message}.${signature}`;
}

/**
 * Clear cached config and public key
 * Call this when KMS key is rotated
 */
export function clearKMSCache(): void {
  cachedConfig = null;
  cachedPublicKey = null;
}

// ============================================
// Helper Functions
// ============================================

/**
 * Convert DER format to PEM format
 */
function derToPem(der: Buffer, label: string): string {
  const base64 = der.toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

/**
 * Base64url encode (JWT standard)
 */
function base64urlEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64url decode
 */
export function base64urlDecode(str: string): Buffer {
  // Add padding if needed
  const padding = 4 - (str.length % 4);
  if (padding !== 4) {
    str += '='.repeat(padding);
  }
  
  return Buffer.from(
    str.replace(/-/g, '+').replace(/_/g, '/'),
    'base64'
  );
}
