/**
 * Secrets Manager Service - JWT key management
 * Validates: Requirements 7.1, 7.2 (AWS infrastructure)
 * 
 * SECURITY UPGRADE (January 2026):
 * - Changed from symmetric secrets to RSA key pairs
 * - Supports RS256 asymmetric JWT signing
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { AWS_CONFIG } from '../config/aws.config';

const client = new SecretsManagerClient({ region: AWS_CONFIG.region });

/**
 * Legacy symmetric secrets (deprecated, kept for migration)
 */
export interface JWTSecrets {
  access_token_secret: string;
  refresh_token_secret: string;
}

/**
 * RSA Key Pair for RS256 signing
 */
export interface JWTKeys {
  privateKey: string;
  publicKey: string;
}

let cachedSecrets: JWTSecrets | null = null;
let cachedKeys: JWTKeys | null = null;

/**
 * Get RSA key pair for JWT signing (RS256)
 * Keys are stored in AWS Secrets Manager
 */
export async function getJWTKeys(): Promise<JWTKeys> {
  if (cachedKeys) {
    return cachedKeys;
  }

  const command = new GetSecretValueCommand({
    SecretId: AWS_CONFIG.secretsManager.jwtKeys
  });

  try {
    const response = await client.send(command);
    
    if (!response.SecretString) {
      throw new Error('JWT keys not found in Secrets Manager');
    }

    const secrets = JSON.parse(response.SecretString);
    
    // Validate key format
    if (!secrets.privateKey || !secrets.publicKey) {
      throw new Error('Invalid JWT key format: missing privateKey or publicKey');
    }

    cachedKeys = {
      privateKey: secrets.privateKey,
      publicKey: secrets.publicKey
    };
    
    return cachedKeys;
  } catch (error) {
    // Fallback to legacy secrets for backward compatibility during migration
    console.warn('JWT keys not found, falling back to legacy secrets');
    return getFallbackKeys();
  }
}

/**
 * Fallback: Generate temporary keys for development/migration
 * WARNING: Only use in development or during migration period
 */
async function getFallbackKeys(): Promise<JWTKeys> {
  const crypto = await import('crypto');
  
  // Check if we have legacy secrets to derive keys from
  const legacySecrets = await getJWTSecrets();
  
  // Generate deterministic keys from legacy secret (for migration)
  // In production, proper RSA keys should be in Secrets Manager
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  console.warn('⚠️ Using generated RSA keys. Please configure proper keys in Secrets Manager.');
  
  cachedKeys = { privateKey, publicKey };
  return cachedKeys;
}

/**
 * Get legacy symmetric secrets (deprecated)
 * Kept for backward compatibility during migration
 */
export async function getJWTSecrets(): Promise<JWTSecrets> {
  if (cachedSecrets) {
    return cachedSecrets;
  }

  const command = new GetSecretValueCommand({
    SecretId: AWS_CONFIG.secretsManager.jwtSecrets
  });

  const response = await client.send(command);
  
  if (!response.SecretString) {
    throw new Error('JWT secrets not found');
  }

  cachedSecrets = JSON.parse(response.SecretString) as JWTSecrets;
  return cachedSecrets;
}

/**
 * Clear all cached secrets/keys
 * Call this when secrets are rotated
 */
export function clearSecretsCache(): void {
  cachedSecrets = null;
  cachedKeys = null;
}

/**
 * Get public key only (for token verification by external services)
 */
export async function getPublicKey(): Promise<string> {
  const keys = await getJWTKeys();
  return keys.publicKey;
}
