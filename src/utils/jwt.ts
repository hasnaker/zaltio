/**
 * JWT Token utilities for Zalt.io Auth Platform
 * Validates: Requirements 2.3 (JWT tokens with configurable expiration)
 * 
 * ENTERPRISE SECURITY UPGRADE (January 2026):
 * - KMS-based signing: Private key NEVER leaves AWS HSM
 * - RSA 4096-bit key (FIPS 140-2 Level 3)
 * - RS256 algorithm (HIPAA/FIPS compliant)
 * - Siberci approved configuration
 * 
 * @see Auth-Security-Research/CLIENT-QUESTIONS-ANSWERS.md
 */

import jwt, { Algorithm } from 'jsonwebtoken';
import crypto from 'crypto';
import { JWTPayload, TokenPair } from '../models/session.model';
import { signJWTWithKMS, getKMSPublicKey, getKMSJWTConfig } from '../services/kms-jwt.service';

// Security: Reduced from 1 hour to 15 minutes per Siberci research
const DEFAULT_ACCESS_TOKEN_EXPIRY = 900; // 15 minutes
const DEFAULT_REFRESH_TOKEN_EXPIRY = 604800; // 7 days

// JWT Configuration (Clerk-compatible format)
const JWT_CONFIG = {
  algorithm: 'RS256' as Algorithm,
  issuer: 'https://api.zalt.io',  // URL format per RFC 7519
  audience: 'https://api.zalt.io', // Same as issuer for consistency
  // Strict algorithm whitelist - prevents algorithm confusion attacks
  allowedAlgorithms: ['RS256'] as Algorithm[]
} as const;

/**
 * Check if KMS should be used for JWT operations
 * IMPORTANT: This is a function, not a constant, to ensure
 * environment variables are read at runtime, not build time.
 */
function shouldUseKMS(): boolean {
  const nodeEnv = process.env.NODE_ENV;
  const useKmsFlag = process.env.USE_KMS;
  const result = nodeEnv === 'production' || useKmsFlag === 'true';
  
  // Log for debugging (only on first call per Lambda instance)
  if (!shouldUseKMS._logged) {
    console.log(`[JWT] KMS mode: ${result ? 'ENABLED' : 'DISABLED'} (NODE_ENV=${nodeEnv}, USE_KMS=${useKmsFlag})`);
    shouldUseKMS._logged = true;
  }
  
  return result;
}
shouldUseKMS._logged = false;

export interface TokenOptions {
  accessTokenExpiry?: number;
  refreshTokenExpiry?: number;
  // RBAC options (additive - backward compatible)
  orgId?: string;
  orgIds?: string[];
  roles?: string[];
  permissions?: string[];
}

/**
 * Generate JWT token pair (access + refresh)
 * Uses KMS for signing in production (private key never exposed!)
 */
export async function generateTokenPair(
  userId: string,
  realmId: string,
  email: string,
  options: TokenOptions = {}
): Promise<TokenPair> {
  const now = Math.floor(Date.now() / 1000);
  
  const accessTokenExpiry = options.accessTokenExpiry || DEFAULT_ACCESS_TOKEN_EXPIRY;
  const refreshTokenExpiry = options.refreshTokenExpiry || DEFAULT_REFRESH_TOKEN_EXPIRY;

  // Generate unique token ID for tracking/revocation
  const accessTokenId = crypto.randomBytes(16).toString('hex');
  const refreshTokenId = crypto.randomBytes(16).toString('hex');

  const accessPayload: JWTPayload = {
    sub: userId,
    realm_id: realmId,
    email,
    iat: now,
    exp: now + accessTokenExpiry,
    type: 'access',
    jti: accessTokenId,
    iss: JWT_CONFIG.issuer,
    aud: JWT_CONFIG.audience,
    // RBAC claims (additive - backward compatible)
    ...(options.orgId && { org_id: options.orgId }),
    ...(options.orgIds && options.orgIds.length > 0 && { org_ids: options.orgIds }),
    ...(options.roles && options.roles.length > 0 && { roles: options.roles }),
    // Include permissions only if <= 50, otherwise use permissions_url
    ...(options.permissions && options.permissions.length > 0 && options.permissions.length <= 50 && { 
      permissions: options.permissions 
    }),
    ...(options.permissions && options.permissions.length > 50 && { 
      permissions_url: `${JWT_CONFIG.issuer}/v1/auth/permissions` 
    }),
  };

  const refreshPayload: JWTPayload = {
    sub: userId,
    realm_id: realmId,
    email,
    iat: now,
    exp: now + refreshTokenExpiry,
    type: 'refresh',
    jti: refreshTokenId,
    iss: JWT_CONFIG.issuer,
    aud: JWT_CONFIG.audience
  };

  let accessToken: string;
  let refreshToken: string;

  if (shouldUseKMS()) {
    // PRODUCTION: Sign with KMS (private key never leaves HSM!)
    accessToken = await signJWTWithKMS(accessPayload);
    refreshToken = await signJWTWithKMS(refreshPayload);
  } else {
    // DEVELOPMENT: Use local keys (for testing only)
    const { getJWTKeys } = await import('../services/secrets.service');
    const keys = await getJWTKeys();
    
    accessToken = jwt.sign(accessPayload, keys.privateKey, {
      algorithm: JWT_CONFIG.algorithm,
      // issuer and audience already in payload
    });

    refreshToken = jwt.sign(refreshPayload, keys.privateKey, {
      algorithm: JWT_CONFIG.algorithm,
    });
  }

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: accessTokenExpiry
  };
}

/**
 * Verify and decode access token
 * Uses KMS public key for verification
 */
export async function verifyAccessToken(token: string): Promise<JWTPayload> {
  const publicKey = await getPublicKeyForVerification();
  
  // Verify with public key and strict options
  const payload = jwt.verify(token, publicKey, {
    algorithms: JWT_CONFIG.allowedAlgorithms, // CRITICAL: Whitelist only RS256
    issuer: JWT_CONFIG.issuer,
    audience: JWT_CONFIG.audience
  }) as JWTPayload;
  
  if (payload.type !== 'access') {
    throw new Error('Invalid token type');
  }
  
  return payload;
}

/**
 * Verify and decode refresh token
 * Uses KMS public key for verification
 */
export async function verifyRefreshToken(token: string): Promise<JWTPayload> {
  const publicKey = await getPublicKeyForVerification();
  
  // Verify with public key and strict options
  const payload = jwt.verify(token, publicKey, {
    algorithms: JWT_CONFIG.allowedAlgorithms, // CRITICAL: Whitelist only RS256
    issuer: JWT_CONFIG.issuer,
    audience: JWT_CONFIG.audience
  }) as JWTPayload;
  
  if (payload.type !== 'refresh') {
    throw new Error('Invalid token type');
  }
  
  return payload;
}

/**
 * Get public key for token verification
 * In production, fetches from KMS
 */
async function getPublicKeyForVerification(): Promise<string> {
  if (shouldUseKMS()) {
    return await getKMSPublicKey();
  } else {
    const { getJWTKeys } = await import('../services/secrets.service');
    const keys = await getJWTKeys();
    return keys.publicKey;
  }
}

/**
 * Get current key ID (kid) for JWKS endpoint
 */
export async function getCurrentKeyId(): Promise<string> {
  if (shouldUseKMS()) {
    const config = await getKMSJWTConfig();
    return config.kid;
  }
  return 'zalt-dev-key';
}

/**
 * Decode token without verification (for debugging/logging only)
 * WARNING: Never trust decoded data without verification!
 */
export function decodeTokenUnsafe(token: string): JWTPayload | null {
  try {
    return jwt.decode(token) as JWTPayload;
  } catch {
    return null;
  }
}

/**
 * Get token expiration time
 */
export function getTokenExpiry(token: string): Date | null {
  const decoded = decodeTokenUnsafe(token);
  if (!decoded?.exp) return null;
  return new Date(decoded.exp * 1000);
}

/**
 * Check if token is expired
 */
export function isTokenExpired(token: string): boolean {
  const expiry = getTokenExpiry(token);
  if (!expiry) return true;
  return expiry.getTime() < Date.now();
}

/**
 * Get JWKS (JSON Web Key Set) for public key distribution
 * Used by external services to verify tokens
 */
export async function getJWKS(): Promise<object> {
  const publicKeyPem = await getPublicKeyForVerification();
  const kid = await getCurrentKeyId();
  
  // Convert PEM to JWK format
  const publicKey = crypto.createPublicKey(publicKeyPem);
  const jwk = publicKey.export({ format: 'jwk' });
  
  return {
    keys: [
      {
        ...jwk,
        kid,
        use: 'sig',
        alg: 'RS256'
      }
    ]
  };
}
