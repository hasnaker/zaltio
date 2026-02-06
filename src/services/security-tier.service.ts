/**
 * Security Tier Service for Zalt.io
 * 
 * Implements configurable security tiers for different customer needs:
 * - Basic: Startups, low-security apps
 * - Standard: Most SaaS applications
 * - Pro: Financial services, e-commerce
 * - Enterprise: Large organizations
 * - Healthcare: HIPAA-compliant (Clinisyn)
 * - Sovereign: Government, defense
 * 
 * Each tier configures:
 * - Password hashing algorithm (bcrypt, scrypt, Argon2id)
 * - JWT signing algorithm (HS256, RS256, ES256, EdDSA)
 * - KMS configuration (shared, dedicated, customer-managed)
 * - Session policies
 * - MFA requirements
 */

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { argon2id, argon2Verify } from 'hash-wasm';

/**
 * Security tier levels
 */
export type SecurityTierLevel = 
  | 'basic'
  | 'standard'
  | 'pro'
  | 'enterprise'
  | 'healthcare'
  | 'sovereign';

/**
 * Password hashing algorithms
 */
export type PasswordHashAlgorithm = 'bcrypt' | 'scrypt' | 'argon2id';

/**
 * JWT signing algorithms
 */
export type JWTAlgorithm = 'HS256' | 'RS256' | 'ES256' | 'EdDSA';

/**
 * KMS configuration types
 */
export type KMSConfigType = 
  | 'shared'           // Basic/Standard - shared KMS key
  | 'dedicated'        // Pro - dedicated KMS key per customer
  | 'customer_managed' // Enterprise - customer provides their own KMS
  | 'hipaa_compliant'  // Healthcare - HIPAA-compliant KMS with audit
  | 'fips_140_3';      // Sovereign - FIPS 140-3 Level 3 HSM

/**
 * MFA requirement levels
 */
export type MFARequirement = 
  | 'disabled'
  | 'optional'
  | 'recommended'
  | 'required'
  | 'webauthn_only';   // Phishing-resistant only

/**
 * Password hashing configuration
 */
export interface PasswordHashConfig {
  algorithm: PasswordHashAlgorithm;
  // bcrypt config
  bcryptRounds?: number;
  // scrypt config
  scryptN?: number;
  scryptR?: number;
  scryptP?: number;
  // argon2id config
  argon2Memory?: number;
  argon2TimeCost?: number;
  argon2Parallelism?: number;
}

/**
 * Session configuration
 */
export interface SessionConfig {
  accessTokenExpiry: number;    // seconds
  refreshTokenExpiry: number;   // seconds
  idleTimeout: number;          // seconds
  absoluteTimeout: number;      // seconds
  maxConcurrentSessions: number;
  deviceTrustEnabled: boolean;
  geoVelocityCheck: boolean;
}

/**
 * Complete security tier configuration
 */
export interface SecurityTierConfig {
  tier: SecurityTierLevel;
  displayName: string;
  description: string;
  
  // Password hashing
  passwordHash: PasswordHashConfig;
  
  // JWT configuration
  jwtAlgorithm: JWTAlgorithm;
  jwtKeyRotationDays: number;
  
  // KMS configuration
  kmsType: KMSConfigType;
  
  // Session configuration
  session: SessionConfig;
  
  // MFA configuration
  mfaRequirement: MFARequirement;
  mfaGracePeriodDays: number;
  
  // Additional security features
  features: {
    auditLogging: boolean;
    auditRetentionDays: number;
    ipWhitelisting: boolean;
    rateLimit: {
      login: number;      // per 15 min
      register: number;   // per hour
      api: number;        // per minute
    };
    credentialStuffingDetection: boolean;
    impossibleTravelDetection: boolean;
    breachedPasswordCheck: boolean;
    passwordHistory: number;  // number of previous passwords to check
  };
  
  // Compliance
  compliance: {
    hipaa: boolean;
    gdpr: boolean;
    soc2: boolean;
    pciDss: boolean;
    fips: boolean;
  };
}

/**
 * Default tier configurations
 */
export const SECURITY_TIERS: Record<SecurityTierLevel, SecurityTierConfig> = {
  basic: {
    tier: 'basic',
    displayName: 'Basic',
    description: 'For startups and low-security applications',
    passwordHash: {
      algorithm: 'bcrypt',
      bcryptRounds: 10
    },
    jwtAlgorithm: 'HS256',
    jwtKeyRotationDays: 90,
    kmsType: 'shared',
    session: {
      accessTokenExpiry: 30 * 60,        // 30 minutes
      refreshTokenExpiry: 30 * 24 * 3600, // 30 days
      idleTimeout: 60 * 60,              // 1 hour
      absoluteTimeout: 24 * 3600,        // 24 hours
      maxConcurrentSessions: 10,
      deviceTrustEnabled: false,
      geoVelocityCheck: false
    },
    mfaRequirement: 'optional',
    mfaGracePeriodDays: 30,
    features: {
      auditLogging: false,
      auditRetentionDays: 30,
      ipWhitelisting: false,
      rateLimit: {
        login: 10,
        register: 5,
        api: 200
      },
      credentialStuffingDetection: false,
      impossibleTravelDetection: false,
      breachedPasswordCheck: false,
      passwordHistory: 0
    },
    compliance: {
      hipaa: false,
      gdpr: false,
      soc2: false,
      pciDss: false,
      fips: false
    }
  },
  
  standard: {
    tier: 'standard',
    displayName: 'Standard',
    description: 'For most SaaS applications',
    passwordHash: {
      algorithm: 'bcrypt',
      bcryptRounds: 12
    },
    jwtAlgorithm: 'RS256',
    jwtKeyRotationDays: 60,
    kmsType: 'shared',
    session: {
      accessTokenExpiry: 15 * 60,        // 15 minutes
      refreshTokenExpiry: 7 * 24 * 3600, // 7 days
      idleTimeout: 30 * 60,              // 30 minutes
      absoluteTimeout: 12 * 3600,        // 12 hours
      maxConcurrentSessions: 5,
      deviceTrustEnabled: true,
      geoVelocityCheck: false
    },
    mfaRequirement: 'recommended',
    mfaGracePeriodDays: 14,
    features: {
      auditLogging: true,
      auditRetentionDays: 90,
      ipWhitelisting: false,
      rateLimit: {
        login: 5,
        register: 3,
        api: 100
      },
      credentialStuffingDetection: true,
      impossibleTravelDetection: false,
      breachedPasswordCheck: true,
      passwordHistory: 3
    },
    compliance: {
      hipaa: false,
      gdpr: true,
      soc2: false,
      pciDss: false,
      fips: false
    }
  },
  
  pro: {
    tier: 'pro',
    displayName: 'Pro',
    description: 'For financial services and e-commerce',
    passwordHash: {
      algorithm: 'argon2id',
      argon2Memory: 32768,    // 32 MB
      argon2TimeCost: 4,
      argon2Parallelism: 2
    },
    jwtAlgorithm: 'RS256',
    jwtKeyRotationDays: 30,
    kmsType: 'dedicated',
    session: {
      accessTokenExpiry: 15 * 60,        // 15 minutes
      refreshTokenExpiry: 7 * 24 * 3600, // 7 days
      idleTimeout: 30 * 60,              // 30 minutes
      absoluteTimeout: 8 * 3600,         // 8 hours
      maxConcurrentSessions: 3,
      deviceTrustEnabled: true,
      geoVelocityCheck: true
    },
    mfaRequirement: 'required',
    mfaGracePeriodDays: 7,
    features: {
      auditLogging: true,
      auditRetentionDays: 365,
      ipWhitelisting: true,
      rateLimit: {
        login: 5,
        register: 3,
        api: 100
      },
      credentialStuffingDetection: true,
      impossibleTravelDetection: true,
      breachedPasswordCheck: true,
      passwordHistory: 5
    },
    compliance: {
      hipaa: false,
      gdpr: true,
      soc2: true,
      pciDss: true,
      fips: false
    }
  },
  
  enterprise: {
    tier: 'enterprise',
    displayName: 'Enterprise',
    description: 'For large organizations with custom requirements',
    passwordHash: {
      algorithm: 'argon2id',
      argon2Memory: 65536,    // 64 MB
      argon2TimeCost: 5,
      argon2Parallelism: 4
    },
    jwtAlgorithm: 'ES256',
    jwtKeyRotationDays: 30,
    kmsType: 'customer_managed',
    session: {
      accessTokenExpiry: 10 * 60,        // 10 minutes
      refreshTokenExpiry: 24 * 3600,     // 24 hours
      idleTimeout: 15 * 60,              // 15 minutes
      absoluteTimeout: 8 * 3600,         // 8 hours
      maxConcurrentSessions: 3,
      deviceTrustEnabled: true,
      geoVelocityCheck: true
    },
    mfaRequirement: 'required',
    mfaGracePeriodDays: 3,
    features: {
      auditLogging: true,
      auditRetentionDays: 730,  // 2 years
      ipWhitelisting: true,
      rateLimit: {
        login: 3,
        register: 2,
        api: 50
      },
      credentialStuffingDetection: true,
      impossibleTravelDetection: true,
      breachedPasswordCheck: true,
      passwordHistory: 10
    },
    compliance: {
      hipaa: false,
      gdpr: true,
      soc2: true,
      pciDss: true,
      fips: false
    }
  },
  
  healthcare: {
    tier: 'healthcare',
    displayName: 'Healthcare',
    description: 'HIPAA-compliant for healthcare applications (Clinisyn)',
    passwordHash: {
      algorithm: 'argon2id',
      argon2Memory: 32768,    // 32 MB (Lambda-optimized)
      argon2TimeCost: 5,
      argon2Parallelism: 2
    },
    jwtAlgorithm: 'RS256',    // FIPS-compliant
    jwtKeyRotationDays: 30,
    kmsType: 'hipaa_compliant',
    session: {
      accessTokenExpiry: 15 * 60,        // 15 minutes
      refreshTokenExpiry: 7 * 24 * 3600, // 7 days
      idleTimeout: 30 * 60,              // 30 minutes (HIPAA requirement)
      absoluteTimeout: 8 * 3600,         // 8 hours (shift-based)
      maxConcurrentSessions: 2,
      deviceTrustEnabled: true,
      geoVelocityCheck: true
    },
    mfaRequirement: 'webauthn_only',  // Phishing-resistant required
    mfaGracePeriodDays: 0,            // No grace period for healthcare
    features: {
      auditLogging: true,
      auditRetentionDays: 2190,  // 6 years (HIPAA requirement)
      ipWhitelisting: true,
      rateLimit: {
        login: 5,
        register: 3,
        api: 100
      },
      credentialStuffingDetection: true,
      impossibleTravelDetection: true,
      breachedPasswordCheck: true,
      passwordHistory: 12
    },
    compliance: {
      hipaa: true,
      gdpr: true,
      soc2: true,
      pciDss: false,
      fips: true
    }
  },
  
  sovereign: {
    tier: 'sovereign',
    displayName: 'Sovereign',
    description: 'For government and defense applications',
    passwordHash: {
      algorithm: 'argon2id',
      argon2Memory: 131072,   // 128 MB
      argon2TimeCost: 6,
      argon2Parallelism: 4
    },
    jwtAlgorithm: 'EdDSA',    // Ed25519 - quantum-resistant preparation
    jwtKeyRotationDays: 14,
    kmsType: 'fips_140_3',
    session: {
      accessTokenExpiry: 5 * 60,         // 5 minutes
      refreshTokenExpiry: 8 * 3600,      // 8 hours
      idleTimeout: 10 * 60,              // 10 minutes
      absoluteTimeout: 8 * 3600,         // 8 hours
      maxConcurrentSessions: 1,
      deviceTrustEnabled: true,
      geoVelocityCheck: true
    },
    mfaRequirement: 'webauthn_only',
    mfaGracePeriodDays: 0,
    features: {
      auditLogging: true,
      auditRetentionDays: 2555,  // 7 years
      ipWhitelisting: true,
      rateLimit: {
        login: 3,
        register: 1,
        api: 30
      },
      credentialStuffingDetection: true,
      impossibleTravelDetection: true,
      breachedPasswordCheck: true,
      passwordHistory: 24
    },
    compliance: {
      hipaa: true,
      gdpr: true,
      soc2: true,
      pciDss: true,
      fips: true
    }
  }
};


/**
 * Get security tier configuration
 */
export function getSecurityTier(tier: SecurityTierLevel): SecurityTierConfig {
  const config = SECURITY_TIERS[tier];
  if (!config) {
    throw new Error(`Unknown security tier: ${tier}`);
  }
  return config;
}

/**
 * Get all available security tiers
 */
export function getAllSecurityTiers(): SecurityTierConfig[] {
  return Object.values(SECURITY_TIERS);
}

/**
 * Check if a tier meets compliance requirements
 */
export function checkTierCompliance(
  tier: SecurityTierLevel,
  requirements: Partial<SecurityTierConfig['compliance']>
): { compliant: boolean; missing: string[] } {
  const config = getSecurityTier(tier);
  const missing: string[] = [];
  
  if (requirements.hipaa && !config.compliance.hipaa) {
    missing.push('HIPAA');
  }
  if (requirements.gdpr && !config.compliance.gdpr) {
    missing.push('GDPR');
  }
  if (requirements.soc2 && !config.compliance.soc2) {
    missing.push('SOC 2');
  }
  if (requirements.pciDss && !config.compliance.pciDss) {
    missing.push('PCI DSS');
  }
  if (requirements.fips && !config.compliance.fips) {
    missing.push('FIPS');
  }
  
  return {
    compliant: missing.length === 0,
    missing
  };
}

/**
 * Recommend a security tier based on requirements
 */
export function recommendSecurityTier(requirements: {
  hipaa?: boolean;
  gdpr?: boolean;
  soc2?: boolean;
  pciDss?: boolean;
  fips?: boolean;
  mfaRequired?: boolean;
  webauthnOnly?: boolean;
  maxUsers?: number;
}): SecurityTierLevel {
  // Sovereign for FIPS or government requirements
  if (requirements.fips) {
    return 'sovereign';
  }
  
  // Healthcare for HIPAA
  if (requirements.hipaa) {
    return 'healthcare';
  }
  
  // Enterprise for large organizations or customer-managed KMS needs
  if (requirements.maxUsers && requirements.maxUsers > 10000) {
    return 'enterprise';
  }
  
  // Pro for PCI DSS or SOC 2
  if (requirements.pciDss || requirements.soc2) {
    return 'pro';
  }
  
  // Standard for GDPR or MFA required
  if (requirements.gdpr || requirements.mfaRequired) {
    return 'standard';
  }
  
  // Basic for everything else
  return 'basic';
}

/**
 * Hash password using tier-specific algorithm
 */
export async function hashPasswordWithTier(
  password: string,
  tier: SecurityTierLevel
): Promise<{ hash: string; algorithm: PasswordHashAlgorithm }> {
  const config = getSecurityTier(tier);
  const { passwordHash } = config;
  
  switch (passwordHash.algorithm) {
    case 'bcrypt': {
      const salt = await bcrypt.genSalt(passwordHash.bcryptRounds || 12);
      const hash = await bcrypt.hash(password, salt);
      return { hash, algorithm: 'bcrypt' };
    }
    
    case 'scrypt': {
      const salt = crypto.randomBytes(32);
      const hash = await new Promise<string>((resolve, reject) => {
        crypto.scrypt(
          password,
          salt,
          64,
          {
            N: passwordHash.scryptN || 16384,
            r: passwordHash.scryptR || 8,
            p: passwordHash.scryptP || 1
          },
          (err, derivedKey) => {
            if (err) reject(err);
            else {
              // Format: $scrypt$N$r$p$salt$hash
              const params = `${passwordHash.scryptN || 16384}$${passwordHash.scryptR || 8}$${passwordHash.scryptP || 1}`;
              resolve(`$scrypt$${params}$${salt.toString('base64')}$${derivedKey.toString('base64')}`);
            }
          }
        );
      });
      return { hash, algorithm: 'scrypt' };
    }
    
    case 'argon2id': {
      const salt = crypto.randomBytes(16);
      const hash = await argon2id({
        password,
        salt,
        parallelism: passwordHash.argon2Parallelism || 2,
        iterations: passwordHash.argon2TimeCost || 5,
        memorySize: passwordHash.argon2Memory || 32768,
        hashLength: 32,
        outputType: 'encoded'
      });
      return { hash, algorithm: 'argon2id' };
    }
    
    default:
      throw new Error(`Unknown password hash algorithm: ${passwordHash.algorithm}`);
  }
}

/**
 * Verify password against hash (auto-detects algorithm)
 */
export async function verifyPasswordWithTier(
  password: string,
  hash: string
): Promise<boolean> {
  // Detect algorithm from hash format
  if (hash.startsWith('$argon2')) {
    return argon2Verify({ password, hash });
  }
  
  if (hash.startsWith('$scrypt$')) {
    // Parse scrypt hash: $scrypt$N$r$p$salt$hash
    const parts = hash.split('$');
    if (parts.length !== 7) return false;
    
    const N = parseInt(parts[2], 10);
    const r = parseInt(parts[3], 10);
    const p = parseInt(parts[4], 10);
    const salt = Buffer.from(parts[5], 'base64');
    const storedHash = Buffer.from(parts[6], 'base64');
    
    return new Promise<boolean>((resolve, reject) => {
      crypto.scrypt(password, salt, 64, { N, r, p }, (err, derivedKey) => {
        if (err) reject(err);
        else resolve(crypto.timingSafeEqual(derivedKey, storedHash));
      });
    });
  }
  
  // bcrypt (starts with $2a$, $2b$, or $2y$)
  if (hash.startsWith('$2')) {
    return bcrypt.compare(password, hash);
  }
  
  throw new Error('Unknown hash format');
}

/**
 * Check if password needs rehashing on tier upgrade
 */
export function needsRehashForTier(
  currentHash: string,
  targetTier: SecurityTierLevel
): boolean {
  const config = getSecurityTier(targetTier);
  const targetAlgorithm = config.passwordHash.algorithm;
  
  // Detect current algorithm
  let currentAlgorithm: PasswordHashAlgorithm;
  if (currentHash.startsWith('$argon2')) {
    currentAlgorithm = 'argon2id';
  } else if (currentHash.startsWith('$scrypt$')) {
    currentAlgorithm = 'scrypt';
  } else if (currentHash.startsWith('$2')) {
    currentAlgorithm = 'bcrypt';
  } else {
    return true; // Unknown format, needs rehash
  }
  
  // If algorithm is different, needs rehash
  if (currentAlgorithm !== targetAlgorithm) {
    return true;
  }
  
  // Check if parameters need upgrade (for argon2id)
  if (targetAlgorithm === 'argon2id' && currentHash.startsWith('$argon2')) {
    // Parse current argon2 parameters
    const match = currentHash.match(/\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)/);
    if (match) {
      const currentMemory = parseInt(match[1], 10);
      const currentTime = parseInt(match[2], 10);
      const currentParallelism = parseInt(match[3], 10);
      
      const targetMemory = config.passwordHash.argon2Memory || 32768;
      const targetTime = config.passwordHash.argon2TimeCost || 5;
      const targetParallelism = config.passwordHash.argon2Parallelism || 2;
      
      // Needs rehash if target parameters are stronger
      if (targetMemory > currentMemory || 
          targetTime > currentTime || 
          targetParallelism > currentParallelism) {
        return true;
      }
    }
  }
  
  // Check bcrypt rounds
  if (targetAlgorithm === 'bcrypt' && currentHash.startsWith('$2')) {
    const match = currentHash.match(/\$2[aby]\$(\d+)\$/);
    if (match) {
      const currentRounds = parseInt(match[1], 10);
      const targetRounds = config.passwordHash.bcryptRounds || 12;
      if (targetRounds > currentRounds) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Get tier-specific rate limits
 */
export function getTierRateLimits(tier: SecurityTierLevel): {
  login: { limit: number; windowMs: number };
  register: { limit: number; windowMs: number };
  api: { limit: number; windowMs: number };
} {
  const config = getSecurityTier(tier);
  
  return {
    login: {
      limit: config.features.rateLimit.login,
      windowMs: 15 * 60 * 1000  // 15 minutes
    },
    register: {
      limit: config.features.rateLimit.register,
      windowMs: 60 * 60 * 1000  // 1 hour
    },
    api: {
      limit: config.features.rateLimit.api,
      windowMs: 60 * 1000  // 1 minute
    }
  };
}

/**
 * Get tier-specific session configuration
 */
export function getTierSessionConfig(tier: SecurityTierLevel): SessionConfig {
  const config = getSecurityTier(tier);
  return config.session;
}

/**
 * Check if MFA is required for tier
 */
export function isMFARequiredForTier(tier: SecurityTierLevel): boolean {
  const config = getSecurityTier(tier);
  return config.mfaRequirement === 'required' || 
         config.mfaRequirement === 'webauthn_only';
}

/**
 * Check if WebAuthn is required for tier
 */
export function isWebAuthnRequiredForTier(tier: SecurityTierLevel): boolean {
  const config = getSecurityTier(tier);
  return config.mfaRequirement === 'webauthn_only';
}

/**
 * Get audit retention days for tier
 */
export function getAuditRetentionDays(tier: SecurityTierLevel): number {
  const config = getSecurityTier(tier);
  return config.features.auditRetentionDays;
}

/**
 * Compare two tiers (returns -1, 0, or 1)
 */
export function compareTiers(a: SecurityTierLevel, b: SecurityTierLevel): number {
  const order: SecurityTierLevel[] = [
    'basic', 'standard', 'pro', 'enterprise', 'healthcare', 'sovereign'
  ];
  return order.indexOf(a) - order.indexOf(b);
}

/**
 * Check if tier upgrade is valid
 */
export function isValidTierUpgrade(
  currentTier: SecurityTierLevel,
  targetTier: SecurityTierLevel
): boolean {
  return compareTiers(targetTier, currentTier) > 0;
}

/**
 * Get tier display info for UI
 */
export function getTierDisplayInfo(tier: SecurityTierLevel): {
  name: string;
  description: string;
  features: string[];
  compliance: string[];
} {
  const config = getSecurityTier(tier);
  
  const features: string[] = [];
  if (config.features.auditLogging) features.push('Audit Logging');
  if (config.features.ipWhitelisting) features.push('IP Whitelisting');
  if (config.features.credentialStuffingDetection) features.push('Credential Stuffing Detection');
  if (config.features.impossibleTravelDetection) features.push('Impossible Travel Detection');
  if (config.features.breachedPasswordCheck) features.push('Breached Password Check');
  if (config.session.deviceTrustEnabled) features.push('Device Trust');
  if (config.session.geoVelocityCheck) features.push('Geo-Velocity Check');
  
  const compliance: string[] = [];
  if (config.compliance.hipaa) compliance.push('HIPAA');
  if (config.compliance.gdpr) compliance.push('GDPR');
  if (config.compliance.soc2) compliance.push('SOC 2');
  if (config.compliance.pciDss) compliance.push('PCI DSS');
  if (config.compliance.fips) compliance.push('FIPS');
  
  return {
    name: config.displayName,
    description: config.description,
    features,
    compliance
  };
}
