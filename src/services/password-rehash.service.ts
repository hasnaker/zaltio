/**
 * Password Rehashing Service for Zalt.io
 * 
 * Handles automatic password rehashing when:
 * - Customer upgrades to a higher security tier
 * - Password hash algorithm parameters are strengthened
 * - Compliance requirements change (e.g., HIPAA)
 * 
 * Rehashing occurs transparently during login:
 * 1. User logs in with correct password
 * 2. System detects hash needs upgrade
 * 3. Password is rehashed with new algorithm
 * 4. New hash is stored
 * 5. User continues without interruption
 * 
 * Security Requirements:
 * - Rehashing only happens after successful password verification
 * - Old hash is immediately replaced (no dual storage)
 * - Audit log records the rehash event
 * - Backward compatibility maintained during migration
 */

import {
  SecurityTierLevel,
  hashPasswordWithTier,
  verifyPasswordWithTier,
  needsRehashForTier,
  getSecurityTier,
  PasswordHashAlgorithm
} from './security-tier.service';

/**
 * Password rehash result
 */
export interface RehashResult {
  rehashed: boolean;
  newHash?: string;
  oldAlgorithm?: PasswordHashAlgorithm;
  newAlgorithm?: PasswordHashAlgorithm;
  reason?: string;
}

/**
 * Password verification with automatic rehashing
 */
export interface VerifyAndRehashResult {
  valid: boolean;
  rehashResult?: RehashResult;
}

/**
 * Rehash statistics for a realm
 */
export interface RehashStats {
  totalUsers: number;
  usersNeedingRehash: number;
  usersRehashed: number;
  percentComplete: number;
}

/**
 * Detect the algorithm used for a password hash
 */
export function detectHashAlgorithm(hash: string): PasswordHashAlgorithm | null {
  if (hash.startsWith('$argon2')) {
    return 'argon2id';
  }
  if (hash.startsWith('$scrypt$')) {
    return 'scrypt';
  }
  if (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$')) {
    return 'bcrypt';
  }
  return null;
}

/**
 * Get hash parameters from an Argon2 hash
 */
export function getArgon2Params(hash: string): {
  memory: number;
  timeCost: number;
  parallelism: number;
} | null {
  const match = hash.match(/\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)/);
  if (!match) return null;
  
  return {
    memory: parseInt(match[1], 10),
    timeCost: parseInt(match[2], 10),
    parallelism: parseInt(match[3], 10)
  };
}

/**
 * Get bcrypt rounds from a hash
 */
export function getBcryptRounds(hash: string): number | null {
  const match = hash.match(/\$2[aby]\$(\d+)\$/);
  if (!match) return null;
  return parseInt(match[1], 10);
}

/**
 * Check if password hash meets tier requirements
 */
export function hashMeetsTierRequirements(
  hash: string,
  tier: SecurityTierLevel
): { meets: boolean; reason?: string } {
  const config = getSecurityTier(tier);
  const currentAlgorithm = detectHashAlgorithm(hash);
  
  if (!currentAlgorithm) {
    return { meets: false, reason: 'Unknown hash algorithm' };
  }
  
  const targetAlgorithm = config.passwordHash.algorithm;
  
  // Check algorithm match
  if (currentAlgorithm !== targetAlgorithm) {
    return {
      meets: false,
      reason: `Algorithm mismatch: ${currentAlgorithm} → ${targetAlgorithm}`
    };
  }
  
  // Check algorithm-specific parameters
  if (targetAlgorithm === 'argon2id') {
    const params = getArgon2Params(hash);
    if (!params) {
      return { meets: false, reason: 'Cannot parse Argon2 parameters' };
    }
    
    const targetMemory = config.passwordHash.argon2Memory || 32768;
    const targetTime = config.passwordHash.argon2TimeCost || 5;
    const targetParallelism = config.passwordHash.argon2Parallelism || 2;
    
    if (params.memory < targetMemory) {
      return {
        meets: false,
        reason: `Argon2 memory too low: ${params.memory} < ${targetMemory}`
      };
    }
    if (params.timeCost < targetTime) {
      return {
        meets: false,
        reason: `Argon2 time cost too low: ${params.timeCost} < ${targetTime}`
      };
    }
    if (params.parallelism < targetParallelism) {
      return {
        meets: false,
        reason: `Argon2 parallelism too low: ${params.parallelism} < ${targetParallelism}`
      };
    }
  }
  
  if (targetAlgorithm === 'bcrypt') {
    const rounds = getBcryptRounds(hash);
    if (!rounds) {
      return { meets: false, reason: 'Cannot parse bcrypt rounds' };
    }
    
    const targetRounds = config.passwordHash.bcryptRounds || 12;
    if (rounds < targetRounds) {
      return {
        meets: false,
        reason: `bcrypt rounds too low: ${rounds} < ${targetRounds}`
      };
    }
  }
  
  return { meets: true };
}

/**
 * Verify password and rehash if needed
 * This is the main function to use during login
 */
export async function verifyAndRehashIfNeeded(
  password: string,
  currentHash: string,
  targetTier: SecurityTierLevel
): Promise<VerifyAndRehashResult> {
  // First, verify the password
  const isValid = await verifyPasswordWithTier(password, currentHash);
  
  if (!isValid) {
    return { valid: false };
  }
  
  // Check if rehash is needed
  const needsRehash = needsRehashForTier(currentHash, targetTier);
  
  if (!needsRehash) {
    return { valid: true };
  }
  
  // Rehash the password
  const oldAlgorithm = detectHashAlgorithm(currentHash);
  const { hash: newHash, algorithm: newAlgorithm } = await hashPasswordWithTier(password, targetTier);
  
  const requirements = hashMeetsTierRequirements(currentHash, targetTier);
  
  return {
    valid: true,
    rehashResult: {
      rehashed: true,
      newHash,
      oldAlgorithm: oldAlgorithm || undefined,
      newAlgorithm,
      reason: requirements.reason
    }
  };
}

/**
 * Force rehash a password (for admin operations)
 * Use with caution - requires the plaintext password
 */
export async function forceRehash(
  password: string,
  currentHash: string,
  targetTier: SecurityTierLevel
): Promise<RehashResult> {
  // Verify password first
  const isValid = await verifyPasswordWithTier(password, currentHash);
  
  if (!isValid) {
    throw new Error('Invalid password - cannot rehash');
  }
  
  const oldAlgorithm = detectHashAlgorithm(currentHash);
  const { hash: newHash, algorithm: newAlgorithm } = await hashPasswordWithTier(password, targetTier);
  
  return {
    rehashed: true,
    newHash,
    oldAlgorithm: oldAlgorithm || undefined,
    newAlgorithm,
    reason: 'Forced rehash'
  };
}

/**
 * Check how many users in a realm need password rehashing
 */
export function calculateRehashStats(
  userHashes: string[],
  targetTier: SecurityTierLevel
): RehashStats {
  const totalUsers = userHashes.length;
  let usersNeedingRehash = 0;
  
  for (const hash of userHashes) {
    if (needsRehashForTier(hash, targetTier)) {
      usersNeedingRehash++;
    }
  }
  
  const usersRehashed = totalUsers - usersNeedingRehash;
  const percentComplete = totalUsers > 0 
    ? Math.round((usersRehashed / totalUsers) * 100) 
    : 100;
  
  return {
    totalUsers,
    usersNeedingRehash,
    usersRehashed,
    percentComplete
  };
}

/**
 * Get recommended tier for a hash based on its strength
 */
export function getRecommendedTierForHash(hash: string): SecurityTierLevel {
  const algorithm = detectHashAlgorithm(hash);
  
  if (!algorithm) {
    return 'basic'; // Unknown hash, recommend basic
  }
  
  if (algorithm === 'argon2id') {
    const params = getArgon2Params(hash);
    if (params) {
      // High memory = higher tier
      if (params.memory >= 131072) return 'sovereign';
      if (params.memory >= 65536) return 'enterprise';
      if (params.memory >= 32768) return 'healthcare';
    }
    return 'pro';
  }
  
  if (algorithm === 'bcrypt') {
    const rounds = getBcryptRounds(hash);
    if (rounds) {
      if (rounds >= 12) return 'standard';
    }
    return 'basic';
  }
  
  return 'basic';
}

/**
 * Estimate rehash time for a batch of users
 */
export function estimateRehashTime(
  userCount: number,
  targetTier: SecurityTierLevel
): {
  estimatedSeconds: number;
  estimatedMinutes: number;
  recommendation: string;
} {
  const config = getSecurityTier(targetTier);
  
  // Estimate time per hash based on algorithm
  let msPerHash: number;
  switch (config.passwordHash.algorithm) {
    case 'argon2id':
      // Argon2 time depends on memory and iterations
      const memory = config.passwordHash.argon2Memory || 32768;
      const timeCost = config.passwordHash.argon2TimeCost || 5;
      msPerHash = (memory / 32768) * timeCost * 100; // Rough estimate
      break;
    case 'scrypt':
      msPerHash = 200;
      break;
    case 'bcrypt':
      const rounds = config.passwordHash.bcryptRounds || 12;
      msPerHash = Math.pow(2, rounds - 10) * 100; // Exponential with rounds
      break;
    default:
      msPerHash = 100;
  }
  
  const totalMs = userCount * msPerHash;
  const estimatedSeconds = Math.ceil(totalMs / 1000);
  const estimatedMinutes = Math.ceil(estimatedSeconds / 60);
  
  let recommendation: string;
  if (estimatedMinutes < 5) {
    recommendation = 'Can be done during maintenance window';
  } else if (estimatedMinutes < 30) {
    recommendation = 'Schedule during low-traffic period';
  } else if (estimatedMinutes < 120) {
    recommendation = 'Use background job with progress tracking';
  } else {
    recommendation = 'Use gradual migration during login';
  }
  
  return {
    estimatedSeconds,
    estimatedMinutes,
    recommendation
  };
}

/**
 * Create audit log entry for password rehash
 */
export function createRehashAuditEntry(
  userId: string,
  realmId: string,
  result: RehashResult
): {
  event: string;
  userId: string;
  realmId: string;
  details: Record<string, unknown>;
  timestamp: string;
} {
  return {
    event: 'password_rehash',
    userId,
    realmId,
    details: {
      rehashed: result.rehashed,
      oldAlgorithm: result.oldAlgorithm,
      newAlgorithm: result.newAlgorithm,
      reason: result.reason
    },
    timestamp: new Date().toISOString()
  };
}

/**
 * Validate tier upgrade is safe for password migration
 */
export function validateTierUpgradeForPasswords(
  currentTier: SecurityTierLevel,
  targetTier: SecurityTierLevel
): {
  safe: boolean;
  warnings: string[];
  recommendations: string[];
} {
  const currentConfig = getSecurityTier(currentTier);
  const targetConfig = getSecurityTier(targetTier);
  
  const warnings: string[] = [];
  const recommendations: string[] = [];
  
  // Check algorithm change
  if (currentConfig.passwordHash.algorithm !== targetConfig.passwordHash.algorithm) {
    warnings.push(
      `Algorithm change: ${currentConfig.passwordHash.algorithm} → ${targetConfig.passwordHash.algorithm}`
    );
    recommendations.push('Users will be rehashed on next login');
  }
  
  // Check if downgrade
  const algorithmStrength: Record<PasswordHashAlgorithm, number> = {
    bcrypt: 1,
    scrypt: 2,
    argon2id: 3
  };
  
  const currentStrength = algorithmStrength[currentConfig.passwordHash.algorithm];
  const targetStrength = algorithmStrength[targetConfig.passwordHash.algorithm];
  
  if (targetStrength < currentStrength) {
    warnings.push('WARNING: Downgrading password algorithm strength');
    recommendations.push('Consider keeping current algorithm for existing users');
  }
  
  // Check compliance implications
  if (currentConfig.compliance.hipaa && !targetConfig.compliance.hipaa) {
    warnings.push('WARNING: Losing HIPAA compliance');
  }
  
  if (currentConfig.compliance.fips && !targetConfig.compliance.fips) {
    warnings.push('WARNING: Losing FIPS compliance');
  }
  
  return {
    safe: warnings.filter(w => w.startsWith('WARNING')).length === 0,
    warnings,
    recommendations
  };
}
