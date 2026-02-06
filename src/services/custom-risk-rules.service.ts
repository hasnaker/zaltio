/**
 * Custom Risk Rules Service for Zalt.io Auth Platform
 * Phase 6: AI Security - Task 15.5
 * 
 * SECURITY FEATURES:
 * - IP whitelist that bypasses risk assessment
 * - Trusted device list that reduces risk score
 * - Custom thresholds per realm (override default 70/90)
 * 
 * COMPLIANCE:
 * - HIPAA: All rule applications are audit logged
 * - GDPR: No PII stored in rules
 * 
 * Validates: Requirement 10.8
 */

import { 
  CustomRiskRules, 
  TrustedDevice, 
  RiskThresholds,
  DEFAULT_CUSTOM_RISK_RULES 
} from '../models/realm.model';
import { logSimpleSecurityEvent } from './security-logger.service';
import { RiskAssessmentResult, RISK_THRESHOLDS, ADAPTIVE_AUTH_THRESHOLDS } from './ai-risk.service';

// ============================================================================
// Types
// ============================================================================

/**
 * Result of applying custom risk rules
 */
export interface CustomRiskRuleResult {
  /** Whether any custom rule was applied */
  ruleApplied: boolean;
  
  /** Type of rule that was applied */
  ruleType?: 'ip_whitelist' | 'trusted_device' | 'custom_threshold';
  
  /** Original risk score before rule application */
  originalScore: number;
  
  /** Adjusted risk score after rule application */
  adjustedScore: number;
  
  /** Score reduction applied */
  scoreReduction: number;
  
  /** Whether risk assessment was bypassed entirely */
  bypassed: boolean;
  
  /** Details about the rule application */
  details: string;
  
  /** Custom thresholds to use (if any) */
  customThresholds?: RiskThresholds;
}

/**
 * IP whitelist check result
 */
export interface IPWhitelistResult {
  /** Whether IP is whitelisted */
  whitelisted: boolean;
  
  /** Matching whitelist entry (if any) */
  matchedEntry?: string;
  
  /** Score reduction to apply */
  scoreReduction: number;
  
  /** Whether to bypass risk assessment entirely */
  bypass: boolean;
}

/**
 * Trusted device check result
 */
export interface TrustedDeviceResult {
  /** Whether device is trusted */
  trusted: boolean;
  
  /** Matching device entry (if any) */
  matchedDevice?: TrustedDevice;
  
  /** Score reduction to apply */
  scoreReduction: number;
}

// ============================================================================
// IP Whitelist Functions
// ============================================================================

/**
 * Check if an IP address is in the whitelist
 * Supports IPv4, IPv6, and CIDR notation
 * 
 * @param ip - IP address to check
 * @param whitelist - List of whitelisted IPs/CIDRs
 * @returns Whether IP is whitelisted
 */
export function isIPWhitelisted(ip: string, whitelist: string[]): boolean {
  if (!ip || !whitelist || whitelist.length === 0) {
    return false;
  }

  for (const entry of whitelist) {
    if (matchIPEntry(ip, entry)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if IP matches a whitelist entry
 * Supports exact match and CIDR notation
 */
function matchIPEntry(ip: string, entry: string): boolean {
  // Normalize both IP and entry
  const normalizedIP = normalizeIP(ip);
  const normalizedEntry = normalizeIP(entry.split('/')[0]);

  // Exact match
  if (normalizedIP === normalizedEntry && !entry.includes('/')) {
    return true;
  }

  // CIDR match
  if (entry.includes('/')) {
    return isIPInCIDR(ip, entry);
  }

  return false;
}

/**
 * Normalize IP address (handle IPv4-mapped IPv6)
 */
function normalizeIP(ip: string): string {
  if (!ip) return '';
  
  // Handle IPv4-mapped IPv6 addresses (::ffff:192.168.1.1)
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7);
  }
  
  return ip.toLowerCase().trim();
}

/**
 * Check if IP is within a CIDR range
 */
function isIPInCIDR(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);

    if (isNaN(mask)) return false;

    // IPv4 check
    if (ip.includes('.') && range.includes('.')) {
      return isIPv4InCIDR(ip, range, mask);
    }

    // IPv6 check
    if (ip.includes(':') && range.includes(':')) {
      return isIPv6InCIDR(ip, range, mask);
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Check if IPv4 is within CIDR range
 */
function isIPv4InCIDR(ip: string, range: string, mask: number): boolean {
  if (mask < 0 || mask > 32) return false;

  const ipNum = ipv4ToNumber(ip);
  const rangeNum = ipv4ToNumber(range);

  if (ipNum === null || rangeNum === null) return false;

  const maskNum = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  return (ipNum & maskNum) === (rangeNum & maskNum);
}

/**
 * Convert IPv4 to number
 */
function ipv4ToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let num = 0;
  for (const part of parts) {
    const octet = parseInt(part, 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    num = (num << 8) + octet;
  }

  return num >>> 0; // Convert to unsigned
}

/**
 * Check if IPv6 is within CIDR range (simplified)
 */
function isIPv6InCIDR(ip: string, range: string, mask: number): boolean {
  if (mask < 0 || mask > 128) return false;

  // Expand both addresses to full form
  const ipExpanded = expandIPv6(ip);
  const rangeExpanded = expandIPv6(range);

  if (!ipExpanded || !rangeExpanded) return false;

  // Compare bit by bit up to mask
  const ipBits = ipv6ToBits(ipExpanded);
  const rangeBits = ipv6ToBits(rangeExpanded);

  return ipBits.substring(0, mask) === rangeBits.substring(0, mask);
}

/**
 * Expand IPv6 address to full form
 */
function expandIPv6(ip: string): string | null {
  try {
    // Handle :: expansion
    if (ip.includes('::')) {
      const parts = ip.split('::');
      const left = parts[0] ? parts[0].split(':') : [];
      const right = parts[1] ? parts[1].split(':') : [];
      const missing = 8 - left.length - right.length;
      const middle = Array(missing).fill('0000');
      const full = [...left, ...middle, ...right];
      return full.map(p => p.padStart(4, '0')).join(':');
    }

    const parts = ip.split(':');
    if (parts.length !== 8) return null;
    return parts.map(p => p.padStart(4, '0')).join(':');
  } catch {
    return null;
  }
}

/**
 * Convert IPv6 to binary string
 */
function ipv6ToBits(ip: string): string {
  return ip
    .split(':')
    .map(hex => parseInt(hex, 16).toString(2).padStart(16, '0'))
    .join('');
}

/**
 * Check IP whitelist and return result
 */
export function checkIPWhitelist(
  ip: string,
  rules: CustomRiskRules
): IPWhitelistResult {
  if (!rules.enabled || rules.ip_whitelist.length === 0) {
    return {
      whitelisted: false,
      scoreReduction: 0,
      bypass: false
    };
  }

  for (const entry of rules.ip_whitelist) {
    if (matchIPEntry(ip, entry)) {
      return {
        whitelisted: true,
        matchedEntry: entry,
        scoreReduction: rules.ip_whitelist_score_reduction,
        bypass: rules.ip_whitelist_score_reduction >= 100
      };
    }
  }

  return {
    whitelisted: false,
    scoreReduction: 0,
    bypass: false
  };
}

// ============================================================================
// Trusted Device Functions
// ============================================================================

/**
 * Check if a device fingerprint is in the trusted list
 * 
 * @param fingerprintHash - SHA-256 hash of device fingerprint
 * @param trustedDevices - List of trusted devices
 * @returns Trusted device result
 */
export function checkTrustedDevice(
  fingerprintHash: string,
  rules: CustomRiskRules
): TrustedDeviceResult {
  if (!rules.enabled || !fingerprintHash || rules.trusted_devices.length === 0) {
    return {
      trusted: false,
      scoreReduction: 0
    };
  }

  const now = new Date();

  for (const device of rules.trusted_devices) {
    // Skip inactive devices
    if (!device.active) continue;

    // Skip expired devices
    if (device.expires_at && new Date(device.expires_at) < now) continue;

    // Check fingerprint match
    if (device.fingerprint_hash === fingerprintHash) {
      return {
        trusted: true,
        matchedDevice: device,
        scoreReduction: rules.trusted_device_score_reduction
      };
    }
  }

  return {
    trusted: false,
    scoreReduction: 0
  };
}

/**
 * Validate a trusted device entry
 */
export function validateTrustedDevice(device: Partial<TrustedDevice>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (!device.fingerprint_hash || device.fingerprint_hash.length !== 64) {
    errors.push('fingerprint_hash must be a 64-character SHA-256 hash');
  }

  if (!device.name || device.name.trim().length === 0) {
    errors.push('name is required');
  }

  if (device.name && device.name.length > 100) {
    errors.push('name must be 100 characters or less');
  }

  if (!device.added_at || isNaN(new Date(device.added_at).getTime())) {
    errors.push('added_at must be a valid ISO 8601 date');
  }

  if (!device.added_by || device.added_by.trim().length === 0) {
    errors.push('added_by is required');
  }

  if (device.expires_at && isNaN(new Date(device.expires_at).getTime())) {
    errors.push('expires_at must be a valid ISO 8601 date');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

// ============================================================================
// Custom Thresholds Functions
// ============================================================================

/**
 * Get effective risk thresholds for a realm
 * Returns custom thresholds if enabled, otherwise defaults
 */
export function getEffectiveThresholds(rules?: CustomRiskRules): RiskThresholds {
  if (!rules || !rules.enabled) {
    return {
      mfa_threshold: RISK_THRESHOLDS.high,      // 75
      block_threshold: RISK_THRESHOLDS.critical, // 90
      alert_threshold: RISK_THRESHOLDS.high      // 75
    };
  }

  return {
    mfa_threshold: rules.thresholds.mfa_threshold,
    block_threshold: rules.thresholds.block_threshold,
    alert_threshold: rules.thresholds.alert_threshold
  };
}

/**
 * Validate custom thresholds
 */
export function validateThresholds(thresholds: Partial<RiskThresholds>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (thresholds.mfa_threshold !== undefined) {
    if (thresholds.mfa_threshold < 0 || thresholds.mfa_threshold > 100) {
      errors.push('mfa_threshold must be between 0 and 100');
    }
  }

  if (thresholds.block_threshold !== undefined) {
    if (thresholds.block_threshold < 0 || thresholds.block_threshold > 100) {
      errors.push('block_threshold must be between 0 and 100');
    }
  }

  if (thresholds.alert_threshold !== undefined) {
    if (thresholds.alert_threshold < 0 || thresholds.alert_threshold > 100) {
      errors.push('alert_threshold must be between 0 and 100');
    }
  }

  // Validate logical ordering
  const mfa = thresholds.mfa_threshold ?? 70;
  const block = thresholds.block_threshold ?? 90;

  if (mfa >= block) {
    errors.push('mfa_threshold must be less than block_threshold');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

// ============================================================================
// Main Rule Application Functions
// ============================================================================

/**
 * Apply custom risk rules to a risk assessment
 * 
 * This is the main entry point for applying custom rules.
 * It checks IP whitelist, trusted devices, and applies custom thresholds.
 * 
 * @param riskScore - Original risk score from AI assessment
 * @param ip - Client IP address
 * @param deviceFingerprintHash - SHA-256 hash of device fingerprint (optional)
 * @param rules - Custom risk rules configuration
 * @param realmId - Realm ID for audit logging
 * @returns Result of rule application
 */
export async function applyCustomRiskRules(
  riskScore: number,
  ip: string,
  deviceFingerprintHash: string | undefined,
  rules: CustomRiskRules | undefined,
  realmId: string
): Promise<CustomRiskRuleResult> {
  // If rules not enabled or not provided, return original score
  if (!rules || !rules.enabled) {
    return {
      ruleApplied: false,
      originalScore: riskScore,
      adjustedScore: riskScore,
      scoreReduction: 0,
      bypassed: false,
      details: 'Custom risk rules not enabled'
    };
  }

  let adjustedScore = riskScore;
  let totalReduction = 0;
  let ruleApplied = false;
  let ruleType: 'ip_whitelist' | 'trusted_device' | 'custom_threshold' | undefined;
  let details = '';
  let bypassed = false;

  // Check IP whitelist first (highest priority)
  const ipResult = checkIPWhitelist(ip, rules);
  if (ipResult.whitelisted) {
    ruleApplied = true;
    ruleType = 'ip_whitelist';
    
    if (ipResult.bypass) {
      // Complete bypass - set score to 0
      adjustedScore = 0;
      totalReduction = riskScore;
      bypassed = true;
      details = `IP ${ip} whitelisted (matched: ${ipResult.matchedEntry}) - risk assessment bypassed`;
    } else {
      // Partial reduction
      totalReduction = Math.min(ipResult.scoreReduction, riskScore);
      adjustedScore = Math.max(0, riskScore - totalReduction);
      details = `IP ${ip} whitelisted (matched: ${ipResult.matchedEntry}) - score reduced by ${totalReduction}`;
    }

    // Audit log the IP whitelist application
    if (rules.audit_enabled) {
      await logRuleApplication(realmId, 'ip_whitelist', {
        ip,
        matched_entry: ipResult.matchedEntry,
        original_score: riskScore,
        adjusted_score: adjustedScore,
        bypassed
      });
    }
  }

  // Check trusted device (if not already bypassed)
  if (!bypassed && deviceFingerprintHash) {
    const deviceResult = checkTrustedDevice(deviceFingerprintHash, rules);
    if (deviceResult.trusted) {
      ruleApplied = true;
      if (!ruleType) ruleType = 'trusted_device';
      
      const deviceReduction = Math.min(deviceResult.scoreReduction, adjustedScore);
      adjustedScore = Math.max(0, adjustedScore - deviceReduction);
      totalReduction += deviceReduction;
      
      const deviceDetails = `Trusted device "${deviceResult.matchedDevice?.name}" - score reduced by ${deviceReduction}`;
      details = details ? `${details}; ${deviceDetails}` : deviceDetails;

      // Audit log the trusted device application
      if (rules.audit_enabled) {
        await logRuleApplication(realmId, 'trusted_device', {
          device_name: deviceResult.matchedDevice?.name,
          original_score: riskScore,
          adjusted_score: adjustedScore
        });
      }
    }
  }

  return {
    ruleApplied,
    ruleType,
    originalScore: riskScore,
    adjustedScore,
    scoreReduction: totalReduction,
    bypassed,
    details: details || 'No custom rules matched',
    customThresholds: rules.thresholds
  };
}

/**
 * Apply custom thresholds to determine risk recommendation
 */
export function applyCustomThresholds(
  riskScore: number,
  thresholds: RiskThresholds
): {
  requiresMfa: boolean;
  shouldBlock: boolean;
  shouldAlert: boolean;
  recommendation: 'allow' | 'mfa_required' | 'block';
} {
  const shouldBlock = riskScore >= thresholds.block_threshold;
  const requiresMfa = riskScore >= thresholds.mfa_threshold && !shouldBlock;
  const shouldAlert = riskScore >= thresholds.alert_threshold;

  let recommendation: 'allow' | 'mfa_required' | 'block' = 'allow';
  if (shouldBlock) {
    recommendation = 'block';
  } else if (requiresMfa) {
    recommendation = 'mfa_required';
  }

  return {
    requiresMfa,
    shouldBlock,
    shouldAlert,
    recommendation
  };
}

/**
 * Adjust risk assessment result with custom rules
 * 
 * This function takes a complete RiskAssessmentResult and applies
 * custom rules, returning an adjusted result.
 */
export async function adjustRiskAssessmentWithCustomRules(
  result: RiskAssessmentResult,
  ip: string,
  deviceFingerprintHash: string | undefined,
  rules: CustomRiskRules | undefined,
  realmId: string
): Promise<RiskAssessmentResult> {
  // Apply custom rules
  const ruleResult = await applyCustomRiskRules(
    result.riskScore,
    ip,
    deviceFingerprintHash,
    rules,
    realmId
  );

  // If no rules applied, return original result
  if (!ruleResult.ruleApplied) {
    return result;
  }

  // Get effective thresholds
  const thresholds = ruleResult.customThresholds || getEffectiveThresholds(rules);

  // Apply custom thresholds to adjusted score
  const thresholdResult = applyCustomThresholds(ruleResult.adjustedScore, thresholds);

  // Determine new risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (ruleResult.adjustedScore >= 90) riskLevel = 'critical';
  else if (ruleResult.adjustedScore >= 75) riskLevel = 'high';
  else if (ruleResult.adjustedScore >= 50) riskLevel = 'medium';

  // Build adjusted result
  return {
    ...result,
    riskScore: ruleResult.adjustedScore,
    riskLevel,
    requiresMfa: thresholdResult.requiresMfa,
    shouldBlock: thresholdResult.shouldBlock,
    shouldAlert: thresholdResult.shouldAlert,
    explanation: ruleResult.bypassed
      ? `Risk assessment bypassed: ${ruleResult.details}`
      : `${result.explanation} (Custom rules applied: ${ruleResult.details})`,
    modelVersion: `${result.modelVersion}-custom-rules`
  };
}

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate custom risk rules configuration
 */
export function validateCustomRiskRules(rules: Partial<CustomRiskRules>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Validate IP whitelist entries
  if (rules.ip_whitelist) {
    for (const entry of rules.ip_whitelist) {
      if (!isValidIPOrCIDR(entry)) {
        errors.push(`Invalid IP whitelist entry: ${entry}`);
      }
    }
  }

  // Validate trusted devices
  if (rules.trusted_devices) {
    for (let i = 0; i < rules.trusted_devices.length; i++) {
      const deviceValidation = validateTrustedDevice(rules.trusted_devices[i]);
      if (!deviceValidation.valid) {
        errors.push(`Trusted device ${i}: ${deviceValidation.errors.join(', ')}`);
      }
    }
  }

  // Validate thresholds
  if (rules.thresholds) {
    const thresholdValidation = validateThresholds(rules.thresholds);
    if (!thresholdValidation.valid) {
      errors.push(...thresholdValidation.errors);
    }
  }

  // Validate score reductions
  if (rules.ip_whitelist_score_reduction !== undefined) {
    if (rules.ip_whitelist_score_reduction < 0 || rules.ip_whitelist_score_reduction > 100) {
      errors.push('ip_whitelist_score_reduction must be between 0 and 100');
    }
  }

  if (rules.trusted_device_score_reduction !== undefined) {
    if (rules.trusted_device_score_reduction < 0 || rules.trusted_device_score_reduction > 100) {
      errors.push('trusted_device_score_reduction must be between 0 and 100');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate IP address or CIDR notation
 */
function isValidIPOrCIDR(entry: string): boolean {
  if (!entry || entry.trim().length === 0) return false;

  // Check for CIDR notation
  if (entry.includes('/')) {
    const [ip, bits] = entry.split('/');
    const mask = parseInt(bits, 10);
    
    if (isNaN(mask)) return false;
    
    // IPv4 CIDR
    if (ip.includes('.')) {
      if (mask < 0 || mask > 32) return false;
      return isValidIPv4(ip);
    }
    
    // IPv6 CIDR
    if (ip.includes(':')) {
      if (mask < 0 || mask > 128) return false;
      return isValidIPv6(ip);
    }
    
    return false;
  }

  // Plain IP address
  return isValidIPv4(entry) || isValidIPv6(entry);
}

/**
 * Validate IPv4 address
 */
function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;

  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return false;
    if (part !== num.toString()) return false; // No leading zeros
  }

  return true;
}

/**
 * Validate IPv6 address
 */
function isValidIPv6(ip: string): boolean {
  // Handle :: shorthand
  if (ip === '::') return true;

  // Count :: occurrences (max 1)
  const doubleColonCount = (ip.match(/::/g) || []).length;
  if (doubleColonCount > 1) return false;

  // Expand and validate
  const expanded = expandIPv6(ip);
  if (!expanded) return false;

  const parts = expanded.split(':');
  if (parts.length !== 8) return false;

  for (const part of parts) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
  }

  return true;
}

// ============================================================================
// Audit Logging
// ============================================================================

/**
 * Log custom rule application for audit
 */
async function logRuleApplication(
  realmId: string,
  ruleType: string,
  details: Record<string, unknown>
): Promise<void> {
  try {
    await logSimpleSecurityEvent({
      event_type: 'custom_risk_rule_applied',
      realm_id: realmId,
      details: {
        rule_type: ruleType,
        ...details
      }
    });
  } catch (error) {
    console.error('Failed to log custom rule application:', error);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create a new trusted device entry
 */
export function createTrustedDevice(
  fingerprintHash: string,
  name: string,
  addedBy: string,
  expiresAt?: string
): TrustedDevice {
  return {
    fingerprint_hash: fingerprintHash,
    name,
    added_at: new Date().toISOString(),
    added_by: addedBy,
    expires_at: expiresAt,
    active: true
  };
}

/**
 * Merge custom risk rules with defaults
 */
export function mergeWithDefaults(
  rules: Partial<CustomRiskRules>
): CustomRiskRules {
  return {
    ...DEFAULT_CUSTOM_RISK_RULES,
    ...rules,
    thresholds: {
      ...DEFAULT_CUSTOM_RISK_RULES.thresholds,
      ...rules.thresholds
    }
  };
}

/**
 * Check if custom rules would affect a given risk score
 */
export function wouldRulesAffectScore(
  riskScore: number,
  ip: string,
  deviceFingerprintHash: string | undefined,
  rules: CustomRiskRules | undefined
): boolean {
  if (!rules || !rules.enabled) return false;

  // Check IP whitelist
  if (isIPWhitelisted(ip, rules.ip_whitelist)) return true;

  // Check trusted device
  if (deviceFingerprintHash) {
    const deviceResult = checkTrustedDevice(deviceFingerprintHash, rules);
    if (deviceResult.trusted) return true;
  }

  // Check if custom thresholds differ from defaults
  if (rules.thresholds.mfa_threshold !== RISK_THRESHOLDS.high ||
      rules.thresholds.block_threshold !== RISK_THRESHOLDS.critical) {
    return true;
  }

  return false;
}
