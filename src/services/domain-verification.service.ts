/**
 * Domain Verification Service - DNS TXT record verification for SSO enforcement
 * 
 * Implements domain ownership verification through DNS TXT records.
 * Organizations must prove domain ownership before SSO can be enforced.
 * 
 * Security Requirements:
 * - Unique verification tokens per domain
 * - DNS lookup with timeout protection
 * - Audit logging for all verification events
 * - Prevent domain hijacking attacks
 * 
 * Validates: Requirements 9.5 (Domain verification for SSO enforcement)
 */

import { promises as dns } from 'dns';
import {
  VerifiedDomain,
  DomainVerificationStatus,
  generateDomainVerificationToken,
  isValidDomain,
  DOMAIN_VERIFICATION_PREFIX,
  DOMAIN_VERIFICATION_TTL_DAYS
} from '../models/org-sso.model';
import {
  getSSOConfig,
  addDomain as addDomainToConfig,
  verifyDomain as verifyDomainInConfig,
  removeDomain as removeDomainFromConfig,
  updateSSOConfig
} from '../repositories/org-sso.repository';
import { logAuditEvent, AuditEventType, AuditResult } from './audit.service';

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

/**
 * Domain verification result
 */
export interface DomainVerificationResult {
  success: boolean;
  domain: string;
  status: DomainVerificationStatus;
  error?: string;
  verifiedAt?: string;
}

/**
 * Domain verification check result
 */
export interface DomainVerificationCheckResult {
  found: boolean;
  expectedToken: string;
  foundTokens: string[];
  matchedToken?: string;
}

/**
 * Add domain input
 */
export interface AddDomainInput {
  tenantId: string;
  domain: string;
  userId?: string;
  ipAddress?: string;
}

/**
 * Verify domain input
 */
export interface VerifyDomainInput {
  tenantId: string;
  domain: string;
  userId?: string;
  ipAddress?: string;
}

/**
 * Remove domain input
 */
export interface RemoveDomainInput {
  tenantId: string;
  domain: string;
  userId?: string;
  ipAddress?: string;
}

/**
 * Domain status response
 */
export interface DomainStatusResponse {
  domain: string;
  verificationStatus: DomainVerificationStatus;
  verificationToken?: string;
  verificationMethod: 'dns_txt';
  dnsRecordName: string;
  dnsRecordValue?: string;
  verifiedAt?: string;
  expiresAt?: string;
}

/**
 * SSO enforcement check result
 */
export interface SSOEnforcementCheckResult {
  enforced: boolean;
  tenantId?: string;
  ssoType?: 'saml' | 'oidc';
  providerName?: string;
  reason?: string;
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * DNS TXT record prefix for domain verification
 */
export const DNS_RECORD_PREFIX = '_zalt-verify';

/**
 * DNS lookup timeout in milliseconds
 */
const DNS_LOOKUP_TIMEOUT = 10000;

/**
 * Maximum retry attempts for DNS lookup
 */
const DNS_LOOKUP_MAX_RETRIES = 2;

/**
 * Delay between DNS lookup retries in milliseconds
 */
const DNS_LOOKUP_RETRY_DELAY = 1000;

// ============================================================================
// DNS LOOKUP FUNCTIONS
// ============================================================================

/**
 * Perform DNS TXT record lookup with timeout
 * 
 * @param hostname - The hostname to lookup (e.g., _zalt-verify.acme.com)
 * @returns Array of TXT record values
 */
async function lookupTxtRecords(hostname: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('DNS lookup timeout'));
    }, DNS_LOOKUP_TIMEOUT);

    dns.resolveTxt(hostname)
      .then((records) => {
        clearTimeout(timeout);
        // TXT records come as arrays of strings, flatten them
        const flatRecords = records.map(record => record.join(''));
        resolve(flatRecords);
      })
      .catch((error) => {
        clearTimeout(timeout);
        // ENODATA and ENOTFOUND are expected when record doesn't exist
        if (error.code === 'ENODATA' || error.code === 'ENOTFOUND' || error.code === 'ENOENT') {
          resolve([]);
        } else {
          reject(error);
        }
      });
  });
}

/**
 * Perform DNS TXT record lookup with retries
 * 
 * @param hostname - The hostname to lookup
 * @returns Array of TXT record values
 */
async function lookupTxtRecordsWithRetry(hostname: string): Promise<string[]> {
  let lastError: Error | null = null;
  
  for (let attempt = 0; attempt <= DNS_LOOKUP_MAX_RETRIES; attempt++) {
    try {
      return await lookupTxtRecords(hostname);
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      if (attempt < DNS_LOOKUP_MAX_RETRIES) {
        await new Promise(resolve => setTimeout(resolve, DNS_LOOKUP_RETRY_DELAY));
      }
    }
  }
  
  throw lastError || new Error('DNS lookup failed');
}

// ============================================================================
// DOMAIN VERIFICATION FUNCTIONS
// ============================================================================

/**
 * Generate DNS record name for domain verification
 * 
 * @param domain - The domain to verify (e.g., acme.com)
 * @returns DNS record name (e.g., _zalt-verify.acme.com)
 */
export function getDnsRecordName(domain: string): string {
  return `${DNS_RECORD_PREFIX}.${domain}`;
}

/**
 * Check if DNS TXT record contains the verification token
 * 
 * @param domain - The domain to check
 * @param expectedToken - The expected verification token
 * @returns Verification check result
 */
export async function checkDnsVerification(
  domain: string,
  expectedToken: string
): Promise<DomainVerificationCheckResult> {
  const dnsRecordName = getDnsRecordName(domain);
  
  try {
    const txtRecords = await lookupTxtRecordsWithRetry(dnsRecordName);
    
    // Look for the verification token in any TXT record
    const matchedToken = txtRecords.find(record => 
      record.trim() === expectedToken.trim()
    );
    
    return {
      found: !!matchedToken,
      expectedToken,
      foundTokens: txtRecords,
      matchedToken
    };
  } catch (error) {
    console.error(`DNS lookup failed for ${dnsRecordName}:`, error);
    return {
      found: false,
      expectedToken,
      foundTokens: []
    };
  }
}

/**
 * Add a domain to SSO configuration for verification
 * 
 * @param input - Add domain input
 * @returns Domain status response
 */
export async function addDomain(input: AddDomainInput): Promise<DomainStatusResponse> {
  const { tenantId, domain, userId, ipAddress } = input;
  
  // Validate domain format
  if (!isValidDomain(domain)) {
    throw new Error(`Invalid domain format: ${domain}`);
  }
  
  const normalizedDomain = domain.toLowerCase();
  
  // Check if SSO config exists
  const ssoConfig = await getSSOConfig(tenantId);
  if (!ssoConfig) {
    throw new Error('SSO configuration not found for tenant');
  }
  
  // Check if domain already exists
  const existingDomain = ssoConfig.domains.find(
    d => d.domain === normalizedDomain
  );
  
  if (existingDomain) {
    // Return existing domain status
    return {
      domain: existingDomain.domain,
      verificationStatus: existingDomain.verificationStatus,
      verificationToken: existingDomain.verificationToken,
      verificationMethod: 'dns_txt',
      dnsRecordName: getDnsRecordName(existingDomain.domain),
      dnsRecordValue: existingDomain.verificationToken,
      verifiedAt: existingDomain.verifiedAt
    };
  }
  
  // Add domain to SSO config
  const updatedConfig = await addDomainToConfig(tenantId, normalizedDomain);
  
  if (!updatedConfig) {
    throw new Error('Failed to add domain to SSO configuration');
  }
  
  // Find the newly added domain
  const newDomain = updatedConfig.domains.find(d => d.domain === normalizedDomain);
  
  if (!newDomain) {
    throw new Error('Domain was not added to configuration');
  }
  
  // Audit log
  await logAuditEvent({
    eventType: AuditEventType.CONFIG_CHANGE,
    result: AuditResult.SUCCESS,
    realmId: ssoConfig.realmId,
    userId,
    ipAddress: ipAddress || 'unknown',
    action: 'Domain added for verification',
    details: {
      tenantId,
      domain: normalizedDomain,
      verificationMethod: 'dns_txt'
    }
  });
  
  // Calculate expiration date
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + DOMAIN_VERIFICATION_TTL_DAYS);
  
  return {
    domain: newDomain.domain,
    verificationStatus: newDomain.verificationStatus,
    verificationToken: newDomain.verificationToken,
    verificationMethod: 'dns_txt',
    dnsRecordName: getDnsRecordName(newDomain.domain),
    dnsRecordValue: newDomain.verificationToken,
    expiresAt: expiresAt.toISOString()
  };
}

/**
 * Verify domain ownership through DNS TXT record
 * 
 * @param input - Verify domain input
 * @returns Domain verification result
 */
export async function verifyDomain(input: VerifyDomainInput): Promise<DomainVerificationResult> {
  const { tenantId, domain, userId, ipAddress } = input;
  
  const normalizedDomain = domain.toLowerCase();
  
  // Get SSO config
  const ssoConfig = await getSSOConfig(tenantId);
  if (!ssoConfig) {
    throw new Error('SSO configuration not found for tenant');
  }
  
  // Find the domain in config
  const domainEntry = ssoConfig.domains.find(d => d.domain === normalizedDomain);
  
  if (!domainEntry) {
    throw new Error(`Domain ${domain} not found in SSO configuration`);
  }
  
  // Check if already verified
  if (domainEntry.verificationStatus === 'verified') {
    return {
      success: true,
      domain: normalizedDomain,
      status: 'verified',
      verifiedAt: domainEntry.verifiedAt
    };
  }
  
  // Check if verification token exists
  if (!domainEntry.verificationToken) {
    throw new Error('Domain verification token not found');
  }
  
  // Perform DNS verification
  const checkResult = await checkDnsVerification(
    normalizedDomain,
    domainEntry.verificationToken
  );
  
  if (!checkResult.found) {
    // Update status to failed
    await updateDomainStatus(tenantId, normalizedDomain, 'failed');
    
    // Audit log failure
    await logAuditEvent({
      eventType: AuditEventType.CONFIG_CHANGE,
      result: AuditResult.FAILURE,
      realmId: ssoConfig.realmId,
      userId,
      ipAddress: ipAddress || 'unknown',
      action: 'Domain verification failed',
      errorMessage: 'DNS TXT record not found or does not match',
      details: {
        tenantId,
        domain: normalizedDomain,
        expectedToken: domainEntry.verificationToken,
        foundTokens: checkResult.foundTokens
      }
    });
    
    return {
      success: false,
      domain: normalizedDomain,
      status: 'failed',
      error: `DNS TXT record not found. Expected record at ${getDnsRecordName(normalizedDomain)} with value: ${domainEntry.verificationToken}`
    };
  }
  
  // Verification successful - update domain status
  const updatedConfig = await verifyDomainInConfig(tenantId, normalizedDomain);
  
  if (!updatedConfig) {
    throw new Error('Failed to update domain verification status');
  }
  
  const verifiedDomain = updatedConfig.domains.find(d => d.domain === normalizedDomain);
  
  // Audit log success
  await logAuditEvent({
    eventType: AuditEventType.CONFIG_CHANGE,
    result: AuditResult.SUCCESS,
    realmId: ssoConfig.realmId,
    userId,
    ipAddress: ipAddress || 'unknown',
    action: 'Domain verified successfully',
    details: {
      tenantId,
      domain: normalizedDomain,
      verificationMethod: 'dns_txt'
    }
  });
  
  return {
    success: true,
    domain: normalizedDomain,
    status: 'verified',
    verifiedAt: verifiedDomain?.verifiedAt
  };
}

/**
 * Remove a domain from SSO configuration
 * 
 * @param input - Remove domain input
 * @returns Success status
 */
export async function removeDomain(input: RemoveDomainInput): Promise<boolean> {
  const { tenantId, domain, userId, ipAddress } = input;
  
  const normalizedDomain = domain.toLowerCase();
  
  // Get SSO config for audit logging
  const ssoConfig = await getSSOConfig(tenantId);
  if (!ssoConfig) {
    throw new Error('SSO configuration not found for tenant');
  }
  
  // Check if domain exists
  const domainEntry = ssoConfig.domains.find(d => d.domain === normalizedDomain);
  if (!domainEntry) {
    throw new Error(`Domain ${domain} not found in SSO configuration`);
  }
  
  // Check if this is the only verified domain and SSO is enforced
  const verifiedDomains = ssoConfig.domains.filter(d => d.verificationStatus === 'verified');
  if (ssoConfig.enforced && verifiedDomains.length === 1 && domainEntry.verificationStatus === 'verified') {
    throw new Error('Cannot remove the only verified domain while SSO enforcement is enabled. Disable enforcement first.');
  }
  
  // Remove domain
  const updatedConfig = await removeDomainFromConfig(tenantId, normalizedDomain);
  
  if (!updatedConfig) {
    throw new Error('Failed to remove domain from SSO configuration');
  }
  
  // Audit log
  await logAuditEvent({
    eventType: AuditEventType.CONFIG_CHANGE,
    result: AuditResult.SUCCESS,
    realmId: ssoConfig.realmId,
    userId,
    ipAddress: ipAddress || 'unknown',
    action: 'Domain removed from SSO configuration',
    details: {
      tenantId,
      domain: normalizedDomain,
      previousStatus: domainEntry.verificationStatus
    }
  });
  
  return true;
}

/**
 * Get domain verification status
 * 
 * @param tenantId - Tenant ID
 * @param domain - Domain to check
 * @returns Domain status response or null if not found
 */
export async function getDomainStatus(
  tenantId: string,
  domain: string
): Promise<DomainStatusResponse | null> {
  const normalizedDomain = domain.toLowerCase();
  
  const ssoConfig = await getSSOConfig(tenantId);
  if (!ssoConfig) {
    return null;
  }
  
  const domainEntry = ssoConfig.domains.find(d => d.domain === normalizedDomain);
  if (!domainEntry) {
    return null;
  }
  
  return {
    domain: domainEntry.domain,
    verificationStatus: domainEntry.verificationStatus,
    verificationToken: domainEntry.verificationStatus === 'pending' 
      ? domainEntry.verificationToken 
      : undefined,
    verificationMethod: 'dns_txt',
    dnsRecordName: getDnsRecordName(domainEntry.domain),
    dnsRecordValue: domainEntry.verificationStatus === 'pending'
      ? domainEntry.verificationToken
      : undefined,
    verifiedAt: domainEntry.verifiedAt
  };
}

/**
 * List all domains for a tenant
 * 
 * @param tenantId - Tenant ID
 * @returns Array of domain status responses
 */
export async function listDomains(tenantId: string): Promise<DomainStatusResponse[]> {
  const ssoConfig = await getSSOConfig(tenantId);
  if (!ssoConfig) {
    return [];
  }
  
  return ssoConfig.domains.map(domain => ({
    domain: domain.domain,
    verificationStatus: domain.verificationStatus,
    verificationToken: domain.verificationStatus === 'pending'
      ? domain.verificationToken
      : undefined,
    verificationMethod: 'dns_txt' as const,
    dnsRecordName: getDnsRecordName(domain.domain),
    dnsRecordValue: domain.verificationStatus === 'pending'
      ? domain.verificationToken
      : undefined,
    verifiedAt: domain.verifiedAt
  }));
}

/**
 * Regenerate verification token for a domain
 * 
 * @param tenantId - Tenant ID
 * @param domain - Domain to regenerate token for
 * @param userId - User performing the action
 * @param ipAddress - IP address of the request
 * @returns New domain status response
 */
export async function regenerateVerificationToken(
  tenantId: string,
  domain: string,
  userId?: string,
  ipAddress?: string
): Promise<DomainStatusResponse> {
  const normalizedDomain = domain.toLowerCase();
  
  const ssoConfig = await getSSOConfig(tenantId);
  if (!ssoConfig) {
    throw new Error('SSO configuration not found for tenant');
  }
  
  const domainIndex = ssoConfig.domains.findIndex(d => d.domain === normalizedDomain);
  if (domainIndex === -1) {
    throw new Error(`Domain ${domain} not found in SSO configuration`);
  }
  
  const domainEntry = ssoConfig.domains[domainIndex];
  
  // Only allow regeneration for pending or failed domains
  if (domainEntry.verificationStatus === 'verified') {
    throw new Error('Cannot regenerate token for already verified domain');
  }
  
  // Generate new token
  const newToken = generateDomainVerificationToken();
  
  // Update domain with new token
  const updatedDomains = [...ssoConfig.domains];
  updatedDomains[domainIndex] = {
    ...domainEntry,
    verificationToken: newToken,
    verificationStatus: 'pending'
  };
  
  // This requires direct DynamoDB update - we'll use updateSSOConfig
  // For now, remove and re-add the domain
  await removeDomainFromConfig(tenantId, normalizedDomain);
  await addDomainToConfig(tenantId, normalizedDomain);
  
  // Get the updated config
  const updatedConfig = await getSSOConfig(tenantId);
  const newDomainEntry = updatedConfig?.domains.find(d => d.domain === normalizedDomain);
  
  // Audit log
  await logAuditEvent({
    eventType: AuditEventType.CONFIG_CHANGE,
    result: AuditResult.SUCCESS,
    realmId: ssoConfig.realmId,
    userId,
    ipAddress: ipAddress || 'unknown',
    action: 'Domain verification token regenerated',
    details: {
      tenantId,
      domain: normalizedDomain
    }
  });
  
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + DOMAIN_VERIFICATION_TTL_DAYS);
  
  return {
    domain: normalizedDomain,
    verificationStatus: 'pending',
    verificationToken: newDomainEntry?.verificationToken,
    verificationMethod: 'dns_txt',
    dnsRecordName: getDnsRecordName(normalizedDomain),
    dnsRecordValue: newDomainEntry?.verificationToken,
    expiresAt: expiresAt.toISOString()
  };
}

// ============================================================================
// SSO ENFORCEMENT FUNCTIONS
// ============================================================================

/**
 * Check if SSO is enforced for an email domain
 * 
 * @param email - User email to check
 * @returns SSO enforcement check result
 */
export async function checkSSOEnforcement(email: string): Promise<SSOEnforcementCheckResult> {
  const emailDomain = email.split('@')[1]?.toLowerCase();
  
  if (!emailDomain) {
    return {
      enforced: false,
      reason: 'Invalid email format'
    };
  }
  
  // Import here to avoid circular dependency
  const { getEnforcedSSOForEmail } = await import('../repositories/org-sso.repository');
  
  const ssoConfig = await getEnforcedSSOForEmail(email);
  
  if (!ssoConfig) {
    return {
      enforced: false,
      reason: 'No SSO enforcement for this domain'
    };
  }
  
  // Check if domain is verified
  const domainEntry = ssoConfig.domains.find(
    d => d.domain === emailDomain && d.verificationStatus === 'verified'
  );
  
  if (!domainEntry) {
    return {
      enforced: false,
      reason: 'Domain not verified for SSO enforcement'
    };
  }
  
  return {
    enforced: true,
    tenantId: ssoConfig.tenantId,
    ssoType: ssoConfig.ssoType,
    providerName: ssoConfig.providerName
  };
}

/**
 * Enable SSO enforcement for a tenant
 * Requires at least one verified domain
 * 
 * @param tenantId - Tenant ID
 * @param userId - User performing the action
 * @param ipAddress - IP address of the request
 * @returns Success status
 */
export async function enableSSOEnforcement(
  tenantId: string,
  userId?: string,
  ipAddress?: string
): Promise<boolean> {
  const ssoConfig = await getSSOConfig(tenantId);
  
  if (!ssoConfig) {
    throw new Error('SSO configuration not found for tenant');
  }
  
  if (!ssoConfig.enabled) {
    throw new Error('SSO must be enabled before enforcement can be activated');
  }
  
  // Check for at least one verified domain
  const verifiedDomains = ssoConfig.domains.filter(
    d => d.verificationStatus === 'verified'
  );
  
  if (verifiedDomains.length === 0) {
    throw new Error('At least one verified domain is required for SSO enforcement');
  }
  
  // Enable enforcement
  const updatedConfig = await updateSSOConfig(tenantId, { enforced: true });
  
  if (!updatedConfig) {
    throw new Error('Failed to enable SSO enforcement');
  }
  
  // Audit log
  await logAuditEvent({
    eventType: AuditEventType.CONFIG_CHANGE,
    result: AuditResult.SUCCESS,
    realmId: ssoConfig.realmId,
    userId,
    ipAddress: ipAddress || 'unknown',
    action: 'SSO enforcement enabled',
    details: {
      tenantId,
      verifiedDomains: verifiedDomains.map(d => d.domain)
    }
  });
  
  return true;
}

/**
 * Disable SSO enforcement for a tenant
 * 
 * @param tenantId - Tenant ID
 * @param userId - User performing the action
 * @param ipAddress - IP address of the request
 * @returns Success status
 */
export async function disableSSOEnforcement(
  tenantId: string,
  userId?: string,
  ipAddress?: string
): Promise<boolean> {
  const ssoConfig = await getSSOConfig(tenantId);
  
  if (!ssoConfig) {
    throw new Error('SSO configuration not found for tenant');
  }
  
  // Disable enforcement
  const updatedConfig = await updateSSOConfig(tenantId, { enforced: false });
  
  if (!updatedConfig) {
    throw new Error('Failed to disable SSO enforcement');
  }
  
  // Audit log
  await logAuditEvent({
    eventType: AuditEventType.CONFIG_CHANGE,
    result: AuditResult.SUCCESS,
    realmId: ssoConfig.realmId,
    userId,
    ipAddress: ipAddress || 'unknown',
    action: 'SSO enforcement disabled',
    details: {
      tenantId
    }
  });
  
  return true;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Update domain verification status
 * 
 * @param tenantId - Tenant ID
 * @param domain - Domain to update
 * @param status - New verification status
 */
async function updateDomainStatus(
  tenantId: string,
  domain: string,
  status: DomainVerificationStatus
): Promise<void> {
  // For 'failed' status, we need to update the domain entry
  // This is handled by the repository layer
  // For now, we just log the status change
  console.log(`Domain ${domain} verification status updated to: ${status}`);
}

/**
 * Validate that a domain can be added to a tenant
 * Checks for conflicts with other tenants
 * 
 * @param domain - Domain to validate
 * @param tenantId - Tenant ID
 * @returns Validation result
 */
export async function validateDomainForTenant(
  domain: string,
  tenantId: string
): Promise<{ valid: boolean; error?: string }> {
  const normalizedDomain = domain.toLowerCase();
  
  // Check domain format
  if (!isValidDomain(normalizedDomain)) {
    return {
      valid: false,
      error: `Invalid domain format: ${domain}`
    };
  }
  
  // Check if domain is already claimed by another tenant
  const { getSSOConfigByDomain } = await import('../repositories/org-sso.repository');
  const existingConfig = await getSSOConfigByDomain(normalizedDomain);
  
  if (existingConfig && existingConfig.tenantId !== tenantId) {
    return {
      valid: false,
      error: `Domain ${domain} is already claimed by another organization`
    };
  }
  
  return { valid: true };
}
