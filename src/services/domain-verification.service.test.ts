/**
 * Domain Verification Service Tests
 * 
 * Tests for DNS TXT record verification for SSO enforcement.
 * 
 * Validates: Requirements 9.5 (Domain verification for SSO enforcement)
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';

// Mock the dns module
jest.mock('dns', () => ({
  promises: {
    resolveTxt: jest.fn()
  }
}));

// Mock the repositories
jest.mock('../repositories/org-sso.repository', () => ({
  getSSOConfig: jest.fn(),
  addDomain: jest.fn(),
  verifyDomain: jest.fn(),
  removeDomain: jest.fn(),
  updateSSOConfig: jest.fn(),
  getSSOConfigByDomain: jest.fn(),
  getEnforcedSSOForEmail: jest.fn()
}));

// Mock audit service
jest.mock('./audit.service', () => ({
  logAuditEvent: jest.fn(() => Promise.resolve()),
  AuditEventType: {
    SSO_CONFIG_UPDATED: 'sso_config_updated'
  },
  AuditResult: {
    SUCCESS: 'success',
    FAILURE: 'failure'
  }
}));

import { promises as dns } from 'dns';
import * as orgSsoRepository from '../repositories/org-sso.repository';
import {
  getDnsRecordName,
  checkDnsVerification,
  addDomain,
  verifyDomain,
  removeDomain,
  getDomainStatus,
  listDomains,
  checkSSOEnforcement,
  enableSSOEnforcement,
  disableSSOEnforcement,
  validateDomainForTenant,
  DNS_RECORD_PREFIX
} from './domain-verification.service';


// ============================================================================
// TEST DATA
// ============================================================================

const mockSSOConfig = {
  id: 'sso_config_test123',
  tenantId: 'tenant_123',
  realmId: 'realm_456',
  ssoType: 'saml' as const,
  enabled: true,
  status: 'active' as const,
  providerName: 'Okta',
  spEntityId: 'https://api.zalt.io/v1/sso/saml/realm_456/tenant_123',
  acsUrl: 'https://api.zalt.io/v1/sso/saml/realm_456/tenant_123/acs',
  domains: [
    {
      domain: 'acme.com',
      verificationStatus: 'pending' as const,
      verificationToken: 'zalt-verify=abc123def456',
      verificationMethod: 'dns_txt' as const
    },
    {
      domain: 'verified.com',
      verificationStatus: 'verified' as const,
      verificationToken: 'zalt-verify=xyz789',
      verifiedAt: '2024-01-15T10:00:00Z',
      verificationMethod: 'dns_txt' as const
    }
  ],
  enforced: false,
  jitProvisioning: {
    enabled: true,
    defaultRole: 'member',
    autoVerifyEmail: true,
    syncGroups: false
  },
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-15T00:00:00Z'
};

// ============================================================================
// TESTS
// ============================================================================

describe('Domain Verification Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('getDnsRecordName', () => {
    it('should generate correct DNS record name', () => {
      const result = getDnsRecordName('acme.com');
      expect(result).toBe(`${DNS_RECORD_PREFIX}.acme.com`);
    });

    it('should handle subdomains', () => {
      const result = getDnsRecordName('sub.acme.com');
      expect(result).toBe(`${DNS_RECORD_PREFIX}.sub.acme.com`);
    });

    it('should handle various TLDs', () => {
      expect(getDnsRecordName('example.co.uk')).toBe(`${DNS_RECORD_PREFIX}.example.co.uk`);
      expect(getDnsRecordName('example.io')).toBe(`${DNS_RECORD_PREFIX}.example.io`);
    });
  });

  describe('checkDnsVerification', () => {
    it('should return found=true when token matches', async () => {
      const mockResolveTxt = dns.resolveTxt as jest.MockedFunction<typeof dns.resolveTxt>;
      mockResolveTxt.mockResolvedValue([['zalt-verify=abc123']]);

      const result = await checkDnsVerification('acme.com', 'zalt-verify=abc123');

      expect(result.found).toBe(true);
      expect(result.matchedToken).toBe('zalt-verify=abc123');
      expect(result.expectedToken).toBe('zalt-verify=abc123');
    });

    it('should return found=false when token does not match', async () => {
      const mockResolveTxt = dns.resolveTxt as jest.MockedFunction<typeof dns.resolveTxt>;
      mockResolveTxt.mockResolvedValue([['zalt-verify=wrong-token']]);

      const result = await checkDnsVerification('acme.com', 'zalt-verify=abc123');

      expect(result.found).toBe(false);
      expect(result.matchedToken).toBeUndefined();
      expect(result.foundTokens).toContain('zalt-verify=wrong-token');
    });

    it('should return found=false when no TXT records exist', async () => {
      const mockResolveTxt = dns.resolveTxt as jest.MockedFunction<typeof dns.resolveTxt>;
      const error = new Error('ENODATA') as NodeJS.ErrnoException;
      error.code = 'ENODATA';
      mockResolveTxt.mockRejectedValue(error);

      const result = await checkDnsVerification('acme.com', 'zalt-verify=abc123');

      expect(result.found).toBe(false);
      expect(result.foundTokens).toEqual([]);
    });

    it('should handle multiple TXT records', async () => {
      const mockResolveTxt = dns.resolveTxt as jest.MockedFunction<typeof dns.resolveTxt>;
      mockResolveTxt.mockResolvedValue([
        ['google-site-verification=xyz'],
        ['zalt-verify=abc123'],
        ['other-record']
      ]);

      const result = await checkDnsVerification('acme.com', 'zalt-verify=abc123');

      expect(result.found).toBe(true);
      expect(result.matchedToken).toBe('zalt-verify=abc123');
    });

    it('should handle ENOTFOUND error gracefully', async () => {
      const mockResolveTxt = dns.resolveTxt as jest.MockedFunction<typeof dns.resolveTxt>;
      const error = new Error('ENOTFOUND') as NodeJS.ErrnoException;
      error.code = 'ENOTFOUND';
      mockResolveTxt.mockRejectedValue(error);

      const result = await checkDnsVerification('nonexistent.com', 'zalt-verify=abc123');

      expect(result.found).toBe(false);
      expect(result.foundTokens).toEqual([]);
    });
  });

  describe('addDomain', () => {
    it('should add a new domain successfully', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      const mockAddDomain = orgSsoRepository.addDomain as jest.MockedFunction<typeof orgSsoRepository.addDomain>;

      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        domains: []
      });

      mockAddDomain.mockResolvedValue({
        ...mockSSOConfig,
        domains: [{
          domain: 'newdomain.com',
          verificationStatus: 'pending',
          verificationToken: 'zalt-verify=newtoken123',
          verificationMethod: 'dns_txt'
        }]
      });

      const result = await addDomain({
        tenantId: 'tenant_123',
        domain: 'newdomain.com'
      });

      expect(result.domain).toBe('newdomain.com');
      expect(result.verificationStatus).toBe('pending');
      expect(result.verificationToken).toBeDefined();
      expect(result.dnsRecordName).toBe('_zalt-verify.newdomain.com');
    });

    it('should return existing domain if already added', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);

      const result = await addDomain({
        tenantId: 'tenant_123',
        domain: 'acme.com'
      });

      expect(result.domain).toBe('acme.com');
      expect(result.verificationStatus).toBe('pending');
    });

    it('should throw error for invalid domain format', async () => {
      await expect(addDomain({
        tenantId: 'tenant_123',
        domain: 'invalid-domain'
      })).rejects.toThrow('Invalid domain format');
    });

    it('should throw error if SSO config not found', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(null);

      await expect(addDomain({
        tenantId: 'tenant_123',
        domain: 'acme.com'
      })).rejects.toThrow('SSO configuration not found');
    });
  });

  describe('verifyDomain', () => {
    it('should verify domain when DNS record matches', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      const mockVerifyDomain = orgSsoRepository.verifyDomain as jest.MockedFunction<typeof orgSsoRepository.verifyDomain>;
      const mockResolveTxt = dns.resolveTxt as jest.MockedFunction<typeof dns.resolveTxt>;

      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);
      mockResolveTxt.mockResolvedValue([['zalt-verify=abc123def456']]);
      mockVerifyDomain.mockResolvedValue({
        ...mockSSOConfig,
        domains: [{
          ...mockSSOConfig.domains[0],
          verificationStatus: 'verified',
          verifiedAt: '2024-01-20T10:00:00Z'
        }]
      });

      const result = await verifyDomain({
        tenantId: 'tenant_123',
        domain: 'acme.com'
      });

      expect(result.success).toBe(true);
      expect(result.status).toBe('verified');
    });

    it('should return already verified for verified domains', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);

      const result = await verifyDomain({
        tenantId: 'tenant_123',
        domain: 'verified.com'
      });

      expect(result.success).toBe(true);
      expect(result.status).toBe('verified');
    });

    it('should fail verification when DNS record does not match', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      const mockResolveTxt = dns.resolveTxt as jest.MockedFunction<typeof dns.resolveTxt>;

      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);
      mockResolveTxt.mockResolvedValue([['wrong-token']]);

      const result = await verifyDomain({
        tenantId: 'tenant_123',
        domain: 'acme.com'
      });

      expect(result.success).toBe(false);
      expect(result.status).toBe('failed');
      expect(result.error).toContain('DNS TXT record not found');
    });

    it('should throw error if domain not found in config', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);

      await expect(verifyDomain({
        tenantId: 'tenant_123',
        domain: 'unknown.com'
      })).rejects.toThrow('Domain unknown.com not found');
    });
  });

  describe('removeDomain', () => {
    it('should remove domain successfully', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      const mockRemoveDomain = orgSsoRepository.removeDomain as jest.MockedFunction<typeof orgSsoRepository.removeDomain>;

      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);
      mockRemoveDomain.mockResolvedValue({
        ...mockSSOConfig,
        domains: [mockSSOConfig.domains[1]]
      });

      const result = await removeDomain({
        tenantId: 'tenant_123',
        domain: 'acme.com'
      });

      expect(result).toBe(true);
    });

    it('should throw error when removing only verified domain with enforcement enabled', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        enforced: true,
        domains: [{
          domain: 'only-verified.com',
          verificationStatus: 'verified',
          verifiedAt: '2024-01-15T10:00:00Z'
        }]
      });

      await expect(removeDomain({
        tenantId: 'tenant_123',
        domain: 'only-verified.com'
      })).rejects.toThrow('Cannot remove the only verified domain');
    });
  });

  describe('getDomainStatus', () => {
    it('should return domain status for existing domain', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);

      const result = await getDomainStatus('tenant_123', 'acme.com');

      expect(result).not.toBeNull();
      expect(result?.domain).toBe('acme.com');
      expect(result?.verificationStatus).toBe('pending');
      expect(result?.verificationToken).toBe('zalt-verify=abc123def456');
    });

    it('should return null for non-existent domain', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);

      const result = await getDomainStatus('tenant_123', 'unknown.com');

      expect(result).toBeNull();
    });

    it('should not expose token for verified domains', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);

      const result = await getDomainStatus('tenant_123', 'verified.com');

      expect(result).not.toBeNull();
      expect(result?.verificationStatus).toBe('verified');
      expect(result?.verificationToken).toBeUndefined();
    });
  });

  describe('listDomains', () => {
    it('should list all domains for a tenant', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);

      const result = await listDomains('tenant_123');

      expect(result).toHaveLength(2);
      expect(result[0].domain).toBe('acme.com');
      expect(result[1].domain).toBe('verified.com');
    });

    it('should return empty array if no SSO config', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue(null);

      const result = await listDomains('tenant_123');

      expect(result).toEqual([]);
    });
  });

  describe('checkSSOEnforcement', () => {
    it('should return enforced=true for verified domain with enforcement', async () => {
      const mockGetEnforcedSSO = orgSsoRepository.getEnforcedSSOForEmail as jest.MockedFunction<typeof orgSsoRepository.getEnforcedSSOForEmail>;
      mockGetEnforcedSSO.mockResolvedValue({
        ...mockSSOConfig,
        enforced: true,
        domains: [{
          domain: 'enforced.com',
          verificationStatus: 'verified',
          verifiedAt: '2024-01-15T10:00:00Z'
        }]
      });

      const result = await checkSSOEnforcement('user@enforced.com');

      expect(result.enforced).toBe(true);
      expect(result.tenantId).toBe('tenant_123');
      expect(result.ssoType).toBe('saml');
    });

    it('should return enforced=false for non-enforced domain', async () => {
      const mockGetEnforcedSSO = orgSsoRepository.getEnforcedSSOForEmail as jest.MockedFunction<typeof orgSsoRepository.getEnforcedSSOForEmail>;
      mockGetEnforcedSSO.mockResolvedValue(null);

      const result = await checkSSOEnforcement('user@nonenforced.com');

      expect(result.enforced).toBe(false);
    });

    it('should return enforced=false for invalid email', async () => {
      const result = await checkSSOEnforcement('invalid-email');

      expect(result.enforced).toBe(false);
      expect(result.reason).toBe('Invalid email format');
    });
  });

  describe('enableSSOEnforcement', () => {
    it('should enable enforcement when verified domain exists', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      const mockUpdateSSOConfig = orgSsoRepository.updateSSOConfig as jest.MockedFunction<typeof orgSsoRepository.updateSSOConfig>;

      mockGetSSOConfig.mockResolvedValue(mockSSOConfig);
      mockUpdateSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        enforced: true
      });

      const result = await enableSSOEnforcement('tenant_123');

      expect(result).toBe(true);
      expect(mockUpdateSSOConfig).toHaveBeenCalledWith('tenant_123', { enforced: true });
    });

    it('should throw error when no verified domains exist', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        domains: [{
          domain: 'pending.com',
          verificationStatus: 'pending'
        }]
      });

      await expect(enableSSOEnforcement('tenant_123'))
        .rejects.toThrow('At least one verified domain is required');
    });

    it('should throw error when SSO is not enabled', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        enabled: false
      });

      await expect(enableSSOEnforcement('tenant_123'))
        .rejects.toThrow('SSO must be enabled before enforcement');
    });
  });

  describe('disableSSOEnforcement', () => {
    it('should disable enforcement successfully', async () => {
      const mockGetSSOConfig = orgSsoRepository.getSSOConfig as jest.MockedFunction<typeof orgSsoRepository.getSSOConfig>;
      const mockUpdateSSOConfig = orgSsoRepository.updateSSOConfig as jest.MockedFunction<typeof orgSsoRepository.updateSSOConfig>;

      mockGetSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        enforced: true
      });
      mockUpdateSSOConfig.mockResolvedValue({
        ...mockSSOConfig,
        enforced: false
      });

      const result = await disableSSOEnforcement('tenant_123');

      expect(result).toBe(true);
      expect(mockUpdateSSOConfig).toHaveBeenCalledWith('tenant_123', { enforced: false });
    });
  });

  describe('validateDomainForTenant', () => {
    it('should return valid for new domain', async () => {
      const mockGetSSOConfigByDomain = orgSsoRepository.getSSOConfigByDomain as jest.MockedFunction<typeof orgSsoRepository.getSSOConfigByDomain>;
      mockGetSSOConfigByDomain.mockResolvedValue(null);

      const result = await validateDomainForTenant('newdomain.com', 'tenant_123');

      expect(result.valid).toBe(true);
    });

    it('should return valid for domain already owned by same tenant', async () => {
      const mockGetSSOConfigByDomain = orgSsoRepository.getSSOConfigByDomain as jest.MockedFunction<typeof orgSsoRepository.getSSOConfigByDomain>;
      mockGetSSOConfigByDomain.mockResolvedValue(mockSSOConfig);

      const result = await validateDomainForTenant('acme.com', 'tenant_123');

      expect(result.valid).toBe(true);
    });

    it('should return invalid for domain owned by another tenant', async () => {
      const mockGetSSOConfigByDomain = orgSsoRepository.getSSOConfigByDomain as jest.MockedFunction<typeof orgSsoRepository.getSSOConfigByDomain>;
      mockGetSSOConfigByDomain.mockResolvedValue({
        ...mockSSOConfig,
        tenantId: 'other_tenant'
      });

      const result = await validateDomainForTenant('acme.com', 'tenant_123');

      expect(result.valid).toBe(false);
      expect(result.error).toContain('already claimed');
    });

    it('should return invalid for malformed domain', async () => {
      const result = await validateDomainForTenant('not-a-domain', 'tenant_123');

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid domain format');
    });
  });
});
