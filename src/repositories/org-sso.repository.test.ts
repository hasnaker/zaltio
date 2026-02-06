/**
 * Organization SSO Repository Tests
 * 
 * Tests for OrgSSO repository DynamoDB operations
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 * 
 * Validates: Requirements 9.1, 9.2 (Organization-Level SSO)
 */

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  }
}));

// Import after mocks
import {
  createSSOConfig,
  getSSOConfig,
  getSSOConfigByDomain,
  getEnforcedSSOForEmail,
  updateSSOConfig,
  addDomain,
  verifyDomain,
  removeDomain,
  recordSSOLogin,
  deleteSSOConfig,
  hardDeleteSSOConfig
} from './org-sso.repository';
import {
  CreateOrgSSOConfigInput,
  OrgSSOConfig,
  SSO_CONFIG_ID_PREFIX,
  DOMAIN_VERIFICATION_PREFIX
} from '../models/org-sso.model';

// Test constants
const TEST_REALM_ID = 'test-realm-sso';
const TEST_TENANT_ID = 'ten_test_123';

// Valid test certificate
const TEST_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P2cM7TANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7VvX3hXLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLq
LqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLq
LqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLq
LqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLq
LqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLq
LqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLqLq
-----END CERTIFICATE-----`;

// Helper to create mock SSO config
function createMockSSOConfig(overrides?: Partial<OrgSSOConfig>): OrgSSOConfig {
  return {
    id: 'sso_config_abc123',
    tenantId: TEST_TENANT_ID,
    realmId: TEST_REALM_ID,
    ssoType: 'saml',
    enabled: false,
    status: 'pending_verification',
    providerName: 'Test IdP',
    samlConfig: {
      idpEntityId: 'https://test-idp.com/entity',
      idpSsoUrl: 'https://test-idp.com/sso',
      idpCertificate: TEST_CERTIFICATE,
      idpCertificateFingerprint: 'ABC123',
      wantAssertionsSigned: true,
      signAuthnRequests: true
    },
    spEntityId: `https://api.zalt.io/v1/sso/saml/${TEST_REALM_ID}/${TEST_TENANT_ID}`,
    acsUrl: `https://api.zalt.io/v1/sso/saml/${TEST_REALM_ID}/${TEST_TENANT_ID}/acs`,
    sloUrl: `https://api.zalt.io/v1/sso/saml/${TEST_REALM_ID}/${TEST_TENANT_ID}/slo`,
    domains: [
      {
        domain: 'test.com',
        verificationStatus: 'pending',
        verificationToken: 'zalt-verify=abc123'
      }
    ],
    enforced: false,
    jitProvisioning: {
      enabled: false,
      defaultRole: 'member',
      autoVerifyEmail: true,
      syncGroups: false
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    totalLogins: 0,
    ...overrides
  };
}

describe('OrgSSO Repository', () => {
  beforeEach(() => {
    mockSend.mockReset();
    process.env.API_BASE_URL = 'https://api.zalt.io';
  });

  describe('createSSOConfig', () => {
    it('should create SAML SSO configuration', async () => {
      // Mock getSSOConfig (check for existing)
      mockSend.mockResolvedValueOnce({ Item: undefined });
      // Mock PutCommand
      mockSend.mockResolvedValueOnce({});
      
      const input: CreateOrgSSOConfigInput = {
        tenantId: TEST_TENANT_ID,
        realmId: TEST_REALM_ID,
        ssoType: 'saml',
        providerName: 'Test IdP',
        samlConfig: {
          idpEntityId: 'https://test-idp.com/entity',
          idpSsoUrl: 'https://test-idp.com/sso',
          idpCertificate: TEST_CERTIFICATE
        },
        domains: ['test.com'],
        createdBy: 'test-user'
      };
      
      const config = await createSSOConfig(input);
      
      expect(config).toBeDefined();
      expect(config.id).toMatch(new RegExp(`^${SSO_CONFIG_ID_PREFIX}`));
      expect(config.tenantId).toBe(TEST_TENANT_ID);
      expect(config.realmId).toBe(TEST_REALM_ID);
      expect(config.ssoType).toBe('saml');
      expect(config.providerName).toBe('Test IdP');
      expect(config.enabled).toBe(false); // Starts disabled
      expect(config.status).toBe('pending_verification');
      expect(config.samlConfig?.idpEntityId).toBe('https://test-idp.com/entity');
      expect(config.samlConfig?.idpCertificateFingerprint).toBeDefined();
      expect(config.spEntityId).toContain(TEST_TENANT_ID);
      expect(config.acsUrl).toContain('/acs');
      expect(config.domains.length).toBe(1);
      expect(config.domains[0].verificationStatus).toBe('pending');
      expect(config.domains[0].verificationToken).toMatch(new RegExp(`^${DOMAIN_VERIFICATION_PREFIX}`));
      
      expect(mockSend).toHaveBeenCalledTimes(2);
    });

    it('should create OIDC SSO configuration', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      mockSend.mockResolvedValueOnce({});
      
      const input: CreateOrgSSOConfigInput = {
        tenantId: TEST_TENANT_ID,
        realmId: TEST_REALM_ID,
        ssoType: 'oidc',
        providerName: 'Google Workspace',
        oidcConfig: {
          providerPreset: 'google_workspace',
          issuer: 'https://accounts.google.com',
          clientId: 'test-client-id'
        },
        domains: ['test.com']
      };
      
      const config = await createSSOConfig(input);
      
      expect(config.ssoType).toBe('oidc');
      expect(config.oidcConfig?.issuer).toBe('https://accounts.google.com');
      expect(config.oidcConfig?.clientId).toBe('test-client-id');
      expect(config.oidcConfig?.scopes).toContain('openid');
    });

    it('should reject duplicate SSO config for same tenant', async () => {
      // Mock getSSOConfig returning existing config
      mockSend.mockResolvedValueOnce({ Item: createMockSSOConfig() });
      
      const input: CreateOrgSSOConfigInput = {
        tenantId: TEST_TENANT_ID,
        realmId: TEST_REALM_ID,
        ssoType: 'saml',
        providerName: 'Test IdP',
        samlConfig: {
          idpEntityId: 'https://test-idp.com/entity',
          idpSsoUrl: 'https://test-idp.com/sso',
          idpCertificate: TEST_CERTIFICATE
        }
      };
      
      await expect(createSSOConfig(input)).rejects.toThrow('already has SSO configuration');
    });

    it('should reject invalid certificate', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      
      const input: CreateOrgSSOConfigInput = {
        tenantId: TEST_TENANT_ID,
        realmId: TEST_REALM_ID,
        ssoType: 'saml',
        providerName: 'Test IdP',
        samlConfig: {
          idpEntityId: 'https://test-idp.com/entity',
          idpSsoUrl: 'https://test-idp.com/sso',
          idpCertificate: 'invalid-certificate'
        }
      };
      
      await expect(createSSOConfig(input)).rejects.toThrow('Invalid X.509 certificate');
    });

    it('should reject invalid domain format', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      
      const input: CreateOrgSSOConfigInput = {
        tenantId: TEST_TENANT_ID,
        realmId: TEST_REALM_ID,
        ssoType: 'saml',
        providerName: 'Test IdP',
        samlConfig: {
          idpEntityId: 'https://test-idp.com/entity',
          idpSsoUrl: 'https://test-idp.com/sso',
          idpCertificate: TEST_CERTIFICATE
        },
        domains: ['invalid-domain']
      };
      
      await expect(createSSOConfig(input)).rejects.toThrow('Invalid domain format');
    });

    it('should set default JIT provisioning config', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      mockSend.mockResolvedValueOnce({});
      
      const input: CreateOrgSSOConfigInput = {
        tenantId: TEST_TENANT_ID,
        realmId: TEST_REALM_ID,
        ssoType: 'saml',
        providerName: 'Test IdP',
        samlConfig: {
          idpEntityId: 'https://test-idp.com/entity',
          idpSsoUrl: 'https://test-idp.com/sso',
          idpCertificate: TEST_CERTIFICATE
        }
      };
      
      const config = await createSSOConfig(input);
      
      expect(config.jitProvisioning).toBeDefined();
      expect(config.jitProvisioning.enabled).toBe(false);
      expect(config.jitProvisioning.defaultRole).toBe('member');
      expect(config.jitProvisioning.autoVerifyEmail).toBe(true);
    });

    it('should allow custom JIT provisioning config', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      mockSend.mockResolvedValueOnce({});
      
      const input: CreateOrgSSOConfigInput = {
        tenantId: TEST_TENANT_ID,
        realmId: TEST_REALM_ID,
        ssoType: 'saml',
        providerName: 'Test IdP',
        samlConfig: {
          idpEntityId: 'https://test-idp.com/entity',
          idpSsoUrl: 'https://test-idp.com/sso',
          idpCertificate: TEST_CERTIFICATE
        },
        jitProvisioning: {
          enabled: true,
          defaultRole: 'admin',
          syncGroups: true
        }
      };
      
      const config = await createSSOConfig(input);
      
      expect(config.jitProvisioning.enabled).toBe(true);
      expect(config.jitProvisioning.defaultRole).toBe('admin');
      expect(config.jitProvisioning.syncGroups).toBe(true);
    });

    it('should set status to inactive when no domains provided', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      mockSend.mockResolvedValueOnce({});
      
      const input: CreateOrgSSOConfigInput = {
        tenantId: TEST_TENANT_ID,
        realmId: TEST_REALM_ID,
        ssoType: 'saml',
        providerName: 'Test IdP',
        samlConfig: {
          idpEntityId: 'https://test-idp.com/entity',
          idpSsoUrl: 'https://test-idp.com/sso',
          idpCertificate: TEST_CERTIFICATE
        },
        domains: [] // No domains
      };
      
      const config = await createSSOConfig(input);
      
      expect(config.status).toBe('inactive');
    });
  });

  describe('getSSOConfig', () => {
    it('should retrieve existing SSO config', async () => {
      const mockConfig = createMockSSOConfig();
      mockSend.mockResolvedValueOnce({ Item: mockConfig });
      
      const retrieved = await getSSOConfig(TEST_TENANT_ID);
      
      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(mockConfig.id);
      expect(retrieved?.tenantId).toBe(TEST_TENANT_ID);
      expect(retrieved?.providerName).toBe('Test IdP');
    });

    it('should return null for non-existent config', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      
      const result = await getSSOConfig('non-existent-tenant');
      
      expect(result).toBeNull();
    });
  });

  describe('getSSOConfigByDomain', () => {
    it('should return config for verified domain', async () => {
      const mockConfig = createMockSSOConfig({
        domains: [
          {
            domain: 'verified.com',
            verificationStatus: 'verified',
            verifiedAt: '2024-01-01T00:00:00Z'
          }
        ]
      });
      
      mockSend.mockResolvedValueOnce({ Items: [mockConfig] });
      
      const result = await getSSOConfigByDomain('verified.com');
      
      expect(result).toBeDefined();
      expect(result?.tenantId).toBe(TEST_TENANT_ID);
    });

    it('should return null for unverified domain', async () => {
      const mockConfig = createMockSSOConfig({
        domains: [
          {
            domain: 'pending.com',
            verificationStatus: 'pending'
          }
        ]
      });
      
      mockSend.mockResolvedValueOnce({ Items: [mockConfig] });
      
      const result = await getSSOConfigByDomain('pending.com');
      
      expect(result).toBeNull();
    });

    it('should return null for unknown domain', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await getSSOConfigByDomain('unknown.com');
      
      expect(result).toBeNull();
    });
  });

  describe('updateSSOConfig', () => {
    it('should update provider name', async () => {
      const mockConfig = createMockSSOConfig();
      mockSend.mockResolvedValueOnce({ Item: mockConfig }); // getSSOConfig
      mockSend.mockResolvedValueOnce({ 
        Attributes: { ...mockConfig, providerName: 'Updated IdP' } 
      }); // UpdateCommand
      
      const updated = await updateSSOConfig(TEST_TENANT_ID, {
        providerName: 'Updated IdP'
      });
      
      expect(updated?.providerName).toBe('Updated IdP');
    });

    it('should update enabled status', async () => {
      const mockConfig = createMockSSOConfig();
      mockSend.mockResolvedValueOnce({ Item: mockConfig });
      mockSend.mockResolvedValueOnce({ 
        Attributes: { ...mockConfig, enabled: true } 
      });
      
      const updated = await updateSSOConfig(TEST_TENANT_ID, {
        enabled: true
      });
      
      expect(updated?.enabled).toBe(true);
    });

    it('should update SAML config', async () => {
      const mockConfig = createMockSSOConfig();
      mockSend.mockResolvedValueOnce({ Item: mockConfig });
      mockSend.mockResolvedValueOnce({ 
        Attributes: { 
          ...mockConfig, 
          samlConfig: { 
            ...mockConfig.samlConfig, 
            idpSsoUrl: 'https://new-idp.com/sso' 
          } 
        } 
      });
      
      const updated = await updateSSOConfig(TEST_TENANT_ID, {
        samlConfig: {
          idpSsoUrl: 'https://new-idp.com/sso'
        }
      });
      
      expect(updated?.samlConfig?.idpSsoUrl).toBe('https://new-idp.com/sso');
    });

    it('should update JIT provisioning config', async () => {
      const mockConfig = createMockSSOConfig();
      mockSend.mockResolvedValueOnce({ Item: mockConfig });
      mockSend.mockResolvedValueOnce({ 
        Attributes: { 
          ...mockConfig, 
          jitProvisioning: { 
            ...mockConfig.jitProvisioning, 
            enabled: true,
            syncGroups: true 
          } 
        } 
      });
      
      const updated = await updateSSOConfig(TEST_TENANT_ID, {
        jitProvisioning: {
          enabled: true,
          syncGroups: true
        }
      });
      
      expect(updated?.jitProvisioning.enabled).toBe(true);
      expect(updated?.jitProvisioning.syncGroups).toBe(true);
    });

    it('should return null for non-existent config', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      
      const result = await updateSSOConfig('non-existent-tenant', {
        providerName: 'Test'
      });
      
      expect(result).toBeNull();
    });

    it('should reject invalid certificate on update', async () => {
      const mockConfig = createMockSSOConfig();
      mockSend.mockResolvedValueOnce({ Item: mockConfig });
      
      await expect(updateSSOConfig(TEST_TENANT_ID, {
        samlConfig: {
          idpCertificate: 'invalid-cert'
        }
      })).rejects.toThrow('Invalid X.509 certificate');
    });
  });

  describe('Domain Management', () => {
    describe('addDomain', () => {
      it('should add new domain to config', async () => {
        const mockConfig = createMockSSOConfig();
        mockSend.mockResolvedValueOnce({ Item: mockConfig }); // getSSOConfig
        mockSend.mockResolvedValueOnce({ 
          Attributes: { 
            ...mockConfig, 
            domains: [
              ...mockConfig.domains,
              { domain: 'newdomain.com', verificationStatus: 'pending', verificationToken: 'zalt-verify=xyz' }
            ] 
          } 
        }); // UpdateCommand
        
        const updated = await addDomain(TEST_TENANT_ID, 'newdomain.com');
        
        expect(updated?.domains.length).toBe(2);
        const newDomain = updated?.domains.find(d => d.domain === 'newdomain.com');
        expect(newDomain).toBeDefined();
        expect(newDomain?.verificationStatus).toBe('pending');
      });

      it('should reject duplicate domain', async () => {
        const mockConfig = createMockSSOConfig({
          domains: [{ domain: 'existing.com', verificationStatus: 'verified' }]
        });
        mockSend.mockResolvedValueOnce({ Item: mockConfig });
        
        await expect(addDomain(TEST_TENANT_ID, 'existing.com')).rejects.toThrow('already exists');
      });

      it('should reject invalid domain format', async () => {
        const mockConfig = createMockSSOConfig();
        mockSend.mockResolvedValueOnce({ Item: mockConfig });
        
        await expect(addDomain(TEST_TENANT_ID, 'invalid')).rejects.toThrow('Invalid domain format');
      });

      it('should return null for non-existent config', async () => {
        mockSend.mockResolvedValueOnce({ Item: undefined });
        
        const result = await addDomain('non-existent', 'test.com');
        
        expect(result).toBeNull();
      });
    });

    describe('verifyDomain', () => {
      it('should verify pending domain', async () => {
        const mockConfig = createMockSSOConfig({
          domains: [{ domain: 'verify-test.com', verificationStatus: 'pending' }]
        });
        mockSend.mockResolvedValueOnce({ Item: mockConfig });
        mockSend.mockResolvedValueOnce({ 
          Attributes: { 
            ...mockConfig, 
            domains: [{ domain: 'verify-test.com', verificationStatus: 'verified', verifiedAt: '2024-01-02T00:00:00Z' }],
            status: 'active'
          } 
        });
        
        const updated = await verifyDomain(TEST_TENANT_ID, 'verify-test.com');
        
        const domain = updated?.domains.find(d => d.domain === 'verify-test.com');
        expect(domain?.verificationStatus).toBe('verified');
        expect(domain?.verifiedAt).toBeDefined();
      });

      it('should update status to active when all domains verified', async () => {
        const mockConfig = createMockSSOConfig({
          domains: [{ domain: 'single-domain.com', verificationStatus: 'pending' }]
        });
        mockSend.mockResolvedValueOnce({ Item: mockConfig });
        mockSend.mockResolvedValueOnce({ 
          Attributes: { 
            ...mockConfig, 
            domains: [{ domain: 'single-domain.com', verificationStatus: 'verified' }],
            status: 'active'
          } 
        });
        
        const updated = await verifyDomain(TEST_TENANT_ID, 'single-domain.com');
        
        expect(updated?.status).toBe('active');
      });

      it('should reject verification of non-existent domain', async () => {
        const mockConfig = createMockSSOConfig();
        mockSend.mockResolvedValueOnce({ Item: mockConfig });
        
        await expect(verifyDomain(TEST_TENANT_ID, 'unknown.com')).rejects.toThrow('not found');
      });
    });

    describe('removeDomain', () => {
      it('should remove domain from config', async () => {
        const mockConfig = createMockSSOConfig({
          domains: [
            { domain: 'domain1.com', verificationStatus: 'verified' },
            { domain: 'domain2.com', verificationStatus: 'verified' }
          ]
        });
        mockSend.mockResolvedValueOnce({ Item: mockConfig });
        mockSend.mockResolvedValueOnce({ 
          Attributes: { 
            ...mockConfig, 
            domains: [{ domain: 'domain2.com', verificationStatus: 'verified' }]
          } 
        });
        
        const updated = await removeDomain(TEST_TENANT_ID, 'domain1.com');
        
        expect(updated?.domains.length).toBe(1);
        expect(updated?.domains[0].domain).toBe('domain2.com');
      });

      it('should reject removal of non-existent domain', async () => {
        const mockConfig = createMockSSOConfig();
        mockSend.mockResolvedValueOnce({ Item: mockConfig });
        
        await expect(removeDomain(TEST_TENANT_ID, 'unknown.com')).rejects.toThrow('not found');
      });
    });
  });

  describe('getEnforcedSSOForEmail', () => {
    it('should return config for enforced SSO domain', async () => {
      const mockConfig = createMockSSOConfig({
        enabled: true,
        enforced: true,
        domains: [{ domain: 'enforced-sso.com', verificationStatus: 'verified' }]
      });
      
      mockSend.mockResolvedValueOnce({ Items: [mockConfig] });
      
      const config = await getEnforcedSSOForEmail('user@enforced-sso.com');
      
      expect(config).toBeDefined();
      expect(config?.tenantId).toBe(TEST_TENANT_ID);
    });

    it('should return null for non-enforced SSO', async () => {
      const mockConfig = createMockSSOConfig({
        enabled: true,
        enforced: false,
        domains: [{ domain: 'non-enforced.com', verificationStatus: 'verified' }]
      });
      
      mockSend.mockResolvedValueOnce({ Items: [mockConfig] });
      
      const config = await getEnforcedSSOForEmail('user@non-enforced.com');
      
      expect(config).toBeNull();
    });

    it('should return null for disabled SSO', async () => {
      const mockConfig = createMockSSOConfig({
        enabled: false,
        enforced: true,
        domains: [{ domain: 'disabled-sso.com', verificationStatus: 'verified' }]
      });
      
      mockSend.mockResolvedValueOnce({ Items: [mockConfig] });
      
      const config = await getEnforcedSSOForEmail('user@disabled-sso.com');
      
      expect(config).toBeNull();
    });

    it('should return null for unknown domain', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const config = await getEnforcedSSOForEmail('user@unknown-domain.com');
      
      expect(config).toBeNull();
    });

    it('should return null for invalid email', async () => {
      const config = await getEnforcedSSOForEmail('invalid-email');
      
      expect(config).toBeNull();
    });
  });

  describe('recordSSOLogin', () => {
    it('should increment login count', async () => {
      mockSend.mockResolvedValueOnce({});
      
      await recordSSOLogin(TEST_TENANT_ID);
      
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should not throw for non-existent config', async () => {
      mockSend.mockRejectedValueOnce(new Error('ConditionalCheckFailedException'));
      
      // Should not throw
      await expect(recordSSOLogin('non-existent')).resolves.not.toThrow();
    });
  });

  describe('deleteSSOConfig', () => {
    it('should soft delete config', async () => {
      const mockConfig = createMockSSOConfig();
      mockSend.mockResolvedValueOnce({ Item: mockConfig }); // getSSOConfig
      mockSend.mockResolvedValueOnce({ 
        Attributes: { ...mockConfig, status: 'deleted', enabled: false, enforced: false } 
      }); // UpdateCommand
      
      const result = await deleteSSOConfig(TEST_TENANT_ID);
      
      expect(result).toBe(true);
    });

    it('should return false for non-existent config', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });
      
      const result = await deleteSSOConfig('non-existent');
      
      expect(result).toBe(false);
    });
  });

  describe('hardDeleteSSOConfig', () => {
    it('should permanently delete config', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const result = await hardDeleteSSOConfig(TEST_TENANT_ID);
      
      expect(result).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
      
      const result = await hardDeleteSSOConfig('non-existent');
      
      expect(result).toBe(false);
    });
  });
});

