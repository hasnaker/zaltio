/**
 * Organization SSO Model Tests
 * 
 * Tests for OrgSSO model helper functions and validation
 * 
 * Validates: Requirements 9.1, 9.2 (Organization-Level SSO)
 */

import {
  generateSSOConfigId,
  generateDomainVerificationToken,
  generateSPEntityId,
  generateACSUrl,
  generateSLOUrl,
  isValidCertificate,
  getCertificateFingerprint,
  isValidDomain,
  isValidSSOType,
  isValidSSOConfigStatus,
  isDomainVerified,
  emailMatchesVerifiedDomain,
  toOrgSSOConfigResponse,
  getDefaultAttributeMapping,
  createDefaultJITConfig,
  SSO_CONFIG_ID_PREFIX,
  DOMAIN_VERIFICATION_PREFIX,
  DEFAULT_OIDC_SCOPES,
  OrgSSOConfig,
  VerifiedDomain
} from './org-sso.model';

describe('OrgSSO Model', () => {
  describe('ID Generation', () => {
    describe('generateSSOConfigId', () => {
      it('should generate ID with correct prefix', () => {
        const id = generateSSOConfigId();
        expect(id).toMatch(new RegExp(`^${SSO_CONFIG_ID_PREFIX}`));
      });

      it('should generate unique IDs', () => {
        const ids = new Set<string>();
        for (let i = 0; i < 100; i++) {
          ids.add(generateSSOConfigId());
        }
        expect(ids.size).toBe(100);
      });

      it('should generate IDs of consistent length', () => {
        const id1 = generateSSOConfigId();
        const id2 = generateSSOConfigId();
        expect(id1.length).toBe(id2.length);
      });
    });

    describe('generateDomainVerificationToken', () => {
      it('should generate token with correct prefix', () => {
        const token = generateDomainVerificationToken();
        expect(token).toMatch(new RegExp(`^${DOMAIN_VERIFICATION_PREFIX}`));
      });

      it('should generate unique tokens', () => {
        const tokens = new Set<string>();
        for (let i = 0; i < 100; i++) {
          tokens.add(generateDomainVerificationToken());
        }
        expect(tokens.size).toBe(100);
      });
    });
  });

  describe('SP URL Generation', () => {
    const realmId = 'test-realm';
    const tenantId = 'ten_123';

    beforeEach(() => {
      process.env.API_BASE_URL = 'https://api.zalt.io';
    });

    describe('generateSPEntityId', () => {
      it('should generate correct SP Entity ID', () => {
        const entityId = generateSPEntityId(realmId, tenantId);
        expect(entityId).toBe(`https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}`);
      });
    });

    describe('generateACSUrl', () => {
      it('should generate correct ACS URL', () => {
        const acsUrl = generateACSUrl(realmId, tenantId);
        expect(acsUrl).toBe(`https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}/acs`);
      });
    });

    describe('generateSLOUrl', () => {
      it('should generate correct SLO URL', () => {
        const sloUrl = generateSLOUrl(realmId, tenantId);
        expect(sloUrl).toBe(`https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}/slo`);
      });
    });
  });

  describe('Certificate Validation', () => {
    const validCert = `-----BEGIN CERTIFICATE-----
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

    describe('isValidCertificate', () => {
      it('should return true for valid PEM certificate', () => {
        expect(isValidCertificate(validCert)).toBe(true);
      });

      it('should return true for certificate with extra whitespace', () => {
        const certWithWhitespace = `  ${validCert}  `;
        expect(isValidCertificate(certWithWhitespace)).toBe(true);
      });

      it('should return false for invalid certificate', () => {
        expect(isValidCertificate('not a certificate')).toBe(false);
      });

      it('should return false for empty string', () => {
        expect(isValidCertificate('')).toBe(false);
      });

      it('should return false for certificate without headers', () => {
        expect(isValidCertificate('MIICpDCCAYwCCQDU+pQ4P2cM7TANBgkqhkiG9w0BAQsFADA=')).toBe(false);
      });
    });

    describe('getCertificateFingerprint', () => {
      it('should return SHA-256 fingerprint in uppercase hex', () => {
        const fingerprint = getCertificateFingerprint(validCert);
        expect(fingerprint).toMatch(/^[A-F0-9]+$/);
        expect(fingerprint.length).toBe(64); // SHA-256 = 32 bytes = 64 hex chars
      });

      it('should return consistent fingerprint for same certificate', () => {
        const fp1 = getCertificateFingerprint(validCert);
        const fp2 = getCertificateFingerprint(validCert);
        expect(fp1).toBe(fp2);
      });
    });
  });

  describe('Domain Validation', () => {
    describe('isValidDomain', () => {
      it('should return true for valid domains', () => {
        expect(isValidDomain('example.com')).toBe(true);
        expect(isValidDomain('sub.example.com')).toBe(true);
        expect(isValidDomain('my-company.co.uk')).toBe(true);
        expect(isValidDomain('test123.org')).toBe(true);
      });

      it('should return false for invalid domains', () => {
        expect(isValidDomain('')).toBe(false);
        expect(isValidDomain('localhost')).toBe(false);
        expect(isValidDomain('example')).toBe(false);
        expect(isValidDomain('.com')).toBe(false);
        expect(isValidDomain('example.')).toBe(false);
        expect(isValidDomain('exam ple.com')).toBe(false);
        expect(isValidDomain('http://example.com')).toBe(false);
      });
    });
  });

  describe('Type Validation', () => {
    describe('isValidSSOType', () => {
      it('should return true for valid SSO types', () => {
        expect(isValidSSOType('saml')).toBe(true);
        expect(isValidSSOType('oidc')).toBe(true);
      });

      it('should return false for invalid SSO types', () => {
        expect(isValidSSOType('oauth')).toBe(false);
        expect(isValidSSOType('')).toBe(false);
        expect(isValidSSOType('SAML')).toBe(false);
      });
    });

    describe('isValidSSOConfigStatus', () => {
      it('should return true for valid statuses', () => {
        expect(isValidSSOConfigStatus('active')).toBe(true);
        expect(isValidSSOConfigStatus('inactive')).toBe(true);
        expect(isValidSSOConfigStatus('pending_verification')).toBe(true);
        expect(isValidSSOConfigStatus('deleted')).toBe(true);
      });

      it('should return false for invalid statuses', () => {
        expect(isValidSSOConfigStatus('enabled')).toBe(false);
        expect(isValidSSOConfigStatus('')).toBe(false);
        expect(isValidSSOConfigStatus('ACTIVE')).toBe(false);
      });
    });
  });

  describe('Domain Verification Helpers', () => {
    const verifiedDomains: VerifiedDomain[] = [
      { domain: 'acme.com', verificationStatus: 'verified', verifiedAt: '2024-01-01T00:00:00Z' },
      { domain: 'pending.com', verificationStatus: 'pending' },
      { domain: 'failed.com', verificationStatus: 'failed' }
    ];

    describe('isDomainVerified', () => {
      it('should return true for verified domain', () => {
        expect(isDomainVerified(verifiedDomains, 'acme.com')).toBe(true);
      });

      it('should return true for verified domain (case insensitive)', () => {
        expect(isDomainVerified(verifiedDomains, 'ACME.COM')).toBe(true);
      });

      it('should return false for pending domain', () => {
        expect(isDomainVerified(verifiedDomains, 'pending.com')).toBe(false);
      });

      it('should return false for failed domain', () => {
        expect(isDomainVerified(verifiedDomains, 'failed.com')).toBe(false);
      });

      it('should return false for non-existent domain', () => {
        expect(isDomainVerified(verifiedDomains, 'unknown.com')).toBe(false);
      });
    });

    describe('emailMatchesVerifiedDomain', () => {
      it('should return true for email with verified domain', () => {
        expect(emailMatchesVerifiedDomain('user@acme.com', verifiedDomains)).toBe(true);
      });

      it('should return true for email with verified domain (case insensitive)', () => {
        expect(emailMatchesVerifiedDomain('user@ACME.COM', verifiedDomains)).toBe(true);
      });

      it('should return false for email with pending domain', () => {
        expect(emailMatchesVerifiedDomain('user@pending.com', verifiedDomains)).toBe(false);
      });

      it('should return false for email with unknown domain', () => {
        expect(emailMatchesVerifiedDomain('user@unknown.com', verifiedDomains)).toBe(false);
      });

      it('should return false for invalid email', () => {
        expect(emailMatchesVerifiedDomain('invalid-email', verifiedDomains)).toBe(false);
      });
    });
  });

  describe('Response Conversion', () => {
    describe('toOrgSSOConfigResponse', () => {
      const mockConfig: OrgSSOConfig = {
        id: 'sso_config_123',
        tenantId: 'ten_123',
        realmId: 'test-realm',
        ssoType: 'saml',
        enabled: true,
        status: 'active',
        providerName: 'Okta',
        samlConfig: {
          idpEntityId: 'https://okta.com/entity',
          idpSsoUrl: 'https://okta.com/sso',
          idpCertificate: '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----'
        },
        spEntityId: 'https://api.zalt.io/v1/sso/saml/test-realm/ten_123',
        acsUrl: 'https://api.zalt.io/v1/sso/saml/test-realm/ten_123/acs',
        sloUrl: 'https://api.zalt.io/v1/sso/saml/test-realm/ten_123/slo',
        domains: [{ domain: 'acme.com', verificationStatus: 'verified' }],
        enforced: true,
        jitProvisioning: {
          enabled: true,
          defaultRole: 'member',
          autoVerifyEmail: true,
          syncGroups: false
        },
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-02T00:00:00Z',
        totalLogins: 100
      };

      it('should convert config to response format', () => {
        const response = toOrgSSOConfigResponse(mockConfig);
        
        expect(response.id).toBe(mockConfig.id);
        expect(response.tenantId).toBe(mockConfig.tenantId);
        expect(response.ssoType).toBe(mockConfig.ssoType);
        expect(response.enabled).toBe(mockConfig.enabled);
        expect(response.providerName).toBe(mockConfig.providerName);
        expect(response.idpEntityId).toBe(mockConfig.samlConfig?.idpEntityId);
        expect(response.idpSsoUrl).toBe(mockConfig.samlConfig?.idpSsoUrl);
      });

      it('should not include sensitive data like certificate', () => {
        const response = toOrgSSOConfigResponse(mockConfig);
        
        expect(response).not.toHaveProperty('samlConfig');
        expect(response).not.toHaveProperty('oidcConfig');
      });

      it('should include domains and JIT config', () => {
        const response = toOrgSSOConfigResponse(mockConfig);
        
        expect(response.domains).toEqual(mockConfig.domains);
        expect(response.jitProvisioning).toEqual(mockConfig.jitProvisioning);
      });
    });
  });

  describe('Default Configurations', () => {
    describe('getDefaultAttributeMapping', () => {
      it('should return Google Workspace mapping', () => {
        const mapping = getDefaultAttributeMapping('google_workspace');
        expect(mapping.email).toBe('email');
        expect(mapping.firstName).toBe('given_name');
        expect(mapping.lastName).toBe('family_name');
      });

      it('should return Microsoft Entra mapping', () => {
        const mapping = getDefaultAttributeMapping('microsoft_entra');
        expect(mapping.email).toBe('email');
        expect(mapping.groups).toBe('groups');
      });

      it('should return Okta mapping', () => {
        const mapping = getDefaultAttributeMapping('okta');
        expect(mapping.email).toBe('email');
        expect(mapping.groups).toBe('groups');
      });

      it('should return SAML default mapping for undefined provider', () => {
        const mapping = getDefaultAttributeMapping(undefined);
        expect(mapping.email).toContain('schemas.xmlsoap.org');
      });
    });

    describe('createDefaultJITConfig', () => {
      it('should return default JIT configuration', () => {
        const config = createDefaultJITConfig();
        
        expect(config.enabled).toBe(false);
        expect(config.defaultRole).toBe('member');
        expect(config.autoVerifyEmail).toBe(true);
        expect(config.syncGroups).toBe(false);
      });
    });

    describe('DEFAULT_OIDC_SCOPES', () => {
      it('should include required OIDC scopes', () => {
        expect(DEFAULT_OIDC_SCOPES).toContain('openid');
        expect(DEFAULT_OIDC_SCOPES).toContain('email');
        expect(DEFAULT_OIDC_SCOPES).toContain('profile');
      });
    });
  });
});

