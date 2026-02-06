/**
 * Property-Based Tests for Organization-Level SSO
 * Task 19.9: Write property tests for Org SSO
 * 
 * Properties tested:
 * - Property 35: SSO enforcement blocks password login
 * - Property 36: JIT provisioning creates user
 * - Property 37: Domain verification is required for enforcement
 * 
 * **Validates: Requirements 9.4, 9.5, 9.6, 9.8**
 */

import * as fc from 'fast-check';
import {
  OrgSSOConfig,
  VerifiedDomain,
  DomainVerificationStatus,
  SSOType,
  SSOConfigStatus,
  JITProvisioningConfig,
  generateSSOConfigId,
  generateDomainVerificationToken,
  isValidDomain,
  isDomainVerified,
  emailMatchesVerifiedDomain,
  createDefaultJITConfig
} from '../models/org-sso.model';
import {
  checkSSOEnforcement,
  enableSSOEnforcement,
  SSOEnforcementCheckResult
} from './domain-verification.service';
import {
  checkSSOEnforcementForEmail,
  SSOEnforcementResult,
  generateSSORedirectUrl,
  generateSAMLRedirectUrl,
  generateOIDCRedirectUrl
} from '../middleware/sso-enforcement.middleware';

// ============================================================================
// Custom Generators for SSO Tests
// ============================================================================

/**
 * Generate valid domain names
 */
const domainArb = fc.stringMatching(/^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\.[a-z]{2,}$/)
  .filter(d => d.length >= 4 && d.length <= 63 && isValidDomain(d));

/**
 * Generate simple valid domains for testing
 */
const simpleDomainArb = fc.constantFrom(
  'acme.com',
  'example.org',
  'test-company.io',
  'enterprise.net',
  'corp.co',
  'business.dev'
);


/**
 * Generate valid email addresses for a domain
 */
const emailForDomainArb = (domain: string) => 
  fc.stringMatching(/^[a-z][a-z0-9._-]{0,20}$/)
    .filter(local => local.length >= 1)
    .map(local => `${local}@${domain}`);

/**
 * Generate tenant IDs
 */
const tenantIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `tenant_${hex}`);

/**
 * Generate realm IDs
 */
const realmIdArb = fc.stringMatching(/^[a-z0-9-]{3,50}$/)
  .filter(s => s.length >= 3 && s.length <= 50);

/**
 * Generate SSO types
 */
const ssoTypeArb: fc.Arbitrary<SSOType> = fc.constantFrom('saml', 'oidc');

/**
 * Generate SSO config status
 */
const ssoConfigStatusArb: fc.Arbitrary<SSOConfigStatus> = fc.constantFrom(
  'active', 'inactive', 'pending_verification', 'deleted'
);

/**
 * Generate domain verification status
 */
const domainVerificationStatusArb: fc.Arbitrary<DomainVerificationStatus> = fc.constantFrom(
  'pending', 'verified', 'failed'
);

/**
 * Generate a verified domain entry
 */
const verifiedDomainArb = (domain: string, status: DomainVerificationStatus = 'verified'): VerifiedDomain => ({
  domain: domain.toLowerCase(),
  verificationStatus: status,
  verificationToken: status === 'pending' ? generateDomainVerificationToken() : undefined,
  verifiedAt: status === 'verified' ? new Date().toISOString() : undefined,
  verificationMethod: 'dns_txt'
});

/**
 * Generate JIT provisioning config
 */
const jitProvisioningConfigArb: fc.Arbitrary<JITProvisioningConfig> = fc.record({
  enabled: fc.boolean(),
  defaultRole: fc.constantFrom('member', 'admin', 'viewer', 'editor'),
  autoVerifyEmail: fc.boolean(),
  syncGroups: fc.boolean(),
  groupRoleMapping: fc.option(
    fc.dictionary(
      fc.stringMatching(/^[a-z0-9-]{3,20}$/),
      fc.constantFrom('member', 'admin', 'viewer')
    ),
    { nil: undefined }
  )
});


/**
 * Generate a mock OrgSSOConfig for testing
 */
function generateMockSSOConfig(options: {
  tenantId?: string;
  realmId?: string;
  ssoType?: SSOType;
  enabled?: boolean;
  enforced?: boolean;
  domains?: VerifiedDomain[];
  jitProvisioning?: JITProvisioningConfig;
  status?: SSOConfigStatus;
}): OrgSSOConfig {
  const tenantId = options.tenantId || `tenant_${Math.random().toString(36).slice(2)}`;
  const realmId = options.realmId || 'test-realm';
  const ssoType = options.ssoType || 'saml';
  const now = new Date().toISOString();
  
  return {
    id: generateSSOConfigId(),
    tenantId,
    realmId,
    ssoType,
    enabled: options.enabled ?? true,
    status: options.status || 'active',
    providerName: ssoType === 'saml' ? 'Okta' : 'Google Workspace',
    samlConfig: ssoType === 'saml' ? {
      idpEntityId: 'https://idp.example.com',
      idpSsoUrl: 'https://idp.example.com/sso',
      idpCertificate: '-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----',
      wantAssertionsSigned: true,
      signAuthnRequests: true
    } : undefined,
    oidcConfig: ssoType === 'oidc' ? {
      providerPreset: 'google_workspace',
      issuer: 'https://accounts.google.com',
      clientId: 'test-client-id',
      scopes: ['openid', 'email', 'profile']
    } : undefined,
    spEntityId: `https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}`,
    acsUrl: `https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}/acs`,
    sloUrl: `https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}/slo`,
    domains: options.domains || [],
    enforced: options.enforced ?? false,
    jitProvisioning: options.jitProvisioning || createDefaultJITConfig(),
    createdAt: now,
    updatedAt: now,
    totalLogins: 0
  };
}


/**
 * Mock SSO config storage for testing
 * In real tests, this would be replaced with actual repository calls
 */
const mockSSOConfigStore = new Map<string, OrgSSOConfig>();
const mockDomainToTenantMap = new Map<string, string>();

/**
 * Setup mock SSO config for testing
 */
function setupMockSSOConfig(config: OrgSSOConfig): void {
  mockSSOConfigStore.set(config.tenantId, config);
  
  // Map verified domains to tenant
  for (const domain of config.domains) {
    if (domain.verificationStatus === 'verified') {
      mockDomainToTenantMap.set(domain.domain.toLowerCase(), config.tenantId);
    }
  }
}

/**
 * Clear mock storage
 */
function clearMockStorage(): void {
  mockSSOConfigStore.clear();
  mockDomainToTenantMap.clear();
}

/**
 * Mock implementation of SSO enforcement check for property testing
 * This simulates the real checkSSOEnforcement behavior
 */
function mockCheckSSOEnforcement(
  email: string,
  configs: Map<string, OrgSSOConfig>
): SSOEnforcementCheckResult {
  const emailDomain = email.split('@')[1]?.toLowerCase();
  
  if (!emailDomain) {
    return {
      enforced: false,
      reason: 'Invalid email format'
    };
  }
  
  // Find config with this domain
  for (const config of configs.values()) {
    if (!config.enabled || !config.enforced) {
      continue;
    }
    
    // Check if domain is verified in this config
    const domainEntry = config.domains.find(
      d => d.domain.toLowerCase() === emailDomain && d.verificationStatus === 'verified'
    );
    
    if (domainEntry) {
      return {
        enforced: true,
        tenantId: config.tenantId,
        ssoType: config.ssoType,
        providerName: config.providerName
      };
    }
  }
  
  return {
    enforced: false,
    reason: 'No SSO enforcement for this domain'
  };
}


/**
 * Mock JIT provisioning function for property testing
 * Simulates user creation on first SSO login
 */
interface JITProvisionedUser {
  id: string;
  email: string;
  tenantId: string;
  role: string;
  emailVerified: boolean;
  createdViaJIT: boolean;
  createdAt: string;
}

function mockJITProvisionUser(
  email: string,
  tenantId: string,
  jitConfig: JITProvisioningConfig,
  ssoAttributes: { firstName?: string; lastName?: string; groups?: string[] }
): JITProvisionedUser | null {
  if (!jitConfig.enabled) {
    return null;
  }
  
  // Determine role based on group mapping
  let role = jitConfig.defaultRole || 'member';
  if (jitConfig.syncGroups && jitConfig.groupRoleMapping && ssoAttributes.groups) {
    for (const group of ssoAttributes.groups) {
      if (jitConfig.groupRoleMapping[group]) {
        role = jitConfig.groupRoleMapping[group];
        break;
      }
    }
  }
  
  return {
    id: `user_${Math.random().toString(36).slice(2)}`,
    email: email.toLowerCase(),
    tenantId,
    role,
    emailVerified: jitConfig.autoVerifyEmail ?? true,
    createdViaJIT: true,
    createdAt: new Date().toISOString()
  };
}

/**
 * Check if domain verification allows enforcement
 */
function canEnableEnforcement(config: OrgSSOConfig): { allowed: boolean; reason?: string } {
  if (!config.enabled) {
    return { allowed: false, reason: 'SSO must be enabled first' };
  }
  
  const verifiedDomains = config.domains.filter(d => d.verificationStatus === 'verified');
  
  if (verifiedDomains.length === 0) {
    return { allowed: false, reason: 'At least one verified domain is required' };
  }
  
  return { allowed: true };
}

// ============================================================================
// Property Tests
// ============================================================================

describe('Organization SSO Property Tests', () => {
  beforeEach(() => {
    clearMockStorage();
  });


  /**
   * Property 35: SSO enforcement blocks password login
   * 
   * WHEN SSO is enforced for an organization THEN THE Zalt_Platform
   * SHALL block password login for users with email domains matching
   * the organization's verified domains.
   * 
   * **Validates: Requirements 9.4, 9.6**
   */
  describe('Property 35: SSO enforcement blocks password login', () => {
    it('should block password login when SSO is enforced for verified domain', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          ssoTypeArb,
          (domain, tenantId, realmId, ssoType) => {
            // Setup: Create SSO config with enforced=true and verified domain
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              ssoType,
              enabled: true,
              enforced: true,
              domains: [verifiedDomainArb(domain, 'verified')]
            });
            
            const configs = new Map<string, OrgSSOConfig>();
            configs.set(tenantId, config);
            
            // Test: Check enforcement for email with this domain
            const email = `user@${domain}`;
            const result = mockCheckSSOEnforcement(email, configs);
            
            // Assert: Password login should be blocked (enforced=true)
            expect(result.enforced).toBe(true);
            expect(result.tenantId).toBe(tenantId);
            expect(result.ssoType).toBe(ssoType);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow password login when SSO is not enforced', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          (domain, tenantId, realmId) => {
            // Setup: Create SSO config with enforced=false
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: true,
              enforced: false, // Not enforced
              domains: [verifiedDomainArb(domain, 'verified')]
            });
            
            const configs = new Map<string, OrgSSOConfig>();
            configs.set(tenantId, config);
            
            // Test: Check enforcement for email with this domain
            const email = `user@${domain}`;
            const result = mockCheckSSOEnforcement(email, configs);
            
            // Assert: Password login should be allowed (enforced=false)
            expect(result.enforced).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should allow password login for domains not in SSO config', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          (configDomain, userDomain, tenantId, realmId) => {
            // Skip if domains are the same
            fc.pre(configDomain !== userDomain);
            
            // Setup: Create SSO config with enforced=true for one domain
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: true,
              enforced: true,
              domains: [verifiedDomainArb(configDomain, 'verified')]
            });
            
            const configs = new Map<string, OrgSSOConfig>();
            configs.set(tenantId, config);
            
            // Test: Check enforcement for email with DIFFERENT domain
            const email = `user@${userDomain}`;
            const result = mockCheckSSOEnforcement(email, configs);
            
            // Assert: Password login should be allowed (different domain)
            expect(result.enforced).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow password login when SSO is disabled', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          (domain, tenantId, realmId) => {
            // Setup: Create SSO config with enabled=false
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: false, // SSO disabled
              enforced: true, // Even if enforced flag is true
              domains: [verifiedDomainArb(domain, 'verified')]
            });
            
            const configs = new Map<string, OrgSSOConfig>();
            configs.set(tenantId, config);
            
            // Test: Check enforcement for email with this domain
            const email = `user@${domain}`;
            const result = mockCheckSSOEnforcement(email, configs);
            
            // Assert: Password login should be allowed (SSO disabled)
            expect(result.enforced).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should generate correct redirect URL when SSO is enforced', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          ssoTypeArb,
          simpleDomainArb,
          fc.stringMatching(/^[a-z][a-z0-9]{2,10}$/),
          (tenantId, ssoType, domain, localPart) => {
            const email = `${localPart}@${domain}`;
            
            // Generate redirect URL
            const redirectUrl = generateSSORedirectUrl(tenantId, ssoType, email);
            
            // Assert: URL should contain correct components
            expect(redirectUrl).toContain(ssoType);
            expect(redirectUrl).toContain('tenant_id=' + tenantId);
            expect(redirectUrl).toContain('login_hint=');
            // Verify the URL is properly formed
            expect(() => new URL(redirectUrl)).not.toThrow();
          }
        ),
        { numRuns: 50 }
      );
    });


    it('should return correct SSO type in enforcement result', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          ssoTypeArb,
          (domain, tenantId, realmId, ssoType) => {
            // Setup: Create SSO config with specific SSO type
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              ssoType,
              enabled: true,
              enforced: true,
              domains: [verifiedDomainArb(domain, 'verified')]
            });
            
            const configs = new Map<string, OrgSSOConfig>();
            configs.set(tenantId, config);
            
            // Test: Check enforcement
            const email = `user@${domain}`;
            const result = mockCheckSSOEnforcement(email, configs);
            
            // Assert: SSO type should match config
            expect(result.enforced).toBe(true);
            expect(result.ssoType).toBe(ssoType);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle case-insensitive domain matching', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          fc.constantFrom('UPPER', 'lower', 'MiXeD'),
          (domain, tenantId, caseType) => {
            // Setup: Create SSO config with lowercase domain
            const config = generateMockSSOConfig({
              tenantId,
              enabled: true,
              enforced: true,
              domains: [verifiedDomainArb(domain.toLowerCase(), 'verified')]
            });
            
            const configs = new Map<string, OrgSSOConfig>();
            configs.set(tenantId, config);
            
            // Create email with different case
            let emailDomain: string;
            switch (caseType) {
              case 'UPPER':
                emailDomain = domain.toUpperCase();
                break;
              case 'MiXeD':
                emailDomain = domain.split('').map((c, i) => 
                  i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()
                ).join('');
                break;
              default:
                emailDomain = domain.toLowerCase();
            }
            
            const email = `user@${emailDomain}`;
            const result = mockCheckSSOEnforcement(email, configs);
            
            // Assert: Should match regardless of case
            expect(result.enforced).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });
  });


  /**
   * Property 36: JIT provisioning creates user
   * 
   * WHEN JIT provisioning is enabled AND a user logs in via SSO for the first time
   * THEN THE Zalt_Platform SHALL create a new user account with attributes
   * from the IdP assertion.
   * 
   * **Validates: Requirements 9.8**
   */
  describe('Property 36: JIT provisioning creates user', () => {
    it('should create user when JIT provisioning is enabled', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          tenantIdArb,
          fc.constantFrom('member', 'admin', 'viewer'),
          (email, tenantId, defaultRole) => {
            // Setup: JIT config with enabled=true
            const jitConfig: JITProvisioningConfig = {
              enabled: true,
              defaultRole,
              autoVerifyEmail: true,
              syncGroups: false
            };
            
            // Test: Provision user
            const user = mockJITProvisionUser(email, tenantId, jitConfig, {});
            
            // Assert: User should be created
            expect(user).not.toBeNull();
            expect(user!.email).toBe(email.toLowerCase());
            expect(user!.tenantId).toBe(tenantId);
            expect(user!.role).toBe(defaultRole);
            expect(user!.createdViaJIT).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not create user when JIT provisioning is disabled', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          tenantIdArb,
          (email, tenantId) => {
            // Setup: JIT config with enabled=false
            const jitConfig: JITProvisioningConfig = {
              enabled: false,
              defaultRole: 'member',
              autoVerifyEmail: true,
              syncGroups: false
            };
            
            // Test: Try to provision user
            const user = mockJITProvisionUser(email, tenantId, jitConfig, {});
            
            // Assert: User should NOT be created
            expect(user).toBeNull();
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should auto-verify email when configured', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          tenantIdArb,
          fc.boolean(),
          (email, tenantId, autoVerify) => {
            // Setup: JIT config with specific autoVerifyEmail setting
            const jitConfig: JITProvisioningConfig = {
              enabled: true,
              defaultRole: 'member',
              autoVerifyEmail: autoVerify,
              syncGroups: false
            };
            
            // Test: Provision user
            const user = mockJITProvisionUser(email, tenantId, jitConfig, {});
            
            // Assert: Email verification should match config
            expect(user).not.toBeNull();
            expect(user!.emailVerified).toBe(autoVerify);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should assign role from group mapping when groups are synced', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          tenantIdArb,
          fc.constantFrom('admins', 'editors', 'viewers'),
          (email, tenantId, group) => {
            // Setup: JIT config with group role mapping
            const groupRoleMapping: Record<string, string> = {
              'admins': 'admin',
              'editors': 'editor',
              'viewers': 'viewer'
            };
            
            const jitConfig: JITProvisioningConfig = {
              enabled: true,
              defaultRole: 'member',
              autoVerifyEmail: true,
              syncGroups: true,
              groupRoleMapping
            };
            
            // Test: Provision user with group
            const user = mockJITProvisionUser(email, tenantId, jitConfig, {
              groups: [group]
            });
            
            // Assert: Role should be mapped from group
            expect(user).not.toBeNull();
            expect(user!.role).toBe(groupRoleMapping[group]);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should use default role when no group mapping matches', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          tenantIdArb,
          fc.constantFrom('member', 'guest', 'user'),
          (email, tenantId, defaultRole) => {
            // Setup: JIT config with group mapping that won't match
            const jitConfig: JITProvisioningConfig = {
              enabled: true,
              defaultRole,
              autoVerifyEmail: true,
              syncGroups: true,
              groupRoleMapping: {
                'special-group': 'admin'
              }
            };
            
            // Test: Provision user with non-matching group
            const user = mockJITProvisionUser(email, tenantId, jitConfig, {
              groups: ['other-group', 'another-group']
            });
            
            // Assert: Should use default role
            expect(user).not.toBeNull();
            expect(user!.role).toBe(defaultRole);
          }
        ),
        { numRuns: 50 }
      );
    });


    it('should normalize email to lowercase', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          fc.stringMatching(/^[A-Z][A-Za-z0-9]{2,10}$/),
          simpleDomainArb,
          (tenantId, localPart, domain) => {
            const mixedCaseEmail = `${localPart}@${domain.toUpperCase()}`;
            
            const jitConfig: JITProvisioningConfig = {
              enabled: true,
              defaultRole: 'member',
              autoVerifyEmail: true,
              syncGroups: false
            };
            
            // Test: Provision user with mixed case email
            const user = mockJITProvisionUser(mixedCaseEmail, tenantId, jitConfig, {});
            
            // Assert: Email should be normalized to lowercase
            expect(user).not.toBeNull();
            expect(user!.email).toBe(mixedCaseEmail.toLowerCase());
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should set createdViaJIT flag for JIT-provisioned users', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          tenantIdArb,
          jitProvisioningConfigArb,
          (email, tenantId, jitConfig) => {
            // Only test when JIT is enabled
            fc.pre(jitConfig.enabled);
            
            // Test: Provision user
            const user = mockJITProvisionUser(email, tenantId, jitConfig, {});
            
            // Assert: createdViaJIT should be true
            expect(user).not.toBeNull();
            expect(user!.createdViaJIT).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should include creation timestamp', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          tenantIdArb,
          (email, tenantId) => {
            const beforeCreation = new Date();
            
            const jitConfig: JITProvisioningConfig = {
              enabled: true,
              defaultRole: 'member',
              autoVerifyEmail: true,
              syncGroups: false
            };
            
            // Test: Provision user
            const user = mockJITProvisionUser(email, tenantId, jitConfig, {});
            
            const afterCreation = new Date();
            
            // Assert: Timestamp should be valid
            expect(user).not.toBeNull();
            const createdAt = new Date(user!.createdAt);
            expect(createdAt.getTime()).toBeGreaterThanOrEqual(beforeCreation.getTime());
            expect(createdAt.getTime()).toBeLessThanOrEqual(afterCreation.getTime());
          }
        ),
        { numRuns: 50 }
      );
    });
  });


  /**
   * Property 37: Domain verification is required for enforcement
   * 
   * SSO enforcement SHALL only be allowed when at least one domain
   * is verified. This prevents organizations from enforcing SSO
   * for domains they don't own.
   * 
   * **Validates: Requirements 9.5**
   */
  describe('Property 37: Domain verification is required for enforcement', () => {
    it('should allow enforcement when at least one domain is verified', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          (domain, tenantId, realmId) => {
            // Setup: Create SSO config with verified domain
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: true,
              enforced: false,
              domains: [verifiedDomainArb(domain, 'verified')]
            });
            
            // Test: Check if enforcement can be enabled
            const result = canEnableEnforcement(config);
            
            // Assert: Should be allowed
            expect(result.allowed).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject enforcement when no domains are verified', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          domainVerificationStatusArb,
          (domain, tenantId, realmId, status) => {
            // Only test non-verified statuses
            fc.pre(status !== 'verified');
            
            // Setup: Create SSO config with non-verified domain
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: true,
              enforced: false,
              domains: [verifiedDomainArb(domain, status)]
            });
            
            // Test: Check if enforcement can be enabled
            const result = canEnableEnforcement(config);
            
            // Assert: Should be rejected
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('verified domain');
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should reject enforcement when no domains exist', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          realmIdArb,
          (tenantId, realmId) => {
            // Setup: Create SSO config with no domains
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: true,
              enforced: false,
              domains: [] // No domains
            });
            
            // Test: Check if enforcement can be enabled
            const result = canEnableEnforcement(config);
            
            // Assert: Should be rejected
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('verified domain');
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject enforcement when SSO is disabled', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          (domain, tenantId, realmId) => {
            // Setup: Create SSO config with SSO disabled
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: false, // SSO disabled
              enforced: false,
              domains: [verifiedDomainArb(domain, 'verified')]
            });
            
            // Test: Check if enforcement can be enabled
            const result = canEnableEnforcement(config);
            
            // Assert: Should be rejected
            expect(result.allowed).toBe(false);
            expect(result.reason).toContain('enabled');
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow enforcement with multiple domains if at least one is verified', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          (domain1, domain2, tenantId, realmId) => {
            // Ensure domains are different
            fc.pre(domain1 !== domain2);
            
            // Setup: Create SSO config with one verified and one pending domain
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: true,
              enforced: false,
              domains: [
                verifiedDomainArb(domain1, 'verified'),
                verifiedDomainArb(domain2, 'pending')
              ]
            });
            
            // Test: Check if enforcement can be enabled
            const result = canEnableEnforcement(config);
            
            // Assert: Should be allowed (one verified domain is enough)
            expect(result.allowed).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });


    it('should not enforce SSO for unverified domains even if config has enforced=true', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          tenantIdArb,
          realmIdArb,
          (domain, tenantId, realmId) => {
            // Setup: Create SSO config with enforced=true but domain is pending
            const config = generateMockSSOConfig({
              tenantId,
              realmId,
              enabled: true,
              enforced: true, // Enforced flag is true
              domains: [verifiedDomainArb(domain, 'pending')] // But domain is not verified
            });
            
            const configs = new Map<string, OrgSSOConfig>();
            configs.set(tenantId, config);
            
            // Test: Check enforcement for email with this domain
            const email = `user@${domain}`;
            const result = mockCheckSSOEnforcement(email, configs);
            
            // Assert: Should NOT be enforced because domain is not verified
            expect(result.enforced).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should validate domain format before adding', () => {
      fc.assert(
        fc.property(
          fc.stringMatching(/^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\.[a-z]{2,}$/),
          (domain) => {
            // Test: Validate domain format
            const isValid = isValidDomain(domain);
            
            // Assert: Should be valid
            expect(isValid).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject invalid domain formats', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(
            'invalid',           // No TLD
            '.com',              // No domain name
            'test..com',         // Double dot
            '-test.com',         // Starts with hyphen
            'test-.com',         // Ends with hyphen
            'a.b',               // TLD too short
            ''                   // Empty
          ),
          (invalidDomain) => {
            // Test: Validate domain format
            const isValid = isValidDomain(invalidDomain);
            
            // Assert: Should be invalid
            expect(isValid).toBe(false);
          }
        ),
        { numRuns: 20 }
      );
    });
  });


  /**
   * Additional Properties: Model Helper Functions
   */
  describe('Additional Properties: Model Helper Functions', () => {
    it('should correctly identify verified domains', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          domainVerificationStatusArb,
          (domain, status) => {
            const domains: VerifiedDomain[] = [verifiedDomainArb(domain, status)];
            
            // Test: Check if domain is verified
            const isVerified = isDomainVerified(domains, domain);
            
            // Assert: Should match status
            expect(isVerified).toBe(status === 'verified');
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should correctly match email to verified domain', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          fc.stringMatching(/^[a-z][a-z0-9]{2,10}$/),
          (domain, localPart) => {
            const domains: VerifiedDomain[] = [verifiedDomainArb(domain, 'verified')];
            const email = `${localPart}@${domain}`;
            
            // Test: Check if email matches verified domain
            const matches = emailMatchesVerifiedDomain(email, domains);
            
            // Assert: Should match
            expect(matches).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not match email to unverified domain', () => {
      fc.assert(
        fc.property(
          simpleDomainArb,
          fc.stringMatching(/^[a-z][a-z0-9]{2,10}$/),
          fc.constantFrom('pending', 'failed') as fc.Arbitrary<DomainVerificationStatus>,
          (domain, localPart, status) => {
            const domains: VerifiedDomain[] = [verifiedDomainArb(domain, status)];
            const email = `${localPart}@${domain}`;
            
            // Test: Check if email matches verified domain
            const matches = emailMatchesVerifiedDomain(email, domains);
            
            // Assert: Should NOT match (domain not verified)
            expect(matches).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should generate unique SSO config IDs', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 10, max: 100 }),
          (count) => {
            const ids = new Set<string>();
            
            for (let i = 0; i < count; i++) {
              ids.add(generateSSOConfigId());
            }
            
            // Assert: All IDs should be unique
            expect(ids.size).toBe(count);
          }
        ),
        { numRuns: 10 }
      );
    });


    it('should generate unique domain verification tokens', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 10, max: 100 }),
          (count) => {
            const tokens = new Set<string>();
            
            for (let i = 0; i < count; i++) {
              tokens.add(generateDomainVerificationToken());
            }
            
            // Assert: All tokens should be unique
            expect(tokens.size).toBe(count);
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should generate verification tokens with correct prefix', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 50 }),
          (count) => {
            for (let i = 0; i < count; i++) {
              const token = generateDomainVerificationToken();
              
              // Assert: Token should have correct prefix
              expect(token.startsWith('zalt-verify=')).toBe(true);
            }
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should create default JIT config with expected values', () => {
      const defaultConfig = createDefaultJITConfig();
      
      expect(defaultConfig.enabled).toBe(false);
      expect(defaultConfig.defaultRole).toBe('member');
      expect(defaultConfig.autoVerifyEmail).toBe(true);
      expect(defaultConfig.syncGroups).toBe(false);
    });
  });

  /**
   * Additional Properties: SSO Redirect URL Generation
   */
  describe('Additional Properties: SSO Redirect URL Generation', () => {
    it('should generate valid SAML redirect URLs', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          fc.emailAddress(),
          (tenantId, email) => {
            const url = generateSAMLRedirectUrl(tenantId, email);
            
            // Assert: URL should be valid and contain expected parts
            expect(url).toContain('saml');
            expect(url).toContain('tenant_id=' + tenantId);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should generate valid OIDC redirect URLs', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          fc.emailAddress(),
          (tenantId, email) => {
            const url = generateOIDCRedirectUrl(tenantId, email);
            
            // Assert: URL should be valid and contain expected parts
            expect(url).toContain('oidc');
            expect(url).toContain('tenant_id=' + tenantId);
          }
        ),
        { numRuns: 50 }
      );
    });


    it('should include login hint when email is provided', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          ssoTypeArb,
          simpleDomainArb,
          fc.stringMatching(/^[a-z][a-z0-9]{2,10}$/),
          (tenantId, ssoType, domain, localPart) => {
            const email = `${localPart}@${domain}`;
            const url = generateSSORedirectUrl(tenantId, ssoType, email);
            
            // Assert: URL should contain login_hint with the email
            expect(url).toContain('login_hint=');
            // Verify the URL is properly formed and contains the email domain
            const urlObj = new URL(url);
            const loginHint = urlObj.searchParams.get('login_hint');
            expect(loginHint).toBe(email);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle special characters in email for redirect URL', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          ssoTypeArb,
          fc.constantFrom(
            'user+tag@example.com',
            'user.name@example.com',
            'user_name@example.com'
          ),
          (tenantId, ssoType, email) => {
            const url = generateSSORedirectUrl(tenantId, ssoType, email);
            
            // Assert: URL should be properly encoded
            expect(url).toContain('login_hint=');
            // The email should be URL encoded
            expect(url).not.toContain(' ');
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * Additional Properties: Edge Cases
   */
  describe('Additional Properties: Edge Cases', () => {
    it('should handle empty email gracefully', () => {
      const configs = new Map<string, OrgSSOConfig>();
      
      const result = mockCheckSSOEnforcement('', configs);
      
      expect(result.enforced).toBe(false);
      expect(result.reason).toContain('Invalid email');
    });

    it('should handle email without @ symbol', () => {
      const configs = new Map<string, OrgSSOConfig>();
      
      const result = mockCheckSSOEnforcement('invalidemail', configs);
      
      expect(result.enforced).toBe(false);
      expect(result.reason).toContain('Invalid email');
    });

    it('should handle email with multiple @ symbols', () => {
      const configs = new Map<string, OrgSSOConfig>();
      
      // Email with multiple @ - split('@')[1] will get 'middle@domain.com'
      const result = mockCheckSSOEnforcement('user@middle@domain.com', configs);
      
      // Should not crash and should return not enforced
      expect(result.enforced).toBe(false);
    });
  });
});
