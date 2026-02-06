/**
 * Organization SSO Model - Per-organization SSO configuration
 * 
 * Enables enterprise customers to configure SSO (SAML 2.0 / OIDC) for their organization.
 * Each tenant can have its own IdP configuration with domain verification and enforcement.
 * 
 * DynamoDB Schema:
 * - Table: zalt-tenants
 * - pk: TENANT#{tenantId}
 * - sk: SSO#CONFIG
 * - GSI: domain-sso-index (domain -> tenantId)
 * 
 * Security Requirements:
 * - X.509 certificates must be validated
 * - Domain verification required before SSO enforcement
 * - Audit logging for all SSO configuration changes
 * 
 * Validates: Requirements 9.1, 9.2 (Organization-Level SSO)
 */

import { randomBytes } from 'crypto';

// ============================================================================
// Types
// ============================================================================

/**
 * SSO provider types
 */
export type SSOType = 'saml' | 'oidc';

/**
 * SSO configuration status
 */
export type SSOConfigStatus = 'active' | 'inactive' | 'pending_verification' | 'deleted';

/**
 * Domain verification status
 */
export type DomainVerificationStatus = 'pending' | 'verified' | 'failed';

/**
 * OIDC provider presets
 */
export type OIDCProviderPreset = 
  | 'google_workspace'
  | 'microsoft_entra'
  | 'okta'
  | 'auth0'
  | 'onelogin'
  | 'custom';

// ============================================================================
// Interfaces
// ============================================================================

/**
 * Verified domain for SSO enforcement
 */
export interface VerifiedDomain {
  domain: string;                      // e.g., "acme.com"
  verificationStatus: DomainVerificationStatus;
  verificationToken?: string;          // DNS TXT record value
  verifiedAt?: string;                 // ISO timestamp
  verificationMethod?: 'dns_txt' | 'dns_cname' | 'email';
}

/**
 * Attribute mapping from IdP to Zalt user profile
 */
export interface AttributeMapping {
  email?: string;                      // IdP attribute for email
  firstName?: string;                  // IdP attribute for first name
  lastName?: string;                   // IdP attribute for last name
  displayName?: string;                // IdP attribute for display name
  groups?: string;                     // IdP attribute for groups
  department?: string;                 // IdP attribute for department
  employeeId?: string;                 // IdP attribute for employee ID
  [key: string]: string | undefined;   // Custom attribute mappings
}

/**
 * SAML-specific configuration
 */
export interface SAMLConfig {
  idpMetadataXml?: string;             // Full IdP metadata XML
  idpEntityId: string;                 // IdP Entity ID
  idpSsoUrl: string;                   // IdP SSO URL
  idpSloUrl?: string;                  // IdP Single Logout URL (optional)
  idpCertificate: string;              // X.509 certificate (PEM format)
  idpCertificateFingerprint?: string;  // SHA-256 fingerprint
  signAuthnRequests?: boolean;         // Sign authentication requests
  wantAssertionsSigned?: boolean;      // Require signed assertions
  wantAssertionsEncrypted?: boolean;   // Require encrypted assertions
  nameIdFormat?: string;               // Name ID format
  authnContextClassRef?: string;       // Authentication context
}

/**
 * OIDC-specific configuration
 */
export interface OIDCConfig {
  providerPreset?: OIDCProviderPreset; // Provider preset for auto-config
  issuer: string;                      // OIDC issuer URL
  clientId: string;                    // OAuth client ID
  clientSecretEncrypted?: string;      // Encrypted client secret
  authorizationUrl?: string;           // Authorization endpoint (auto-discovered if issuer supports)
  tokenUrl?: string;                   // Token endpoint
  userinfoUrl?: string;                // Userinfo endpoint
  jwksUrl?: string;                    // JWKS endpoint
  scopes?: string[];                   // OAuth scopes
}

/**
 * JIT (Just-In-Time) provisioning configuration
 */
export interface JITProvisioningConfig {
  enabled: boolean;                    // Enable JIT user creation
  defaultRole?: string;                // Default role for new users
  autoVerifyEmail?: boolean;           // Auto-verify email from IdP
  syncGroups?: boolean;                // Sync groups from IdP
  groupRoleMapping?: Record<string, string>; // Map IdP groups to roles
}

/**
 * Organization SSO Configuration
 */
export interface OrgSSOConfig {
  id: string;                          // sso_config_xxx format
  tenantId: string;                    // Tenant this config belongs to
  realmId: string;                     // Realm for this tenant
  
  // SSO Type
  ssoType: SSOType;                    // 'saml' or 'oidc'
  enabled: boolean;                    // Is SSO enabled
  status: SSOConfigStatus;             // Configuration status
  
  // Provider name for display
  providerName: string;                // e.g., "Okta", "Azure AD"
  
  // Type-specific configuration
  samlConfig?: SAMLConfig;             // SAML configuration (if ssoType === 'saml')
  oidcConfig?: OIDCConfig;             // OIDC configuration (if ssoType === 'oidc')
  
  // SP (Service Provider) configuration - Zalt.io side
  spEntityId: string;                  // Zalt SP Entity ID
  acsUrl: string;                      // Assertion Consumer Service URL
  sloUrl?: string;                     // Single Logout URL
  
  // Attribute mapping
  attributeMapping?: AttributeMapping;
  
  // Domain verification and enforcement
  domains: VerifiedDomain[];           // Verified domains for SSO
  enforced: boolean;                   // Block password login for domain users
  
  // JIT Provisioning
  jitProvisioning: JITProvisioningConfig;
  
  // Metadata
  createdAt: string;                   // ISO timestamp
  updatedAt: string;                   // ISO timestamp
  createdBy?: string;                  // User who created the config
  lastUsedAt?: string;                 // Last successful SSO login
  
  // Statistics
  totalLogins?: number;                // Total SSO logins
  lastLoginAt?: string;                // Last login timestamp
}

/**
 * Input for creating SSO configuration
 */
export interface CreateOrgSSOConfigInput {
  tenantId: string;
  realmId: string;
  ssoType: SSOType;
  providerName: string;
  
  // Type-specific config
  samlConfig?: Omit<SAMLConfig, 'idpCertificateFingerprint'>;
  oidcConfig?: OIDCConfig;
  
  // Attribute mapping
  attributeMapping?: AttributeMapping;
  
  // Domains to verify
  domains?: string[];
  
  // Enforcement
  enforced?: boolean;
  
  // JIT Provisioning
  jitProvisioning?: Partial<JITProvisioningConfig>;
  
  // Metadata
  createdBy?: string;
}

/**
 * Input for updating SSO configuration
 */
export interface UpdateOrgSSOConfigInput {
  providerName?: string;
  enabled?: boolean;
  status?: SSOConfigStatus;
  
  // Type-specific config updates
  samlConfig?: Partial<SAMLConfig>;
  oidcConfig?: Partial<OIDCConfig>;
  
  // Attribute mapping
  attributeMapping?: AttributeMapping;
  
  // Enforcement
  enforced?: boolean;
  
  // JIT Provisioning
  jitProvisioning?: Partial<JITProvisioningConfig>;
}

/**
 * SSO configuration response (API response format)
 */
export interface OrgSSOConfigResponse {
  id: string;
  tenantId: string;
  realmId: string;
  ssoType: SSOType;
  enabled: boolean;
  status: SSOConfigStatus;
  providerName: string;
  
  // SP configuration
  spEntityId: string;
  acsUrl: string;
  sloUrl?: string;
  
  // IdP configuration (sanitized - no secrets)
  idpEntityId?: string;
  idpSsoUrl?: string;
  
  // Domains
  domains: VerifiedDomain[];
  enforced: boolean;
  
  // JIT
  jitProvisioning: JITProvisioningConfig;
  
  // Timestamps
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
  
  // Statistics
  totalLogins?: number;
}

/**
 * DynamoDB item structure
 */
export interface OrgSSOConfigDynamoDBItem {
  pk: string;                          // TENANT#{tenantId}
  sk: string;                          // SSO#CONFIG
  
  // GSI for domain lookup
  GSI1PK?: string;                     // DOMAIN#{domain}
  GSI1SK?: string;                     // SSO#CONFIG
  
  // Entity data
  id: string;
  tenantId: string;
  realmId: string;
  ssoType: SSOType;
  enabled: boolean;
  status: SSOConfigStatus;
  providerName: string;
  
  samlConfig?: SAMLConfig;
  oidcConfig?: OIDCConfig;
  
  spEntityId: string;
  acsUrl: string;
  sloUrl?: string;
  
  attributeMapping?: AttributeMapping;
  domains: VerifiedDomain[];
  enforced: boolean;
  jitProvisioning: JITProvisioningConfig;
  
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
  lastUsedAt?: string;
  totalLogins?: number;
  lastLoginAt?: string;
  
  // Entity type for filtering
  entityType: 'ORG_SSO_CONFIG';
}

// ============================================================================
// Constants
// ============================================================================

/**
 * SSO Config ID prefix
 */
export const SSO_CONFIG_ID_PREFIX = 'sso_config_';

/**
 * Default Name ID format for SAML
 */
export const DEFAULT_NAME_ID_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

/**
 * Default OIDC scopes
 */
export const DEFAULT_OIDC_SCOPES = ['openid', 'email', 'profile'];

/**
 * Domain verification token prefix
 */
export const DOMAIN_VERIFICATION_PREFIX = 'zalt-verify=';

/**
 * Domain verification TTL (7 days)
 */
export const DOMAIN_VERIFICATION_TTL_DAYS = 7;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate unique SSO config ID
 */
export function generateSSOConfigId(): string {
  return `${SSO_CONFIG_ID_PREFIX}${randomBytes(12).toString('hex')}`;
}

/**
 * Generate domain verification token
 */
export function generateDomainVerificationToken(): string {
  return `${DOMAIN_VERIFICATION_PREFIX}${randomBytes(16).toString('hex')}`;
}

/**
 * Generate SP Entity ID for a tenant
 */
export function generateSPEntityId(realmId: string, tenantId: string): string {
  const baseUrl = process.env.API_BASE_URL || 'https://api.zalt.io';
  return `${baseUrl}/v1/sso/saml/${realmId}/${tenantId}`;
}

/**
 * Generate ACS URL for a tenant
 */
export function generateACSUrl(realmId: string, tenantId: string): string {
  const baseUrl = process.env.API_BASE_URL || 'https://api.zalt.io';
  return `${baseUrl}/v1/sso/saml/${realmId}/${tenantId}/acs`;
}

/**
 * Generate SLO URL for a tenant
 */
export function generateSLOUrl(realmId: string, tenantId: string): string {
  const baseUrl = process.env.API_BASE_URL || 'https://api.zalt.io';
  return `${baseUrl}/v1/sso/saml/${realmId}/${tenantId}/slo`;
}

/**
 * Validate X.509 certificate format
 */
export function isValidCertificate(cert: string): boolean {
  const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/;
  return certRegex.test(cert.trim());
}

/**
 * Extract certificate fingerprint (SHA-256)
 */
export function getCertificateFingerprint(cert: string): string {
  const { createHash } = require('crypto');
  
  // Remove PEM headers and whitespace
  const certBody = cert
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '');
  
  // Decode base64 and hash
  const certBuffer = Buffer.from(certBody, 'base64');
  return createHash('sha256').update(certBuffer).digest('hex').toUpperCase();
}

/**
 * Validate domain format
 */
export function isValidDomain(domain: string): boolean {
  // Basic domain validation
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

/**
 * Validate SSO type
 */
export function isValidSSOType(type: string): type is SSOType {
  return ['saml', 'oidc'].includes(type);
}

/**
 * Validate SSO config status
 */
export function isValidSSOConfigStatus(status: string): status is SSOConfigStatus {
  return ['active', 'inactive', 'pending_verification', 'deleted'].includes(status);
}

/**
 * Check if domain is verified
 */
export function isDomainVerified(domains: VerifiedDomain[], domain: string): boolean {
  const found = domains.find(d => d.domain.toLowerCase() === domain.toLowerCase());
  return found?.verificationStatus === 'verified';
}

/**
 * Check if email domain matches any verified domain
 */
export function emailMatchesVerifiedDomain(email: string, domains: VerifiedDomain[]): boolean {
  const emailDomain = email.split('@')[1]?.toLowerCase();
  if (!emailDomain) return false;
  
  return domains.some(
    d => d.domain.toLowerCase() === emailDomain && d.verificationStatus === 'verified'
  );
}

/**
 * Convert OrgSSOConfig to API response format (excludes sensitive data)
 */
export function toOrgSSOConfigResponse(config: OrgSSOConfig): OrgSSOConfigResponse {
  return {
    id: config.id,
    tenantId: config.tenantId,
    realmId: config.realmId,
    ssoType: config.ssoType,
    enabled: config.enabled,
    status: config.status,
    providerName: config.providerName,
    spEntityId: config.spEntityId,
    acsUrl: config.acsUrl,
    sloUrl: config.sloUrl,
    idpEntityId: config.ssoType === 'saml' 
      ? config.samlConfig?.idpEntityId 
      : config.oidcConfig?.issuer,
    idpSsoUrl: config.samlConfig?.idpSsoUrl,
    domains: config.domains,
    enforced: config.enforced,
    jitProvisioning: config.jitProvisioning,
    createdAt: config.createdAt,
    updatedAt: config.updatedAt,
    lastUsedAt: config.lastUsedAt,
    totalLogins: config.totalLogins
  };
}

/**
 * Get default attribute mapping for common IdPs
 */
export function getDefaultAttributeMapping(provider?: OIDCProviderPreset): AttributeMapping {
  switch (provider) {
    case 'google_workspace':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name'
      };
    case 'microsoft_entra':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name',
        groups: 'groups'
      };
    case 'okta':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name',
        groups: 'groups'
      };
    default:
      // SAML default mapping
      return {
        email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        firstName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
        lastName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
      };
  }
}

/**
 * Create default JIT provisioning config
 */
export function createDefaultJITConfig(): JITProvisioningConfig {
  return {
    enabled: false,
    defaultRole: 'member',
    autoVerifyEmail: true,
    syncGroups: false
  };
}

