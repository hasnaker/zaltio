/**
 * Data Residency Service for Zalt.io Auth Platform
 * Task 20.2: Data Residency Implementation
 * 
 * Supports:
 * - Region selection (EU, US, Asia-Pacific)
 * - Data isolation per region
 * - Cross-region data transfer controls
 * - Compliance with GDPR, HIPAA, and regional regulations
 * 
 * Architecture:
 * - Each region has dedicated DynamoDB tables
 * - Data never leaves the designated region
 * - Metadata can be replicated for routing
 */

import * as crypto from 'crypto';

// ============================================================================
// Types
// ============================================================================

/**
 * Supported data regions
 */
export enum DataRegion {
  EU = 'eu',           // Europe (Frankfurt, Ireland)
  US = 'us',           // United States (Virginia, Oregon)
  APAC = 'apac',       // Asia-Pacific (Singapore, Tokyo)
  BRAZIL = 'brazil',   // Brazil (São Paulo) - LGPD compliance
  CANADA = 'canada',   // Canada (Montreal) - PIPEDA compliance
  AUSTRALIA = 'australia' // Australia (Sydney) - Privacy Act compliance
}

/**
 * AWS region mapping for each data region
 */
export const REGION_AWS_MAPPING: Record<DataRegion, { primary: string; secondary: string }> = {
  [DataRegion.EU]: { primary: 'eu-central-1', secondary: 'eu-west-1' },
  [DataRegion.US]: { primary: 'us-east-1', secondary: 'us-west-2' },
  [DataRegion.APAC]: { primary: 'ap-southeast-1', secondary: 'ap-northeast-1' },
  [DataRegion.BRAZIL]: { primary: 'sa-east-1', secondary: 'sa-east-1' },
  [DataRegion.CANADA]: { primary: 'ca-central-1', secondary: 'ca-central-1' },
  [DataRegion.AUSTRALIA]: { primary: 'ap-southeast-2', secondary: 'ap-southeast-2' }
};

/**
 * Compliance frameworks per region
 */
export const REGION_COMPLIANCE: Record<DataRegion, string[]> = {
  [DataRegion.EU]: ['GDPR', 'ePrivacy', 'NIS2'],
  [DataRegion.US]: ['HIPAA', 'SOC2', 'CCPA', 'FERPA'],
  [DataRegion.APAC]: ['PDPA', 'APPI', 'PIPL'],
  [DataRegion.BRAZIL]: ['LGPD'],
  [DataRegion.CANADA]: ['PIPEDA', 'PHIPA'],
  [DataRegion.AUSTRALIA]: ['Privacy Act', 'APPs']
};

/**
 * Data residency configuration for a realm
 */
export interface DataResidencyConfig {
  realmId: string;
  primaryRegion: DataRegion;
  allowedRegions: DataRegion[];
  dataTypes: DataTypeConfig[];
  crossRegionTransfer: CrossRegionTransferPolicy;
  retentionPolicy: RetentionPolicy;
  encryptionConfig: EncryptionConfig;
  createdAt: string;
  updatedAt: string;
}

/**
 * Configuration for specific data types
 */
export interface DataTypeConfig {
  dataType: DataType;
  region: DataRegion;
  encrypted: boolean;
  retentionDays: number;
}

/**
 * Data types that can be configured
 */
export enum DataType {
  USER_PROFILE = 'user_profile',
  CREDENTIALS = 'credentials',
  SESSIONS = 'sessions',
  AUDIT_LOGS = 'audit_logs',
  MFA_SECRETS = 'mfa_secrets',
  TOKENS = 'tokens',
  WEBHOOKS = 'webhooks',
  ANALYTICS = 'analytics'
}

/**
 * Cross-region data transfer policy
 */
export interface CrossRegionTransferPolicy {
  enabled: boolean;
  allowedDestinations: DataRegion[];
  requiresConsent: boolean;
  transferMechanism: TransferMechanism;
  sccs: boolean; // Standard Contractual Clauses (EU)
}

/**
 * Transfer mechanisms for cross-region data
 */
export enum TransferMechanism {
  NONE = 'none',
  ADEQUACY_DECISION = 'adequacy_decision',
  STANDARD_CONTRACTUAL_CLAUSES = 'scc',
  BINDING_CORPORATE_RULES = 'bcr',
  EXPLICIT_CONSENT = 'explicit_consent'
}

/**
 * Data retention policy
 */
export interface RetentionPolicy {
  defaultRetentionDays: number;
  auditLogRetentionDays: number;
  sessionRetentionDays: number;
  deletedUserRetentionDays: number;
  backupRetentionDays: number;
}

/**
 * Encryption configuration
 */
export interface EncryptionConfig {
  atRest: boolean;
  inTransit: boolean;
  kmsKeyArn?: string;
  customerManagedKey: boolean;
}

/**
 * Data location record
 */
export interface DataLocationRecord {
  id: string;
  entityType: string;
  entityId: string;
  realmId: string;
  region: DataRegion;
  awsRegion: string;
  tableName: string;
  encrypted: boolean;
  createdAt: string;
  lastAccessedAt?: string;
}

/**
 * Region routing result
 */
export interface RegionRoutingResult {
  region: DataRegion;
  awsRegion: string;
  tableSuffix: string;
  endpoint?: string;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_RETENTION_DAYS = 365;
const AUDIT_LOG_RETENTION_DAYS = 2190; // 6 years for HIPAA
const SESSION_RETENTION_DAYS = 30;
const DELETED_USER_RETENTION_DAYS = 90;
const BACKUP_RETENTION_DAYS = 365;

// ============================================================================
// Region Routing
// ============================================================================

/**
 * Get the AWS region for a data region
 */
export function getAWSRegion(dataRegion: DataRegion, usePrimary: boolean = true): string {
  const mapping = REGION_AWS_MAPPING[dataRegion];
  return usePrimary ? mapping.primary : mapping.secondary;
}

/**
 * Get table suffix for a region
 */
export function getTableSuffix(dataRegion: DataRegion): string {
  return `-${dataRegion}`;
}

/**
 * Route data to the correct region based on realm configuration
 */
export function routeToRegion(
  realmId: string,
  config: DataResidencyConfig,
  dataType?: DataType
): RegionRoutingResult {
  // Check if specific data type has a different region
  if (dataType) {
    const typeConfig = config.dataTypes.find(dt => dt.dataType === dataType);
    if (typeConfig && typeConfig.region !== config.primaryRegion) {
      return {
        region: typeConfig.region,
        awsRegion: getAWSRegion(typeConfig.region),
        tableSuffix: getTableSuffix(typeConfig.region)
      };
    }
  }

  // Use primary region
  return {
    region: config.primaryRegion,
    awsRegion: getAWSRegion(config.primaryRegion),
    tableSuffix: getTableSuffix(config.primaryRegion)
  };
}

/**
 * Check if cross-region transfer is allowed
 */
export function isTransferAllowed(
  sourceRegion: DataRegion,
  destinationRegion: DataRegion,
  policy: CrossRegionTransferPolicy
): { allowed: boolean; mechanism?: TransferMechanism; requiresConsent: boolean } {
  // Same region - always allowed
  if (sourceRegion === destinationRegion) {
    return { allowed: true, requiresConsent: false };
  }

  // Cross-region disabled
  if (!policy.enabled) {
    return { allowed: false, requiresConsent: false };
  }

  // Check if destination is in allowed list
  if (!policy.allowedDestinations.includes(destinationRegion)) {
    return { allowed: false, requiresConsent: false };
  }

  return {
    allowed: true,
    mechanism: policy.transferMechanism,
    requiresConsent: policy.requiresConsent
  };
}

// ============================================================================
// Configuration Management
// ============================================================================

/**
 * Create default data residency configuration
 */
export function createDefaultConfig(
  realmId: string,
  primaryRegion: DataRegion
): DataResidencyConfig {
  const now = new Date().toISOString();

  return {
    realmId,
    primaryRegion,
    allowedRegions: [primaryRegion],
    dataTypes: [
      { dataType: DataType.USER_PROFILE, region: primaryRegion, encrypted: true, retentionDays: DEFAULT_RETENTION_DAYS },
      { dataType: DataType.CREDENTIALS, region: primaryRegion, encrypted: true, retentionDays: DEFAULT_RETENTION_DAYS },
      { dataType: DataType.SESSIONS, region: primaryRegion, encrypted: true, retentionDays: SESSION_RETENTION_DAYS },
      { dataType: DataType.AUDIT_LOGS, region: primaryRegion, encrypted: true, retentionDays: AUDIT_LOG_RETENTION_DAYS },
      { dataType: DataType.MFA_SECRETS, region: primaryRegion, encrypted: true, retentionDays: DEFAULT_RETENTION_DAYS },
      { dataType: DataType.TOKENS, region: primaryRegion, encrypted: true, retentionDays: SESSION_RETENTION_DAYS },
      { dataType: DataType.WEBHOOKS, region: primaryRegion, encrypted: false, retentionDays: DEFAULT_RETENTION_DAYS },
      { dataType: DataType.ANALYTICS, region: primaryRegion, encrypted: false, retentionDays: DEFAULT_RETENTION_DAYS }
    ],
    crossRegionTransfer: {
      enabled: false,
      allowedDestinations: [],
      requiresConsent: true,
      transferMechanism: TransferMechanism.NONE,
      sccs: false
    },
    retentionPolicy: {
      defaultRetentionDays: DEFAULT_RETENTION_DAYS,
      auditLogRetentionDays: AUDIT_LOG_RETENTION_DAYS,
      sessionRetentionDays: SESSION_RETENTION_DAYS,
      deletedUserRetentionDays: DELETED_USER_RETENTION_DAYS,
      backupRetentionDays: BACKUP_RETENTION_DAYS
    },
    encryptionConfig: {
      atRest: true,
      inTransit: true,
      customerManagedKey: false
    },
    createdAt: now,
    updatedAt: now
  };
}

/**
 * Create GDPR-compliant EU configuration
 */
export function createGDPRConfig(realmId: string): DataResidencyConfig {
  const config = createDefaultConfig(realmId, DataRegion.EU);
  
  // GDPR-specific settings
  config.crossRegionTransfer = {
    enabled: false, // Disabled by default for GDPR
    allowedDestinations: [],
    requiresConsent: true,
    transferMechanism: TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES,
    sccs: true
  };

  // Shorter retention for GDPR data minimization
  config.retentionPolicy.defaultRetentionDays = 365;
  config.retentionPolicy.deletedUserRetentionDays = 30; // GDPR right to erasure

  return config;
}

/**
 * Create HIPAA-compliant US configuration
 */
export function createHIPAAConfig(realmId: string): DataResidencyConfig {
  const config = createDefaultConfig(realmId, DataRegion.US);
  
  // HIPAA-specific settings
  config.retentionPolicy.auditLogRetentionDays = 2190; // 6 years
  config.retentionPolicy.defaultRetentionDays = 2190;
  
  // Customer-managed encryption for HIPAA
  config.encryptionConfig.customerManagedKey = true;

  return config;
}

// ============================================================================
// Validation
// ============================================================================

/**
 * Validate data residency configuration
 */
export function validateConfig(config: Partial<DataResidencyConfig>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (!config.realmId) {
    errors.push('Realm ID is required');
  }

  if (!config.primaryRegion) {
    errors.push('Primary region is required');
  } else if (!Object.values(DataRegion).includes(config.primaryRegion)) {
    errors.push(`Invalid primary region: ${config.primaryRegion}`);
  }

  if (config.allowedRegions) {
    for (const region of config.allowedRegions) {
      if (!Object.values(DataRegion).includes(region)) {
        errors.push(`Invalid allowed region: ${region}`);
      }
    }

    if (config.primaryRegion && !config.allowedRegions.includes(config.primaryRegion)) {
      errors.push('Primary region must be in allowed regions');
    }
  }

  if (config.crossRegionTransfer?.enabled) {
    if (!config.crossRegionTransfer.allowedDestinations?.length) {
      errors.push('Cross-region transfer enabled but no destinations specified');
    }

    if (config.crossRegionTransfer.transferMechanism === TransferMechanism.NONE) {
      errors.push('Cross-region transfer enabled but no transfer mechanism specified');
    }
  }

  if (config.retentionPolicy) {
    if (config.retentionPolicy.defaultRetentionDays < 1) {
      errors.push('Default retention must be at least 1 day');
    }

    if (config.retentionPolicy.auditLogRetentionDays < 365) {
      errors.push('Audit log retention must be at least 365 days for compliance');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

// ============================================================================
// Data Location Tracking
// ============================================================================

/**
 * Create data location record
 */
export function createDataLocationRecord(
  entityType: string,
  entityId: string,
  realmId: string,
  config: DataResidencyConfig,
  dataType?: DataType
): DataLocationRecord {
  const routing = routeToRegion(realmId, config, dataType);
  const now = new Date().toISOString();

  return {
    id: crypto.randomUUID(),
    entityType,
    entityId,
    realmId,
    region: routing.region,
    awsRegion: routing.awsRegion,
    tableName: `zalt-${entityType}${routing.tableSuffix}`,
    encrypted: config.encryptionConfig.atRest,
    createdAt: now
  };
}

/**
 * Get compliance frameworks for a region
 */
export function getComplianceFrameworks(region: DataRegion): string[] {
  return REGION_COMPLIANCE[region] || [];
}

/**
 * Check if a region is compliant with a specific framework
 */
export function isCompliantWith(region: DataRegion, framework: string): boolean {
  const frameworks = getComplianceFrameworks(region);
  return frameworks.includes(framework);
}

// ============================================================================
// Region Selection Helpers
// ============================================================================

/**
 * Suggest region based on user location
 */
export function suggestRegion(countryCode: string): DataRegion {
  const euCountries = [
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
    'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
    'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'GB', 'CH', 'NO', 'IS'
  ];

  const apacCountries = [
    'JP', 'KR', 'SG', 'HK', 'TW', 'MY', 'TH', 'ID', 'PH', 'VN',
    'IN', 'NZ'
  ];

  if (countryCode === 'BR') {
    return DataRegion.BRAZIL;
  }

  if (countryCode === 'CA') {
    return DataRegion.CANADA;
  }

  if (countryCode === 'AU') {
    return DataRegion.AUSTRALIA;
  }

  if (euCountries.includes(countryCode)) {
    return DataRegion.EU;
  }

  if (apacCountries.includes(countryCode)) {
    return DataRegion.APAC;
  }

  // Default to US
  return DataRegion.US;
}

/**
 * Get all available regions with their details
 */
export function getAvailableRegions(): Array<{
  region: DataRegion;
  name: string;
  awsRegions: string[];
  compliance: string[];
}> {
  return [
    {
      region: DataRegion.EU,
      name: 'Europe',
      awsRegions: [REGION_AWS_MAPPING[DataRegion.EU].primary, REGION_AWS_MAPPING[DataRegion.EU].secondary],
      compliance: REGION_COMPLIANCE[DataRegion.EU]
    },
    {
      region: DataRegion.US,
      name: 'United States',
      awsRegions: [REGION_AWS_MAPPING[DataRegion.US].primary, REGION_AWS_MAPPING[DataRegion.US].secondary],
      compliance: REGION_COMPLIANCE[DataRegion.US]
    },
    {
      region: DataRegion.APAC,
      name: 'Asia-Pacific',
      awsRegions: [REGION_AWS_MAPPING[DataRegion.APAC].primary, REGION_AWS_MAPPING[DataRegion.APAC].secondary],
      compliance: REGION_COMPLIANCE[DataRegion.APAC]
    },
    {
      region: DataRegion.BRAZIL,
      name: 'Brazil',
      awsRegions: [REGION_AWS_MAPPING[DataRegion.BRAZIL].primary],
      compliance: REGION_COMPLIANCE[DataRegion.BRAZIL]
    },
    {
      region: DataRegion.CANADA,
      name: 'Canada',
      awsRegions: [REGION_AWS_MAPPING[DataRegion.CANADA].primary],
      compliance: REGION_COMPLIANCE[DataRegion.CANADA]
    },
    {
      region: DataRegion.AUSTRALIA,
      name: 'Australia',
      awsRegions: [REGION_AWS_MAPPING[DataRegion.AUSTRALIA].primary],
      compliance: REGION_COMPLIANCE[DataRegion.AUSTRALIA]
    }
  ];
}
