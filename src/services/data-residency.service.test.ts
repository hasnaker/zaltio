/**
 * Data Residency Service Tests
 * Task 20.2: Data Residency Implementation
 * 
 * Tests:
 * - Region routing
 * - Cross-region transfer policies
 * - Configuration validation
 * - Compliance framework mapping
 * - Region suggestion
 */

import {
  DataRegion,
  DataType,
  TransferMechanism,
  DataResidencyConfig,
  getAWSRegion,
  getTableSuffix,
  routeToRegion,
  isTransferAllowed,
  createDefaultConfig,
  createGDPRConfig,
  createHIPAAConfig,
  validateConfig,
  createDataLocationRecord,
  getComplianceFrameworks,
  isCompliantWith,
  suggestRegion,
  getAvailableRegions,
  REGION_AWS_MAPPING,
  REGION_COMPLIANCE
} from './data-residency.service';

// ============================================================================
// Test Data
// ============================================================================

const createMockConfig = (overrides: Partial<DataResidencyConfig> = {}): DataResidencyConfig => ({
  realmId: 'realm-clinisyn',
  primaryRegion: DataRegion.EU,
  allowedRegions: [DataRegion.EU],
  dataTypes: [
    { dataType: DataType.USER_PROFILE, region: DataRegion.EU, encrypted: true, retentionDays: 365 },
    { dataType: DataType.CREDENTIALS, region: DataRegion.EU, encrypted: true, retentionDays: 365 },
    { dataType: DataType.AUDIT_LOGS, region: DataRegion.EU, encrypted: true, retentionDays: 2190 }
  ],
  crossRegionTransfer: {
    enabled: false,
    allowedDestinations: [],
    requiresConsent: true,
    transferMechanism: TransferMechanism.NONE,
    sccs: false
  },
  retentionPolicy: {
    defaultRetentionDays: 365,
    auditLogRetentionDays: 2190,
    sessionRetentionDays: 30,
    deletedUserRetentionDays: 90,
    backupRetentionDays: 365
  },
  encryptionConfig: {
    atRest: true,
    inTransit: true,
    customerManagedKey: false
  },
  createdAt: '2026-02-01T00:00:00.000Z',
  updatedAt: '2026-02-01T00:00:00.000Z',
  ...overrides
});

// ============================================================================
// Region Routing Tests
// ============================================================================

describe('Data Residency - Region Routing', () => {
  describe('getAWSRegion', () => {
    it('should return primary AWS region for EU', () => {
      const result = getAWSRegion(DataRegion.EU, true);
      expect(result).toBe('eu-central-1');
    });

    it('should return secondary AWS region for EU', () => {
      const result = getAWSRegion(DataRegion.EU, false);
      expect(result).toBe('eu-west-1');
    });

    it('should return primary AWS region for US', () => {
      const result = getAWSRegion(DataRegion.US, true);
      expect(result).toBe('us-east-1');
    });

    it('should return primary AWS region for APAC', () => {
      const result = getAWSRegion(DataRegion.APAC, true);
      expect(result).toBe('ap-southeast-1');
    });

    it('should return correct regions for all data regions', () => {
      for (const region of Object.values(DataRegion)) {
        const awsRegion = getAWSRegion(region);
        expect(awsRegion).toBeDefined();
        expect(awsRegion.length).toBeGreaterThan(0);
      }
    });
  });

  describe('getTableSuffix', () => {
    it('should return correct suffix for EU', () => {
      expect(getTableSuffix(DataRegion.EU)).toBe('-eu');
    });

    it('should return correct suffix for US', () => {
      expect(getTableSuffix(DataRegion.US)).toBe('-us');
    });

    it('should return correct suffix for APAC', () => {
      expect(getTableSuffix(DataRegion.APAC)).toBe('-apac');
    });
  });

  describe('routeToRegion', () => {
    it('should route to primary region by default', () => {
      const config = createMockConfig({ primaryRegion: DataRegion.EU });
      
      const result = routeToRegion('realm-123', config);
      
      expect(result.region).toBe(DataRegion.EU);
      expect(result.awsRegion).toBe('eu-central-1');
      expect(result.tableSuffix).toBe('-eu');
    });

    it('should route to specific region for data type', () => {
      const config = createMockConfig({
        primaryRegion: DataRegion.EU,
        dataTypes: [
          { dataType: DataType.ANALYTICS, region: DataRegion.US, encrypted: false, retentionDays: 365 }
        ]
      });
      
      const result = routeToRegion('realm-123', config, DataType.ANALYTICS);
      
      expect(result.region).toBe(DataRegion.US);
      expect(result.awsRegion).toBe('us-east-1');
    });

    it('should use primary region when data type not configured', () => {
      const config = createMockConfig({ primaryRegion: DataRegion.APAC });
      
      const result = routeToRegion('realm-123', config, DataType.WEBHOOKS);
      
      expect(result.region).toBe(DataRegion.APAC);
    });
  });
});

// ============================================================================
// Cross-Region Transfer Tests
// ============================================================================

describe('Data Residency - Cross-Region Transfer', () => {
  describe('isTransferAllowed', () => {
    it('should allow transfer within same region', () => {
      const policy = {
        enabled: false,
        allowedDestinations: [],
        requiresConsent: true,
        transferMechanism: TransferMechanism.NONE,
        sccs: false
      };
      
      const result = isTransferAllowed(DataRegion.EU, DataRegion.EU, policy);
      
      expect(result.allowed).toBe(true);
      expect(result.requiresConsent).toBe(false);
    });

    it('should deny transfer when cross-region disabled', () => {
      const policy = {
        enabled: false,
        allowedDestinations: [DataRegion.US],
        requiresConsent: true,
        transferMechanism: TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES,
        sccs: true
      };
      
      const result = isTransferAllowed(DataRegion.EU, DataRegion.US, policy);
      
      expect(result.allowed).toBe(false);
    });

    it('should deny transfer to non-allowed destination', () => {
      const policy = {
        enabled: true,
        allowedDestinations: [DataRegion.US],
        requiresConsent: true,
        transferMechanism: TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES,
        sccs: true
      };
      
      const result = isTransferAllowed(DataRegion.EU, DataRegion.APAC, policy);
      
      expect(result.allowed).toBe(false);
    });

    it('should allow transfer to allowed destination with mechanism', () => {
      const policy = {
        enabled: true,
        allowedDestinations: [DataRegion.US],
        requiresConsent: true,
        transferMechanism: TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES,
        sccs: true
      };
      
      const result = isTransferAllowed(DataRegion.EU, DataRegion.US, policy);
      
      expect(result.allowed).toBe(true);
      expect(result.mechanism).toBe(TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES);
      expect(result.requiresConsent).toBe(true);
    });
  });
});

// ============================================================================
// Configuration Tests
// ============================================================================

describe('Data Residency - Configuration', () => {
  describe('createDefaultConfig', () => {
    it('should create config with specified primary region', () => {
      const config = createDefaultConfig('realm-123', DataRegion.US);
      
      expect(config.realmId).toBe('realm-123');
      expect(config.primaryRegion).toBe(DataRegion.US);
      expect(config.allowedRegions).toContain(DataRegion.US);
    });

    it('should include all data types', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      
      expect(config.dataTypes.length).toBeGreaterThan(0);
      expect(config.dataTypes.map(dt => dt.dataType)).toContain(DataType.USER_PROFILE);
      expect(config.dataTypes.map(dt => dt.dataType)).toContain(DataType.CREDENTIALS);
      expect(config.dataTypes.map(dt => dt.dataType)).toContain(DataType.AUDIT_LOGS);
    });

    it('should have encryption enabled by default', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      
      expect(config.encryptionConfig.atRest).toBe(true);
      expect(config.encryptionConfig.inTransit).toBe(true);
    });

    it('should have cross-region transfer disabled by default', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      
      expect(config.crossRegionTransfer.enabled).toBe(false);
    });
  });

  describe('createGDPRConfig', () => {
    it('should create EU-based config', () => {
      const config = createGDPRConfig('realm-gdpr');
      
      expect(config.primaryRegion).toBe(DataRegion.EU);
    });

    it('should have SCCs enabled', () => {
      const config = createGDPRConfig('realm-gdpr');
      
      expect(config.crossRegionTransfer.sccs).toBe(true);
      expect(config.crossRegionTransfer.transferMechanism).toBe(TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES);
    });

    it('should have shorter deleted user retention for right to erasure', () => {
      const config = createGDPRConfig('realm-gdpr');
      
      expect(config.retentionPolicy.deletedUserRetentionDays).toBe(30);
    });
  });

  describe('createHIPAAConfig', () => {
    it('should create US-based config', () => {
      const config = createHIPAAConfig('realm-hipaa');
      
      expect(config.primaryRegion).toBe(DataRegion.US);
    });

    it('should have 6-year audit log retention', () => {
      const config = createHIPAAConfig('realm-hipaa');
      
      expect(config.retentionPolicy.auditLogRetentionDays).toBe(2190);
    });

    it('should require customer-managed encryption', () => {
      const config = createHIPAAConfig('realm-hipaa');
      
      expect(config.encryptionConfig.customerManagedKey).toBe(true);
    });
  });

  describe('validateConfig', () => {
    it('should validate complete config', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      
      const result = validateConfig(config);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject missing realm ID', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      delete (config as Partial<DataResidencyConfig>).realmId;
      
      const result = validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Realm ID is required');
    });

    it('should reject missing primary region', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      delete (config as Partial<DataResidencyConfig>).primaryRegion;
      
      const result = validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Primary region is required');
    });

    it('should reject invalid primary region', () => {
      const config = {
        realmId: 'realm-123',
        primaryRegion: 'invalid-region' as DataRegion
      };
      
      const result = validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('Invalid primary region'))).toBe(true);
    });

    it('should reject primary region not in allowed regions', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      config.allowedRegions = [DataRegion.US]; // EU not included
      
      const result = validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Primary region must be in allowed regions');
    });

    it('should reject cross-region transfer without destinations', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      config.crossRegionTransfer.enabled = true;
      config.crossRegionTransfer.allowedDestinations = [];
      
      const result = validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Cross-region transfer enabled but no destinations specified');
    });

    it('should reject cross-region transfer without mechanism', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      config.crossRegionTransfer.enabled = true;
      config.crossRegionTransfer.allowedDestinations = [DataRegion.US];
      config.crossRegionTransfer.transferMechanism = TransferMechanism.NONE;
      
      const result = validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Cross-region transfer enabled but no transfer mechanism specified');
    });

    it('should reject audit log retention less than 365 days', () => {
      const config = createDefaultConfig('realm-123', DataRegion.EU);
      config.retentionPolicy.auditLogRetentionDays = 90;
      
      const result = validateConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Audit log retention must be at least 365 days for compliance');
    });
  });
});

// ============================================================================
// Data Location Tests
// ============================================================================

describe('Data Residency - Data Location', () => {
  describe('createDataLocationRecord', () => {
    it('should create location record with correct region', () => {
      const config = createMockConfig({ primaryRegion: DataRegion.EU });
      
      const record = createDataLocationRecord('users', 'user-123', 'realm-456', config);
      
      expect(record.entityType).toBe('users');
      expect(record.entityId).toBe('user-123');
      expect(record.realmId).toBe('realm-456');
      expect(record.region).toBe(DataRegion.EU);
      expect(record.awsRegion).toBe('eu-central-1');
      expect(record.tableName).toBe('zalt-users-eu');
      expect(record.encrypted).toBe(true);
    });

    it('should use data type specific region', () => {
      const config = createMockConfig({
        primaryRegion: DataRegion.EU,
        dataTypes: [
          { dataType: DataType.ANALYTICS, region: DataRegion.US, encrypted: false, retentionDays: 365 }
        ]
      });
      
      const record = createDataLocationRecord('analytics', 'event-123', 'realm-456', config, DataType.ANALYTICS);
      
      expect(record.region).toBe(DataRegion.US);
      expect(record.awsRegion).toBe('us-east-1');
      expect(record.tableName).toBe('zalt-analytics-us');
    });

    it('should include unique ID and timestamp', () => {
      const config = createMockConfig();
      
      const record = createDataLocationRecord('users', 'user-123', 'realm-456', config);
      
      expect(record.id).toBeDefined();
      expect(record.id.length).toBeGreaterThan(0);
      expect(record.createdAt).toBeDefined();
    });
  });
});

// ============================================================================
// Compliance Tests
// ============================================================================

describe('Data Residency - Compliance', () => {
  describe('getComplianceFrameworks', () => {
    it('should return GDPR for EU region', () => {
      const frameworks = getComplianceFrameworks(DataRegion.EU);
      
      expect(frameworks).toContain('GDPR');
    });

    it('should return HIPAA for US region', () => {
      const frameworks = getComplianceFrameworks(DataRegion.US);
      
      expect(frameworks).toContain('HIPAA');
    });

    it('should return LGPD for Brazil region', () => {
      const frameworks = getComplianceFrameworks(DataRegion.BRAZIL);
      
      expect(frameworks).toContain('LGPD');
    });

    it('should return PIPEDA for Canada region', () => {
      const frameworks = getComplianceFrameworks(DataRegion.CANADA);
      
      expect(frameworks).toContain('PIPEDA');
    });
  });

  describe('isCompliantWith', () => {
    it('should return true for EU and GDPR', () => {
      expect(isCompliantWith(DataRegion.EU, 'GDPR')).toBe(true);
    });

    it('should return true for US and HIPAA', () => {
      expect(isCompliantWith(DataRegion.US, 'HIPAA')).toBe(true);
    });

    it('should return false for EU and HIPAA', () => {
      expect(isCompliantWith(DataRegion.EU, 'HIPAA')).toBe(false);
    });

    it('should return false for US and GDPR', () => {
      expect(isCompliantWith(DataRegion.US, 'GDPR')).toBe(false);
    });
  });
});

// ============================================================================
// Region Suggestion Tests
// ============================================================================

describe('Data Residency - Region Suggestion', () => {
  describe('suggestRegion', () => {
    it('should suggest EU for Germany', () => {
      expect(suggestRegion('DE')).toBe(DataRegion.EU);
    });

    it('should suggest EU for France', () => {
      expect(suggestRegion('FR')).toBe(DataRegion.EU);
    });

    it('should suggest EU for UK', () => {
      expect(suggestRegion('GB')).toBe(DataRegion.EU);
    });

    it('should suggest US for United States', () => {
      expect(suggestRegion('US')).toBe(DataRegion.US);
    });

    it('should suggest APAC for Japan', () => {
      expect(suggestRegion('JP')).toBe(DataRegion.APAC);
    });

    it('should suggest APAC for Singapore', () => {
      expect(suggestRegion('SG')).toBe(DataRegion.APAC);
    });

    it('should suggest Brazil for Brazil', () => {
      expect(suggestRegion('BR')).toBe(DataRegion.BRAZIL);
    });

    it('should suggest Canada for Canada', () => {
      expect(suggestRegion('CA')).toBe(DataRegion.CANADA);
    });

    it('should suggest Australia for Australia', () => {
      expect(suggestRegion('AU')).toBe(DataRegion.AUSTRALIA);
    });

    it('should default to US for unknown countries', () => {
      expect(suggestRegion('XX')).toBe(DataRegion.US);
    });
  });

  describe('getAvailableRegions', () => {
    it('should return all regions', () => {
      const regions = getAvailableRegions();
      
      expect(regions.length).toBe(6);
      expect(regions.map(r => r.region)).toContain(DataRegion.EU);
      expect(regions.map(r => r.region)).toContain(DataRegion.US);
      expect(regions.map(r => r.region)).toContain(DataRegion.APAC);
    });

    it('should include AWS regions for each data region', () => {
      const regions = getAvailableRegions();
      
      for (const region of regions) {
        expect(region.awsRegions.length).toBeGreaterThan(0);
      }
    });

    it('should include compliance frameworks for each region', () => {
      const regions = getAvailableRegions();
      
      for (const region of regions) {
        expect(region.compliance.length).toBeGreaterThan(0);
      }
    });
  });
});

// ============================================================================
// AWS Region Mapping Tests
// ============================================================================

describe('Data Residency - AWS Region Mapping', () => {
  it('should have mapping for all data regions', () => {
    for (const region of Object.values(DataRegion)) {
      expect(REGION_AWS_MAPPING[region]).toBeDefined();
      expect(REGION_AWS_MAPPING[region].primary).toBeDefined();
    }
  });

  it('should have compliance frameworks for all data regions', () => {
    for (const region of Object.values(DataRegion)) {
      expect(REGION_COMPLIANCE[region]).toBeDefined();
      expect(REGION_COMPLIANCE[region].length).toBeGreaterThan(0);
    }
  });
});
