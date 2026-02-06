/**
 * Organization SSO Repository - DynamoDB operations for org-level SSO configurations
 * 
 * Table: zalt-tenants
 * PK: TENANT#{tenantId}
 * SK: SSO#CONFIG
 * GSI: domain-sso-index (domain -> tenantId)
 * 
 * Security Requirements:
 * - X.509 certificates must be validated
 * - Domain verification required before SSO enforcement
 * - Audit logging for all SSO configuration changes
 * 
 * Validates: Requirements 9.1, 9.2 (Organization-Level SSO)
 */

import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  DeleteCommand,
  BatchWriteCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from '../services/dynamodb.service';
import {
  OrgSSOConfig,
  OrgSSOConfigDynamoDBItem,
  OrgSSOConfigResponse,
  CreateOrgSSOConfigInput,
  UpdateOrgSSOConfigInput,
  VerifiedDomain,
  SSOConfigStatus,
  generateSSOConfigId,
  generateDomainVerificationToken,
  generateSPEntityId,
  generateACSUrl,
  generateSLOUrl,
  isValidCertificate,
  getCertificateFingerprint,
  isValidDomain,
  toOrgSSOConfigResponse,
  getDefaultAttributeMapping,
  createDefaultJITConfig,
  DEFAULT_OIDC_SCOPES
} from '../models/org-sso.model';

// Table and index names
const TABLE_NAME = process.env.TENANTS_TABLE || 'zalt-tenants';
const DOMAIN_SSO_INDEX = 'domain-sso-index';

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Create primary key for SSO config
 */
function createPK(tenantId: string): string {
  return `TENANT#${tenantId}`;
}

/**
 * Create sort key for SSO config
 */
function createSK(): string {
  return 'SSO#CONFIG';
}

// ============================================================================
// Create Operations
// ============================================================================

/**
 * Create a new SSO configuration for a tenant
 * 
 * @param input - SSO configuration input
 * @returns Created SSO configuration
 * @throws Error if tenant already has SSO config or validation fails
 */
export async function createSSOConfig(
  input: CreateOrgSSOConfigInput
): Promise<OrgSSOConfig> {
  // Check if tenant already has SSO config
  const existing = await getSSOConfig(input.tenantId);
  if (existing) {
    throw new Error('Tenant already has SSO configuration. Use update instead.');
  }
  
  // Validate SAML certificate if provided
  if (input.ssoType === 'saml' && input.samlConfig?.idpCertificate) {
    if (!isValidCertificate(input.samlConfig.idpCertificate)) {
      throw new Error('Invalid X.509 certificate format');
    }
  }
  
  // Validate domains if provided
  if (input.domains) {
    for (const domain of input.domains) {
      if (!isValidDomain(domain)) {
        throw new Error(`Invalid domain format: ${domain}`);
      }
    }
  }
  
  const configId = generateSSOConfigId();
  const now = new Date().toISOString();
  
  // Generate SP configuration
  const spEntityId = generateSPEntityId(input.realmId, input.tenantId);
  const acsUrl = generateACSUrl(input.realmId, input.tenantId);
  const sloUrl = generateSLOUrl(input.realmId, input.tenantId);
  
  // Prepare domains with verification tokens
  const domains: VerifiedDomain[] = (input.domains || []).map(domain => ({
    domain: domain.toLowerCase(),
    verificationStatus: 'pending',
    verificationToken: generateDomainVerificationToken(),
    verificationMethod: 'dns_txt'
  }));
  
  // Prepare SAML config with fingerprint
  let finalSamlConfig: OrgSSOConfig['samlConfig'] | undefined;
  if (input.samlConfig?.idpCertificate) {
    finalSamlConfig = {
      ...input.samlConfig,
      idpCertificateFingerprint: getCertificateFingerprint(input.samlConfig.idpCertificate),
      wantAssertionsSigned: input.samlConfig.wantAssertionsSigned ?? true,
      signAuthnRequests: input.samlConfig.signAuthnRequests ?? true
    };
  } else if (input.samlConfig) {
    finalSamlConfig = {
      ...input.samlConfig,
      wantAssertionsSigned: input.samlConfig.wantAssertionsSigned ?? true,
      signAuthnRequests: input.samlConfig.signAuthnRequests ?? true
    };
  }
  
  // Prepare OIDC config with defaults
  let oidcConfig = input.oidcConfig;
  if (oidcConfig) {
    oidcConfig = {
      ...oidcConfig,
      scopes: oidcConfig.scopes || DEFAULT_OIDC_SCOPES
    };
  }
  
  // Get default attribute mapping if not provided
  const attributeMapping = input.attributeMapping || 
    getDefaultAttributeMapping(input.oidcConfig?.providerPreset);
  
  // Create JIT config with defaults
  const jitProvisioning = {
    ...createDefaultJITConfig(),
    ...input.jitProvisioning
  };
  
  const config: OrgSSOConfig = {
    id: configId,
    tenantId: input.tenantId,
    realmId: input.realmId,
    ssoType: input.ssoType,
    enabled: false, // Start disabled until verified
    status: domains.length > 0 ? 'pending_verification' : 'inactive',
    providerName: input.providerName,
    samlConfig: finalSamlConfig,
    oidcConfig,
    spEntityId,
    acsUrl,
    sloUrl,
    attributeMapping,
    domains,
    enforced: input.enforced ?? false,
    jitProvisioning,
    createdAt: now,
    updatedAt: now,
    createdBy: input.createdBy,
    totalLogins: 0
  };
  
  // Create DynamoDB item
  const item: OrgSSOConfigDynamoDBItem = {
    pk: createPK(input.tenantId),
    sk: createSK(),
    ...config,
    entityType: 'ORG_SSO_CONFIG'
  };
  
  // Add GSI for first domain if exists
  if (domains.length > 0) {
    item.GSI1PK = `DOMAIN#${domains[0].domain}`;
    item.GSI1SK = 'SSO#CONFIG';
  }
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: item,
    ConditionExpression: 'attribute_not_exists(pk) OR attribute_not_exists(sk)'
  }));
  
  return config;
}

// ============================================================================
// Read Operations
// ============================================================================

/**
 * Get SSO configuration for a tenant
 * 
 * @param tenantId - Tenant ID
 * @returns SSO configuration or null if not found
 */
export async function getSSOConfig(tenantId: string): Promise<OrgSSOConfig | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(tenantId),
      sk: createSK()
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  return itemToOrgSSOConfig(result.Item);
}

/**
 * Get SSO configuration by verified domain
 * Used for domain-based SSO routing
 * 
 * @param domain - Email domain (e.g., "acme.com")
 * @returns SSO configuration or null if not found
 */
export async function getSSOConfigByDomain(domain: string): Promise<OrgSSOConfig | null> {
  const normalizedDomain = domain.toLowerCase();
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: DOMAIN_SSO_INDEX,
    KeyConditionExpression: 'GSI1PK = :domainPk AND GSI1SK = :sk',
    ExpressionAttributeValues: {
      ':domainPk': `DOMAIN#${normalizedDomain}`,
      ':sk': 'SSO#CONFIG'
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  const config = itemToOrgSSOConfig(result.Items[0]);
  
  // Verify the domain is actually verified in the config
  const domainEntry = config.domains.find(
    d => d.domain === normalizedDomain && d.verificationStatus === 'verified'
  );
  
  if (!domainEntry) {
    return null;
  }
  
  return config;
}

/**
 * List all SSO configurations for a realm
 * 
 * @param realmId - Realm ID
 * @param options - Query options
 * @returns List of SSO configurations
 */
export async function listSSOConfigs(
  realmId: string,
  options?: {
    status?: SSOConfigStatus;
    limit?: number;
    cursor?: string;
  }
): Promise<{ configs: OrgSSOConfigResponse[]; nextCursor?: string }> {
  const limit = options?.limit || 50;
  
  // Query by realm using a scan with filter (not ideal but works for small datasets)
  // In production, consider adding a GSI for realm_id
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'realm-index', // Assuming this GSI exists
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: options?.status 
      ? 'sk = :sk AND #status = :status AND entityType = :entityType'
      : 'sk = :sk AND entityType = :entityType',
    ExpressionAttributeNames: options?.status ? { '#status': 'status' } : undefined,
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':sk': 'SSO#CONFIG',
      ':entityType': 'ORG_SSO_CONFIG',
      ...(options?.status && { ':status': options.status })
    },
    Limit: limit,
    ExclusiveStartKey: options?.cursor
      ? JSON.parse(Buffer.from(options.cursor, 'base64').toString())
      : undefined
  }));
  
  const configs = (result.Items || []).map(item => 
    toOrgSSOConfigResponse(itemToOrgSSOConfig(item))
  );
  
  return {
    configs,
    nextCursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined
  };
}

/**
 * Check if SSO is enforced for an email domain
 * 
 * @param email - User email
 * @returns SSO config if enforced, null otherwise
 */
export async function getEnforcedSSOForEmail(email: string): Promise<OrgSSOConfig | null> {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) {
    return null;
  }
  
  const config = await getSSOConfigByDomain(domain);
  
  if (!config || !config.enabled || !config.enforced) {
    return null;
  }
  
  return config;
}

// ============================================================================
// Update Operations
// ============================================================================

/**
 * Update SSO configuration
 * 
 * @param tenantId - Tenant ID
 * @param input - Update input
 * @returns Updated SSO configuration or null if not found
 */
export async function updateSSOConfig(
  tenantId: string,
  input: UpdateOrgSSOConfigInput
): Promise<OrgSSOConfig | null> {
  const existing = await getSSOConfig(tenantId);
  if (!existing) {
    return null;
  }
  
  // Validate SAML certificate if provided
  if (input.samlConfig?.idpCertificate) {
    if (!isValidCertificate(input.samlConfig.idpCertificate)) {
      throw new Error('Invalid X.509 certificate format');
    }
  }
  
  const now = new Date().toISOString();
  
  // Build update expression dynamically
  const updateParts: string[] = ['updatedAt = :now'];
  const expressionAttributeValues: Record<string, unknown> = {
    ':now': now
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (input.providerName !== undefined) {
    updateParts.push('providerName = :providerName');
    expressionAttributeValues[':providerName'] = input.providerName;
  }
  
  if (input.enabled !== undefined) {
    updateParts.push('enabled = :enabled');
    expressionAttributeValues[':enabled'] = input.enabled;
  }
  
  if (input.status !== undefined) {
    updateParts.push('#status = :status');
    expressionAttributeNames['#status'] = 'status';
    expressionAttributeValues[':status'] = input.status;
  }
  
  if (input.samlConfig !== undefined) {
    const updatedSamlConfig = { ...existing.samlConfig, ...input.samlConfig };
    
    // Update fingerprint if certificate changed
    if (input.samlConfig.idpCertificate) {
      updatedSamlConfig.idpCertificateFingerprint = getCertificateFingerprint(
        input.samlConfig.idpCertificate
      );
    }
    
    updateParts.push('samlConfig = :samlConfig');
    expressionAttributeValues[':samlConfig'] = updatedSamlConfig;
  }
  
  if (input.oidcConfig !== undefined) {
    updateParts.push('oidcConfig = :oidcConfig');
    expressionAttributeValues[':oidcConfig'] = { ...existing.oidcConfig, ...input.oidcConfig };
  }
  
  if (input.attributeMapping !== undefined) {
    updateParts.push('attributeMapping = :attributeMapping');
    expressionAttributeValues[':attributeMapping'] = input.attributeMapping;
  }
  
  if (input.enforced !== undefined) {
    updateParts.push('enforced = :enforced');
    expressionAttributeValues[':enforced'] = input.enforced;
  }
  
  if (input.jitProvisioning !== undefined) {
    updateParts.push('jitProvisioning = :jitProvisioning');
    expressionAttributeValues[':jitProvisioning'] = {
      ...existing.jitProvisioning,
      ...input.jitProvisioning
    };
  }
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId),
        sk: createSK()
      },
      UpdateExpression: `SET ${updateParts.join(', ')}`,
      ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0
        ? expressionAttributeNames
        : undefined,
      ExpressionAttributeValues: expressionAttributeValues,
      ConditionExpression: 'attribute_exists(pk) AND attribute_exists(sk)',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToOrgSSOConfig(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Add a domain to SSO configuration
 * 
 * @param tenantId - Tenant ID
 * @param domain - Domain to add
 * @returns Updated SSO configuration
 */
export async function addDomain(
  tenantId: string,
  domain: string
): Promise<OrgSSOConfig | null> {
  if (!isValidDomain(domain)) {
    throw new Error(`Invalid domain format: ${domain}`);
  }
  
  const existing = await getSSOConfig(tenantId);
  if (!existing) {
    return null;
  }
  
  const normalizedDomain = domain.toLowerCase();
  
  // Check if domain already exists
  if (existing.domains.some(d => d.domain === normalizedDomain)) {
    throw new Error(`Domain ${domain} already exists in configuration`);
  }
  
  const newDomain: VerifiedDomain = {
    domain: normalizedDomain,
    verificationStatus: 'pending',
    verificationToken: generateDomainVerificationToken(),
    verificationMethod: 'dns_txt'
  };
  
  const updatedDomains = [...existing.domains, newDomain];
  const now = new Date().toISOString();
  
  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(tenantId),
      sk: createSK()
    },
    UpdateExpression: 'SET domains = :domains, updatedAt = :now, #status = :status',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':domains': updatedDomains,
      ':now': now,
      ':status': 'pending_verification'
    },
    ReturnValues: 'ALL_NEW'
  }));
  
  if (!result.Attributes) {
    return null;
  }
  
  return itemToOrgSSOConfig(result.Attributes);
}

/**
 * Verify a domain
 * 
 * @param tenantId - Tenant ID
 * @param domain - Domain to verify
 * @returns Updated SSO configuration
 */
export async function verifyDomain(
  tenantId: string,
  domain: string
): Promise<OrgSSOConfig | null> {
  const existing = await getSSOConfig(tenantId);
  if (!existing) {
    return null;
  }
  
  const normalizedDomain = domain.toLowerCase();
  const domainIndex = existing.domains.findIndex(d => d.domain === normalizedDomain);
  
  if (domainIndex === -1) {
    throw new Error(`Domain ${domain} not found in configuration`);
  }
  
  const now = new Date().toISOString();
  const updatedDomains = [...existing.domains];
  updatedDomains[domainIndex] = {
    ...updatedDomains[domainIndex],
    verificationStatus: 'verified',
    verifiedAt: now
  };
  
  // Check if all domains are verified
  const allVerified = updatedDomains.every(d => d.verificationStatus === 'verified');
  const newStatus: SSOConfigStatus = allVerified ? 'active' : 'pending_verification';
  
  // Update GSI for domain lookup
  const updateExpression = domainIndex === 0
    ? 'SET domains = :domains, updatedAt = :now, #status = :status, GSI1PK = :gsi1pk, GSI1SK = :gsi1sk'
    : 'SET domains = :domains, updatedAt = :now, #status = :status';
  
  const expressionAttributeValues: Record<string, unknown> = {
    ':domains': updatedDomains,
    ':now': now,
    ':status': newStatus
  };
  
  if (domainIndex === 0) {
    expressionAttributeValues[':gsi1pk'] = `DOMAIN#${normalizedDomain}`;
    expressionAttributeValues[':gsi1sk'] = 'SSO#CONFIG';
  }
  
  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(tenantId),
      sk: createSK()
    },
    UpdateExpression: updateExpression,
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: expressionAttributeValues,
    ReturnValues: 'ALL_NEW'
  }));
  
  if (!result.Attributes) {
    return null;
  }
  
  return itemToOrgSSOConfig(result.Attributes);
}

/**
 * Remove a domain from SSO configuration
 * 
 * @param tenantId - Tenant ID
 * @param domain - Domain to remove
 * @returns Updated SSO configuration
 */
export async function removeDomain(
  tenantId: string,
  domain: string
): Promise<OrgSSOConfig | null> {
  const existing = await getSSOConfig(tenantId);
  if (!existing) {
    return null;
  }
  
  const normalizedDomain = domain.toLowerCase();
  const updatedDomains = existing.domains.filter(d => d.domain !== normalizedDomain);
  
  if (updatedDomains.length === existing.domains.length) {
    throw new Error(`Domain ${domain} not found in configuration`);
  }
  
  const now = new Date().toISOString();
  
  // If removing the primary domain (index 0), update GSI
  const wasPrimaryDomain = existing.domains[0]?.domain === normalizedDomain;
  
  let updateExpression = 'SET domains = :domains, updatedAt = :now';
  const expressionAttributeValues: Record<string, unknown> = {
    ':domains': updatedDomains,
    ':now': now
  };
  
  if (wasPrimaryDomain && updatedDomains.length > 0) {
    // Update GSI to new primary domain
    updateExpression += ', GSI1PK = :gsi1pk, GSI1SK = :gsi1sk';
    expressionAttributeValues[':gsi1pk'] = `DOMAIN#${updatedDomains[0].domain}`;
    expressionAttributeValues[':gsi1sk'] = 'SSO#CONFIG';
  } else if (wasPrimaryDomain) {
    // Remove GSI
    updateExpression += ' REMOVE GSI1PK, GSI1SK';
  }
  
  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(tenantId),
      sk: createSK()
    },
    UpdateExpression: updateExpression,
    ExpressionAttributeValues: expressionAttributeValues,
    ReturnValues: 'ALL_NEW'
  }));
  
  if (!result.Attributes) {
    return null;
  }
  
  return itemToOrgSSOConfig(result.Attributes);
}

/**
 * Record SSO login
 * 
 * @param tenantId - Tenant ID
 */
export async function recordSSOLogin(tenantId: string): Promise<void> {
  const now = new Date().toISOString();
  
  try {
    await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId),
        sk: createSK()
      },
      UpdateExpression: 'SET totalLogins = if_not_exists(totalLogins, :zero) + :one, lastUsedAt = :now, lastLoginAt = :now',
      ExpressionAttributeValues: {
        ':zero': 0,
        ':one': 1,
        ':now': now
      },
      ConditionExpression: 'attribute_exists(pk)'
    }));
  } catch (error: unknown) {
    // Log but don't throw - login recording is not critical
    console.error('Failed to record SSO login:', error);
  }
}

// ============================================================================
// Delete Operations
// ============================================================================

/**
 * Soft delete SSO configuration (mark as deleted)
 * 
 * @param tenantId - Tenant ID
 * @returns True if deleted, false if not found
 */
export async function deleteSSOConfig(tenantId: string): Promise<boolean> {
  const result = await updateSSOConfig(tenantId, { 
    status: 'deleted',
    enabled: false,
    enforced: false
  });
  return result !== null;
}

/**
 * Hard delete SSO configuration permanently
 * 
 * @param tenantId - Tenant ID
 * @returns True if deleted, false otherwise
 */
export async function hardDeleteSSOConfig(tenantId: string): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId),
        sk: createSK()
      }
    }));
    return true;
  } catch {
    return false;
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to OrgSSOConfig
 */
function itemToOrgSSOConfig(item: Record<string, unknown>): OrgSSOConfig {
  return {
    id: item.id as string,
    tenantId: item.tenantId as string,
    realmId: item.realmId as string,
    ssoType: item.ssoType as OrgSSOConfig['ssoType'],
    enabled: item.enabled as boolean,
    status: item.status as OrgSSOConfig['status'],
    providerName: item.providerName as string,
    samlConfig: item.samlConfig as OrgSSOConfig['samlConfig'],
    oidcConfig: item.oidcConfig as OrgSSOConfig['oidcConfig'],
    spEntityId: item.spEntityId as string,
    acsUrl: item.acsUrl as string,
    sloUrl: item.sloUrl as string | undefined,
    attributeMapping: item.attributeMapping as OrgSSOConfig['attributeMapping'],
    domains: item.domains as VerifiedDomain[],
    enforced: item.enforced as boolean,
    jitProvisioning: item.jitProvisioning as OrgSSOConfig['jitProvisioning'],
    createdAt: item.createdAt as string,
    updatedAt: item.updatedAt as string,
    createdBy: item.createdBy as string | undefined,
    lastUsedAt: item.lastUsedAt as string | undefined,
    totalLogins: item.totalLogins as number | undefined,
    lastLoginAt: item.lastLoginAt as string | undefined
  };
}

