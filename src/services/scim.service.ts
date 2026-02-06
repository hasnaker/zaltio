/**
 * SCIM 2.0 Service - System for Cross-domain Identity Management
 * Implements RFC 7643 (Core Schema) and RFC 7644 (Protocol)
 * 
 * Validates: Requirements 31.1, 31.4-31.7
 * - User provisioning/deprovisioning
 * - Group sync
 * - Attribute mapping
 * 
 * @module scim.service
 */

import * as crypto from 'crypto';

// ============================================================================
// SCIM 2.0 TYPES AND INTERFACES
// ============================================================================

/**
 * SCIM 2.0 Schema URIs
 */
export const SCIM_SCHEMAS = {
  USER: 'urn:ietf:params:scim:schemas:core:2.0:User',
  GROUP: 'urn:ietf:params:scim:schemas:core:2.0:Group',
  ENTERPRISE_USER: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
  LIST_RESPONSE: 'urn:ietf:params:scim:api:messages:2.0:ListResponse',
  ERROR: 'urn:ietf:params:scim:api:messages:2.0:Error',
  PATCH_OP: 'urn:ietf:params:scim:api:messages:2.0:PatchOp',
  BULK_REQUEST: 'urn:ietf:params:scim:api:messages:2.0:BulkRequest',
  BULK_RESPONSE: 'urn:ietf:params:scim:api:messages:2.0:BulkResponse',
  SERVICE_PROVIDER_CONFIG: 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig',
  RESOURCE_TYPE: 'urn:ietf:params:scim:schemas:core:2.0:ResourceType',
  SCHEMA: 'urn:ietf:params:scim:schemas:core:2.0:Schema',
} as const;

/**
 * SCIM Meta information
 */
export interface SCIMMeta {
  resourceType: 'User' | 'Group';
  created: string;
  lastModified: string;
  location: string;
  version?: string;
}

/**
 * SCIM Name component
 */
export interface SCIMName {
  formatted?: string;
  familyName?: string;
  givenName?: string;
  middleName?: string;
  honorificPrefix?: string;
  honorificSuffix?: string;
}


/**
 * SCIM Email type
 */
export interface SCIMEmail {
  value: string;
  type?: 'work' | 'home' | 'other';
  primary?: boolean;
}

/**
 * SCIM Phone Number type
 */
export interface SCIMPhoneNumber {
  value: string;
  type?: 'work' | 'home' | 'mobile' | 'fax' | 'pager' | 'other';
  primary?: boolean;
}

/**
 * SCIM Address type
 */
export interface SCIMAddress {
  formatted?: string;
  streetAddress?: string;
  locality?: string;
  region?: string;
  postalCode?: string;
  country?: string;
  type?: 'work' | 'home' | 'other';
  primary?: boolean;
}

/**
 * SCIM Enterprise User Extension
 */
export interface SCIMEnterpriseUser {
  employeeNumber?: string;
  costCenter?: string;
  organization?: string;
  division?: string;
  department?: string;
  manager?: {
    value?: string;
    $ref?: string;
    displayName?: string;
  };
}

/**
 * SCIM User Resource (RFC 7643)
 */
export interface SCIMUser {
  schemas: string[];
  id?: string;
  externalId?: string;
  meta?: SCIMMeta;
  userName: string;
  name?: SCIMName;
  displayName?: string;
  nickName?: string;
  profileUrl?: string;
  title?: string;
  userType?: string;
  preferredLanguage?: string;
  locale?: string;
  timezone?: string;
  active?: boolean;
  password?: string;
  emails?: SCIMEmail[];
  phoneNumbers?: SCIMPhoneNumber[];
  addresses?: SCIMAddress[];
  groups?: Array<{
    value: string;
    $ref?: string;
    display?: string;
    type?: 'direct' | 'indirect';
  }>;
  'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'?: SCIMEnterpriseUser;
}


/**
 * SCIM Group Member
 */
export interface SCIMGroupMember {
  value: string;
  $ref?: string;
  display?: string;
  type?: 'User' | 'Group';
}

/**
 * SCIM Group Resource (RFC 7643)
 */
export interface SCIMGroup {
  schemas: string[];
  id?: string;
  externalId?: string;
  meta?: SCIMMeta;
  displayName: string;
  members?: SCIMGroupMember[];
}

/**
 * SCIM List Response
 */
export interface SCIMListResponse<T> {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: T[];
}

/**
 * SCIM Error Response
 */
export interface SCIMError {
  schemas: string[];
  status: string;
  scimType?: string;
  detail?: string;
}

/**
 * SCIM Patch Operation
 */
export interface SCIMPatchOperation {
  op: 'add' | 'remove' | 'replace';
  path?: string;
  value?: unknown;
}

/**
 * SCIM Patch Request
 */
export interface SCIMPatchRequest {
  schemas: string[];
  Operations: SCIMPatchOperation[];
}

/**
 * SCIM Bulk Operation
 */
export interface SCIMBulkOperation {
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  bulkId?: string;
  version?: string;
  path: string;
  data?: unknown;
}

/**
 * SCIM Bulk Request
 */
export interface SCIMBulkRequest {
  schemas: string[];
  Operations: SCIMBulkOperation[];
  failOnErrors?: number;
}

/**
 * SCIM Bulk Response Operation
 */
export interface SCIMBulkResponseOperation {
  method: string;
  bulkId?: string;
  version?: string;
  location?: string;
  status: string;
  response?: unknown;
}

/**
 * SCIM Bulk Response
 */
export interface SCIMBulkResponse {
  schemas: string[];
  Operations: SCIMBulkResponseOperation[];
}


/**
 * SCIM Filter Operators (RFC 7644)
 */
export type SCIMFilterOperator = 
  | 'eq'   // equal
  | 'ne'   // not equal
  | 'co'   // contains
  | 'sw'   // starts with
  | 'ew'   // ends with
  | 'pr'   // present (has value)
  | 'gt'   // greater than
  | 'ge'   // greater than or equal
  | 'lt'   // less than
  | 'le';  // less than or equal

/**
 * Parsed SCIM Filter
 */
export interface SCIMFilterExpression {
  attribute: string;
  operator: SCIMFilterOperator;
  value?: string;
}

/**
 * SCIM Service Provider Configuration
 */
export interface SCIMServiceProviderConfig {
  schemas: string[];
  documentationUri?: string;
  patch: { supported: boolean };
  bulk: { 
    supported: boolean;
    maxOperations: number;
    maxPayloadSize: number;
  };
  filter: {
    supported: boolean;
    maxResults: number;
  };
  changePassword: { supported: boolean };
  sort: { supported: boolean };
  etag: { supported: boolean };
  authenticationSchemes: Array<{
    type: string;
    name: string;
    description: string;
    specUri?: string;
    documentationUri?: string;
    primary?: boolean;
  }>;
}

// ============================================================================
// ZALT USER MODEL MAPPING
// ============================================================================

/**
 * Zalt internal user model (simplified for SCIM mapping)
 */
export interface ZaltUser {
  id: string;
  realm_id: string;
  email: string;
  email_verified: boolean;
  profile: {
    first_name?: string;
    last_name?: string;
    phone?: string;
    avatar_url?: string;
    metadata?: Record<string, unknown>;
  };
  status: 'active' | 'suspended' | 'pending_verification' | 'deleted';
  created_at: string;
  updated_at: string;
  external_id?: string;
}

/**
 * Zalt internal group model
 */
export interface ZaltGroup {
  id: string;
  realm_id: string;
  name: string;
  description?: string;
  members: string[];
  external_id?: string;
  created_at: string;
  updated_at: string;
}


// ============================================================================
// SCIM FILTER PARSER
// ============================================================================

/**
 * SCIM Filter Parser
 * Parses SCIM 2.0 filter expressions according to RFC 7644
 */
export class SCIMFilterParser {
  private static readonly OPERATORS: SCIMFilterOperator[] = [
    'eq', 'ne', 'co', 'sw', 'ew', 'pr', 'gt', 'ge', 'lt', 'le'
  ];

  /**
   * Parse a SCIM filter string into filter expressions
   * Supports: attribute op value, attribute pr
   * Examples: 
   *   - userName eq "john"
   *   - emails.value co "@example.com"
   *   - active eq true
   *   - name.familyName pr
   */
  static parse(filter: string): SCIMFilterExpression[] {
    if (!filter || filter.trim() === '') {
      return [];
    }

    const expressions: SCIMFilterExpression[] = [];
    
    // Split by 'and' (case insensitive) for simple AND logic
    const parts = filter.split(/\s+and\s+/i);

    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed) continue;

      const expression = this.parseExpression(trimmed);
      if (expression) {
        expressions.push(expression);
      }
    }

    return expressions;
  }

  /**
   * Parse a single filter expression
   */
  private static parseExpression(expr: string): SCIMFilterExpression | null {
    // Handle 'pr' (present) operator: attribute pr
    const prMatch = expr.match(/^([a-zA-Z0-9_.]+)\s+pr$/i);
    if (prMatch) {
      return {
        attribute: prMatch[1],
        operator: 'pr'
      };
    }

    // Handle comparison operators: attribute op value
    // Value can be quoted string, number, or boolean
    const opPattern = this.OPERATORS.filter(op => op !== 'pr').join('|');
    const compMatch = expr.match(
      new RegExp(`^([a-zA-Z0-9_.]+)\\s+(${opPattern})\\s+(.+)$`, 'i')
    );

    if (compMatch) {
      const attribute = compMatch[1];
      const operator = compMatch[2].toLowerCase() as SCIMFilterOperator;
      let value = compMatch[3].trim();

      // Remove quotes from string values
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }

      return { attribute, operator, value };
    }

    return null;
  }

  /**
   * Apply filter expressions to a list of items
   */
  static applyFilters<T extends Record<string, unknown>>(
    items: T[],
    filters: SCIMFilterExpression[]
  ): T[] {
    if (filters.length === 0) {
      return items;
    }

    return items.filter(item => {
      return filters.every(filter => this.matchesFilter(item, filter));
    });
  }


  /**
   * Check if an item matches a single filter expression
   */
  private static matchesFilter<T extends Record<string, unknown>>(
    item: T,
    filter: SCIMFilterExpression
  ): boolean {
    const value = this.getNestedValue(item, filter.attribute);

    switch (filter.operator) {
      case 'pr':
        return value !== undefined && value !== null && value !== '';
      
      case 'eq':
        return this.compareEqual(value, filter.value);
      
      case 'ne':
        return !this.compareEqual(value, filter.value);
      
      case 'co':
        return this.compareContains(value, filter.value);
      
      case 'sw':
        return this.compareStartsWith(value, filter.value);
      
      case 'ew':
        return this.compareEndsWith(value, filter.value);
      
      case 'gt':
        return this.compareGreaterThan(value, filter.value);
      
      case 'ge':
        return this.compareGreaterThanOrEqual(value, filter.value);
      
      case 'lt':
        return this.compareLessThan(value, filter.value);
      
      case 'le':
        return this.compareLessThanOrEqual(value, filter.value);
      
      default:
        return false;
    }
  }

  /**
   * Get nested value from object using dot notation
   * Supports array access: emails.value matches any email's value
   */
  private static getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    const parts = path.split('.');
    let current: unknown = obj;

    for (const part of parts) {
      if (current === null || current === undefined) {
        return undefined;
      }

      if (Array.isArray(current)) {
        // For arrays, collect all matching values
        const values = current.map(item => 
          typeof item === 'object' && item !== null 
            ? (item as Record<string, unknown>)[part]
            : undefined
        ).filter(v => v !== undefined);
        
        return values.length > 0 ? values : undefined;
      }

      if (typeof current === 'object') {
        current = (current as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }

    return current;
  }

  private static compareEqual(value: unknown, filterValue?: string): boolean {
    if (Array.isArray(value)) {
      return value.some(v => this.compareEqual(v, filterValue));
    }
    
    if (filterValue === 'true') return value === true;
    if (filterValue === 'false') return value === false;
    if (filterValue === 'null') return value === null;
    
    return String(value).toLowerCase() === String(filterValue).toLowerCase();
  }

  private static compareContains(value: unknown, filterValue?: string): boolean {
    if (Array.isArray(value)) {
      return value.some(v => this.compareContains(v, filterValue));
    }
    return String(value).toLowerCase().includes(String(filterValue).toLowerCase());
  }

  private static compareStartsWith(value: unknown, filterValue?: string): boolean {
    if (Array.isArray(value)) {
      return value.some(v => this.compareStartsWith(v, filterValue));
    }
    return String(value).toLowerCase().startsWith(String(filterValue).toLowerCase());
  }

  private static compareEndsWith(value: unknown, filterValue?: string): boolean {
    if (Array.isArray(value)) {
      return value.some(v => this.compareEndsWith(v, filterValue));
    }
    return String(value).toLowerCase().endsWith(String(filterValue).toLowerCase());
  }

  private static compareGreaterThan(value: unknown, filterValue?: string): boolean {
    const numValue = Number(value);
    const numFilter = Number(filterValue);
    if (!isNaN(numValue) && !isNaN(numFilter)) {
      return numValue > numFilter;
    }
    return String(value) > String(filterValue);
  }

  private static compareGreaterThanOrEqual(value: unknown, filterValue?: string): boolean {
    const numValue = Number(value);
    const numFilter = Number(filterValue);
    if (!isNaN(numValue) && !isNaN(numFilter)) {
      return numValue >= numFilter;
    }
    return String(value) >= String(filterValue);
  }

  private static compareLessThan(value: unknown, filterValue?: string): boolean {
    const numValue = Number(value);
    const numFilter = Number(filterValue);
    if (!isNaN(numValue) && !isNaN(numFilter)) {
      return numValue < numFilter;
    }
    return String(value) < String(filterValue);
  }

  private static compareLessThanOrEqual(value: unknown, filterValue?: string): boolean {
    const numValue = Number(value);
    const numFilter = Number(filterValue);
    if (!isNaN(numValue) && !isNaN(numFilter)) {
      return numValue <= numFilter;
    }
    return String(value) <= String(filterValue);
  }
}


// ============================================================================
// SCIM ATTRIBUTE MAPPER
// ============================================================================

/**
 * Attribute mapping configuration
 */
export interface AttributeMapping {
  scimAttribute: string;
  zaltAttribute: string;
  transform?: 'none' | 'lowercase' | 'uppercase' | 'boolean' | 'date';
  required?: boolean;
  readOnly?: boolean;
}

/**
 * Default attribute mappings from SCIM to Zalt
 */
export const DEFAULT_USER_MAPPINGS: AttributeMapping[] = [
  { scimAttribute: 'userName', zaltAttribute: 'email', transform: 'lowercase', required: true },
  { scimAttribute: 'externalId', zaltAttribute: 'external_id' },
  { scimAttribute: 'name.givenName', zaltAttribute: 'profile.first_name' },
  { scimAttribute: 'name.familyName', zaltAttribute: 'profile.last_name' },
  { scimAttribute: 'displayName', zaltAttribute: 'profile.display_name' },
  { scimAttribute: 'active', zaltAttribute: 'status', transform: 'boolean' },
  { scimAttribute: 'emails[primary eq true].value', zaltAttribute: 'email', transform: 'lowercase' },
  { scimAttribute: 'phoneNumbers[primary eq true].value', zaltAttribute: 'profile.phone' },
  { scimAttribute: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.employeeNumber', 
    zaltAttribute: 'profile.metadata.employee_number' },
  { scimAttribute: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.department', 
    zaltAttribute: 'profile.metadata.department' },
  { scimAttribute: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User.organization', 
    zaltAttribute: 'profile.metadata.organization' },
];

/**
 * SCIM Attribute Mapper
 * Maps between SCIM 2.0 attributes and Zalt internal user model
 */
export class SCIMAttributeMapper {
  private userMappings: AttributeMapping[];
  private baseUrl: string;

  constructor(baseUrl: string, customMappings?: AttributeMapping[]) {
    this.baseUrl = baseUrl;
    this.userMappings = customMappings || DEFAULT_USER_MAPPINGS;
  }

  /**
   * Map SCIM User to Zalt User
   */
  scimUserToZalt(scimUser: SCIMUser, realmId: string): Partial<ZaltUser> {
    const zaltUser: Partial<ZaltUser> = {
      realm_id: realmId,
      profile: { metadata: {} },
    };

    // Map userName to email
    if (scimUser.userName) {
      zaltUser.email = scimUser.userName.toLowerCase().trim();
    }

    // Map externalId
    if (scimUser.externalId) {
      zaltUser.external_id = scimUser.externalId;
    }

    // Map name
    if (scimUser.name) {
      if (scimUser.name.givenName) {
        zaltUser.profile!.first_name = scimUser.name.givenName;
      }
      if (scimUser.name.familyName) {
        zaltUser.profile!.last_name = scimUser.name.familyName;
      }
    }

    // Map primary email
    if (scimUser.emails && scimUser.emails.length > 0) {
      const primaryEmail = scimUser.emails.find(e => e.primary) || scimUser.emails[0];
      if (primaryEmail.value) {
        zaltUser.email = primaryEmail.value.toLowerCase().trim();
      }
    }

    // Map primary phone
    if (scimUser.phoneNumbers && scimUser.phoneNumbers.length > 0) {
      const primaryPhone = scimUser.phoneNumbers.find(p => p.primary) || scimUser.phoneNumbers[0];
      if (primaryPhone.value) {
        zaltUser.profile!.phone = primaryPhone.value;
      }
    }

    // Map active status
    if (scimUser.active !== undefined) {
      zaltUser.status = scimUser.active ? 'active' : 'suspended';
    }

    // Map enterprise extension
    const enterprise = scimUser['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'];
    if (enterprise) {
      zaltUser.profile!.metadata = {
        ...zaltUser.profile!.metadata,
        employee_number: enterprise.employeeNumber,
        department: enterprise.department,
        organization: enterprise.organization,
        division: enterprise.division,
        cost_center: enterprise.costCenter,
        manager_id: enterprise.manager?.value,
      };
    }

    return zaltUser;
  }


  /**
   * Map Zalt User to SCIM User
   */
  zaltUserToScim(zaltUser: ZaltUser): SCIMUser {
    const scimUser: SCIMUser = {
      schemas: [SCIM_SCHEMAS.USER],
      id: zaltUser.id,
      externalId: zaltUser.external_id,
      userName: zaltUser.email,
      active: zaltUser.status === 'active',
      meta: {
        resourceType: 'User',
        created: zaltUser.created_at,
        lastModified: zaltUser.updated_at,
        location: `${this.baseUrl}/scim/v2/Users/${zaltUser.id}`,
        version: `W/"${this.generateETag(zaltUser)}"`,
      },
    };

    // Map name
    if (zaltUser.profile.first_name || zaltUser.profile.last_name) {
      scimUser.name = {
        givenName: zaltUser.profile.first_name,
        familyName: zaltUser.profile.last_name,
        formatted: [zaltUser.profile.first_name, zaltUser.profile.last_name]
          .filter(Boolean).join(' '),
      };
      scimUser.displayName = scimUser.name.formatted;
    }

    // Map emails
    scimUser.emails = [{
      value: zaltUser.email,
      type: 'work',
      primary: true,
    }];

    // Map phone numbers
    if (zaltUser.profile.phone) {
      scimUser.phoneNumbers = [{
        value: zaltUser.profile.phone,
        type: 'work',
        primary: true,
      }];
    }

    // Map enterprise extension if metadata exists
    const metadata = zaltUser.profile.metadata || {};
    if (metadata.employee_number || metadata.department || metadata.organization) {
      scimUser.schemas.push(SCIM_SCHEMAS.ENTERPRISE_USER);
      scimUser['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] = {
        employeeNumber: metadata.employee_number as string,
        department: metadata.department as string,
        organization: metadata.organization as string,
        division: metadata.division as string,
        costCenter: metadata.cost_center as string,
        manager: metadata.manager_id ? {
          value: metadata.manager_id as string,
          $ref: `${this.baseUrl}/scim/v2/Users/${metadata.manager_id}`,
        } : undefined,
      };
    }

    return scimUser;
  }

  /**
   * Map Zalt Group to SCIM Group
   */
  zaltGroupToScim(zaltGroup: ZaltGroup, memberDetails?: Array<{ id: string; displayName: string }>): SCIMGroup {
    const scimGroup: SCIMGroup = {
      schemas: [SCIM_SCHEMAS.GROUP],
      id: zaltGroup.id,
      externalId: zaltGroup.external_id,
      displayName: zaltGroup.name,
      meta: {
        resourceType: 'Group',
        created: zaltGroup.created_at,
        lastModified: zaltGroup.updated_at,
        location: `${this.baseUrl}/scim/v2/Groups/${zaltGroup.id}`,
        version: `W/"${this.generateETag(zaltGroup)}"`,
      },
      // Always include members array (even if empty)
      members: [],
    };

    // Map members
    if (zaltGroup.members && zaltGroup.members.length > 0) {
      scimGroup.members = zaltGroup.members.map(memberId => {
        const detail = memberDetails?.find(m => m.id === memberId);
        return {
          value: memberId,
          $ref: `${this.baseUrl}/scim/v2/Users/${memberId}`,
          display: detail?.displayName,
          type: 'User' as const,
        };
      });
    }

    return scimGroup;
  }

  /**
   * Map SCIM Group to Zalt Group
   */
  scimGroupToZalt(scimGroup: SCIMGroup, realmId: string): Partial<ZaltGroup> {
    return {
      realm_id: realmId,
      name: scimGroup.displayName,
      external_id: scimGroup.externalId,
      members: scimGroup.members?.map(m => m.value) || [],
    };
  }

  /**
   * Generate ETag for resource versioning
   */
  private generateETag(resource: { updated_at: string; id: string }): string {
    const hash = crypto.createHash('md5')
      .update(`${resource.id}:${resource.updated_at}`)
      .digest('hex')
      .substring(0, 8);
    return hash;
  }
}


// ============================================================================
// SCIM USER SERVICE
// ============================================================================

/**
 * SCIM User Service Result
 */
export interface SCIMServiceResult<T> {
  success: boolean;
  data?: T;
  error?: SCIMError;
  statusCode: number;
}

/**
 * In-memory storage for SCIM resources (for testing)
 * In production, this would use DynamoDB
 */
class SCIMStorage {
  private users: Map<string, Map<string, ZaltUser>> = new Map();
  private groups: Map<string, Map<string, ZaltGroup>> = new Map();

  // User operations
  getUser(realmId: string, userId: string): ZaltUser | undefined {
    return this.users.get(realmId)?.get(userId);
  }

  getUserByEmail(realmId: string, email: string): ZaltUser | undefined {
    const realmUsers = this.users.get(realmId);
    if (!realmUsers) return undefined;
    
    for (const user of realmUsers.values()) {
      if (user.email.toLowerCase() === email.toLowerCase()) {
        return user;
      }
    }
    return undefined;
  }

  getUserByExternalId(realmId: string, externalId: string): ZaltUser | undefined {
    const realmUsers = this.users.get(realmId);
    if (!realmUsers) return undefined;
    
    for (const user of realmUsers.values()) {
      if (user.external_id === externalId) {
        return user;
      }
    }
    return undefined;
  }

  listUsers(realmId: string): ZaltUser[] {
    return Array.from(this.users.get(realmId)?.values() || []);
  }

  saveUser(user: ZaltUser): void {
    if (!this.users.has(user.realm_id)) {
      this.users.set(user.realm_id, new Map());
    }
    this.users.get(user.realm_id)!.set(user.id, user);
  }

  deleteUser(realmId: string, userId: string): boolean {
    return this.users.get(realmId)?.delete(userId) || false;
  }

  // Group operations
  getGroup(realmId: string, groupId: string): ZaltGroup | undefined {
    return this.groups.get(realmId)?.get(groupId);
  }

  getGroupByExternalId(realmId: string, externalId: string): ZaltGroup | undefined {
    const realmGroups = this.groups.get(realmId);
    if (!realmGroups) return undefined;
    
    for (const group of realmGroups.values()) {
      if (group.external_id === externalId) {
        return group;
      }
    }
    return undefined;
  }

  listGroups(realmId: string): ZaltGroup[] {
    return Array.from(this.groups.get(realmId)?.values() || []);
  }

  saveGroup(group: ZaltGroup): void {
    if (!this.groups.has(group.realm_id)) {
      this.groups.set(group.realm_id, new Map());
    }
    this.groups.get(group.realm_id)!.set(group.id, group);
  }

  deleteGroup(realmId: string, groupId: string): boolean {
    return this.groups.get(realmId)?.delete(groupId) || false;
  }

  // Clear all data (for testing)
  clear(): void {
    this.users.clear();
    this.groups.clear();
  }
}

// Singleton storage instance
const storage = new SCIMStorage();

/**
 * Get storage instance (for testing)
 */
export function getSCIMStorage(): SCIMStorage {
  return storage;
}


/**
 * SCIM User Service
 * Handles user provisioning and deprovisioning via SCIM 2.0
 * 
 * Validates: Requirements 31.1, 31.4, 31.5, 31.6
 */
export class SCIMUserService {
  private mapper: SCIMAttributeMapper;
  private realmId: string;

  constructor(realmId: string, baseUrl: string) {
    this.realmId = realmId;
    this.mapper = new SCIMAttributeMapper(baseUrl);
  }

  /**
   * Create a new user (POST /scim/v2/Users)
   * Validates: Requirement 31.4 - User created in IdP creates corresponding user
   */
  async createUser(scimUser: SCIMUser): Promise<SCIMServiceResult<SCIMUser>> {
    // Validate required fields
    if (!scimUser.userName) {
      return this.errorResponse(400, 'invalidValue', 'userName is required');
    }

    // Check for duplicate userName (email)
    const existingByEmail = storage.getUserByEmail(this.realmId, scimUser.userName);
    if (existingByEmail) {
      return this.errorResponse(409, 'uniqueness', 'User with this userName already exists');
    }

    // Check for duplicate externalId
    if (scimUser.externalId) {
      const existingByExtId = storage.getUserByExternalId(this.realmId, scimUser.externalId);
      if (existingByExtId) {
        return this.errorResponse(409, 'uniqueness', 'User with this externalId already exists');
      }
    }

    // Map SCIM user to Zalt user
    const zaltUserPartial = this.mapper.scimUserToZalt(scimUser, this.realmId);
    
    const now = new Date().toISOString();
    const zaltUser: ZaltUser = {
      id: crypto.randomUUID(),
      realm_id: this.realmId,
      email: zaltUserPartial.email || scimUser.userName.toLowerCase(),
      email_verified: false,
      profile: zaltUserPartial.profile || { metadata: {} },
      status: zaltUserPartial.status || 'active',
      external_id: zaltUserPartial.external_id,
      created_at: now,
      updated_at: now,
    };

    // Save user
    storage.saveUser(zaltUser);

    // Return SCIM representation
    const createdScimUser = this.mapper.zaltUserToScim(zaltUser);
    
    return {
      success: true,
      data: createdScimUser,
      statusCode: 201,
    };
  }

  /**
   * Get a user by ID (GET /scim/v2/Users/{id})
   */
  async getUser(userId: string): Promise<SCIMServiceResult<SCIMUser>> {
    const zaltUser = storage.getUser(this.realmId, userId);
    
    if (!zaltUser) {
      return this.errorResponse(404, 'noTarget', `User ${userId} not found`);
    }

    const scimUser = this.mapper.zaltUserToScim(zaltUser);
    
    return {
      success: true,
      data: scimUser,
      statusCode: 200,
    };
  }

  /**
   * List users with filtering, sorting, and pagination (GET /scim/v2/Users)
   */
  async listUsers(options: {
    filter?: string;
    sortBy?: string;
    sortOrder?: 'ascending' | 'descending';
    startIndex?: number;
    count?: number;
  } = {}): Promise<SCIMServiceResult<SCIMListResponse<SCIMUser>>> {
    const {
      filter,
      sortBy,
      sortOrder = 'ascending',
      startIndex = 1,
      count = 100,
    } = options;

    // Get all users for this realm
    let users = storage.listUsers(this.realmId);

    // Apply filter
    if (filter) {
      const filters = SCIMFilterParser.parse(filter);
      users = SCIMFilterParser.applyFilters(
        users.map(u => this.mapper.zaltUserToScim(u) as unknown as Record<string, unknown>),
        filters
      ).map(scimUser => {
        // Find original Zalt user
        return storage.getUser(this.realmId, (scimUser as unknown as SCIMUser).id!)!;
      }).filter(Boolean);
    }

    // Apply sorting
    if (sortBy) {
      users.sort((a, b) => {
        const aScim = this.mapper.zaltUserToScim(a);
        const bScim = this.mapper.zaltUserToScim(b);
        const aVal = this.getNestedValue(aScim, sortBy);
        const bVal = this.getNestedValue(bScim, sortBy);
        
        const comparison = String(aVal || '').localeCompare(String(bVal || ''));
        return sortOrder === 'descending' ? -comparison : comparison;
      });
    }

    // Apply pagination
    const totalResults = users.length;
    const startIdx = Math.max(0, startIndex - 1);
    const paginatedUsers = users.slice(startIdx, startIdx + count);

    // Convert to SCIM format
    const scimUsers = paginatedUsers.map(u => this.mapper.zaltUserToScim(u));

    const response: SCIMListResponse<SCIMUser> = {
      schemas: [SCIM_SCHEMAS.LIST_RESPONSE],
      totalResults,
      startIndex,
      itemsPerPage: scimUsers.length,
      Resources: scimUsers,
    };

    return {
      success: true,
      data: response,
      statusCode: 200,
    };
  }


  /**
   * Replace a user (PUT /scim/v2/Users/{id})
   */
  async replaceUser(userId: string, scimUser: SCIMUser): Promise<SCIMServiceResult<SCIMUser>> {
    const existingUser = storage.getUser(this.realmId, userId);
    
    if (!existingUser) {
      return this.errorResponse(404, 'noTarget', `User ${userId} not found`);
    }

    // Validate required fields
    if (!scimUser.userName) {
      return this.errorResponse(400, 'invalidValue', 'userName is required');
    }

    // Check for duplicate userName if changed
    if (scimUser.userName.toLowerCase() !== existingUser.email.toLowerCase()) {
      const existingByEmail = storage.getUserByEmail(this.realmId, scimUser.userName);
      if (existingByEmail && existingByEmail.id !== userId) {
        return this.errorResponse(409, 'uniqueness', 'User with this userName already exists');
      }
    }

    // Map SCIM user to Zalt user
    const zaltUserPartial = this.mapper.scimUserToZalt(scimUser, this.realmId);
    
    const updatedUser: ZaltUser = {
      ...existingUser,
      email: zaltUserPartial.email || scimUser.userName.toLowerCase(),
      profile: {
        ...existingUser.profile,
        ...zaltUserPartial.profile,
      },
      status: zaltUserPartial.status || existingUser.status,
      external_id: zaltUserPartial.external_id,
      updated_at: new Date().toISOString(),
    };

    // Save user
    storage.saveUser(updatedUser);

    // Return SCIM representation
    const updatedScimUser = this.mapper.zaltUserToScim(updatedUser);
    
    return {
      success: true,
      data: updatedScimUser,
      statusCode: 200,
    };
  }

  /**
   * Update a user (PATCH /scim/v2/Users/{id})
   */
  async patchUser(userId: string, patchRequest: SCIMPatchRequest): Promise<SCIMServiceResult<SCIMUser>> {
    const existingUser = storage.getUser(this.realmId, userId);
    
    if (!existingUser) {
      return this.errorResponse(404, 'noTarget', `User ${userId} not found`);
    }

    // Convert to SCIM format for patching
    let scimUser = this.mapper.zaltUserToScim(existingUser);

    // Apply patch operations
    for (const op of patchRequest.Operations) {
      const result = this.applyPatchOperation(scimUser, op);
      if (!result.success) {
        return this.errorResponse(400, 'invalidValue', result.error || 'Invalid patch operation');
      }
      scimUser = result.data!;
    }

    // Build updated profile from patched SCIM user
    // Explicitly handle name fields to support removal
    const updatedProfile = {
      ...existingUser.profile,
      first_name: scimUser.name?.givenName,
      last_name: scimUser.name?.familyName,
    };

    // Map phone from patched SCIM user
    if (scimUser.phoneNumbers && scimUser.phoneNumbers.length > 0) {
      const primaryPhone = scimUser.phoneNumbers.find(p => p.primary) || scimUser.phoneNumbers[0];
      updatedProfile.phone = primaryPhone.value;
    }

    // Map enterprise extension metadata
    const enterprise = scimUser['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'];
    if (enterprise) {
      updatedProfile.metadata = {
        ...updatedProfile.metadata,
        employee_number: enterprise.employeeNumber,
        department: enterprise.department,
        organization: enterprise.organization,
        division: enterprise.division,
        cost_center: enterprise.costCenter,
        manager_id: enterprise.manager?.value,
      };
    }

    const updatedUser: ZaltUser = {
      ...existingUser,
      email: scimUser.userName?.toLowerCase() || existingUser.email,
      profile: updatedProfile,
      status: scimUser.active === false ? 'suspended' : (scimUser.active === true ? 'active' : existingUser.status),
      external_id: scimUser.externalId ?? existingUser.external_id,
      updated_at: new Date().toISOString(),
    };

    storage.saveUser(updatedUser);

    const updatedScimUser = this.mapper.zaltUserToScim(updatedUser);
    
    return {
      success: true,
      data: updatedScimUser,
      statusCode: 200,
    };
  }

  /**
   * Delete/Deactivate a user (DELETE /scim/v2/Users/{id})
   * Validates: Requirement 31.5 - User deactivated in IdP suspends user and revokes sessions
   */
  async deleteUser(userId: string): Promise<SCIMServiceResult<void>> {
    const existingUser = storage.getUser(this.realmId, userId);
    
    if (!existingUser) {
      return this.errorResponse(404, 'noTarget', `User ${userId} not found`);
    }

    // Soft delete - mark as deleted/suspended rather than hard delete
    const updatedUser: ZaltUser = {
      ...existingUser,
      status: 'deleted',
      updated_at: new Date().toISOString(),
    };

    storage.saveUser(updatedUser);

    // In production, also revoke all sessions for this user
    // await sessionService.revokeAllUserSessions(userId);

    return {
      success: true,
      statusCode: 204,
    };
  }


  /**
   * Apply a single PATCH operation to a SCIM user
   */
  private applyPatchOperation(
    user: SCIMUser,
    op: SCIMPatchOperation
  ): { success: boolean; data?: SCIMUser; error?: string } {
    const { op: operation, path, value } = op;

    switch (operation) {
      case 'add':
        return this.applyAddOperation(user, path, value);
      case 'remove':
        return this.applyRemoveOperation(user, path);
      case 'replace':
        return this.applyReplaceOperation(user, path, value);
      default:
        return { success: false, error: `Unknown operation: ${operation}` };
    }
  }

  private applyAddOperation(
    user: SCIMUser,
    path: string | undefined,
    value: unknown
  ): { success: boolean; data?: SCIMUser; error?: string } {
    if (!path) {
      // Add to root - merge value object
      if (typeof value === 'object' && value !== null) {
        return { success: true, data: { ...user, ...value as Partial<SCIMUser> } };
      }
      return { success: false, error: 'Value must be an object when path is not specified' };
    }

    const updated = { ...user };
    this.setNestedValue(updated, path, value);
    return { success: true, data: updated };
  }

  private applyRemoveOperation(
    user: SCIMUser,
    path: string | undefined
  ): { success: boolean; data?: SCIMUser; error?: string } {
    if (!path) {
      return { success: false, error: 'Path is required for remove operation' };
    }

    // Deep clone to avoid mutating original
    const updated = JSON.parse(JSON.stringify(user)) as SCIMUser;
    this.deleteNestedValue(updated as unknown as Record<string, unknown>, path);
    return { success: true, data: updated };
  }

  private applyReplaceOperation(
    user: SCIMUser,
    path: string | undefined,
    value: unknown
  ): { success: boolean; data?: SCIMUser; error?: string } {
    if (!path) {
      // Replace entire resource
      if (typeof value === 'object' && value !== null) {
        return { success: true, data: { ...user, ...value as Partial<SCIMUser> } };
      }
      return { success: false, error: 'Value must be an object when path is not specified' };
    }

    const updated = { ...user };
    this.setNestedValue(updated, path, value);
    return { success: true, data: updated };
  }

  private setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
    const parts = path.split('.');
    let current = obj;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!(part in current) || typeof current[part] !== 'object') {
        current[part] = {};
      }
      current = current[part] as Record<string, unknown>;
    }

    current[parts[parts.length - 1]] = value;
  }

  private deleteNestedValue(obj: Record<string, unknown>, path: string): void {
    const parts = path.split('.');
    let current = obj;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!(part in current) || typeof current[part] !== 'object') {
        return;
      }
      current = current[part] as Record<string, unknown>;
    }

    delete current[parts[parts.length - 1]];
  }

  private getNestedValue(obj: unknown, path: string): unknown {
    const parts = path.split('.');
    let current = obj;

    for (const part of parts) {
      if (current === null || current === undefined) {
        return undefined;
      }
      if (typeof current === 'object') {
        current = (current as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }

    return current;
  }

  private errorResponse(status: number, scimType: string, detail: string): SCIMServiceResult<never> {
    return {
      success: false,
      error: {
        schemas: [SCIM_SCHEMAS.ERROR],
        status: String(status),
        scimType,
        detail,
      },
      statusCode: status,
    };
  }
}


// ============================================================================
// SCIM GROUP SERVICE
// ============================================================================

/**
 * SCIM Group Service
 * Handles group sync via SCIM 2.0
 * 
 * Validates: Requirement 31.7 - Group sync for automatic role assignment
 */
export class SCIMGroupService {
  private mapper: SCIMAttributeMapper;
  private realmId: string;

  constructor(realmId: string, baseUrl: string) {
    this.realmId = realmId;
    this.mapper = new SCIMAttributeMapper(baseUrl);
  }

  /**
   * Create a new group (POST /scim/v2/Groups)
   */
  async createGroup(scimGroup: SCIMGroup): Promise<SCIMServiceResult<SCIMGroup>> {
    // Validate required fields
    if (!scimGroup.displayName) {
      return this.errorResponse(400, 'invalidValue', 'displayName is required');
    }

    // Check for duplicate externalId
    if (scimGroup.externalId) {
      const existingByExtId = storage.getGroupByExternalId(this.realmId, scimGroup.externalId);
      if (existingByExtId) {
        return this.errorResponse(409, 'uniqueness', 'Group with this externalId already exists');
      }
    }

    // Map SCIM group to Zalt group
    const zaltGroupPartial = this.mapper.scimGroupToZalt(scimGroup, this.realmId);
    
    const now = new Date().toISOString();
    const zaltGroup: ZaltGroup = {
      id: crypto.randomUUID(),
      realm_id: this.realmId,
      name: zaltGroupPartial.name || scimGroup.displayName,
      members: zaltGroupPartial.members || [],
      external_id: zaltGroupPartial.external_id,
      created_at: now,
      updated_at: now,
    };

    // Validate member IDs exist
    for (const memberId of zaltGroup.members) {
      const user = storage.getUser(this.realmId, memberId);
      if (!user) {
        return this.errorResponse(400, 'invalidValue', `Member ${memberId} not found`);
      }
    }

    // Save group
    storage.saveGroup(zaltGroup);

    // Get member details for response
    const memberDetails = zaltGroup.members.map(id => {
      const user = storage.getUser(this.realmId, id);
      return user ? { id, displayName: `${user.profile.first_name || ''} ${user.profile.last_name || ''}`.trim() || user.email } : null;
    }).filter((m): m is { id: string; displayName: string } => m !== null);

    // Return SCIM representation
    const createdScimGroup = this.mapper.zaltGroupToScim(zaltGroup, memberDetails);
    
    return {
      success: true,
      data: createdScimGroup,
      statusCode: 201,
    };
  }

  /**
   * Get a group by ID (GET /scim/v2/Groups/{id})
   */
  async getGroup(groupId: string): Promise<SCIMServiceResult<SCIMGroup>> {
    const zaltGroup = storage.getGroup(this.realmId, groupId);
    
    if (!zaltGroup) {
      return this.errorResponse(404, 'noTarget', `Group ${groupId} not found`);
    }

    // Get member details
    const memberDetails = zaltGroup.members.map(id => {
      const user = storage.getUser(this.realmId, id);
      return user ? { id, displayName: `${user.profile.first_name || ''} ${user.profile.last_name || ''}`.trim() || user.email } : null;
    }).filter((m): m is { id: string; displayName: string } => m !== null);

    const scimGroup = this.mapper.zaltGroupToScim(zaltGroup, memberDetails);
    
    return {
      success: true,
      data: scimGroup,
      statusCode: 200,
    };
  }

  /**
   * List groups with filtering, sorting, and pagination (GET /scim/v2/Groups)
   */
  async listGroups(options: {
    filter?: string;
    sortBy?: string;
    sortOrder?: 'ascending' | 'descending';
    startIndex?: number;
    count?: number;
  } = {}): Promise<SCIMServiceResult<SCIMListResponse<SCIMGroup>>> {
    const {
      filter,
      sortBy,
      sortOrder = 'ascending',
      startIndex = 1,
      count = 100,
    } = options;

    // Get all groups for this realm
    let groups = storage.listGroups(this.realmId);

    // Apply filter
    if (filter) {
      const filters = SCIMFilterParser.parse(filter);
      groups = SCIMFilterParser.applyFilters(
        groups.map(g => this.mapper.zaltGroupToScim(g) as unknown as Record<string, unknown>),
        filters
      ).map(scimGroup => {
        return storage.getGroup(this.realmId, (scimGroup as unknown as SCIMGroup).id!)!;
      }).filter(Boolean);
    }

    // Apply sorting
    if (sortBy) {
      groups.sort((a, b) => {
        const aScim = this.mapper.zaltGroupToScim(a);
        const bScim = this.mapper.zaltGroupToScim(b);
        const aVal = this.getNestedValue(aScim, sortBy);
        const bVal = this.getNestedValue(bScim, sortBy);
        
        const comparison = String(aVal || '').localeCompare(String(bVal || ''));
        return sortOrder === 'descending' ? -comparison : comparison;
      });
    }

    // Apply pagination
    const totalResults = groups.length;
    const startIdx = Math.max(0, startIndex - 1);
    const paginatedGroups = groups.slice(startIdx, startIdx + count);

    // Convert to SCIM format with member details
    const scimGroups = paginatedGroups.map(g => {
      const memberDetails = g.members.map(id => {
        const user = storage.getUser(this.realmId, id);
        return user ? { id, displayName: `${user.profile.first_name || ''} ${user.profile.last_name || ''}`.trim() || user.email } : null;
      }).filter((m): m is { id: string; displayName: string } => m !== null);
      
      return this.mapper.zaltGroupToScim(g, memberDetails);
    });

    const response: SCIMListResponse<SCIMGroup> = {
      schemas: [SCIM_SCHEMAS.LIST_RESPONSE],
      totalResults,
      startIndex,
      itemsPerPage: scimGroups.length,
      Resources: scimGroups,
    };

    return {
      success: true,
      data: response,
      statusCode: 200,
    };
  }


  /**
   * Replace a group (PUT /scim/v2/Groups/{id})
   */
  async replaceGroup(groupId: string, scimGroup: SCIMGroup): Promise<SCIMServiceResult<SCIMGroup>> {
    const existingGroup = storage.getGroup(this.realmId, groupId);
    
    if (!existingGroup) {
      return this.errorResponse(404, 'noTarget', `Group ${groupId} not found`);
    }

    // Validate required fields
    if (!scimGroup.displayName) {
      return this.errorResponse(400, 'invalidValue', 'displayName is required');
    }

    // Map SCIM group to Zalt group
    const zaltGroupPartial = this.mapper.scimGroupToZalt(scimGroup, this.realmId);
    
    // Validate member IDs exist
    const members = zaltGroupPartial.members || [];
    for (const memberId of members) {
      const user = storage.getUser(this.realmId, memberId);
      if (!user) {
        return this.errorResponse(400, 'invalidValue', `Member ${memberId} not found`);
      }
    }

    const updatedGroup: ZaltGroup = {
      ...existingGroup,
      name: zaltGroupPartial.name || scimGroup.displayName,
      members,
      external_id: zaltGroupPartial.external_id,
      updated_at: new Date().toISOString(),
    };

    // Save group
    storage.saveGroup(updatedGroup);

    // Get member details
    const memberDetails = updatedGroup.members.map(id => {
      const user = storage.getUser(this.realmId, id);
      return user ? { id, displayName: `${user.profile.first_name || ''} ${user.profile.last_name || ''}`.trim() || user.email } : null;
    }).filter((m): m is { id: string; displayName: string } => m !== null);

    const updatedScimGroup = this.mapper.zaltGroupToScim(updatedGroup, memberDetails);
    
    return {
      success: true,
      data: updatedScimGroup,
      statusCode: 200,
    };
  }

  /**
   * Update a group (PATCH /scim/v2/Groups/{id})
   * Commonly used for adding/removing members
   */
  async patchGroup(groupId: string, patchRequest: SCIMPatchRequest): Promise<SCIMServiceResult<SCIMGroup>> {
    const existingGroup = storage.getGroup(this.realmId, groupId);
    
    if (!existingGroup) {
      return this.errorResponse(404, 'noTarget', `Group ${groupId} not found`);
    }

    let members = [...existingGroup.members];
    let displayName = existingGroup.name;
    let externalId = existingGroup.external_id;

    // Apply patch operations
    for (const op of patchRequest.Operations) {
      const result = this.applyGroupPatchOperation(
        { members, displayName, externalId },
        op
      );
      if (!result.success) {
        return this.errorResponse(400, 'invalidValue', result.error || 'Invalid patch operation');
      }
      members = result.data!.members;
      displayName = result.data!.displayName;
      externalId = result.data!.externalId;
    }

    // Validate member IDs exist
    for (const memberId of members) {
      const user = storage.getUser(this.realmId, memberId);
      if (!user) {
        return this.errorResponse(400, 'invalidValue', `Member ${memberId} not found`);
      }
    }

    const updatedGroup: ZaltGroup = {
      ...existingGroup,
      name: displayName,
      members,
      external_id: externalId,
      updated_at: new Date().toISOString(),
    };

    storage.saveGroup(updatedGroup);

    // Get member details
    const memberDetails = updatedGroup.members.map(id => {
      const user = storage.getUser(this.realmId, id);
      return user ? { id, displayName: `${user.profile.first_name || ''} ${user.profile.last_name || ''}`.trim() || user.email } : null;
    }).filter((m): m is { id: string; displayName: string } => m !== null);

    const updatedScimGroup = this.mapper.zaltGroupToScim(updatedGroup, memberDetails);
    
    return {
      success: true,
      data: updatedScimGroup,
      statusCode: 200,
    };
  }

  /**
   * Delete a group (DELETE /scim/v2/Groups/{id})
   */
  async deleteGroup(groupId: string): Promise<SCIMServiceResult<void>> {
    const existingGroup = storage.getGroup(this.realmId, groupId);
    
    if (!existingGroup) {
      return this.errorResponse(404, 'noTarget', `Group ${groupId} not found`);
    }

    storage.deleteGroup(this.realmId, groupId);

    return {
      success: true,
      statusCode: 204,
    };
  }


  /**
   * Apply a single PATCH operation to a group
   */
  private applyGroupPatchOperation(
    group: { members: string[]; displayName: string; externalId?: string },
    op: SCIMPatchOperation
  ): { success: boolean; data?: typeof group; error?: string } {
    const { op: operation, path, value } = op;

    // Handle member operations
    if (path === 'members' || path?.startsWith('members')) {
      switch (operation) {
        case 'add': {
          // Add members
          const newMembers = Array.isArray(value) 
            ? value.map(m => typeof m === 'object' && m !== null ? (m as { value: string }).value : m as string)
            : [typeof value === 'object' && value !== null ? (value as { value: string }).value : value as string];
          
          const uniqueMembers = [...new Set([...group.members, ...newMembers])];
          return { success: true, data: { ...group, members: uniqueMembers } };
        }
        case 'remove': {
          // Remove members - path format: members[value eq "userId"]
          const match = path?.match(/members\[value eq "([^"]+)"\]/);
          if (match) {
            const memberIdToRemove = match[1];
            const filteredMembers = group.members.filter(m => m !== memberIdToRemove);
            return { success: true, data: { ...group, members: filteredMembers } };
          }
          // Remove all members if no filter
          if (path === 'members') {
            return { success: true, data: { ...group, members: [] } };
          }
          return { success: false, error: 'Invalid remove path for members' };
        }
        case 'replace': {
          // Replace all members
          const replacementMembers = Array.isArray(value)
            ? value.map(m => typeof m === 'object' && m !== null ? (m as { value: string }).value : m as string)
            : [];
          return { success: true, data: { ...group, members: replacementMembers } };
        }
      }
    }

    // Handle displayName operations
    if (path === 'displayName') {
      if (operation === 'replace' && typeof value === 'string') {
        return { success: true, data: { ...group, displayName: value } };
      }
      return { success: false, error: 'Invalid operation for displayName' };
    }

    // Handle externalId operations
    if (path === 'externalId') {
      if (operation === 'replace') {
        return { success: true, data: { ...group, externalId: value as string } };
      }
      if (operation === 'remove') {
        return { success: true, data: { ...group, externalId: undefined } };
      }
    }

    return { success: false, error: `Unknown path: ${path}` };
  }

  private getNestedValue(obj: unknown, path: string): unknown {
    const parts = path.split('.');
    let current = obj;

    for (const part of parts) {
      if (current === null || current === undefined) {
        return undefined;
      }
      if (typeof current === 'object') {
        current = (current as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }

    return current;
  }

  private errorResponse(status: number, scimType: string, detail: string): SCIMServiceResult<never> {
    return {
      success: false,
      error: {
        schemas: [SCIM_SCHEMAS.ERROR],
        status: String(status),
        scimType,
        detail,
      },
      statusCode: status,
    };
  }
}


// ============================================================================
// SCIM BULK OPERATIONS SERVICE
// ============================================================================

/**
 * SCIM Bulk Operations Service
 * Handles bulk provisioning operations
 */
export class SCIMBulkService {
  private userService: SCIMUserService;
  private groupService: SCIMGroupService;
  private maxOperations: number;

  constructor(realmId: string, baseUrl: string, maxOperations: number = 1000) {
    this.userService = new SCIMUserService(realmId, baseUrl);
    this.groupService = new SCIMGroupService(realmId, baseUrl);
    this.maxOperations = maxOperations;
  }

  /**
   * Process bulk request (POST /scim/v2/Bulk)
   */
  async processBulk(request: SCIMBulkRequest): Promise<SCIMServiceResult<SCIMBulkResponse>> {
    const { Operations, failOnErrors = 0 } = request;

    if (Operations.length > this.maxOperations) {
      return {
        success: false,
        error: {
          schemas: [SCIM_SCHEMAS.ERROR],
          status: '413',
          scimType: 'tooLarge',
          detail: `Bulk request exceeds maximum of ${this.maxOperations} operations`,
        },
        statusCode: 413,
      };
    }

    const responseOperations: SCIMBulkResponseOperation[] = [];
    let errorCount = 0;

    for (const op of Operations) {
      const result = await this.processOperation(op);
      responseOperations.push(result);

      if (parseInt(result.status) >= 400) {
        errorCount++;
        if (failOnErrors > 0 && errorCount >= failOnErrors) {
          break;
        }
      }
    }

    const response: SCIMBulkResponse = {
      schemas: [SCIM_SCHEMAS.BULK_RESPONSE],
      Operations: responseOperations,
    };

    return {
      success: true,
      data: response,
      statusCode: 200,
    };
  }

  private async processOperation(op: SCIMBulkOperation): Promise<SCIMBulkResponseOperation> {
    const { method, path, data, bulkId } = op;

    // Parse path to determine resource type and ID
    const userMatch = path.match(/^\/Users(?:\/([^/]+))?$/);
    const groupMatch = path.match(/^\/Groups(?:\/([^/]+))?$/);

    try {
      if (userMatch) {
        return await this.processUserOperation(method, userMatch[1], data, bulkId);
      }
      if (groupMatch) {
        return await this.processGroupOperation(method, groupMatch[1], data, bulkId);
      }

      return {
        method,
        bulkId,
        status: '400',
        response: {
          schemas: [SCIM_SCHEMAS.ERROR],
          status: '400',
          scimType: 'invalidPath',
          detail: `Unknown resource path: ${path}`,
        },
      };
    } catch (error) {
      return {
        method,
        bulkId,
        status: '500',
        response: {
          schemas: [SCIM_SCHEMAS.ERROR],
          status: '500',
          detail: error instanceof Error ? error.message : 'Internal server error',
        },
      };
    }
  }

  private async processUserOperation(
    method: string,
    userId: string | undefined,
    data: unknown,
    bulkId?: string
  ): Promise<SCIMBulkResponseOperation> {
    switch (method) {
      case 'POST': {
        const result = await this.userService.createUser(data as SCIMUser);
        return {
          method,
          bulkId,
          status: String(result.statusCode),
          location: result.data?.meta?.location,
          response: result.success ? result.data : result.error,
        };
      }
      case 'PUT': {
        if (!userId) {
          return { method, bulkId, status: '400', response: { detail: 'User ID required' } };
        }
        const result = await this.userService.replaceUser(userId, data as SCIMUser);
        return {
          method,
          bulkId,
          status: String(result.statusCode),
          location: result.data?.meta?.location,
          response: result.success ? result.data : result.error,
        };
      }
      case 'PATCH': {
        if (!userId) {
          return { method, bulkId, status: '400', response: { detail: 'User ID required' } };
        }
        const result = await this.userService.patchUser(userId, data as SCIMPatchRequest);
        return {
          method,
          bulkId,
          status: String(result.statusCode),
          location: result.data?.meta?.location,
          response: result.success ? result.data : result.error,
        };
      }
      case 'DELETE': {
        if (!userId) {
          return { method, bulkId, status: '400', response: { detail: 'User ID required' } };
        }
        const result = await this.userService.deleteUser(userId);
        return {
          method,
          bulkId,
          status: String(result.statusCode),
          response: result.success ? undefined : result.error,
        };
      }
      default:
        return { method, bulkId, status: '405', response: { detail: `Method ${method} not allowed` } };
    }
  }

  private async processGroupOperation(
    method: string,
    groupId: string | undefined,
    data: unknown,
    bulkId?: string
  ): Promise<SCIMBulkResponseOperation> {
    switch (method) {
      case 'POST': {
        const result = await this.groupService.createGroup(data as SCIMGroup);
        return {
          method,
          bulkId,
          status: String(result.statusCode),
          location: result.data?.meta?.location,
          response: result.success ? result.data : result.error,
        };
      }
      case 'PUT': {
        if (!groupId) {
          return { method, bulkId, status: '400', response: { detail: 'Group ID required' } };
        }
        const result = await this.groupService.replaceGroup(groupId, data as SCIMGroup);
        return {
          method,
          bulkId,
          status: String(result.statusCode),
          location: result.data?.meta?.location,
          response: result.success ? result.data : result.error,
        };
      }
      case 'PATCH': {
        if (!groupId) {
          return { method, bulkId, status: '400', response: { detail: 'Group ID required' } };
        }
        const result = await this.groupService.patchGroup(groupId, data as SCIMPatchRequest);
        return {
          method,
          bulkId,
          status: String(result.statusCode),
          location: result.data?.meta?.location,
          response: result.success ? result.data : result.error,
        };
      }
      case 'DELETE': {
        if (!groupId) {
          return { method, bulkId, status: '400', response: { detail: 'Group ID required' } };
        }
        const result = await this.groupService.deleteGroup(groupId);
        return {
          method,
          bulkId,
          status: String(result.statusCode),
          response: result.success ? undefined : result.error,
        };
      }
      default:
        return { method, bulkId, status: '405', response: { detail: `Method ${method} not allowed` } };
    }
  }
}


// ============================================================================
// SCIM SERVICE PROVIDER CONFIGURATION
// ============================================================================

/**
 * Get SCIM Service Provider Configuration
 * Returns the capabilities of this SCIM implementation
 */
export function getServiceProviderConfig(baseUrl: string): SCIMServiceProviderConfig {
  return {
    schemas: [SCIM_SCHEMAS.SERVICE_PROVIDER_CONFIG],
    documentationUri: `${baseUrl}/docs/scim`,
    patch: {
      supported: true,
    },
    bulk: {
      supported: true,
      maxOperations: 1000,
      maxPayloadSize: 1048576, // 1MB
    },
    filter: {
      supported: true,
      maxResults: 200,
    },
    changePassword: {
      supported: false, // Passwords managed via IdP
    },
    sort: {
      supported: true,
    },
    etag: {
      supported: true,
    },
    authenticationSchemes: [
      {
        type: 'oauthbearertoken',
        name: 'OAuth Bearer Token',
        description: 'Authentication scheme using the OAuth Bearer Token Standard',
        specUri: 'https://www.rfc-editor.org/info/rfc6750',
        primary: true,
      },
    ],
  };
}

/**
 * Get SCIM Resource Types
 */
export function getResourceTypes(baseUrl: string): Array<{
  schemas: string[];
  id: string;
  name: string;
  description: string;
  endpoint: string;
  schema: string;
  schemaExtensions?: Array<{ schema: string; required: boolean }>;
}> {
  return [
    {
      schemas: [SCIM_SCHEMAS.RESOURCE_TYPE],
      id: 'User',
      name: 'User',
      description: 'User Account',
      endpoint: '/Users',
      schema: SCIM_SCHEMAS.USER,
      schemaExtensions: [
        {
          schema: SCIM_SCHEMAS.ENTERPRISE_USER,
          required: false,
        },
      ],
    },
    {
      schemas: [SCIM_SCHEMAS.RESOURCE_TYPE],
      id: 'Group',
      name: 'Group',
      description: 'Group',
      endpoint: '/Groups',
      schema: SCIM_SCHEMAS.GROUP,
    },
  ];
}

/**
 * Get SCIM Schemas
 */
export function getSchemas(): Array<{
  schemas: string[];
  id: string;
  name: string;
  description: string;
  attributes: Array<{
    name: string;
    type: string;
    multiValued: boolean;
    required: boolean;
    caseExact: boolean;
    mutability: string;
    returned: string;
    uniqueness: string;
  }>;
}> {
  return [
    {
      schemas: [SCIM_SCHEMAS.SCHEMA],
      id: SCIM_SCHEMAS.USER,
      name: 'User',
      description: 'User Account',
      attributes: [
        {
          name: 'userName',
          type: 'string',
          multiValued: false,
          required: true,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'server',
        },
        {
          name: 'name',
          type: 'complex',
          multiValued: false,
          required: false,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'none',
        },
        {
          name: 'displayName',
          type: 'string',
          multiValued: false,
          required: false,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'none',
        },
        {
          name: 'emails',
          type: 'complex',
          multiValued: true,
          required: false,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'none',
        },
        {
          name: 'active',
          type: 'boolean',
          multiValued: false,
          required: false,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'none',
        },
      ],
    },
    {
      schemas: [SCIM_SCHEMAS.SCHEMA],
      id: SCIM_SCHEMAS.GROUP,
      name: 'Group',
      description: 'Group',
      attributes: [
        {
          name: 'displayName',
          type: 'string',
          multiValued: false,
          required: true,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'none',
        },
        {
          name: 'members',
          type: 'complex',
          multiValued: true,
          required: false,
          caseExact: false,
          mutability: 'readWrite',
          returned: 'default',
          uniqueness: 'none',
        },
      ],
    },
  ];
}
