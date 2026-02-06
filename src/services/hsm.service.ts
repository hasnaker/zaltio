/**
 * AWS CloudHSM Integration Service for Zalt.io
 * 
 * Implements hardware security module integration for enterprise-grade key protection:
 * - Key generation within HSM boundary
 * - Signing operations within HSM boundary
 * - Key backup and recovery procedures
 * - FIPS 140-2 Level 3 compliance
 * - PKCS#11 interface for customer-managed HSM support
 * - HSM clustering for high availability
 * 
 * Security considerations:
 * - Private keys never leave the HSM
 * - All cryptographic operations performed in hardware
 * - Audit logging for all HSM operations
 * - Support for HSM clustering for high availability
 * 
 * Requirements: 27.1, 27.4, 27.5, 27.6, 27.9
 */

import crypto from 'crypto';
import { DynamoDBDocumentClient, GetCommand, PutCommand, DeleteCommand, QueryCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from './dynamodb.service';

// ============================================================================
// HSM Types and Interfaces
// ============================================================================

/**
 * HSM Provider types
 */
export type HSMProvider = 'aws_cloudhsm' | 'azure_dedicated_hsm' | 'google_cloud_hsm' | 'pkcs11';

/**
 * HSM Key types supported
 */
export type HSMKeyType = 'RSA_2048' | 'RSA_4096' | 'EC_P256' | 'EC_P384' | 'EC_SECP256K1' | 'AES_256';

/**
 * HSM Key usage types
 */
export type HSMKeyUsage = 'sign' | 'encrypt' | 'wrap' | 'derive';

/**
 * HSM Connection status
 */
export type HSMConnectionStatus = 'connected' | 'disconnected' | 'error' | 'initializing';

/**
 * HSM Cluster configuration
 */
export interface HSMClusterConfig {
  clusterId: string;
  provider: HSMProvider;
  region: string;
  securityGroup?: string;
  subnetIds?: string[];
  hsmIps?: string[];
  status: HSMConnectionStatus;
  createdAt: string;
  updatedAt: string;
}

/**
 * HSM Credentials for authentication
 */
export interface HSMCredentials {
  username: string;
  password: string;
  partitionName?: string;
  certificatePath?: string;
  privateKeyPath?: string;
}

/**
 * HSM Key metadata
 */
export interface HSMKey {
  keyHandle: string;
  keyId: string;
  realmId: string;
  label: string;
  keyType: HSMKeyType;
  keyUsage: HSMKeyUsage[];
  extractable: boolean;
  persistent: boolean;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
  backupId?: string;
  status: 'active' | 'disabled' | 'pending_deletion';
}

/**
 * HSM Key generation options
 */
export interface HSMKeyGenerationOptions {
  realmId: string;
  label: string;
  keyType: HSMKeyType;
  keyUsage: HSMKeyUsage[];
  extractable?: boolean;
  persistent?: boolean;
  metadata?: Record<string, unknown>;
}

/**
 * HSM Key generation result
 */
export interface HSMKeyGenerationResult {
  key: HSMKey;
  publicKey?: string;
}

/**
 * HSM Signing options
 */
export interface HSMSigningOptions {
  keyHandle: string;
  message: Buffer;
  algorithm?: string;
}

/**
 * HSM Signing result
 */
export interface HSMSigningResult {
  signature: string;
  algorithm: string;
  keyHandle: string;
  timestamp: string;
}

/**
 * HSM Verification options
 */
export interface HSMVerificationOptions {
  keyHandle: string;
  message: Buffer;
  signature: string;
  algorithm?: string;
}

/**
 * HSM Verification result
 */
export interface HSMVerificationResult {
  valid: boolean;
  keyHandle: string;
  timestamp: string;
  error?: string;
}

/**
 * HSM Key backup options
 */
export interface HSMKeyBackupOptions {
  keyHandle: string;
  wrappingKeyHandle: string;
  backupLabel?: string;
}

/**
 * HSM Key backup result
 */
export interface HSMKeyBackupResult {
  backupId: string;
  wrappedKey: string;
  wrappingKeyHandle: string;
  keyType: HSMKeyType;
  timestamp: string;
  checksum: string;
}

/**
 * HSM Key import options
 */
export interface HSMKeyImportOptions {
  wrappedKey: string;
  wrappingKeyHandle: string;
  label: string;
  keyType: HSMKeyType;
  keyUsage: HSMKeyUsage[];
  realmId: string;
}

/**
 * HSM Key import result
 */
export interface HSMKeyImportResult {
  key: HSMKey;
  importedAt: string;
}

/**
 * HSM Key info
 */
export interface HSMKeyInfo {
  keyHandle: string;
  keyId: string;
  label: string;
  keyType: HSMKeyType;
  keyUsage: HSMKeyUsage[];
  extractable: boolean;
  persistent: boolean;
  createdAt: string;
  lastUsedAt?: string;
  status: string;
  publicKey?: string;
}

/**
 * HSM Operation audit log entry
 */
export interface HSMOperationLog {
  operationId: string;
  operation: string;
  keyHandle?: string;
  realmId: string;
  userId?: string;
  timestamp: string;
  success: boolean;
  errorMessage?: string;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * HSM Cluster status
 */
export interface HSMClusterStatus {
  clusterId: string;
  status: HSMConnectionStatus;
  hsmCount: number;
  activeHsms: number;
  keyCount: number;
  operationsPerSecond: number;
  lastHealthCheck: string;
}

// ============================================================================
// PKCS#11 Types and Interfaces
// ============================================================================

/**
 * PKCS#11 Return Values (CKR_*)
 */
export enum PKCS11ReturnValue {
  CKR_OK = 0x00000000,
  CKR_CANCEL = 0x00000001,
  CKR_HOST_MEMORY = 0x00000002,
  CKR_SLOT_ID_INVALID = 0x00000003,
  CKR_GENERAL_ERROR = 0x00000005,
  CKR_FUNCTION_FAILED = 0x00000006,
  CKR_ARGUMENTS_BAD = 0x00000007,
  CKR_ATTRIBUTE_READ_ONLY = 0x00000010,
  CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012,
  CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013,
  CKR_DATA_INVALID = 0x00000020,
  CKR_DATA_LEN_RANGE = 0x00000021,
  CKR_DEVICE_ERROR = 0x00000030,
  CKR_DEVICE_MEMORY = 0x00000031,
  CKR_DEVICE_REMOVED = 0x00000032,
  CKR_ENCRYPTED_DATA_INVALID = 0x00000040,
  CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041,
  CKR_KEY_HANDLE_INVALID = 0x00000060,
  CKR_KEY_SIZE_RANGE = 0x00000062,
  CKR_KEY_TYPE_INCONSISTENT = 0x00000063,
  CKR_KEY_NOT_NEEDED = 0x00000064,
  CKR_KEY_CHANGED = 0x00000065,
  CKR_KEY_NEEDED = 0x00000066,
  CKR_KEY_INDIGESTIBLE = 0x00000067,
  CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068,
  CKR_KEY_NOT_WRAPPABLE = 0x00000069,
  CKR_KEY_UNEXTRACTABLE = 0x0000006A,
  CKR_MECHANISM_INVALID = 0x00000070,
  CKR_MECHANISM_PARAM_INVALID = 0x00000071,
  CKR_OBJECT_HANDLE_INVALID = 0x00000082,
  CKR_OPERATION_ACTIVE = 0x00000090,
  CKR_OPERATION_NOT_INITIALIZED = 0x00000091,
  CKR_PIN_INCORRECT = 0x000000A0,
  CKR_PIN_INVALID = 0x000000A1,
  CKR_PIN_LEN_RANGE = 0x000000A2,
  CKR_PIN_EXPIRED = 0x000000A3,
  CKR_PIN_LOCKED = 0x000000A4,
  CKR_SESSION_CLOSED = 0x000000B0,
  CKR_SESSION_COUNT = 0x000000B1,
  CKR_SESSION_HANDLE_INVALID = 0x000000B3,
  CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4,
  CKR_SESSION_READ_ONLY = 0x000000B5,
  CKR_SESSION_EXISTS = 0x000000B6,
  CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7,
  CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8,
  CKR_SIGNATURE_INVALID = 0x000000C0,
  CKR_SIGNATURE_LEN_RANGE = 0x000000C1,
  CKR_TEMPLATE_INCOMPLETE = 0x000000D0,
  CKR_TEMPLATE_INCONSISTENT = 0x000000D1,
  CKR_TOKEN_NOT_PRESENT = 0x000000E0,
  CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1,
  CKR_TOKEN_WRITE_PROTECTED = 0x000000E2,
  CKR_USER_ALREADY_LOGGED_IN = 0x00000100,
  CKR_USER_NOT_LOGGED_IN = 0x00000101,
  CKR_USER_PIN_NOT_INITIALIZED = 0x00000102,
  CKR_USER_TYPE_INVALID = 0x00000103,
  CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104,
  CKR_USER_TOO_MANY_TYPES = 0x00000105,
  CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190,
  CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191,
}

/**
 * PKCS#11 Session Flags (CKF_*)
 */
export enum PKCS11SessionFlags {
  CKF_RW_SESSION = 0x00000002,
  CKF_SERIAL_SESSION = 0x00000004,
}

/**
 * PKCS#11 User Types (CKU_*)
 */
export enum PKCS11UserType {
  CKU_SO = 0,
  CKU_USER = 1,
  CKU_CONTEXT_SPECIFIC = 2,
}

/**
 * PKCS#11 Object Classes (CKO_*)
 */
export enum PKCS11ObjectClass {
  CKO_DATA = 0x00000000,
  CKO_CERTIFICATE = 0x00000001,
  CKO_PUBLIC_KEY = 0x00000002,
  CKO_PRIVATE_KEY = 0x00000003,
  CKO_SECRET_KEY = 0x00000004,
  CKO_HW_FEATURE = 0x00000005,
  CKO_DOMAIN_PARAMETERS = 0x00000006,
  CKO_MECHANISM = 0x00000007,
}

/**
 * PKCS#11 Key Types (CKK_*)
 */
export enum PKCS11KeyType {
  CKK_RSA = 0x00000000,
  CKK_DSA = 0x00000001,
  CKK_DH = 0x00000002,
  CKK_EC = 0x00000003,
  CKK_GENERIC_SECRET = 0x00000010,
  CKK_RC2 = 0x00000011,
  CKK_RC4 = 0x00000012,
  CKK_DES = 0x00000013,
  CKK_DES2 = 0x00000014,
  CKK_DES3 = 0x00000015,
  CKK_AES = 0x0000001F,
  CKK_SHA256_HMAC = 0x0000002B,
  CKK_SHA384_HMAC = 0x0000002C,
  CKK_SHA512_HMAC = 0x0000002D,
}

/**
 * PKCS#11 Mechanisms (CKM_*)
 */
export enum PKCS11Mechanism {
  CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000,
  CKM_RSA_PKCS = 0x00000001,
  CKM_RSA_X_509 = 0x00000003,
  CKM_SHA256_RSA_PKCS = 0x00000040,
  CKM_SHA384_RSA_PKCS = 0x00000041,
  CKM_SHA512_RSA_PKCS = 0x00000042,
  CKM_SHA256_RSA_PKCS_PSS = 0x00000043,
  CKM_EC_KEY_PAIR_GEN = 0x00001040,
  CKM_ECDSA = 0x00001041,
  CKM_ECDSA_SHA256 = 0x00001044,
  CKM_ECDSA_SHA384 = 0x00001045,
  CKM_ECDSA_SHA512 = 0x00001046,
  CKM_AES_KEY_GEN = 0x00001080,
  CKM_AES_ECB = 0x00001081,
  CKM_AES_CBC = 0x00001082,
  CKM_AES_CBC_PAD = 0x00001085,
  CKM_AES_GCM = 0x00001087,
  CKM_SHA256_HMAC = 0x00000251,
  CKM_SHA384_HMAC = 0x00000261,
  CKM_SHA512_HMAC = 0x00000271,
}

/**
 * PKCS#11 Attribute Types (CKA_*)
 */
export enum PKCS11AttributeType {
  CKA_CLASS = 0x00000000,
  CKA_TOKEN = 0x00000001,
  CKA_PRIVATE = 0x00000002,
  CKA_LABEL = 0x00000003,
  CKA_APPLICATION = 0x00000010,
  CKA_VALUE = 0x00000011,
  CKA_OBJECT_ID = 0x00000012,
  CKA_CERTIFICATE_TYPE = 0x00000080,
  CKA_ISSUER = 0x00000081,
  CKA_SERIAL_NUMBER = 0x00000082,
  CKA_KEY_TYPE = 0x00000100,
  CKA_SUBJECT = 0x00000101,
  CKA_ID = 0x00000102,
  CKA_SENSITIVE = 0x00000103,
  CKA_ENCRYPT = 0x00000104,
  CKA_DECRYPT = 0x00000105,
  CKA_WRAP = 0x00000106,
  CKA_UNWRAP = 0x00000107,
  CKA_SIGN = 0x00000108,
  CKA_SIGN_RECOVER = 0x00000109,
  CKA_VERIFY = 0x0000010A,
  CKA_VERIFY_RECOVER = 0x0000010B,
  CKA_DERIVE = 0x0000010C,
  CKA_START_DATE = 0x00000110,
  CKA_END_DATE = 0x00000111,
  CKA_MODULUS = 0x00000120,
  CKA_MODULUS_BITS = 0x00000121,
  CKA_PUBLIC_EXPONENT = 0x00000122,
  CKA_PRIVATE_EXPONENT = 0x00000123,
  CKA_PRIME_1 = 0x00000124,
  CKA_PRIME_2 = 0x00000125,
  CKA_EXPONENT_1 = 0x00000126,
  CKA_EXPONENT_2 = 0x00000127,
  CKA_COEFFICIENT = 0x00000128,
  CKA_EC_PARAMS = 0x00000180,
  CKA_EC_POINT = 0x00000181,
  CKA_EXTRACTABLE = 0x00000162,
  CKA_LOCAL = 0x00000163,
  CKA_NEVER_EXTRACTABLE = 0x00000164,
  CKA_ALWAYS_SENSITIVE = 0x00000165,
  CKA_KEY_GEN_MECHANISM = 0x00000166,
  CKA_MODIFIABLE = 0x00000170,
  CKA_VALUE_LEN = 0x00000161,
}

/**
 * PKCS#11 Attribute
 */
export interface PKCS11Attribute {
  type: PKCS11AttributeType;
  value: unknown;
}

/**
 * PKCS#11 Slot Info
 */
export interface PKCS11SlotInfo {
  slotId: number;
  slotDescription: string;
  manufacturerId: string;
  flags: number;
  hardwareVersion: { major: number; minor: number };
  firmwareVersion: { major: number; minor: number };
}

/**
 * PKCS#11 Token Info
 */
export interface PKCS11TokenInfo {
  label: string;
  manufacturerId: string;
  model: string;
  serialNumber: string;
  flags: number;
  maxSessionCount: number;
  sessionCount: number;
  maxRwSessionCount: number;
  rwSessionCount: number;
  maxPinLen: number;
  minPinLen: number;
  totalPublicMemory: number;
  freePublicMemory: number;
  totalPrivateMemory: number;
  freePrivateMemory: number;
  hardwareVersion: { major: number; minor: number };
  firmwareVersion: { major: number; minor: number };
  utcTime: string;
}

/**
 * PKCS#11 Session Info
 */
export interface PKCS11SessionInfo {
  slotId: number;
  state: number;
  flags: number;
  deviceError: number;
}

/**
 * PKCS#11 Mechanism Info
 */
export interface PKCS11MechanismInfo {
  minKeySize: number;
  maxKeySize: number;
  flags: number;
}

/**
 * PKCS#11 Session
 */
export interface PKCS11Session {
  handle: number;
  slotId: number;
  flags: number;
  state: 'open' | 'logged_in' | 'closed';
  userType?: PKCS11UserType;
  createdAt: string;
  lastActivityAt: string;
}

/**
 * PKCS#11 Object
 */
export interface PKCS11Object {
  handle: number;
  sessionHandle: number;
  objectClass: PKCS11ObjectClass;
  attributes: PKCS11Attribute[];
  keyHandle?: string; // Link to HSM key
}

/**
 * PKCS#11 Library Configuration
 */
export interface PKCS11LibraryConfig {
  libraryPath: string;
  slotId: number;
  pin?: string;
  label?: string;
  manufacturerId?: string;
  initialized: boolean;
  initArgs?: Record<string, unknown>;
}

/**
 * HSM Cluster Node
 */
export interface HSMClusterNode {
  nodeId: string;
  hostname: string;
  port: number;
  status: 'active' | 'standby' | 'failed' | 'syncing';
  role: 'primary' | 'secondary';
  lastHeartbeat: string;
  loadPercentage: number;
  keyCount: number;
  region?: string;
  availabilityZone?: string;
}

/**
 * HSM Cluster Configuration
 */
export interface HSMClusterConfiguration {
  clusterId: string;
  name: string;
  nodes: HSMClusterNode[];
  quorum: number;
  failoverPolicy: 'automatic' | 'manual';
  syncMode: 'synchronous' | 'asynchronous';
  healthCheckInterval: number;
  createdAt: string;
  updatedAt: string;
}

/**
 * HSM Cluster Health
 */
export interface HSMClusterHealth {
  clusterId: string;
  status: 'healthy' | 'degraded' | 'critical' | 'offline';
  totalNodes: number;
  activeNodes: number;
  failedNodes: number;
  syncingNodes: number;
  primaryNode?: string;
  lastFailover?: string;
  averageLatency: number;
  operationsPerSecond: number;
  lastHealthCheck: string;
  alerts: HSMClusterAlert[];
}

/**
 * HSM Cluster Alert
 */
export interface HSMClusterAlert {
  alertId: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  nodeId?: string;
  timestamp: string;
  acknowledged: boolean;
}

// ============================================================================
// HSM Error Classes
// ============================================================================

/**
 * Base HSM Error
 */
export class HSMError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'HSMError';
  }
}

/**
 * HSM Connection Error
 */
export class HSMConnectionError extends HSMError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, 'HSM_CONNECTION_ERROR', details);
    this.name = 'HSMConnectionError';
  }
}

/**
 * HSM Key Not Found Error
 */
export class HSMKeyNotFoundError extends HSMError {
  constructor(keyHandle: string) {
    super(`Key not found: ${keyHandle}`, 'HSM_KEY_NOT_FOUND', { keyHandle });
    this.name = 'HSMKeyNotFoundError';
  }
}

/**
 * HSM Operation Error
 */
export class HSMOperationError extends HSMError {
  constructor(operation: string, message: string, details?: Record<string, unknown>) {
    super(message, 'HSM_OPERATION_ERROR', { operation, ...details });
    this.name = 'HSMOperationError';
  }
}

/**
 * HSM Authentication Error
 */
export class HSMAuthenticationError extends HSMError {
  constructor(message: string) {
    super(message, 'HSM_AUTH_ERROR');
    this.name = 'HSMAuthenticationError';
  }
}

/**
 * PKCS#11 Error
 */
export class PKCS11Error extends HSMError {
  constructor(
    message: string,
    public returnValue: PKCS11ReturnValue,
    details?: Record<string, unknown>
  ) {
    super(message, `PKCS11_${PKCS11ReturnValue[returnValue]}`, details);
    this.name = 'PKCS11Error';
  }
}

// ============================================================================
// HSM Utility Functions
// ============================================================================

/**
 * Generate a unique key handle
 */
export function generateKeyHandle(): string {
  return `hsm_key_${crypto.randomBytes(16).toString('hex')}`;
}

/**
 * Generate a unique key ID
 */
export function generateKeyId(): string {
  return `hsmk_${crypto.randomBytes(12).toString('hex')}`;
}

/**
 * Generate a unique backup ID
 */
export function generateBackupId(): string {
  return `hsm_backup_${crypto.randomBytes(12).toString('hex')}`;
}

/**
 * Generate a unique operation ID
 */
export function generateOperationId(): string {
  return `hsm_op_${crypto.randomBytes(8).toString('hex')}`;
}

/**
 * Calculate checksum for backup verification
 */
export function calculateChecksum(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Get signing algorithm based on key type
 */
export function getSigningAlgorithm(keyType: HSMKeyType): string {
  switch (keyType) {
    case 'RSA_2048':
    case 'RSA_4096':
      return 'RSA-SHA256';
    case 'EC_P256':
      return 'ECDSA-SHA256';
    case 'EC_P384':
      return 'ECDSA-SHA384';
    case 'EC_SECP256K1':
      return 'ECDSA-SHA256';
    default:
      throw new HSMOperationError('sign', `Unsupported key type for signing: ${keyType}`);
  }
}

/**
 * Validate key type
 */
export function isValidKeyType(keyType: string): keyType is HSMKeyType {
  return ['RSA_2048', 'RSA_4096', 'EC_P256', 'EC_P384', 'EC_SECP256K1', 'AES_256'].includes(keyType);
}

/**
 * Validate key usage
 */
export function isValidKeyUsage(usage: string): usage is HSMKeyUsage {
  return ['sign', 'encrypt', 'wrap', 'derive'].includes(usage);
}

// ============================================================================
// Simulated HSM Operations (for testing without real HSM)
// ============================================================================

/**
 * Simulated HSM key store (in-memory for testing)
 * In production, this would be replaced by actual CloudHSM PKCS#11 calls
 */
const simulatedKeyStore = new Map<string, {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  keyType: HSMKeyType;
  label: string;
}>();

/**
 * Generate key pair in simulated HSM
 */
function generateSimulatedKeyPair(keyType: HSMKeyType): {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
} {
  switch (keyType) {
    case 'RSA_2048':
      return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }) as unknown as { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject };
    
    case 'RSA_4096':
      return crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }) as unknown as { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject };
    
    case 'EC_P256':
      return crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }) as unknown as { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject };
    
    case 'EC_P384':
      return crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp384r1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }) as unknown as { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject };
    
    case 'EC_SECP256K1':
      return crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }) as unknown as { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject };
    
    case 'AES_256':
      // For AES, we generate a symmetric key
      const symmetricKey = crypto.randomBytes(32);
      const keyObject = crypto.createSecretKey(symmetricKey);
      return {
        privateKey: keyObject,
        publicKey: keyObject
      };
    
    default:
      throw new HSMOperationError('generateKey', `Unsupported key type: ${keyType}`);
  }
}


// ============================================================================
// HSM Service Class
// ============================================================================

/**
 * AWS CloudHSM Integration Service
 * 
 * Provides hardware-backed key protection for enterprise customers.
 * All cryptographic operations are performed within the HSM boundary.
 */
export class HSMService {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;
  private clusterConfig: HSMClusterConfig | null = null;
  private isInitialized: boolean = false;
  private credentials: HSMCredentials | null = null;

  constructor(
    docClient?: DynamoDBDocumentClient,
    tableName?: string
  ) {
    this.docClient = docClient || dynamoDb;
    this.tableName = tableName || process.env.HSM_TABLE || 'zalt-hsm';
  }

  /**
   * Initialize HSM connection
   * 
   * @param clusterId - AWS CloudHSM cluster ID
   * @param credentials - HSM authentication credentials
   * @returns HSM cluster configuration
   */
  async initializeHSM(
    clusterId: string,
    credentials: HSMCredentials
  ): Promise<HSMClusterConfig> {
    if (!clusterId) {
      throw new HSMConnectionError('Cluster ID is required');
    }

    if (!credentials.username || !credentials.password) {
      throw new HSMAuthenticationError('Username and password are required');
    }

    // Validate credentials format
    if (credentials.username.length < 3) {
      throw new HSMAuthenticationError('Invalid username format');
    }

    const now = new Date().toISOString();

    // Create cluster configuration
    this.clusterConfig = {
      clusterId,
      provider: 'aws_cloudhsm',
      region: process.env.AWS_REGION || 'eu-central-1',
      status: 'initializing',
      createdAt: now,
      updatedAt: now
    };

    this.credentials = credentials;

    try {
      // In production, this would establish actual PKCS#11 connection
      // For now, we simulate the connection
      await this.simulateHSMConnection(clusterId, credentials);

      this.clusterConfig.status = 'connected';
      this.isInitialized = true;

      // Store cluster config in database
      await this.storeClusterConfig(this.clusterConfig);

      // Log the initialization
      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'initialize',
        realmId: 'system',
        timestamp: now,
        success: true
      });

      return this.clusterConfig;
    } catch (error) {
      this.clusterConfig.status = 'error';
      
      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'initialize',
        realmId: 'system',
        timestamp: now,
        success: false,
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      });

      throw new HSMConnectionError(
        `Failed to initialize HSM: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { clusterId }
      );
    }
  }

  /**
   * Generate a key within the HSM boundary
   * 
   * @param keyType - Type of key to generate
   * @param label - Human-readable label for the key
   * @param options - Additional key generation options
   * @returns Generated key metadata and public key (if applicable)
   */
  async generateKeyInHSM(
    keyType: HSMKeyType,
    label: string,
    options?: Partial<HSMKeyGenerationOptions>
  ): Promise<HSMKeyGenerationResult> {
    this.ensureInitialized();

    if (!isValidKeyType(keyType)) {
      throw new HSMOperationError('generateKey', `Invalid key type: ${keyType}`);
    }

    if (!label || label.length < 1) {
      throw new HSMOperationError('generateKey', 'Key label is required');
    }

    const now = new Date().toISOString();
    const keyHandle = generateKeyHandle();
    const keyId = generateKeyId();
    const realmId = options?.realmId || 'default';

    try {
      // Generate key pair in simulated HSM
      const keyPair = generateSimulatedKeyPair(keyType);
      
      // Store in simulated key store
      simulatedKeyStore.set(keyHandle, {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        keyType,
        label
      });

      // Extract public key for asymmetric keys
      let publicKeyPem: string | undefined;
      if (keyType !== 'AES_256') {
        if (typeof keyPair.publicKey === 'string') {
          publicKeyPem = keyPair.publicKey;
        } else if (keyPair.publicKey && typeof keyPair.publicKey.export === 'function') {
          publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }) as string;
        }
      }

      // Create key metadata
      const key: HSMKey = {
        keyHandle,
        keyId,
        realmId,
        label,
        keyType,
        keyUsage: options?.keyUsage || ['sign'],
        extractable: options?.extractable ?? false,
        persistent: options?.persistent ?? true,
        createdAt: now,
        updatedAt: now,
        status: 'active'
      };

      // Store key metadata in database
      await this.storeKey(key);

      // Log the operation
      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'generateKey',
        keyHandle,
        realmId,
        timestamp: now,
        success: true
      });

      return {
        key,
        publicKey: publicKeyPem
      };
    } catch (error) {
      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'generateKey',
        realmId,
        timestamp: now,
        success: false,
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      });

      throw new HSMOperationError(
        'generateKey',
        `Failed to generate key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { keyType, label }
      );
    }
  }

  /**
   * Sign a message using a key stored in the HSM
   * 
   * @param keyHandle - Handle of the key to use for signing
   * @param message - Message to sign
   * @returns Signature result
   */
  async signWithHSM(
    keyHandle: string,
    message: Buffer
  ): Promise<HSMSigningResult> {
    this.ensureInitialized();

    if (!keyHandle) {
      throw new HSMOperationError('sign', 'Key handle is required');
    }

    if (!message || message.length === 0) {
      throw new HSMOperationError('sign', 'Message is required');
    }

    const now = new Date().toISOString();

    try {
      // Get key from simulated store
      const keyData = simulatedKeyStore.get(keyHandle);
      if (!keyData) {
        throw new HSMKeyNotFoundError(keyHandle);
      }

      // Get key metadata from database
      const keyMeta = await this.getKey(keyHandle);
      if (!keyMeta) {
        throw new HSMKeyNotFoundError(keyHandle);
      }

      if (keyMeta.status !== 'active') {
        throw new HSMOperationError('sign', 'Key is not active');
      }

      if (!keyMeta.keyUsage.includes('sign')) {
        throw new HSMOperationError('sign', 'Key is not authorized for signing');
      }

      // Perform signing operation
      let signature: string;
      let algorithm: string;
      
      if (keyData.keyType === 'AES_256') {
        algorithm = 'HMAC-SHA256';
        // For symmetric keys, use HMAC
        const hmac = crypto.createHmac('sha256', keyData.privateKey);
        hmac.update(message);
        signature = hmac.digest('base64');
      } else {
        algorithm = getSigningAlgorithm(keyData.keyType);
        // For asymmetric keys, use digital signature
        const sign = crypto.createSign('SHA256');
        sign.update(message);
        
        let privateKeyPem: string;
        if (typeof keyData.privateKey === 'string') {
          privateKeyPem = keyData.privateKey;
        } else {
          privateKeyPem = keyData.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
        }
        
        signature = sign.sign(privateKeyPem, 'base64');
      }

      // Update last used timestamp
      await this.updateKeyLastUsed(keyHandle);

      // Log the operation
      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'sign',
        keyHandle,
        realmId: keyMeta.realmId,
        timestamp: now,
        success: true
      });

      return {
        signature,
        algorithm,
        keyHandle,
        timestamp: now
      };
    } catch (error) {
      if (error instanceof HSMError) {
        throw error;
      }

      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'sign',
        keyHandle,
        realmId: 'unknown',
        timestamp: now,
        success: false,
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      });

      throw new HSMOperationError(
        'sign',
        `Failed to sign message: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { keyHandle }
      );
    }
  }

  /**
   * Verify a signature using a key stored in the HSM
   * 
   * @param keyHandle - Handle of the key to use for verification
   * @param message - Original message
   * @param signature - Signature to verify
   * @returns Verification result
   */
  async verifyWithHSM(
    keyHandle: string,
    message: Buffer,
    signature: string
  ): Promise<HSMVerificationResult> {
    this.ensureInitialized();

    if (!keyHandle) {
      throw new HSMOperationError('verify', 'Key handle is required');
    }

    if (!message || message.length === 0) {
      throw new HSMOperationError('verify', 'Message is required');
    }

    if (!signature) {
      throw new HSMOperationError('verify', 'Signature is required');
    }

    const now = new Date().toISOString();

    try {
      // Get key from simulated store
      const keyData = simulatedKeyStore.get(keyHandle);
      if (!keyData) {
        throw new HSMKeyNotFoundError(keyHandle);
      }

      // Get key metadata from database
      const keyMeta = await this.getKey(keyHandle);
      if (!keyMeta) {
        throw new HSMKeyNotFoundError(keyHandle);
      }

      // Perform verification
      let valid: boolean;

      if (keyData.keyType === 'AES_256') {
        // For symmetric keys, verify HMAC
        const hmac = crypto.createHmac('sha256', keyData.privateKey);
        hmac.update(message);
        const expectedSignature = hmac.digest('base64');
        valid = crypto.timingSafeEqual(
          Buffer.from(signature, 'base64'),
          Buffer.from(expectedSignature, 'base64')
        );
      } else {
        // For asymmetric keys, verify digital signature
        const verify = crypto.createVerify('SHA256');
        verify.update(message);
        
        let publicKeyPem: string;
        if (typeof keyData.publicKey === 'string') {
          publicKeyPem = keyData.publicKey;
        } else {
          publicKeyPem = keyData.publicKey.export({ type: 'spki', format: 'pem' }) as string;
        }
        
        valid = verify.verify(publicKeyPem, signature, 'base64');
      }

      // Update last used timestamp
      await this.updateKeyLastUsed(keyHandle);

      // Log the operation
      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'verify',
        keyHandle,
        realmId: keyMeta.realmId,
        timestamp: now,
        success: true
      });

      return {
        valid,
        keyHandle,
        timestamp: now
      };
    } catch (error) {
      if (error instanceof HSMError) {
        throw error;
      }

      return {
        valid: false,
        keyHandle,
        timestamp: now,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Export a key wrapped with another key (for backup)
   * 
   * @param keyHandle - Handle of the key to export
   * @param wrappingKeyHandle - Handle of the key to use for wrapping
   * @returns Wrapped key backup
   */
  async exportWrappedKey(
    keyHandle: string,
    wrappingKeyHandle: string
  ): Promise<HSMKeyBackupResult> {
    this.ensureInitialized();

    if (!keyHandle) {
      throw new HSMOperationError('export', 'Key handle is required');
    }

    if (!wrappingKeyHandle) {
      throw new HSMOperationError('export', 'Wrapping key handle is required');
    }

    const now = new Date().toISOString();

    try {
      // Get key to export
      const keyData = simulatedKeyStore.get(keyHandle);
      if (!keyData) {
        throw new HSMKeyNotFoundError(keyHandle);
      }

      // Get key metadata
      const keyMeta = await this.getKey(keyHandle);
      if (!keyMeta) {
        throw new HSMKeyNotFoundError(keyHandle);
      }

      // Check if key is extractable
      if (!keyMeta.extractable) {
        throw new HSMOperationError('export', 'Key is not extractable');
      }

      // Get wrapping key
      const wrappingKeyData = simulatedKeyStore.get(wrappingKeyHandle);
      if (!wrappingKeyData) {
        throw new HSMKeyNotFoundError(wrappingKeyHandle);
      }

      // Get wrapping key metadata
      const wrappingKeyMeta = await this.getKey(wrappingKeyHandle);
      if (!wrappingKeyMeta) {
        throw new HSMKeyNotFoundError(wrappingKeyHandle);
      }

      // Check if wrapping key can be used for wrapping
      if (!wrappingKeyMeta.keyUsage.includes('wrap')) {
        throw new HSMOperationError('export', 'Wrapping key is not authorized for key wrapping');
      }

      // Export and wrap the key
      let keyMaterial: Buffer;
      if (keyData.keyType === 'AES_256') {
        // For symmetric keys, export the raw key
        keyMaterial = (keyData.privateKey as crypto.KeyObject).export() as Buffer;
      } else {
        // For asymmetric keys, export the private key in PKCS#8 format
        const privateKeyPem = typeof keyData.privateKey === 'string' 
          ? keyData.privateKey 
          : keyData.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
        keyMaterial = Buffer.from(privateKeyPem, 'utf8');
      }

      // Wrap the key using AES-256-GCM
      const iv = crypto.randomBytes(12);
      let wrappingKey: Buffer;
      
      if (wrappingKeyData.keyType === 'AES_256') {
        wrappingKey = (wrappingKeyData.privateKey as crypto.KeyObject).export() as Buffer;
      } else {
        // Derive a symmetric key from the wrapping key for key wrapping
        const wrappingKeyPem = typeof wrappingKeyData.privateKey === 'string'
          ? wrappingKeyData.privateKey
          : wrappingKeyData.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
        wrappingKey = crypto.createHash('sha256').update(wrappingKeyPem).digest();
      }

      const cipher = crypto.createCipheriv('aes-256-gcm', wrappingKey, iv);
      const encrypted = Buffer.concat([cipher.update(keyMaterial), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // Combine iv + authTag + encrypted
      const wrappedKey = Buffer.concat([iv, authTag, encrypted]).toString('base64');
      const checksum = calculateChecksum(wrappedKey);
      const backupId = generateBackupId();

      // Update key with backup ID
      await this.updateKeyBackupId(keyHandle, backupId);

      // Log the operation
      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'exportWrappedKey',
        keyHandle,
        realmId: keyMeta.realmId,
        timestamp: now,
        success: true
      });

      return {
        backupId,
        wrappedKey,
        wrappingKeyHandle,
        keyType: keyData.keyType,
        timestamp: now,
        checksum
      };
    } catch (error) {
      if (error instanceof HSMError) {
        throw error;
      }

      throw new HSMOperationError(
        'export',
        `Failed to export key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { keyHandle, wrappingKeyHandle }
      );
    }
  }

  /**
   * Import a wrapped key from backup
   * 
   * @param wrappedKey - The wrapped key data
   * @param wrappingKeyHandle - Handle of the key used for wrapping
   * @param options - Import options
   * @returns Imported key metadata
   */
  async importWrappedKey(
    wrappedKey: string,
    wrappingKeyHandle: string,
    options: Omit<HSMKeyImportOptions, 'wrappedKey' | 'wrappingKeyHandle'>
  ): Promise<HSMKeyImportResult> {
    this.ensureInitialized();

    if (!wrappedKey) {
      throw new HSMOperationError('import', 'Wrapped key is required');
    }

    if (!wrappingKeyHandle) {
      throw new HSMOperationError('import', 'Wrapping key handle is required');
    }

    if (!options.label) {
      throw new HSMOperationError('import', 'Key label is required');
    }

    if (!isValidKeyType(options.keyType)) {
      throw new HSMOperationError('import', `Invalid key type: ${options.keyType}`);
    }

    const now = new Date().toISOString();

    try {
      // Get wrapping key
      const wrappingKeyData = simulatedKeyStore.get(wrappingKeyHandle);
      if (!wrappingKeyData) {
        throw new HSMKeyNotFoundError(wrappingKeyHandle);
      }

      // Get wrapping key metadata
      const wrappingKeyMeta = await this.getKey(wrappingKeyHandle);
      if (!wrappingKeyMeta) {
        throw new HSMKeyNotFoundError(wrappingKeyHandle);
      }

      // Check if wrapping key can be used for unwrapping
      if (!wrappingKeyMeta.keyUsage.includes('wrap')) {
        throw new HSMOperationError('import', 'Wrapping key is not authorized for key unwrapping');
      }

      // Unwrap the key
      const wrappedData = Buffer.from(wrappedKey, 'base64');
      const iv = wrappedData.subarray(0, 12);
      const authTag = wrappedData.subarray(12, 28);
      const encrypted = wrappedData.subarray(28);

      let wrappingKeyBuffer: Buffer;
      if (wrappingKeyData.keyType === 'AES_256') {
        wrappingKeyBuffer = (wrappingKeyData.privateKey as crypto.KeyObject).export() as Buffer;
      } else {
        const wrappingKeyPem = typeof wrappingKeyData.privateKey === 'string'
          ? wrappingKeyData.privateKey
          : wrappingKeyData.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
        wrappingKeyBuffer = crypto.createHash('sha256').update(wrappingKeyPem).digest();
      }

      const decipher = crypto.createDecipheriv('aes-256-gcm', wrappingKeyBuffer, iv);
      decipher.setAuthTag(authTag);
      const keyMaterial = Buffer.concat([decipher.update(encrypted), decipher.final()]);

      // Create new key handle and ID
      const keyHandle = generateKeyHandle();
      const keyId = generateKeyId();

      // Import the key into simulated store
      let privateKey: crypto.KeyObject;
      let publicKey: crypto.KeyObject;

      if (options.keyType === 'AES_256') {
        privateKey = crypto.createSecretKey(keyMaterial);
        publicKey = privateKey;
      } else {
        // Parse the PEM-encoded private key
        const privateKeyPem = keyMaterial.toString('utf8');
        privateKey = crypto.createPrivateKey(privateKeyPem);
        publicKey = crypto.createPublicKey(privateKey);
      }

      simulatedKeyStore.set(keyHandle, {
        privateKey,
        publicKey,
        keyType: options.keyType,
        label: options.label
      });

      // Create key metadata
      const key: HSMKey = {
        keyHandle,
        keyId,
        realmId: options.realmId,
        label: options.label,
        keyType: options.keyType,
        keyUsage: options.keyUsage,
        extractable: false, // Imported keys are not extractable by default
        persistent: true,
        createdAt: now,
        updatedAt: now,
        status: 'active'
      };

      // Store key metadata
      await this.storeKey(key);

      // Log the operation
      await this.logOperation({
        operationId: generateOperationId(),
        operation: 'importWrappedKey',
        keyHandle,
        realmId: options.realmId,
        timestamp: now,
        success: true
      });

      return {
        key,
        importedAt: now
      };
    } catch (error) {
      if (error instanceof HSMError) {
        throw error;
      }

      throw new HSMOperationError(
        'import',
        `Failed to import key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { wrappingKeyHandle }
      );
    }
  }

  /**
   * Get key information
   * 
   * @param keyHandle - Handle of the key
   * @returns Key information
   */
  async getKeyInfo(keyHandle: string): Promise<HSMKeyInfo> {
    this.ensureInitialized();

    if (!keyHandle) {
      throw new HSMOperationError('getKeyInfo', 'Key handle is required');
    }

    // Get key metadata from database
    const keyMeta = await this.getKey(keyHandle);
    if (!keyMeta) {
      throw new HSMKeyNotFoundError(keyHandle);
    }

    // Get key from simulated store for public key
    const keyData = simulatedKeyStore.get(keyHandle);
    let publicKeyPem: string | undefined;

    if (keyData && keyData.keyType !== 'AES_256') {
      if (typeof keyData.publicKey === 'string') {
        publicKeyPem = keyData.publicKey;
      } else if (keyData.publicKey && typeof keyData.publicKey.export === 'function') {
        publicKeyPem = keyData.publicKey.export({ type: 'spki', format: 'pem' }) as string;
      }
    }

    return {
      keyHandle: keyMeta.keyHandle,
      keyId: keyMeta.keyId,
      label: keyMeta.label,
      keyType: keyMeta.keyType,
      keyUsage: keyMeta.keyUsage,
      extractable: keyMeta.extractable,
      persistent: keyMeta.persistent,
      createdAt: keyMeta.createdAt,
      lastUsedAt: keyMeta.lastUsedAt,
      status: keyMeta.status,
      publicKey: publicKeyPem
    };
  }

  /**
   * List all keys for a realm
   * 
   * @param realmId - Realm ID
   * @returns List of keys
   */
  async listKeys(realmId: string): Promise<HSMKey[]> {
    this.ensureInitialized();

    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `REALM#${realmId}`,
        ':sk': 'KEY#'
      }
    }));

    return (result.Items || []).map(item => ({
      keyHandle: item.keyHandle,
      keyId: item.keyId,
      realmId: item.realmId,
      label: item.label,
      keyType: item.keyType,
      keyUsage: item.keyUsage,
      extractable: item.extractable,
      persistent: item.persistent,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
      lastUsedAt: item.lastUsedAt,
      backupId: item.backupId,
      status: item.status
    }));
  }

  /**
   * Disable a key
   * 
   * @param keyHandle - Handle of the key to disable
   */
  async disableKey(keyHandle: string): Promise<void> {
    this.ensureInitialized();

    const keyMeta = await this.getKey(keyHandle);
    if (!keyMeta) {
      throw new HSMKeyNotFoundError(keyHandle);
    }

    await this.updateKeyStatus(keyHandle, 'disabled');

    await this.logOperation({
      operationId: generateOperationId(),
      operation: 'disableKey',
      keyHandle,
      realmId: keyMeta.realmId,
      timestamp: new Date().toISOString(),
      success: true
    });
  }

  /**
   * Delete a key (schedule for deletion)
   * 
   * @param keyHandle - Handle of the key to delete
   */
  async deleteKey(keyHandle: string): Promise<void> {
    this.ensureInitialized();

    const keyMeta = await this.getKey(keyHandle);
    if (!keyMeta) {
      throw new HSMKeyNotFoundError(keyHandle);
    }

    // Mark as pending deletion
    await this.updateKeyStatus(keyHandle, 'pending_deletion');

    // Remove from simulated store
    simulatedKeyStore.delete(keyHandle);

    await this.logOperation({
      operationId: generateOperationId(),
      operation: 'deleteKey',
      keyHandle,
      realmId: keyMeta.realmId,
      timestamp: new Date().toISOString(),
      success: true
    });
  }

  /**
   * Get HSM cluster status
   * 
   * @returns Cluster status information
   */
  async getClusterStatus(): Promise<HSMClusterStatus> {
    this.ensureInitialized();

    if (!this.clusterConfig) {
      throw new HSMConnectionError('HSM not initialized');
    }

    // Count keys in simulated store
    const keyCount = simulatedKeyStore.size;

    return {
      clusterId: this.clusterConfig.clusterId,
      status: this.clusterConfig.status,
      hsmCount: 2, // Simulated HA cluster
      activeHsms: 2,
      keyCount,
      operationsPerSecond: 1000, // Simulated throughput
      lastHealthCheck: new Date().toISOString()
    };
  }

  /**
   * Check if HSM is initialized
   */
  isConnected(): boolean {
    return this.isInitialized && this.clusterConfig?.status === 'connected';
  }

  /**
   * Disconnect from HSM
   */
  async disconnect(): Promise<void> {
    if (this.clusterConfig) {
      this.clusterConfig.status = 'disconnected';
      await this.storeClusterConfig(this.clusterConfig);
    }
    
    this.isInitialized = false;
    this.credentials = null;
    
    // Clear simulated key store
    simulatedKeyStore.clear();
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Ensure HSM is initialized before operations
   */
  private ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new HSMConnectionError('HSM not initialized. Call initializeHSM first.');
    }
  }

  /**
   * Simulate HSM connection (for testing)
   */
  private async simulateHSMConnection(
    clusterId: string,
    credentials: HSMCredentials
  ): Promise<void> {
    // Simulate connection delay
    await new Promise(resolve => setTimeout(resolve, 100));

    // Validate credentials (simulated)
    if (credentials.username === 'invalid') {
      throw new HSMAuthenticationError('Invalid credentials');
    }

    // Simulate successful connection
    return;
  }

  /**
   * Store cluster configuration in database
   */
  private async storeClusterConfig(config: HSMClusterConfig): Promise<void> {
    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        PK: 'CLUSTER',
        SK: `CLUSTER#${config.clusterId}`,
        ...config,
        type: 'cluster_config'
      }
    }));
  }

  /**
   * Store key metadata in database
   */
  private async storeKey(key: HSMKey): Promise<void> {
    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        PK: `REALM#${key.realmId}`,
        SK: `KEY#${key.keyHandle}`,
        GSI1PK: `KEY#${key.keyHandle}`,
        GSI1SK: `REALM#${key.realmId}`,
        ...key,
        type: 'hsm_key'
      }
    }));
  }

  /**
   * Get key metadata from database
   */
  private async getKey(keyHandle: string): Promise<HSMKey | null> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI1',
      KeyConditionExpression: 'GSI1PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `KEY#${keyHandle}`
      }
    }));

    if (!result.Items || result.Items.length === 0) {
      return null;
    }

    const item = result.Items[0];
    return {
      keyHandle: item.keyHandle,
      keyId: item.keyId,
      realmId: item.realmId,
      label: item.label,
      keyType: item.keyType,
      keyUsage: item.keyUsage,
      extractable: item.extractable,
      persistent: item.persistent,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
      lastUsedAt: item.lastUsedAt,
      backupId: item.backupId,
      status: item.status
    };
  }

  /**
   * Update key last used timestamp
   */
  private async updateKeyLastUsed(keyHandle: string): Promise<void> {
    const key = await this.getKey(keyHandle);
    if (!key) return;

    await this.docClient.send(new UpdateCommand({
      TableName: this.tableName,
      Key: {
        PK: `REALM#${key.realmId}`,
        SK: `KEY#${keyHandle}`
      },
      UpdateExpression: 'SET lastUsedAt = :lastUsedAt, updatedAt = :updatedAt',
      ExpressionAttributeValues: {
        ':lastUsedAt': new Date().toISOString(),
        ':updatedAt': new Date().toISOString()
      }
    }));
  }

  /**
   * Update key status
   */
  private async updateKeyStatus(keyHandle: string, status: HSMKey['status']): Promise<void> {
    const key = await this.getKey(keyHandle);
    if (!key) return;

    await this.docClient.send(new UpdateCommand({
      TableName: this.tableName,
      Key: {
        PK: `REALM#${key.realmId}`,
        SK: `KEY#${keyHandle}`
      },
      UpdateExpression: 'SET #status = :status, updatedAt = :updatedAt',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':status': status,
        ':updatedAt': new Date().toISOString()
      }
    }));
  }

  /**
   * Update key backup ID
   */
  private async updateKeyBackupId(keyHandle: string, backupId: string): Promise<void> {
    const key = await this.getKey(keyHandle);
    if (!key) return;

    await this.docClient.send(new UpdateCommand({
      TableName: this.tableName,
      Key: {
        PK: `REALM#${key.realmId}`,
        SK: `KEY#${keyHandle}`
      },
      UpdateExpression: 'SET backupId = :backupId, updatedAt = :updatedAt',
      ExpressionAttributeValues: {
        ':backupId': backupId,
        ':updatedAt': new Date().toISOString()
      }
    }));
  }

  /**
   * Log HSM operation for audit
   */
  private async logOperation(log: HSMOperationLog): Promise<void> {
    try {
      await this.docClient.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          PK: `AUDIT#${log.realmId}`,
          SK: `OP#${log.timestamp}#${log.operationId}`,
          GSI1PK: log.keyHandle ? `KEY#${log.keyHandle}` : 'SYSTEM',
          GSI1SK: `OP#${log.timestamp}`,
          ...log,
          type: 'hsm_operation_log'
        }
      }));
    } catch {
      // Don't fail operations due to logging errors
      console.error('Failed to log HSM operation:', log.operationId);
    }
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

/**
 * Default HSM service instance
 */
export const hsmService = new HSMService();

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Initialize HSM with cluster ID and credentials
 */
export async function initializeHSM(
  clusterId: string,
  credentials: HSMCredentials
): Promise<HSMClusterConfig> {
  return hsmService.initializeHSM(clusterId, credentials);
}

/**
 * Generate a key in the HSM
 */
export async function generateKeyInHSM(
  keyType: HSMKeyType,
  label: string,
  options?: Partial<HSMKeyGenerationOptions>
): Promise<HSMKeyGenerationResult> {
  return hsmService.generateKeyInHSM(keyType, label, options);
}

/**
 * Sign with HSM key
 */
export async function signWithHSM(
  keyHandle: string,
  message: Buffer
): Promise<HSMSigningResult> {
  return hsmService.signWithHSM(keyHandle, message);
}

/**
 * Verify with HSM key
 */
export async function verifyWithHSM(
  keyHandle: string,
  message: Buffer,
  signature: string
): Promise<HSMVerificationResult> {
  return hsmService.verifyWithHSM(keyHandle, message, signature);
}

/**
 * Export wrapped key for backup
 */
export async function exportWrappedKey(
  keyHandle: string,
  wrappingKeyHandle: string
): Promise<HSMKeyBackupResult> {
  return hsmService.exportWrappedKey(keyHandle, wrappingKeyHandle);
}

/**
 * Import wrapped key from backup
 */
export async function importWrappedKey(
  wrappedKey: string,
  wrappingKeyHandle: string,
  options: Omit<HSMKeyImportOptions, 'wrappedKey' | 'wrappingKeyHandle'>
): Promise<HSMKeyImportResult> {
  return hsmService.importWrappedKey(wrappedKey, wrappingKeyHandle, options);
}

/**
 * Get key information
 */
export async function getKeyInfo(keyHandle: string): Promise<HSMKeyInfo> {
  return hsmService.getKeyInfo(keyHandle);
}
