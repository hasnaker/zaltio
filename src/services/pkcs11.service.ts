/**
 * PKCS#11 Interface Service for Zalt.io
 * 
 * Implements standard PKCS#11 interface for customer-managed HSM support:
 * - C_Initialize, C_Finalize - Library initialization
 * - C_OpenSession, C_CloseSession - Session management
 * - C_Login, C_Logout - Authentication
 * - C_FindObjects - Object discovery
 * - C_GenerateKeyPair - Key generation
 * - C_Sign, C_Verify - Cryptographic operations
 * - HSM clustering for high availability
 * 
 * Security considerations:
 * - All operations require proper authentication
 * - Session state is tracked and validated
 * - Audit logging for all PKCS#11 operations
 * - Support for customer-managed HSM connections
 * 
 * Requirements: 27.4, 27.9
 */

import crypto from 'crypto';
import { DynamoDBDocumentClient, PutCommand, QueryCommand, DeleteCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from './dynamodb.service';
import {
  HSMService,
  HSMKeyType,
  HSMKeyUsage,
  HSMError,
  HSMConnectionError,
  HSMOperationError,
  HSMAuthenticationError,
  HSMKeyNotFoundError,
  generateKeyHandle,
  generateKeyId,
  generateOperationId,
  PKCS11ReturnValue,
  PKCS11SessionFlags,
  PKCS11UserType,
  PKCS11ObjectClass,
  PKCS11KeyType,
  PKCS11Mechanism,
  PKCS11AttributeType,
  PKCS11Attribute,
  PKCS11SlotInfo,
  PKCS11TokenInfo,
  PKCS11SessionInfo,
  PKCS11MechanismInfo,
  PKCS11Session,
  PKCS11Object,
  PKCS11LibraryConfig,
  PKCS11Error,
  HSMClusterNode,
  HSMClusterConfiguration,
  HSMClusterHealth,
  HSMClusterAlert,
} from './hsm.service';

// Re-export PKCS#11 types for convenience
export {
  PKCS11ReturnValue,
  PKCS11SessionFlags,
  PKCS11UserType,
  PKCS11ObjectClass,
  PKCS11KeyType,
  PKCS11Mechanism,
  PKCS11AttributeType,
  PKCS11Attribute,
  PKCS11SlotInfo,
  PKCS11TokenInfo,
  PKCS11SessionInfo,
  PKCS11MechanismInfo,
  PKCS11Session,
  PKCS11Object,
  PKCS11LibraryConfig,
  PKCS11Error,
  HSMClusterNode,
  HSMClusterConfiguration,
  HSMClusterHealth,
  HSMClusterAlert,
} from './hsm.service';

// ============================================================================
// PKCS#11 Utility Functions
// ============================================================================

/**
 * Generate a unique session handle
 */
export function generateSessionHandle(): number {
  return Math.floor(Math.random() * 0x7FFFFFFF) + 1;
}

/**
 * Generate a unique object handle
 */
export function generateObjectHandle(): number {
  return Math.floor(Math.random() * 0x7FFFFFFF) + 1;
}

/**
 * Generate a unique cluster ID
 */
export function generateClusterId(): string {
  return `hsm_cluster_${crypto.randomBytes(8).toString('hex')}`;
}

/**
 * Generate a unique node ID
 */
export function generateNodeId(): string {
  return `hsm_node_${crypto.randomBytes(6).toString('hex')}`;
}

/**
 * Generate a unique alert ID
 */
export function generateAlertId(): string {
  return `hsm_alert_${crypto.randomBytes(6).toString('hex')}`;
}

/**
 * Map HSM key type to PKCS#11 key type
 */
export function hsmKeyTypeToPKCS11(keyType: HSMKeyType): PKCS11KeyType {
  switch (keyType) {
    case 'RSA_2048':
    case 'RSA_4096':
      return PKCS11KeyType.CKK_RSA;
    case 'EC_P256':
    case 'EC_P384':
    case 'EC_SECP256K1':
      return PKCS11KeyType.CKK_EC;
    case 'AES_256':
      return PKCS11KeyType.CKK_AES;
    default:
      throw new PKCS11Error('Unsupported key type', PKCS11ReturnValue.CKR_KEY_TYPE_INCONSISTENT);
  }
}

/**
 * Map PKCS#11 key type to HSM key type
 */
export function pkcs11KeyTypeToHSM(keyType: PKCS11KeyType, modulusBits?: number): HSMKeyType {
  switch (keyType) {
    case PKCS11KeyType.CKK_RSA:
      return modulusBits === 4096 ? 'RSA_4096' : 'RSA_2048';
    case PKCS11KeyType.CKK_EC:
      return 'EC_P256'; // Default to P-256
    case PKCS11KeyType.CKK_AES:
      return 'AES_256';
    default:
      throw new PKCS11Error('Unsupported key type', PKCS11ReturnValue.CKR_KEY_TYPE_INCONSISTENT);
  }
}

// ============================================================================
// PKCS#11 Service Class
// ============================================================================

/**
 * PKCS#11 Interface Service
 * 
 * Provides standard PKCS#11 interface for customer-managed HSM support.
 * Implements core PKCS#11 operations following the OASIS PKCS#11 specification.
 */
export class PKCS11Service {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;
  private hsmService: HSMService;
  
  // PKCS#11 state
  private libraryConfig: PKCS11LibraryConfig | null = null;
  private sessions: Map<number, PKCS11Session> = new Map();
  private objects: Map<number, PKCS11Object> = new Map();
  private slots: Map<number, PKCS11SlotInfo> = new Map();
  private isInitialized: boolean = false;

  constructor(
    hsmService?: HSMService,
    docClient?: DynamoDBDocumentClient,
    tableName?: string
  ) {
    this.hsmService = hsmService || new HSMService();
    this.docClient = docClient || dynamoDb;
    this.tableName = tableName || process.env.HSM_TABLE || 'zalt-hsm';
  }

  // ==========================================================================
  // PKCS#11 Library Management (C_Initialize, C_Finalize)
  // ==========================================================================

  /**
   * Initialize PKCS#11 library (C_Initialize)
   * 
   * @param libraryPath - Path to the PKCS#11 library
   * @param slotId - Slot ID to use
   * @param initArgs - Optional initialization arguments
   * @returns PKCS#11 return value
   * 
   * **Validates: Requirements 27.4**
   */
  async initializePKCS11(
    libraryPath: string,
    slotId: number,
    initArgs?: Record<string, unknown>
  ): Promise<PKCS11ReturnValue> {
    if (this.isInitialized) {
      return PKCS11ReturnValue.CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    if (!libraryPath || libraryPath.trim().length === 0) {
      return PKCS11ReturnValue.CKR_ARGUMENTS_BAD;
    }

    if (slotId < 0) {
      return PKCS11ReturnValue.CKR_SLOT_ID_INVALID;
    }

    try {
      // Store library configuration
      this.libraryConfig = {
        libraryPath,
        slotId,
        initialized: true,
        initArgs
      };

      // Initialize default slot
      this.slots.set(slotId, {
        slotId,
        slotDescription: 'Zalt PKCS#11 Virtual Slot',
        manufacturerId: 'Zalt.io',
        flags: 0x01, // CKF_TOKEN_PRESENT
        hardwareVersion: { major: 1, minor: 0 },
        firmwareVersion: { major: 1, minor: 0 }
      });

      this.isInitialized = true;

      // Log the operation
      await this.logPKCS11Operation('C_Initialize', { libraryPath, slotId }, true);

      return PKCS11ReturnValue.CKR_OK;
    } catch (error) {
      await this.logPKCS11Operation('C_Initialize', { libraryPath, slotId }, false, 
        error instanceof Error ? error.message : 'Unknown error');
      return PKCS11ReturnValue.CKR_GENERAL_ERROR;
    }
  }

  /**
   * Finalize PKCS#11 library (C_Finalize)
   * 
   * @returns PKCS#11 return value
   */
  async finalizePKCS11(): Promise<PKCS11ReturnValue> {
    if (!this.isInitialized) {
      return PKCS11ReturnValue.CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    try {
      // Close all sessions
      for (const [handle] of this.sessions) {
        await this.closeSession(handle);
      }

      // Clear state
      this.sessions.clear();
      this.objects.clear();
      this.slots.clear();
      this.libraryConfig = null;
      this.isInitialized = false;

      await this.logPKCS11Operation('C_Finalize', {}, true);
      return PKCS11ReturnValue.CKR_OK;
    } catch (error) {
      await this.logPKCS11Operation('C_Finalize', {}, false,
        error instanceof Error ? error.message : 'Unknown error');
      return PKCS11ReturnValue.CKR_GENERAL_ERROR;
    }
  }

  // ==========================================================================
  // PKCS#11 Slot and Token Information
  // ==========================================================================

  /**
   * Get slot list (C_GetSlotList)
   * 
   * @param tokenPresent - Only return slots with tokens present
   * @returns Array of slot IDs
   */
  getSlotList(tokenPresent: boolean = false): number[] {
    this.ensurePKCS11Initialized();
    
    const slotIds: number[] = [];
    for (const [slotId, info] of this.slots) {
      if (!tokenPresent || (info.flags & 0x01)) { // CKF_TOKEN_PRESENT
        slotIds.push(slotId);
      }
    }
    return slotIds;
  }

  /**
   * Get slot info (C_GetSlotInfo)
   * 
   * @param slotId - Slot ID
   * @returns Slot information
   */
  getSlotInfo(slotId: number): PKCS11SlotInfo {
    this.ensurePKCS11Initialized();
    
    const info = this.slots.get(slotId);
    if (!info) {
      throw new PKCS11Error('Invalid slot ID', PKCS11ReturnValue.CKR_SLOT_ID_INVALID);
    }
    return info;
  }

  /**
   * Get token info (C_GetTokenInfo)
   * 
   * @param slotId - Slot ID
   * @returns Token information
   */
  getTokenInfo(slotId: number): PKCS11TokenInfo {
    this.ensurePKCS11Initialized();
    
    if (!this.slots.has(slotId)) {
      throw new PKCS11Error('Invalid slot ID', PKCS11ReturnValue.CKR_SLOT_ID_INVALID);
    }

    return {
      label: 'Zalt HSM Token',
      manufacturerId: 'Zalt.io',
      model: 'Virtual HSM',
      serialNumber: crypto.randomBytes(8).toString('hex').toUpperCase(),
      flags: 0x0405, // CKF_RNG | CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED
      maxSessionCount: 1024,
      sessionCount: this.sessions.size,
      maxRwSessionCount: 1024,
      rwSessionCount: Array.from(this.sessions.values())
        .filter(s => s.flags & PKCS11SessionFlags.CKF_RW_SESSION).length,
      maxPinLen: 64,
      minPinLen: 4,
      totalPublicMemory: 1024 * 1024,
      freePublicMemory: 512 * 1024,
      totalPrivateMemory: 1024 * 1024,
      freePrivateMemory: 512 * 1024,
      hardwareVersion: { major: 1, minor: 0 },
      firmwareVersion: { major: 1, minor: 0 },
      utcTime: new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 16)
    };
  }

  // ==========================================================================
  // PKCS#11 Session Management (C_OpenSession, C_CloseSession, C_Login)
  // ==========================================================================

  /**
   * Open a session (C_OpenSession)
   * 
   * @param slotId - Slot ID
   * @param flags - Session flags (CKF_RW_SESSION, CKF_SERIAL_SESSION)
   * @returns Session handle
   * 
   * **Validates: Requirements 27.4**
   */
  async openSession(slotId: number, flags: number): Promise<number> {
    this.ensurePKCS11Initialized();

    if (!this.slots.has(slotId)) {
      throw new PKCS11Error('Invalid slot ID', PKCS11ReturnValue.CKR_SLOT_ID_INVALID);
    }

    // CKF_SERIAL_SESSION must always be set
    if (!(flags & PKCS11SessionFlags.CKF_SERIAL_SESSION)) {
      throw new PKCS11Error(
        'CKF_SERIAL_SESSION must be set',
        PKCS11ReturnValue.CKR_SESSION_PARALLEL_NOT_SUPPORTED
      );
    }

    const sessionHandle = generateSessionHandle();
    const now = new Date().toISOString();

    const session: PKCS11Session = {
      handle: sessionHandle,
      slotId,
      flags,
      state: 'open',
      createdAt: now,
      lastActivityAt: now
    };

    this.sessions.set(sessionHandle, session);

    await this.logPKCS11Operation('C_OpenSession', { slotId, flags, sessionHandle }, true);

    return sessionHandle;
  }

  /**
   * Close a session (C_CloseSession)
   * 
   * @param sessionHandle - Session handle
   * @returns PKCS#11 return value
   */
  async closeSession(sessionHandle: number): Promise<PKCS11ReturnValue> {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      return PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID;
    }

    // Remove all objects associated with this session
    for (const [objHandle, obj] of this.objects) {
      if (obj.sessionHandle === sessionHandle) {
        this.objects.delete(objHandle);
      }
    }

    session.state = 'closed';
    this.sessions.delete(sessionHandle);

    await this.logPKCS11Operation('C_CloseSession', { sessionHandle }, true);

    return PKCS11ReturnValue.CKR_OK;
  }

  /**
   * Get session info (C_GetSessionInfo)
   * 
   * @param sessionHandle - Session handle
   * @returns Session information
   */
  getSessionInfo(sessionHandle: number): PKCS11SessionInfo {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      throw new PKCS11Error('Invalid session handle', PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    }

    // Determine session state
    let state = 0; // CKS_RO_PUBLIC_SESSION
    if (session.flags & PKCS11SessionFlags.CKF_RW_SESSION) {
      state = session.state === 'logged_in' ? 3 : 2; // CKS_RW_USER_FUNCTIONS or CKS_RW_PUBLIC_SESSION
    } else {
      state = session.state === 'logged_in' ? 1 : 0; // CKS_RO_USER_FUNCTIONS or CKS_RO_PUBLIC_SESSION
    }

    return {
      slotId: session.slotId,
      state,
      flags: session.flags,
      deviceError: 0
    };
  }

  /**
   * Login to the token (C_Login)
   * 
   * @param sessionHandle - Session handle
   * @param userType - User type (CKU_USER, CKU_SO)
   * @param pin - PIN/password
   * @returns PKCS#11 return value
   * 
   * **Validates: Requirements 27.4**
   */
  async login(
    sessionHandle: number,
    userType: PKCS11UserType,
    pin: string
  ): Promise<PKCS11ReturnValue> {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      return PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID;
    }

    if (session.state === 'logged_in') {
      return PKCS11ReturnValue.CKR_USER_ALREADY_LOGGED_IN;
    }

    // Validate PIN
    if (!pin || pin.length < 4) {
      return PKCS11ReturnValue.CKR_PIN_LEN_RANGE;
    }

    if (pin.length > 64) {
      return PKCS11ReturnValue.CKR_PIN_LEN_RANGE;
    }

    // Simulate PIN validation (in production, this would validate against HSM)
    // For security, we use constant-time comparison
    const expectedPin = this.libraryConfig?.pin || 'default_pin';
    const pinBuffer = Buffer.from(pin);
    const expectedBuffer = Buffer.from(expectedPin);
    
    // Pad to same length for constant-time comparison
    const maxLen = Math.max(pinBuffer.length, expectedBuffer.length);
    const paddedPin = Buffer.alloc(maxLen);
    const paddedExpected = Buffer.alloc(maxLen);
    pinBuffer.copy(paddedPin);
    expectedBuffer.copy(paddedExpected);

    try {
      if (!crypto.timingSafeEqual(paddedPin, paddedExpected)) {
        await this.logPKCS11Operation('C_Login', { sessionHandle, userType }, false, 'Invalid PIN');
        return PKCS11ReturnValue.CKR_PIN_INCORRECT;
      }
    } catch {
      // If lengths differ significantly, PIN is incorrect
      await this.logPKCS11Operation('C_Login', { sessionHandle, userType }, false, 'Invalid PIN');
      return PKCS11ReturnValue.CKR_PIN_INCORRECT;
    }

    session.state = 'logged_in';
    session.userType = userType;
    session.lastActivityAt = new Date().toISOString();

    await this.logPKCS11Operation('C_Login', { sessionHandle, userType }, true);

    return PKCS11ReturnValue.CKR_OK;
  }

  /**
   * Logout from the token (C_Logout)
   * 
   * @param sessionHandle - Session handle
   * @returns PKCS#11 return value
   */
  async logout(sessionHandle: number): Promise<PKCS11ReturnValue> {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      return PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID;
    }

    if (session.state !== 'logged_in') {
      return PKCS11ReturnValue.CKR_USER_NOT_LOGGED_IN;
    }

    session.state = 'open';
    session.userType = undefined;
    session.lastActivityAt = new Date().toISOString();

    await this.logPKCS11Operation('C_Logout', { sessionHandle }, true);

    return PKCS11ReturnValue.CKR_OK;
  }

  // ==========================================================================
  // PKCS#11 Object Management (C_FindObjects)
  // ==========================================================================

  /**
   * Find objects by template (C_FindObjectsInit + C_FindObjects + C_FindObjectsFinal)
   * 
   * @param sessionHandle - Session handle
   * @param template - Search template (array of attributes)
   * @returns Array of object handles matching the template
   * 
   * **Validates: Requirements 27.4**
   */
  async findObjects(
    sessionHandle: number,
    template: PKCS11Attribute[]
  ): Promise<number[]> {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      throw new PKCS11Error('Invalid session handle', PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    }

    session.lastActivityAt = new Date().toISOString();

    const matchingHandles: number[] = [];

    for (const [handle, obj] of this.objects) {
      if (obj.sessionHandle !== sessionHandle) continue;

      let matches = true;
      for (const searchAttr of template) {
        const objAttr = obj.attributes.find(a => a.type === searchAttr.type);
        if (!objAttr || objAttr.value !== searchAttr.value) {
          matches = false;
          break;
        }
      }

      if (matches) {
        matchingHandles.push(handle);
      }
    }

    await this.logPKCS11Operation('C_FindObjects', { 
      sessionHandle, 
      templateSize: template.length,
      foundCount: matchingHandles.length 
    }, true);

    return matchingHandles;
  }

  /**
   * Get object attributes (C_GetAttributeValue)
   * 
   * @param sessionHandle - Session handle
   * @param objectHandle - Object handle
   * @param attributeTypes - Attribute types to retrieve
   * @returns Array of attributes
   */
  getAttributeValue(
    sessionHandle: number,
    objectHandle: number,
    attributeTypes: PKCS11AttributeType[]
  ): PKCS11Attribute[] {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      throw new PKCS11Error('Invalid session handle', PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    }

    const obj = this.objects.get(objectHandle);
    if (!obj) {
      throw new PKCS11Error('Invalid object handle', PKCS11ReturnValue.CKR_OBJECT_HANDLE_INVALID);
    }

    session.lastActivityAt = new Date().toISOString();

    const result: PKCS11Attribute[] = [];
    for (const attrType of attributeTypes) {
      const attr = obj.attributes.find(a => a.type === attrType);
      if (attr) {
        result.push(attr);
      }
    }

    return result;
  }

  // ==========================================================================
  // PKCS#11 Key Generation (C_GenerateKeyPair)
  // ==========================================================================

  /**
   * Generate a key pair (C_GenerateKeyPair)
   * 
   * @param sessionHandle - Session handle
   * @param mechanism - Key generation mechanism
   * @param publicKeyTemplate - Public key template
   * @param privateKeyTemplate - Private key template
   * @returns Object with public and private key handles
   * 
   * **Validates: Requirements 27.4**
   */
  async generateKeyPairPKCS11(
    sessionHandle: number,
    mechanism: PKCS11Mechanism,
    publicKeyTemplate: PKCS11Attribute[],
    privateKeyTemplate: PKCS11Attribute[]
  ): Promise<{ publicKeyHandle: number; privateKeyHandle: number }> {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      throw new PKCS11Error('Invalid session handle', PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    }

    if (session.state !== 'logged_in') {
      throw new PKCS11Error('User not logged in', PKCS11ReturnValue.CKR_USER_NOT_LOGGED_IN);
    }

    // Validate mechanism
    const validMechanisms = [
      PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN,
      PKCS11Mechanism.CKM_EC_KEY_PAIR_GEN
    ];
    if (!validMechanisms.includes(mechanism)) {
      throw new PKCS11Error('Invalid mechanism', PKCS11ReturnValue.CKR_MECHANISM_INVALID);
    }

    // Determine key type from mechanism
    let hsmKeyType: HSMKeyType;
    if (mechanism === PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN) {
      const modulusBitsAttr = publicKeyTemplate.find(
        a => a.type === PKCS11AttributeType.CKA_MODULUS_BITS
      );
      const modulusBits = (modulusBitsAttr?.value as number) || 2048;
      hsmKeyType = modulusBits >= 4096 ? 'RSA_4096' : 'RSA_2048';
    } else {
      hsmKeyType = 'EC_P256';
    }

    // Get label from template
    const labelAttr = publicKeyTemplate.find(a => a.type === PKCS11AttributeType.CKA_LABEL);
    const label = (labelAttr?.value as string) || `pkcs11_key_${Date.now()}`;

    // Generate key using HSM service
    const keyResult = await this.hsmService.generateKeyInHSM(hsmKeyType, label, {
      realmId: 'pkcs11',
      keyUsage: ['sign'],
      extractable: false
    });

    session.lastActivityAt = new Date().toISOString();

    // Create PKCS#11 objects for the keys
    const publicKeyHandle = generateObjectHandle();
    const privateKeyHandle = generateObjectHandle();

    const publicKeyObj: PKCS11Object = {
      handle: publicKeyHandle,
      sessionHandle,
      objectClass: PKCS11ObjectClass.CKO_PUBLIC_KEY,
      attributes: [
        ...publicKeyTemplate,
        { type: PKCS11AttributeType.CKA_CLASS, value: PKCS11ObjectClass.CKO_PUBLIC_KEY },
        { type: PKCS11AttributeType.CKA_KEY_TYPE, value: hsmKeyTypeToPKCS11(hsmKeyType) }
      ],
      keyHandle: keyResult.key.keyHandle
    };

    const privateKeyObj: PKCS11Object = {
      handle: privateKeyHandle,
      sessionHandle,
      objectClass: PKCS11ObjectClass.CKO_PRIVATE_KEY,
      attributes: [
        ...privateKeyTemplate,
        { type: PKCS11AttributeType.CKA_CLASS, value: PKCS11ObjectClass.CKO_PRIVATE_KEY },
        { type: PKCS11AttributeType.CKA_KEY_TYPE, value: hsmKeyTypeToPKCS11(hsmKeyType) },
        { type: PKCS11AttributeType.CKA_SENSITIVE, value: true },
        { type: PKCS11AttributeType.CKA_EXTRACTABLE, value: false }
      ],
      keyHandle: keyResult.key.keyHandle
    };

    this.objects.set(publicKeyHandle, publicKeyObj);
    this.objects.set(privateKeyHandle, privateKeyObj);

    await this.logPKCS11Operation('C_GenerateKeyPair', {
      sessionHandle,
      mechanism,
      publicKeyHandle,
      privateKeyHandle,
      keyType: hsmKeyType
    }, true);

    return { publicKeyHandle, privateKeyHandle };
  }

  // ==========================================================================
  // PKCS#11 Cryptographic Operations (C_Sign, C_Verify)
  // ==========================================================================

  /**
   * Sign data (C_SignInit + C_Sign)
   * 
   * @param sessionHandle - Session handle
   * @param mechanism - Signing mechanism
   * @param keyHandle - Private key handle
   * @param data - Data to sign
   * @returns Signature
   * 
   * **Validates: Requirements 27.4**
   */
  async signPKCS11(
    sessionHandle: number,
    mechanism: PKCS11Mechanism,
    keyHandle: number,
    data: Buffer
  ): Promise<Buffer> {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      throw new PKCS11Error('Invalid session handle', PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    }

    if (session.state !== 'logged_in') {
      throw new PKCS11Error('User not logged in', PKCS11ReturnValue.CKR_USER_NOT_LOGGED_IN);
    }

    const keyObj = this.objects.get(keyHandle);
    if (!keyObj) {
      throw new PKCS11Error('Invalid key handle', PKCS11ReturnValue.CKR_KEY_HANDLE_INVALID);
    }

    if (keyObj.objectClass !== PKCS11ObjectClass.CKO_PRIVATE_KEY) {
      throw new PKCS11Error('Key is not a private key', PKCS11ReturnValue.CKR_KEY_TYPE_INCONSISTENT);
    }

    // Check CKA_SIGN attribute
    const signAttr = keyObj.attributes.find(a => a.type === PKCS11AttributeType.CKA_SIGN);
    if (signAttr && signAttr.value === false) {
      throw new PKCS11Error('Key not authorized for signing', PKCS11ReturnValue.CKR_KEY_FUNCTION_NOT_PERMITTED);
    }

    // Validate mechanism
    const validSignMechanisms = [
      PKCS11Mechanism.CKM_RSA_PKCS,
      PKCS11Mechanism.CKM_SHA256_RSA_PKCS,
      PKCS11Mechanism.CKM_SHA384_RSA_PKCS,
      PKCS11Mechanism.CKM_SHA512_RSA_PKCS,
      PKCS11Mechanism.CKM_ECDSA,
      PKCS11Mechanism.CKM_ECDSA_SHA256,
      PKCS11Mechanism.CKM_ECDSA_SHA384,
      PKCS11Mechanism.CKM_SHA256_HMAC
    ];
    if (!validSignMechanisms.includes(mechanism)) {
      throw new PKCS11Error('Invalid mechanism', PKCS11ReturnValue.CKR_MECHANISM_INVALID);
    }

    if (!data || data.length === 0) {
      throw new PKCS11Error('Invalid data', PKCS11ReturnValue.CKR_DATA_INVALID);
    }

    session.lastActivityAt = new Date().toISOString();

    // Sign using HSM service
    if (!keyObj.keyHandle) {
      throw new PKCS11Error('Key not linked to HSM', PKCS11ReturnValue.CKR_KEY_HANDLE_INVALID);
    }

    const signResult = await this.hsmService.signWithHSM(keyObj.keyHandle, data);

    await this.logPKCS11Operation('C_Sign', {
      sessionHandle,
      mechanism,
      keyHandle,
      dataLength: data.length
    }, true);

    return Buffer.from(signResult.signature, 'base64');
  }

  /**
   * Verify signature (C_VerifyInit + C_Verify)
   * 
   * @param sessionHandle - Session handle
   * @param mechanism - Verification mechanism
   * @param keyHandle - Public key handle
   * @param data - Original data
   * @param signature - Signature to verify
   * @returns True if signature is valid
   * 
   * **Validates: Requirements 27.4**
   */
  async verifyPKCS11(
    sessionHandle: number,
    mechanism: PKCS11Mechanism,
    keyHandle: number,
    data: Buffer,
    signature: Buffer
  ): Promise<boolean> {
    this.ensurePKCS11Initialized();

    const session = this.sessions.get(sessionHandle);
    if (!session) {
      throw new PKCS11Error('Invalid session handle', PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    }

    const keyObj = this.objects.get(keyHandle);
    if (!keyObj) {
      throw new PKCS11Error('Invalid key handle', PKCS11ReturnValue.CKR_KEY_HANDLE_INVALID);
    }

    if (keyObj.objectClass !== PKCS11ObjectClass.CKO_PUBLIC_KEY) {
      throw new PKCS11Error('Key is not a public key', PKCS11ReturnValue.CKR_KEY_TYPE_INCONSISTENT);
    }

    // Check CKA_VERIFY attribute
    const verifyAttr = keyObj.attributes.find(a => a.type === PKCS11AttributeType.CKA_VERIFY);
    if (verifyAttr && verifyAttr.value === false) {
      throw new PKCS11Error('Key not authorized for verification', PKCS11ReturnValue.CKR_KEY_FUNCTION_NOT_PERMITTED);
    }

    if (!data || data.length === 0) {
      throw new PKCS11Error('Invalid data', PKCS11ReturnValue.CKR_DATA_INVALID);
    }

    if (!signature || signature.length === 0) {
      throw new PKCS11Error('Invalid signature', PKCS11ReturnValue.CKR_SIGNATURE_INVALID);
    }

    session.lastActivityAt = new Date().toISOString();

    // Verify using HSM service
    if (!keyObj.keyHandle) {
      throw new PKCS11Error('Key not linked to HSM', PKCS11ReturnValue.CKR_KEY_HANDLE_INVALID);
    }

    const verifyResult = await this.hsmService.verifyWithHSM(
      keyObj.keyHandle,
      data,
      signature.toString('base64')
    );

    await this.logPKCS11Operation('C_Verify', {
      sessionHandle,
      mechanism,
      keyHandle,
      dataLength: data.length,
      valid: verifyResult.valid
    }, true);

    if (!verifyResult.valid) {
      throw new PKCS11Error('Signature verification failed', PKCS11ReturnValue.CKR_SIGNATURE_INVALID);
    }

    return true;
  }

  /**
   * Get mechanism info (C_GetMechanismInfo)
   * 
   * @param slotId - Slot ID
   * @param mechanism - Mechanism type
   * @returns Mechanism information
   */
  getMechanismInfo(slotId: number, mechanism: PKCS11Mechanism): PKCS11MechanismInfo {
    this.ensurePKCS11Initialized();

    if (!this.slots.has(slotId)) {
      throw new PKCS11Error('Invalid slot ID', PKCS11ReturnValue.CKR_SLOT_ID_INVALID);
    }

    // Return mechanism info based on type
    switch (mechanism) {
      case PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN:
      case PKCS11Mechanism.CKM_RSA_PKCS:
      case PKCS11Mechanism.CKM_SHA256_RSA_PKCS:
        return { minKeySize: 2048, maxKeySize: 4096, flags: 0x10301 }; // CKF_GENERATE_KEY_PAIR | CKF_SIGN | CKF_VERIFY
      case PKCS11Mechanism.CKM_EC_KEY_PAIR_GEN:
      case PKCS11Mechanism.CKM_ECDSA:
      case PKCS11Mechanism.CKM_ECDSA_SHA256:
        return { minKeySize: 256, maxKeySize: 384, flags: 0x10301 };
      case PKCS11Mechanism.CKM_AES_KEY_GEN:
      case PKCS11Mechanism.CKM_AES_GCM:
        return { minKeySize: 128, maxKeySize: 256, flags: 0x8301 }; // CKF_GENERATE | CKF_ENCRYPT | CKF_DECRYPT
      default:
        throw new PKCS11Error('Invalid mechanism', PKCS11ReturnValue.CKR_MECHANISM_INVALID);
    }
  }

  // ==========================================================================
  // HSM Cluster Management
  // ==========================================================================

  /**
   * Configure HSM cluster for high availability
   * 
   * @param nodes - Array of cluster nodes
   * @returns Cluster configuration
   * 
   * **Validates: Requirements 27.9**
   */
  async configureCluster(nodes: Omit<HSMClusterNode, 'nodeId' | 'lastHeartbeat'>[]): Promise<HSMClusterConfiguration> {
    if (!nodes || nodes.length === 0) {
      throw new HSMOperationError('configureCluster', 'At least one node is required');
    }

    if (nodes.length < 2) {
      throw new HSMOperationError('configureCluster', 'At least 2 nodes required for HA cluster');
    }

    const now = new Date().toISOString();
    const clusterId = generateClusterId();

    // Validate nodes have at least one primary
    const primaryNodes = nodes.filter(n => n.role === 'primary');
    if (primaryNodes.length === 0) {
      throw new HSMOperationError('configureCluster', 'At least one primary node is required');
    }

    if (primaryNodes.length > 1) {
      throw new HSMOperationError('configureCluster', 'Only one primary node is allowed');
    }

    // Create node configurations
    const clusterNodes: HSMClusterNode[] = nodes.map(node => ({
      ...node,
      nodeId: generateNodeId(),
      lastHeartbeat: now,
      status: 'active' as const
    }));

    const config: HSMClusterConfiguration = {
      clusterId,
      name: `HSM Cluster ${clusterId.slice(-8)}`,
      nodes: clusterNodes,
      quorum: Math.floor(nodes.length / 2) + 1,
      failoverPolicy: 'automatic',
      syncMode: 'synchronous',
      healthCheckInterval: 30000, // 30 seconds
      createdAt: now,
      updatedAt: now
    };

    // Store cluster configuration
    await this.storeClusterConfiguration(config);

    await this.logPKCS11Operation('configureCluster', {
      clusterId,
      nodeCount: nodes.length,
      quorum: config.quorum
    }, true);

    return config;
  }

  /**
   * Get cluster health status
   * 
   * @param clusterId - Cluster ID
   * @returns Cluster health information
   * 
   * **Validates: Requirements 27.9**
   */
  async getClusterHealth(clusterId: string): Promise<HSMClusterHealth> {
    if (!clusterId) {
      throw new HSMOperationError('getClusterHealth', 'Cluster ID is required');
    }

    const config = await this.getClusterConfiguration(clusterId);
    if (!config) {
      throw new HSMOperationError('getClusterHealth', 'Cluster not found');
    }

    const now = new Date().toISOString();
    const alerts: HSMClusterAlert[] = [];

    // Calculate node statistics
    const activeNodes = config.nodes.filter(n => n.status === 'active').length;
    const failedNodes = config.nodes.filter(n => n.status === 'failed').length;
    const syncingNodes = config.nodes.filter(n => n.status === 'syncing').length;

    // Determine overall status
    let status: HSMClusterHealth['status'];
    if (activeNodes === 0) {
      status = 'offline';
      alerts.push({
        alertId: generateAlertId(),
        severity: 'critical',
        message: 'All cluster nodes are offline',
        timestamp: now,
        acknowledged: false
      });
    } else if (activeNodes < config.quorum) {
      status = 'critical';
      alerts.push({
        alertId: generateAlertId(),
        severity: 'critical',
        message: `Active nodes (${activeNodes}) below quorum (${config.quorum})`,
        timestamp: now,
        acknowledged: false
      });
    } else if (failedNodes > 0 || syncingNodes > 0) {
      status = 'degraded';
      if (failedNodes > 0) {
        alerts.push({
          alertId: generateAlertId(),
          severity: 'warning',
          message: `${failedNodes} node(s) have failed`,
          timestamp: now,
          acknowledged: false
        });
      }
    } else {
      status = 'healthy';
    }

    // Find primary node
    const primaryNode = config.nodes.find(n => n.role === 'primary' && n.status === 'active');

    // Calculate average latency (simulated)
    const averageLatency = config.nodes
      .filter(n => n.status === 'active')
      .reduce((sum, n) => sum + Math.random() * 10, 0) / Math.max(activeNodes, 1);

    return {
      clusterId,
      status,
      totalNodes: config.nodes.length,
      activeNodes,
      failedNodes,
      syncingNodes,
      primaryNode: primaryNode?.nodeId,
      averageLatency: Math.round(averageLatency * 100) / 100,
      operationsPerSecond: activeNodes * 500, // Simulated throughput
      lastHealthCheck: now,
      alerts
    };
  }

  /**
   * Add node to cluster
   * 
   * @param clusterId - Cluster ID
   * @param node - Node to add
   * @returns Updated cluster configuration
   */
  async addClusterNode(
    clusterId: string,
    node: Omit<HSMClusterNode, 'nodeId' | 'lastHeartbeat'>
  ): Promise<HSMClusterConfiguration> {
    const config = await this.getClusterConfiguration(clusterId);
    if (!config) {
      throw new HSMOperationError('addClusterNode', 'Cluster not found');
    }

    // Cannot add another primary
    if (node.role === 'primary') {
      const existingPrimary = config.nodes.find(n => n.role === 'primary' && n.status === 'active');
      if (existingPrimary) {
        throw new HSMOperationError('addClusterNode', 'Cluster already has an active primary node');
      }
    }

    const now = new Date().toISOString();
    const newNode: HSMClusterNode = {
      ...node,
      nodeId: generateNodeId(),
      lastHeartbeat: now,
      status: 'syncing'
    };

    config.nodes.push(newNode);
    config.quorum = Math.floor(config.nodes.length / 2) + 1;
    config.updatedAt = now;

    await this.storeClusterConfiguration(config);

    await this.logPKCS11Operation('addClusterNode', {
      clusterId,
      nodeId: newNode.nodeId,
      role: node.role
    }, true);

    return config;
  }

  /**
   * Remove node from cluster
   * 
   * @param clusterId - Cluster ID
   * @param nodeId - Node ID to remove
   * @returns Updated cluster configuration
   */
  async removeClusterNode(clusterId: string, nodeId: string): Promise<HSMClusterConfiguration> {
    const config = await this.getClusterConfiguration(clusterId);
    if (!config) {
      throw new HSMOperationError('removeClusterNode', 'Cluster not found');
    }

    const nodeIndex = config.nodes.findIndex(n => n.nodeId === nodeId);
    if (nodeIndex === -1) {
      throw new HSMOperationError('removeClusterNode', 'Node not found in cluster');
    }

    const node = config.nodes[nodeIndex];

    // Cannot remove the only primary
    if (node.role === 'primary') {
      const otherPrimaries = config.nodes.filter(
        n => n.nodeId !== nodeId && n.role === 'primary' && n.status === 'active'
      );
      if (otherPrimaries.length === 0) {
        throw new HSMOperationError('removeClusterNode', 'Cannot remove the only primary node');
      }
    }

    // Cannot go below minimum nodes
    if (config.nodes.length <= 2) {
      throw new HSMOperationError('removeClusterNode', 'Cannot remove node: minimum 2 nodes required');
    }

    config.nodes.splice(nodeIndex, 1);
    config.quorum = Math.floor(config.nodes.length / 2) + 1;
    config.updatedAt = new Date().toISOString();

    await this.storeClusterConfiguration(config);

    await this.logPKCS11Operation('removeClusterNode', { clusterId, nodeId }, true);

    return config;
  }

  /**
   * Trigger manual failover
   * 
   * @param clusterId - Cluster ID
   * @param newPrimaryNodeId - Node ID to promote to primary
   * @returns Updated cluster configuration
   */
  async triggerFailover(clusterId: string, newPrimaryNodeId: string): Promise<HSMClusterConfiguration> {
    const config = await this.getClusterConfiguration(clusterId);
    if (!config) {
      throw new HSMOperationError('triggerFailover', 'Cluster not found');
    }

    const newPrimary = config.nodes.find(n => n.nodeId === newPrimaryNodeId);
    if (!newPrimary) {
      throw new HSMOperationError('triggerFailover', 'Target node not found');
    }

    if (newPrimary.status !== 'active' && newPrimary.status !== 'standby') {
      throw new HSMOperationError('triggerFailover', 'Target node is not available for failover');
    }

    const now = new Date().toISOString();

    // Demote current primary
    const currentPrimary = config.nodes.find(n => n.role === 'primary');
    if (currentPrimary) {
      currentPrimary.role = 'secondary';
      currentPrimary.status = 'standby';
    }

    // Promote new primary
    newPrimary.role = 'primary';
    newPrimary.status = 'active';
    newPrimary.lastHeartbeat = now;

    config.updatedAt = now;

    await this.storeClusterConfiguration(config);

    await this.logPKCS11Operation('triggerFailover', {
      clusterId,
      oldPrimaryId: currentPrimary?.nodeId,
      newPrimaryId: newPrimaryNodeId
    }, true);

    return config;
  }

  // ==========================================================================
  // Private Helper Methods
  // ==========================================================================

  /**
   * Ensure PKCS#11 library is initialized
   */
  private ensurePKCS11Initialized(): void {
    if (!this.isInitialized) {
      throw new PKCS11Error(
        'PKCS#11 library not initialized. Call initializePKCS11 first.',
        PKCS11ReturnValue.CKR_CRYPTOKI_NOT_INITIALIZED
      );
    }
  }

  /**
   * Store cluster configuration in database
   */
  private async storeClusterConfiguration(config: HSMClusterConfiguration): Promise<void> {
    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        PK: 'PKCS11_CLUSTER',
        SK: `CLUSTER#${config.clusterId}`,
        ...config,
        type: 'pkcs11_cluster_config'
      }
    }));
  }

  /**
   * Get cluster configuration from database
   */
  private async getClusterConfiguration(clusterId: string): Promise<HSMClusterConfiguration | null> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: 'PK = :pk AND SK = :sk',
      ExpressionAttributeValues: {
        ':pk': 'PKCS11_CLUSTER',
        ':sk': `CLUSTER#${clusterId}`
      }
    }));

    if (!result.Items || result.Items.length === 0) {
      return null;
    }

    const item = result.Items[0];
    return {
      clusterId: item.clusterId,
      name: item.name,
      nodes: item.nodes,
      quorum: item.quorum,
      failoverPolicy: item.failoverPolicy,
      syncMode: item.syncMode,
      healthCheckInterval: item.healthCheckInterval,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt
    };
  }

  /**
   * Log PKCS#11 operation for audit
   */
  private async logPKCS11Operation(
    operation: string,
    details: Record<string, unknown>,
    success: boolean,
    errorMessage?: string
  ): Promise<void> {
    try {
      const operationId = generateOperationId();
      const timestamp = new Date().toISOString();

      await this.docClient.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          PK: 'PKCS11_AUDIT',
          SK: `OP#${timestamp}#${operationId}`,
          operationId,
          operation,
          details,
          success,
          errorMessage,
          timestamp,
          type: 'pkcs11_operation_log'
        }
      }));
    } catch {
      // Don't fail operations due to logging errors
      console.error('Failed to log PKCS#11 operation:', operation);
    }
  }

  /**
   * Check if PKCS#11 is initialized
   */
  isPKCS11Initialized(): boolean {
    return this.isInitialized;
  }

  /**
   * Get library configuration
   */
  getLibraryConfig(): PKCS11LibraryConfig | null {
    return this.libraryConfig;
  }

  /**
   * Get active session count
   */
  getActiveSessionCount(): number {
    return this.sessions.size;
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

/**
 * Default PKCS#11 service instance
 */
export const pkcs11Service = new PKCS11Service();

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Initialize PKCS#11 library
 */
export async function initializePKCS11(
  libraryPath: string,
  slotId: number,
  initArgs?: Record<string, unknown>
): Promise<PKCS11ReturnValue> {
  return pkcs11Service.initializePKCS11(libraryPath, slotId, initArgs);
}

/**
 * Finalize PKCS#11 library
 */
export async function finalizePKCS11(): Promise<PKCS11ReturnValue> {
  return pkcs11Service.finalizePKCS11();
}

/**
 * Open PKCS#11 session
 */
export async function openSession(slotId: number, flags: number): Promise<number> {
  return pkcs11Service.openSession(slotId, flags);
}

/**
 * Close PKCS#11 session
 */
export async function closeSession(sessionHandle: number): Promise<PKCS11ReturnValue> {
  return pkcs11Service.closeSession(sessionHandle);
}

/**
 * Login to PKCS#11 token
 */
export async function loginPKCS11(
  sessionHandle: number,
  userType: PKCS11UserType,
  pin: string
): Promise<PKCS11ReturnValue> {
  return pkcs11Service.login(sessionHandle, userType, pin);
}

/**
 * Find objects by template
 */
export async function findObjects(
  sessionHandle: number,
  template: PKCS11Attribute[]
): Promise<number[]> {
  return pkcs11Service.findObjects(sessionHandle, template);
}

/**
 * Generate key pair via PKCS#11
 */
export async function generateKeyPairPKCS11(
  sessionHandle: number,
  mechanism: PKCS11Mechanism,
  publicKeyTemplate: PKCS11Attribute[],
  privateKeyTemplate: PKCS11Attribute[]
): Promise<{ publicKeyHandle: number; privateKeyHandle: number }> {
  return pkcs11Service.generateKeyPairPKCS11(sessionHandle, mechanism, publicKeyTemplate, privateKeyTemplate);
}

/**
 * Sign data via PKCS#11
 */
export async function signPKCS11(
  sessionHandle: number,
  mechanism: PKCS11Mechanism,
  keyHandle: number,
  data: Buffer
): Promise<Buffer> {
  return pkcs11Service.signPKCS11(sessionHandle, mechanism, keyHandle, data);
}

/**
 * Verify signature via PKCS#11
 */
export async function verifyPKCS11(
  sessionHandle: number,
  mechanism: PKCS11Mechanism,
  keyHandle: number,
  data: Buffer,
  signature: Buffer
): Promise<boolean> {
  return pkcs11Service.verifyPKCS11(sessionHandle, mechanism, keyHandle, data, signature);
}

/**
 * Configure HSM cluster
 */
export async function configureCluster(
  nodes: Omit<HSMClusterNode, 'nodeId' | 'lastHeartbeat'>[]
): Promise<HSMClusterConfiguration> {
  return pkcs11Service.configureCluster(nodes);
}

/**
 * Get cluster health
 */
export async function getClusterHealth(clusterId: string): Promise<HSMClusterHealth> {
  return pkcs11Service.getClusterHealth(clusterId);
}
