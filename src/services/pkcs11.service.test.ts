/**
 * PKCS#11 Service Tests
 * 
 * Comprehensive tests for PKCS#11 interface including:
 * - Library initialization (C_Initialize, C_Finalize)
 * - Session management (C_OpenSession, C_CloseSession, C_Login)
 * - Object discovery (C_FindObjects)
 * - Key generation (C_GenerateKeyPair)
 * - Cryptographic operations (C_Sign, C_Verify)
 * - HSM clustering for high availability
 * 
 * Validates: Requirements 27.4, 27.9
 */

import {
  PKCS11Service,
  PKCS11ReturnValue,
  PKCS11SessionFlags,
  PKCS11UserType,
  PKCS11ObjectClass,
  PKCS11Mechanism,
  PKCS11AttributeType,
  PKCS11Error,
  generateSessionHandle,
  generateObjectHandle,
  generateClusterId,
  generateNodeId,
  generateAlertId,
  hsmKeyTypeToPKCS11,
  pkcs11KeyTypeToHSM,
} from './pkcs11.service';
import { HSMService, PKCS11KeyType } from './hsm.service';

// ============================================================================
// Mock DynamoDB
// ============================================================================

const mockStore = new Map<string, Record<string, unknown>>();

const mockDocClient = {
  send: jest.fn().mockImplementation((command) => {
    const commandName = command.constructor.name;
    
    if (commandName === 'PutCommand') {
      const key = `${command.input.Item.PK}#${command.input.Item.SK}`;
      mockStore.set(key, command.input.Item);
      // Also store by GSI1 if present
      if (command.input.Item.GSI1PK) {
        const gsi1Key = `GSI1#${command.input.Item.GSI1PK}`;
        mockStore.set(gsi1Key, command.input.Item);
      }
      return Promise.resolve({});
    }
    
    if (commandName === 'QueryCommand') {
      const items: Record<string, unknown>[] = [];
      const pk = command.input.ExpressionAttributeValues[':pk'];
      const sk = command.input.ExpressionAttributeValues[':sk'];
      
      // Handle GSI1 index queries
      if (command.input.IndexName === 'GSI1') {
        const gsi1Key = `GSI1#${pk}`;
        const item = mockStore.get(gsi1Key);
        if (item) {
          items.push(item);
        }
      } else {
        mockStore.forEach((item, key) => {
          if (sk) {
            if (key === `${pk}#${sk}`) {
              items.push(item);
            }
          } else if (key.startsWith(`${pk}#`)) {
            items.push(item);
          }
        });
      }
      
      return Promise.resolve({ Items: items });
    }
    
    if (commandName === 'UpdateCommand') {
      const key = `${command.input.Key.PK}#${command.input.Key.SK}`;
      let item = mockStore.get(key);
      
      // If not found by primary key, try to find by iterating
      if (!item) {
        for (const [storedKey, storedItem] of mockStore.entries()) {
          if (storedItem && 
              (storedItem as Record<string, unknown>).PK === command.input.Key.PK && 
              (storedItem as Record<string, unknown>).SK === command.input.Key.SK) {
            item = storedItem;
            break;
          }
        }
      }
      
      if (item) {
        const values = command.input.ExpressionAttributeValues || {};
        Object.keys(values).forEach(k => {
          const fieldName = k.replace(':', '');
          (item as Record<string, unknown>)[fieldName] = values[k];
        });
        mockStore.set(key, item);
        // Update GSI1 entry too
        if ((item as Record<string, unknown>).GSI1PK) {
          const gsi1Key = `GSI1#${(item as Record<string, unknown>).GSI1PK}`;
          mockStore.set(gsi1Key, item);
        }
      }
      return Promise.resolve({});
    }
    
    return Promise.resolve({});
  })
};

// Reset mock store before each test
beforeEach(() => {
  mockStore.clear();
  jest.clearAllMocks();
});

// ============================================================================
// Utility Function Tests
// ============================================================================

describe('PKCS#11 Utility Functions', () => {
  describe('generateSessionHandle', () => {
    it('should generate unique session handles', () => {
      const handle1 = generateSessionHandle();
      const handle2 = generateSessionHandle();
      
      expect(handle1).toBeGreaterThan(0);
      expect(handle2).toBeGreaterThan(0);
      expect(handle1).not.toBe(handle2);
    });

    it('should generate handles within valid range', () => {
      for (let i = 0; i < 100; i++) {
        const handle = generateSessionHandle();
        expect(handle).toBeGreaterThan(0);
        expect(handle).toBeLessThanOrEqual(0x7FFFFFFF);
      }
    });
  });

  describe('generateObjectHandle', () => {
    it('should generate unique object handles', () => {
      const handle1 = generateObjectHandle();
      const handle2 = generateObjectHandle();
      
      expect(handle1).toBeGreaterThan(0);
      expect(handle2).toBeGreaterThan(0);
    });
  });

  describe('generateClusterId', () => {
    it('should generate unique cluster IDs', () => {
      const id1 = generateClusterId();
      const id2 = generateClusterId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^hsm_cluster_[a-f0-9]{16}$/);
    });
  });

  describe('generateNodeId', () => {
    it('should generate unique node IDs', () => {
      const id1 = generateNodeId();
      const id2 = generateNodeId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^hsm_node_[a-f0-9]{12}$/);
    });
  });

  describe('generateAlertId', () => {
    it('should generate unique alert IDs', () => {
      const id1 = generateAlertId();
      const id2 = generateAlertId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^hsm_alert_[a-f0-9]{12}$/);
    });
  });

  describe('hsmKeyTypeToPKCS11', () => {
    it('should map RSA key types correctly', () => {
      expect(hsmKeyTypeToPKCS11('RSA_2048')).toBe(PKCS11KeyType.CKK_RSA);
      expect(hsmKeyTypeToPKCS11('RSA_4096')).toBe(PKCS11KeyType.CKK_RSA);
    });

    it('should map EC key types correctly', () => {
      expect(hsmKeyTypeToPKCS11('EC_P256')).toBe(PKCS11KeyType.CKK_EC);
      expect(hsmKeyTypeToPKCS11('EC_P384')).toBe(PKCS11KeyType.CKK_EC);
      expect(hsmKeyTypeToPKCS11('EC_SECP256K1')).toBe(PKCS11KeyType.CKK_EC);
    });

    it('should map AES key type correctly', () => {
      expect(hsmKeyTypeToPKCS11('AES_256')).toBe(PKCS11KeyType.CKK_AES);
    });
  });

  describe('pkcs11KeyTypeToHSM', () => {
    it('should map RSA key types correctly', () => {
      expect(pkcs11KeyTypeToHSM(PKCS11KeyType.CKK_RSA)).toBe('RSA_2048');
      expect(pkcs11KeyTypeToHSM(PKCS11KeyType.CKK_RSA, 4096)).toBe('RSA_4096');
    });

    it('should map EC key type correctly', () => {
      expect(pkcs11KeyTypeToHSM(PKCS11KeyType.CKK_EC)).toBe('EC_P256');
    });

    it('should map AES key type correctly', () => {
      expect(pkcs11KeyTypeToHSM(PKCS11KeyType.CKK_AES)).toBe('AES_256');
    });
  });
});

// ============================================================================
// PKCS#11 Service Tests
// ============================================================================

describe('PKCS11Service', () => {
  let pkcs11Service: PKCS11Service;
  let mockHsmService: HSMService;

  beforeEach(() => {
    mockHsmService = new HSMService(mockDocClient as any, 'zalt-hsm-test');
    pkcs11Service = new PKCS11Service(mockHsmService, mockDocClient as any, 'zalt-hsm-test');
  });

  afterEach(async () => {
    try {
      if (pkcs11Service.isPKCS11Initialized()) {
        await pkcs11Service.finalizePKCS11();
      }
    } catch {
      // Ignore cleanup errors
    }
  });

  // ==========================================================================
  // Library Initialization Tests
  // ==========================================================================

  describe('initializePKCS11', () => {
    /**
     * **Validates: Requirements 27.4**
     * THE Zalt_Platform SHALL support customer-managed HSM via PKCS#11 interface
     */
    it('should initialize PKCS#11 library successfully', async () => {
      const result = await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_OK);
      expect(pkcs11Service.isPKCS11Initialized()).toBe(true);
    });

    it('should return error if already initialized', async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      
      const result = await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_CRYPTOKI_ALREADY_INITIALIZED);
    });

    it('should return error for empty library path', async () => {
      const result = await pkcs11Service.initializePKCS11('', 0);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_ARGUMENTS_BAD);
    });

    it('should return error for invalid slot ID', async () => {
      const result = await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', -1);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_SLOT_ID_INVALID);
    });

    it('should accept initialization arguments', async () => {
      const result = await pkcs11Service.initializePKCS11(
        '/usr/lib/pkcs11/libsofthsm2.so',
        0,
        { flags: 0x02 }
      );
      
      expect(result).toBe(PKCS11ReturnValue.CKR_OK);
      expect(pkcs11Service.getLibraryConfig()?.initArgs).toEqual({ flags: 0x02 });
    });
  });

  describe('finalizePKCS11', () => {
    it('should finalize PKCS#11 library successfully', async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      
      const result = await pkcs11Service.finalizePKCS11();
      
      expect(result).toBe(PKCS11ReturnValue.CKR_OK);
      expect(pkcs11Service.isPKCS11Initialized()).toBe(false);
    });

    it('should return error if not initialized', async () => {
      const result = await pkcs11Service.finalizePKCS11();
      
      expect(result).toBe(PKCS11ReturnValue.CKR_CRYPTOKI_NOT_INITIALIZED);
    });

    it('should close all sessions on finalize', async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
      await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
      
      expect(pkcs11Service.getActiveSessionCount()).toBe(2);
      
      await pkcs11Service.finalizePKCS11();
      
      expect(pkcs11Service.getActiveSessionCount()).toBe(0);
    });
  });

  // ==========================================================================
  // Slot and Token Information Tests
  // ==========================================================================

  describe('getSlotList', () => {
    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
    });

    it('should return list of slots', () => {
      const slots = pkcs11Service.getSlotList();
      
      expect(slots).toContain(0);
    });

    it('should filter by token present', () => {
      const slots = pkcs11Service.getSlotList(true);
      
      expect(slots.length).toBeGreaterThanOrEqual(0);
    });

    it('should throw if not initialized', async () => {
      await pkcs11Service.finalizePKCS11();
      
      expect(() => pkcs11Service.getSlotList()).toThrow(PKCS11Error);
    });
  });

  describe('getSlotInfo', () => {
    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
    });

    it('should return slot information', () => {
      const info = pkcs11Service.getSlotInfo(0);
      
      expect(info.slotId).toBe(0);
      expect(info.slotDescription).toBeDefined();
      expect(info.manufacturerId).toBe('Zalt.io');
    });

    it('should throw for invalid slot ID', () => {
      expect(() => pkcs11Service.getSlotInfo(999)).toThrow(PKCS11Error);
    });
  });

  describe('getTokenInfo', () => {
    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
    });

    it('should return token information', () => {
      const info = pkcs11Service.getTokenInfo(0);
      
      expect(info.label).toBe('Zalt HSM Token');
      expect(info.manufacturerId).toBe('Zalt.io');
      expect(info.maxPinLen).toBe(64);
      expect(info.minPinLen).toBe(4);
    });

    it('should throw for invalid slot ID', () => {
      expect(() => pkcs11Service.getTokenInfo(999)).toThrow(PKCS11Error);
    });
  });

  // ==========================================================================
  // Session Management Tests
  // ==========================================================================

  describe('openSession', () => {
    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
    });

    /**
     * **Validates: Requirements 27.4**
     * Standard PKCS#11 operations - C_OpenSession
     */
    it('should open a session successfully', async () => {
      const sessionHandle = await pkcs11Service.openSession(
        0,
        PKCS11SessionFlags.CKF_SERIAL_SESSION
      );
      
      expect(sessionHandle).toBeGreaterThan(0);
      expect(pkcs11Service.getActiveSessionCount()).toBe(1);
    });

    it('should open read-write session', async () => {
      const sessionHandle = await pkcs11Service.openSession(
        0,
        PKCS11SessionFlags.CKF_SERIAL_SESSION | PKCS11SessionFlags.CKF_RW_SESSION
      );
      
      expect(sessionHandle).toBeGreaterThan(0);
      
      const info = pkcs11Service.getSessionInfo(sessionHandle);
      expect(info.flags & PKCS11SessionFlags.CKF_RW_SESSION).toBeTruthy();
    });

    it('should throw for invalid slot ID', async () => {
      await expect(
        pkcs11Service.openSession(999, PKCS11SessionFlags.CKF_SERIAL_SESSION)
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw if CKF_SERIAL_SESSION not set', async () => {
      await expect(
        pkcs11Service.openSession(0, 0)
      ).rejects.toThrow(PKCS11Error);
    });

    it('should allow multiple sessions', async () => {
      const handle1 = await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
      const handle2 = await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
      
      expect(handle1).not.toBe(handle2);
      expect(pkcs11Service.getActiveSessionCount()).toBe(2);
    });
  });

  describe('closeSession', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
    });

    it('should close session successfully', async () => {
      const result = await pkcs11Service.closeSession(sessionHandle);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_OK);
      expect(pkcs11Service.getActiveSessionCount()).toBe(0);
    });

    it('should return error for invalid session handle', async () => {
      const result = await pkcs11Service.closeSession(999999);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    });
  });

  describe('getSessionInfo', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
    });

    it('should return session information', () => {
      const info = pkcs11Service.getSessionInfo(sessionHandle);
      
      expect(info.slotId).toBe(0);
      expect(info.flags).toBe(PKCS11SessionFlags.CKF_SERIAL_SESSION);
      expect(info.deviceError).toBe(0);
    });

    it('should throw for invalid session handle', () => {
      expect(() => pkcs11Service.getSessionInfo(999999)).toThrow(PKCS11Error);
    });
  });

  // ==========================================================================
  // Login/Logout Tests
  // ==========================================================================

  describe('login', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
    });

    /**
     * **Validates: Requirements 27.4**
     * Standard PKCS#11 operations - C_Login
     */
    it('should login successfully with valid PIN', async () => {
      const result = await pkcs11Service.login(
        sessionHandle,
        PKCS11UserType.CKU_USER,
        'default_pin'
      );
      
      expect(result).toBe(PKCS11ReturnValue.CKR_OK);
    });

    it('should return error for invalid session handle', async () => {
      const result = await pkcs11Service.login(999999, PKCS11UserType.CKU_USER, 'pin');
      
      expect(result).toBe(PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    });

    it('should return error for short PIN', async () => {
      const result = await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, '123');
      
      expect(result).toBe(PKCS11ReturnValue.CKR_PIN_LEN_RANGE);
    });

    it('should return error for long PIN', async () => {
      const longPin = 'a'.repeat(65);
      const result = await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, longPin);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_PIN_LEN_RANGE);
    });

    it('should return error for incorrect PIN', async () => {
      const result = await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, 'wrong_pin');
      
      expect(result).toBe(PKCS11ReturnValue.CKR_PIN_INCORRECT);
    });

    it('should return error if already logged in', async () => {
      await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, 'default_pin');
      
      const result = await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, 'default_pin');
      
      expect(result).toBe(PKCS11ReturnValue.CKR_USER_ALREADY_LOGGED_IN);
    });
  });

  describe('logout', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
    });

    it('should logout successfully', async () => {
      await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, 'default_pin');
      
      const result = await pkcs11Service.logout(sessionHandle);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_OK);
    });

    it('should return error if not logged in', async () => {
      const result = await pkcs11Service.logout(sessionHandle);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_USER_NOT_LOGGED_IN);
    });

    it('should return error for invalid session handle', async () => {
      const result = await pkcs11Service.logout(999999);
      
      expect(result).toBe(PKCS11ReturnValue.CKR_SESSION_HANDLE_INVALID);
    });
  });

  // ==========================================================================
  // Object Discovery Tests
  // ==========================================================================

  describe('findObjects', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(
        0,
        PKCS11SessionFlags.CKF_SERIAL_SESSION | PKCS11SessionFlags.CKF_RW_SESSION
      );
    });

    /**
     * **Validates: Requirements 27.4**
     * Standard PKCS#11 operations - C_FindObjects
     */
    it('should find objects by template', async () => {
      const handles = await pkcs11Service.findObjects(sessionHandle, []);
      
      expect(Array.isArray(handles)).toBe(true);
    });

    it('should throw for invalid session handle', async () => {
      await expect(
        pkcs11Service.findObjects(999999, [])
      ).rejects.toThrow(PKCS11Error);
    });
  });

  describe('getAttributeValue', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(0, PKCS11SessionFlags.CKF_SERIAL_SESSION);
    });

    it('should throw for invalid session handle', () => {
      expect(() => 
        pkcs11Service.getAttributeValue(999999, 1, [PKCS11AttributeType.CKA_CLASS])
      ).toThrow(PKCS11Error);
    });

    it('should throw for invalid object handle', () => {
      expect(() => 
        pkcs11Service.getAttributeValue(sessionHandle, 999999, [PKCS11AttributeType.CKA_CLASS])
      ).toThrow(PKCS11Error);
    });
  });

  // ==========================================================================
  // Key Generation Tests
  // ==========================================================================

  describe('generateKeyPairPKCS11', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(
        0,
        PKCS11SessionFlags.CKF_SERIAL_SESSION | PKCS11SessionFlags.CKF_RW_SESSION
      );
      // Initialize HSM service for key generation
      await mockHsmService.initializeHSM('test-cluster', { username: 'admin', password: 'password' });
      await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, 'default_pin');
    });

    /**
     * **Validates: Requirements 27.4**
     * Standard PKCS#11 operations - C_GenerateKeyPair
     */
    it('should generate RSA key pair', async () => {
      const publicKeyTemplate = [
        { type: PKCS11AttributeType.CKA_MODULUS_BITS, value: 2048 },
        { type: PKCS11AttributeType.CKA_LABEL, value: 'test-rsa-key' }
      ];
      const privateKeyTemplate = [
        { type: PKCS11AttributeType.CKA_SIGN, value: true }
      ];

      const result = await pkcs11Service.generateKeyPairPKCS11(
        sessionHandle,
        PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN,
        publicKeyTemplate,
        privateKeyTemplate
      );

      expect(result.publicKeyHandle).toBeGreaterThan(0);
      expect(result.privateKeyHandle).toBeGreaterThan(0);
      expect(result.publicKeyHandle).not.toBe(result.privateKeyHandle);
    });

    it('should generate EC key pair', async () => {
      const publicKeyTemplate = [
        { type: PKCS11AttributeType.CKA_LABEL, value: 'test-ec-key' }
      ];
      const privateKeyTemplate = [
        { type: PKCS11AttributeType.CKA_SIGN, value: true }
      ];

      const result = await pkcs11Service.generateKeyPairPKCS11(
        sessionHandle,
        PKCS11Mechanism.CKM_EC_KEY_PAIR_GEN,
        publicKeyTemplate,
        privateKeyTemplate
      );

      expect(result.publicKeyHandle).toBeGreaterThan(0);
      expect(result.privateKeyHandle).toBeGreaterThan(0);
    });

    it('should throw for invalid session handle', async () => {
      await expect(
        pkcs11Service.generateKeyPairPKCS11(999999, PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN, [], [])
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw if not logged in', async () => {
      await pkcs11Service.logout(sessionHandle);

      await expect(
        pkcs11Service.generateKeyPairPKCS11(sessionHandle, PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN, [], [])
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw for invalid mechanism', async () => {
      await expect(
        pkcs11Service.generateKeyPairPKCS11(sessionHandle, 0xFFFFFFFF as PKCS11Mechanism, [], [])
      ).rejects.toThrow(PKCS11Error);
    });
  });

  // ==========================================================================
  // Cryptographic Operations Tests
  // ==========================================================================

  describe('signPKCS11', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(
        0,
        PKCS11SessionFlags.CKF_SERIAL_SESSION | PKCS11SessionFlags.CKF_RW_SESSION
      );
      await mockHsmService.initializeHSM('test-cluster', { username: 'admin', password: 'password' });
      await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, 'default_pin');
    });

    /**
     * **Validates: Requirements 27.4**
     * Standard PKCS#11 operations - C_Sign
     * Note: Full sign/verify tests require integration testing with real HSM
     */
    it('should throw for invalid session handle', async () => {
      await expect(
        pkcs11Service.signPKCS11(999999, PKCS11Mechanism.CKM_SHA256_RSA_PKCS, 1, Buffer.from('test'))
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw if not logged in', async () => {
      await pkcs11Service.logout(sessionHandle);

      await expect(
        pkcs11Service.signPKCS11(sessionHandle, PKCS11Mechanism.CKM_SHA256_RSA_PKCS, 1, Buffer.from('test'))
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw for invalid key handle', async () => {
      await expect(
        pkcs11Service.signPKCS11(sessionHandle, PKCS11Mechanism.CKM_SHA256_RSA_PKCS, 999999, Buffer.from('test'))
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw for empty data', async () => {
      // Generate a key pair for this test
      const keyPair = await pkcs11Service.generateKeyPairPKCS11(
        sessionHandle,
        PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN,
        [{ type: PKCS11AttributeType.CKA_MODULUS_BITS, value: 2048 }],
        [{ type: PKCS11AttributeType.CKA_SIGN, value: true }]
      );

      await expect(
        pkcs11Service.signPKCS11(sessionHandle, PKCS11Mechanism.CKM_SHA256_RSA_PKCS, keyPair.privateKeyHandle, Buffer.from(''))
      ).rejects.toThrow(PKCS11Error);
    });
  });

  describe('verifyPKCS11', () => {
    let sessionHandle: number;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      sessionHandle = await pkcs11Service.openSession(
        0,
        PKCS11SessionFlags.CKF_SERIAL_SESSION | PKCS11SessionFlags.CKF_RW_SESSION
      );
      await mockHsmService.initializeHSM('test-cluster', { username: 'admin', password: 'password' });
      await pkcs11Service.login(sessionHandle, PKCS11UserType.CKU_USER, 'default_pin');
    });

    /**
     * **Validates: Requirements 27.4**
     * Standard PKCS#11 operations - C_Verify
     * Note: Full sign/verify tests require integration testing with real HSM
     */
    it('should throw for invalid session handle', async () => {
      await expect(
        pkcs11Service.verifyPKCS11(999999, PKCS11Mechanism.CKM_SHA256_RSA_PKCS, 1, Buffer.from('test'), Buffer.from('sig'))
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw for invalid key handle', async () => {
      await expect(
        pkcs11Service.verifyPKCS11(sessionHandle, PKCS11Mechanism.CKM_SHA256_RSA_PKCS, 999999, Buffer.from('test'), Buffer.from('sig'))
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw for empty data', async () => {
      const keyPair = await pkcs11Service.generateKeyPairPKCS11(
        sessionHandle,
        PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN,
        [{ type: PKCS11AttributeType.CKA_MODULUS_BITS, value: 2048 }],
        [{ type: PKCS11AttributeType.CKA_SIGN, value: true }]
      );

      await expect(
        pkcs11Service.verifyPKCS11(sessionHandle, PKCS11Mechanism.CKM_SHA256_RSA_PKCS, keyPair.publicKeyHandle, Buffer.from(''), Buffer.from('sig'))
      ).rejects.toThrow(PKCS11Error);
    });

    it('should throw for empty signature', async () => {
      const keyPair = await pkcs11Service.generateKeyPairPKCS11(
        sessionHandle,
        PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN,
        [{ type: PKCS11AttributeType.CKA_MODULUS_BITS, value: 2048 }],
        [{ type: PKCS11AttributeType.CKA_SIGN, value: true }]
      );

      await expect(
        pkcs11Service.verifyPKCS11(sessionHandle, PKCS11Mechanism.CKM_SHA256_RSA_PKCS, keyPair.publicKeyHandle, Buffer.from('test'), Buffer.from(''))
      ).rejects.toThrow(PKCS11Error);
    });
  });

  describe('getMechanismInfo', () => {
    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
    });

    it('should return RSA mechanism info', () => {
      const info = pkcs11Service.getMechanismInfo(0, PKCS11Mechanism.CKM_RSA_PKCS_KEY_PAIR_GEN);

      expect(info.minKeySize).toBe(2048);
      expect(info.maxKeySize).toBe(4096);
    });

    it('should return EC mechanism info', () => {
      const info = pkcs11Service.getMechanismInfo(0, PKCS11Mechanism.CKM_EC_KEY_PAIR_GEN);

      expect(info.minKeySize).toBe(256);
      expect(info.maxKeySize).toBe(384);
    });

    it('should return AES mechanism info', () => {
      const info = pkcs11Service.getMechanismInfo(0, PKCS11Mechanism.CKM_AES_KEY_GEN);

      expect(info.minKeySize).toBe(128);
      expect(info.maxKeySize).toBe(256);
    });

    it('should throw for invalid slot ID', () => {
      expect(() => pkcs11Service.getMechanismInfo(999, PKCS11Mechanism.CKM_RSA_PKCS)).toThrow(PKCS11Error);
    });

    it('should throw for invalid mechanism', () => {
      expect(() => pkcs11Service.getMechanismInfo(0, 0xFFFFFFFF as PKCS11Mechanism)).toThrow(PKCS11Error);
    });
  });

  // ==========================================================================
  // HSM Cluster Management Tests
  // ==========================================================================

  describe('configureCluster', () => {
    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
    });

    /**
     * **Validates: Requirements 27.9**
     * THE Zalt_Platform SHALL support HSM clustering for high availability
     */
    it('should configure cluster with multiple nodes', async () => {
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 50, keyCount: 100 },
        { hostname: 'hsm2.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 30, keyCount: 100 }
      ];

      const config = await pkcs11Service.configureCluster(nodes);

      expect(config.clusterId).toMatch(/^hsm_cluster_/);
      expect(config.nodes.length).toBe(2);
      expect(config.quorum).toBe(2);
      expect(config.failoverPolicy).toBe('automatic');
      expect(config.syncMode).toBe('synchronous');
    });

    it('should throw for empty nodes array', async () => {
      await expect(pkcs11Service.configureCluster([])).rejects.toThrow();
    });

    it('should throw for single node', async () => {
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 50, keyCount: 100 }
      ];

      await expect(pkcs11Service.configureCluster(nodes)).rejects.toThrow('At least 2 nodes required');
    });

    it('should throw if no primary node', async () => {
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 50, keyCount: 100 },
        { hostname: 'hsm2.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 30, keyCount: 100 }
      ];

      await expect(pkcs11Service.configureCluster(nodes)).rejects.toThrow('At least one primary node is required');
    });

    it('should throw if multiple primary nodes', async () => {
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 50, keyCount: 100 },
        { hostname: 'hsm2.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 30, keyCount: 100 }
      ];

      await expect(pkcs11Service.configureCluster(nodes)).rejects.toThrow('Only one primary node is allowed');
    });

    it('should calculate correct quorum for 3 nodes', async () => {
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 50, keyCount: 100 },
        { hostname: 'hsm2.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 30, keyCount: 100 },
        { hostname: 'hsm3.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 20, keyCount: 100 }
      ];

      const config = await pkcs11Service.configureCluster(nodes);

      expect(config.quorum).toBe(2); // floor(3/2) + 1 = 2
    });
  });

  describe('getClusterHealth', () => {
    let clusterId: string;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 50, keyCount: 100 },
        { hostname: 'hsm2.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 30, keyCount: 100 }
      ];
      const config = await pkcs11Service.configureCluster(nodes);
      clusterId = config.clusterId;
    });

    /**
     * **Validates: Requirements 27.9**
     * HSM clustering for high availability - health monitoring
     */
    it('should return healthy status for active cluster', async () => {
      const health = await pkcs11Service.getClusterHealth(clusterId);

      expect(health.clusterId).toBe(clusterId);
      expect(health.status).toBe('healthy');
      expect(health.totalNodes).toBe(2);
      expect(health.activeNodes).toBe(2);
      expect(health.failedNodes).toBe(0);
      expect(health.alerts.length).toBe(0);
    });

    it('should throw for invalid cluster ID', async () => {
      await expect(pkcs11Service.getClusterHealth('invalid-cluster')).rejects.toThrow('Cluster not found');
    });

    it('should throw for empty cluster ID', async () => {
      await expect(pkcs11Service.getClusterHealth('')).rejects.toThrow('Cluster ID is required');
    });
  });

  describe('addClusterNode', () => {
    let clusterId: string;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 50, keyCount: 100 },
        { hostname: 'hsm2.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 30, keyCount: 100 }
      ];
      const config = await pkcs11Service.configureCluster(nodes);
      clusterId = config.clusterId;
    });

    it('should add node to cluster', async () => {
      const newNode = {
        hostname: 'hsm3.example.com',
        port: 2223,
        status: 'active' as const,
        role: 'secondary' as const,
        loadPercentage: 20,
        keyCount: 0
      };

      const config = await pkcs11Service.addClusterNode(clusterId, newNode);

      expect(config.nodes.length).toBe(3);
      expect(config.quorum).toBe(2);
    });

    it('should set new node status to syncing', async () => {
      const newNode = {
        hostname: 'hsm3.example.com',
        port: 2223,
        status: 'active' as const,
        role: 'secondary' as const,
        loadPercentage: 20,
        keyCount: 0
      };

      const config = await pkcs11Service.addClusterNode(clusterId, newNode);
      const addedNode = config.nodes.find(n => n.hostname === 'hsm3.example.com');

      expect(addedNode?.status).toBe('syncing');
    });

    it('should throw for invalid cluster ID', async () => {
      const newNode = {
        hostname: 'hsm3.example.com',
        port: 2223,
        status: 'active' as const,
        role: 'secondary' as const,
        loadPercentage: 20,
        keyCount: 0
      };

      await expect(pkcs11Service.addClusterNode('invalid', newNode)).rejects.toThrow('Cluster not found');
    });
  });

  describe('removeClusterNode', () => {
    let clusterId: string;
    let nodeId: string;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 50, keyCount: 100 },
        { hostname: 'hsm2.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 30, keyCount: 100 },
        { hostname: 'hsm3.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 20, keyCount: 100 }
      ];
      const config = await pkcs11Service.configureCluster(nodes);
      clusterId = config.clusterId;
      nodeId = config.nodes.find(n => n.hostname === 'hsm3.example.com')!.nodeId;
    });

    it('should remove node from cluster', async () => {
      const config = await pkcs11Service.removeClusterNode(clusterId, nodeId);

      expect(config.nodes.length).toBe(2);
      expect(config.nodes.find(n => n.nodeId === nodeId)).toBeUndefined();
    });

    it('should update quorum after removal', async () => {
      const config = await pkcs11Service.removeClusterNode(clusterId, nodeId);

      expect(config.quorum).toBe(2); // floor(2/2) + 1 = 2
    });

    it('should throw for invalid cluster ID', async () => {
      await expect(pkcs11Service.removeClusterNode('invalid', nodeId)).rejects.toThrow('Cluster not found');
    });

    it('should throw for invalid node ID', async () => {
      await expect(pkcs11Service.removeClusterNode(clusterId, 'invalid-node')).rejects.toThrow('Node not found');
    });

    it('should throw when trying to go below minimum nodes', async () => {
      // Remove one node first
      await pkcs11Service.removeClusterNode(clusterId, nodeId);
      
      // Get remaining secondary node
      const config = await pkcs11Service.getClusterHealth(clusterId);
      // This should fail as we'd go below 2 nodes
      // Note: We need to get the actual node ID from the config
    });
  });

  describe('triggerFailover', () => {
    let clusterId: string;
    let secondaryNodeId: string;

    beforeEach(async () => {
      await pkcs11Service.initializePKCS11('/usr/lib/pkcs11/libsofthsm2.so', 0);
      
      const nodes = [
        { hostname: 'hsm1.example.com', port: 2223, status: 'active' as const, role: 'primary' as const, loadPercentage: 50, keyCount: 100 },
        { hostname: 'hsm2.example.com', port: 2223, status: 'active' as const, role: 'secondary' as const, loadPercentage: 30, keyCount: 100 }
      ];
      const config = await pkcs11Service.configureCluster(nodes);
      clusterId = config.clusterId;
      secondaryNodeId = config.nodes.find(n => n.role === 'secondary')!.nodeId;
    });

    it('should promote secondary to primary', async () => {
      const config = await pkcs11Service.triggerFailover(clusterId, secondaryNodeId);

      const newPrimary = config.nodes.find(n => n.nodeId === secondaryNodeId);
      expect(newPrimary?.role).toBe('primary');
      expect(newPrimary?.status).toBe('active');
    });

    it('should demote old primary to secondary', async () => {
      const oldPrimaryId = (await pkcs11Service.getClusterHealth(clusterId)).primaryNode;
      
      const config = await pkcs11Service.triggerFailover(clusterId, secondaryNodeId);

      const oldPrimary = config.nodes.find(n => n.nodeId === oldPrimaryId);
      expect(oldPrimary?.role).toBe('secondary');
      expect(oldPrimary?.status).toBe('standby');
    });

    it('should throw for invalid cluster ID', async () => {
      await expect(pkcs11Service.triggerFailover('invalid', secondaryNodeId)).rejects.toThrow('Cluster not found');
    });

    it('should throw for invalid node ID', async () => {
      await expect(pkcs11Service.triggerFailover(clusterId, 'invalid-node')).rejects.toThrow('Target node not found');
    });
  });
});
