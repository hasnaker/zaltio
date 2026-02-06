/**
 * HSM Service Tests
 * 
 * Comprehensive tests for AWS CloudHSM integration including:
 * - HSM initialization and connection
 * - Key generation within HSM boundary
 * - Signing operations within HSM boundary
 * - Key backup and recovery procedures
 * 
 * Validates: Requirements 27.1, 27.5, 27.6
 */

import {
  HSMService,
  HSMCredentials,
  HSMKeyType,
  HSMKeyUsage,
  HSMError,
  HSMConnectionError,
  HSMKeyNotFoundError,
  HSMOperationError,
  HSMAuthenticationError,
  generateKeyHandle,
  generateKeyId,
  generateBackupId,
  generateOperationId,
  calculateChecksum,
  getSigningAlgorithm,
  isValidKeyType,
  isValidKeyUsage
} from './hsm.service';

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
      return Promise.resolve({});
    }
    
    if (commandName === 'GetCommand') {
      const key = `${command.input.Key.PK}#${command.input.Key.SK}`;
      const item = mockStore.get(key);
      return Promise.resolve({ Item: item });
    }
    
    if (commandName === 'DeleteCommand') {
      const key = `${command.input.Key.PK}#${command.input.Key.SK}`;
      mockStore.delete(key);
      return Promise.resolve({});
    }
    
    if (commandName === 'QueryCommand') {
      const items: Record<string, unknown>[] = [];
      const pk = command.input.ExpressionAttributeValues[':pk'];
      const skPrefix = command.input.ExpressionAttributeValues[':sk'];
      
      mockStore.forEach((item, key) => {
        if (command.input.IndexName === 'GSI1') {
          if (item.GSI1PK === pk) {
            items.push(item);
          }
        } else if (command.input.IndexName === 'GSI2') {
          if (item.GSI2PK === pk) {
            items.push(item);
          }
        } else {
          if (key.startsWith(`${pk}#`) && (!skPrefix || key.includes(skPrefix))) {
            items.push(item);
          }
        }
      });
      
      return Promise.resolve({ Items: items });
    }
    
    if (commandName === 'UpdateCommand') {
      const key = `${command.input.Key.PK}#${command.input.Key.SK}`;
      const item = mockStore.get(key);
      if (item) {
        const values = command.input.ExpressionAttributeValues;
        Object.keys(values).forEach(k => {
          const fieldName = k.replace(':', '');
          item[fieldName] = values[k];
        });
        mockStore.set(key, item);
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

describe('HSM Utility Functions', () => {
  describe('generateKeyHandle', () => {
    it('should generate unique key handles', () => {
      const handle1 = generateKeyHandle();
      const handle2 = generateKeyHandle();
      
      expect(handle1).not.toBe(handle2);
      expect(handle1).toMatch(/^hsm_key_[a-f0-9]{32}$/);
      expect(handle2).toMatch(/^hsm_key_[a-f0-9]{32}$/);
    });
  });

  describe('generateKeyId', () => {
    it('should generate unique key IDs', () => {
      const id1 = generateKeyId();
      const id2 = generateKeyId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^hsmk_[a-f0-9]{24}$/);
    });
  });

  describe('generateBackupId', () => {
    it('should generate unique backup IDs', () => {
      const id1 = generateBackupId();
      const id2 = generateBackupId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^hsm_backup_[a-f0-9]{24}$/);
    });
  });

  describe('generateOperationId', () => {
    it('should generate unique operation IDs', () => {
      const id1 = generateOperationId();
      const id2 = generateOperationId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^hsm_op_[a-f0-9]{16}$/);
    });
  });

  describe('calculateChecksum', () => {
    it('should calculate consistent checksums', () => {
      const data = 'test data';
      const checksum1 = calculateChecksum(data);
      const checksum2 = calculateChecksum(data);
      
      expect(checksum1).toBe(checksum2);
      expect(checksum1).toHaveLength(64); // SHA-256 hex
    });

    it('should produce different checksums for different data', () => {
      const checksum1 = calculateChecksum('data1');
      const checksum2 = calculateChecksum('data2');
      
      expect(checksum1).not.toBe(checksum2);
    });
  });

  describe('getSigningAlgorithm', () => {
    it('should return RSA-SHA256 for RSA keys', () => {
      expect(getSigningAlgorithm('RSA_2048')).toBe('RSA-SHA256');
      expect(getSigningAlgorithm('RSA_4096')).toBe('RSA-SHA256');
    });

    it('should return ECDSA-SHA256 for EC P-256 keys', () => {
      expect(getSigningAlgorithm('EC_P256')).toBe('ECDSA-SHA256');
    });

    it('should return ECDSA-SHA384 for EC P-384 keys', () => {
      expect(getSigningAlgorithm('EC_P384')).toBe('ECDSA-SHA384');
    });

    it('should return ECDSA-SHA256 for secp256k1 keys', () => {
      expect(getSigningAlgorithm('EC_SECP256K1')).toBe('ECDSA-SHA256');
    });

    it('should throw for AES keys', () => {
      expect(() => getSigningAlgorithm('AES_256')).toThrow('Unsupported key type for signing');
    });
  });

  describe('isValidKeyType', () => {
    it('should return true for valid key types', () => {
      expect(isValidKeyType('RSA_2048')).toBe(true);
      expect(isValidKeyType('RSA_4096')).toBe(true);
      expect(isValidKeyType('EC_P256')).toBe(true);
      expect(isValidKeyType('EC_P384')).toBe(true);
      expect(isValidKeyType('EC_SECP256K1')).toBe(true);
      expect(isValidKeyType('AES_256')).toBe(true);
    });

    it('should return false for invalid key types', () => {
      expect(isValidKeyType('INVALID')).toBe(false);
      expect(isValidKeyType('RSA_1024')).toBe(false);
      expect(isValidKeyType('')).toBe(false);
    });
  });

  describe('isValidKeyUsage', () => {
    it('should return true for valid key usages', () => {
      expect(isValidKeyUsage('sign')).toBe(true);
      expect(isValidKeyUsage('encrypt')).toBe(true);
      expect(isValidKeyUsage('wrap')).toBe(true);
      expect(isValidKeyUsage('derive')).toBe(true);
    });

    it('should return false for invalid key usages', () => {
      expect(isValidKeyUsage('invalid')).toBe(false);
      expect(isValidKeyUsage('')).toBe(false);
    });
  });
});

// ============================================================================
// HSM Error Classes Tests
// ============================================================================

describe('HSM Error Classes', () => {
  describe('HSMError', () => {
    it('should create error with message and code', () => {
      const error = new HSMError('Test error', 'TEST_CODE');
      
      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_CODE');
      expect(error.name).toBe('HSMError');
    });

    it('should include details when provided', () => {
      const error = new HSMError('Test error', 'TEST_CODE', { key: 'value' });
      
      expect(error.details).toEqual({ key: 'value' });
    });
  });

  describe('HSMConnectionError', () => {
    it('should create connection error', () => {
      const error = new HSMConnectionError('Connection failed');
      
      expect(error.message).toBe('Connection failed');
      expect(error.code).toBe('HSM_CONNECTION_ERROR');
      expect(error.name).toBe('HSMConnectionError');
    });
  });

  describe('HSMKeyNotFoundError', () => {
    it('should create key not found error with handle', () => {
      const error = new HSMKeyNotFoundError('hsm_key_123');
      
      expect(error.message).toBe('Key not found: hsm_key_123');
      expect(error.code).toBe('HSM_KEY_NOT_FOUND');
      expect(error.details).toEqual({ keyHandle: 'hsm_key_123' });
    });
  });

  describe('HSMOperationError', () => {
    it('should create operation error', () => {
      const error = new HSMOperationError('sign', 'Signing failed');
      
      expect(error.message).toBe('Signing failed');
      expect(error.code).toBe('HSM_OPERATION_ERROR');
      expect(error.details?.operation).toBe('sign');
    });
  });

  describe('HSMAuthenticationError', () => {
    it('should create authentication error', () => {
      const error = new HSMAuthenticationError('Invalid credentials');
      
      expect(error.message).toBe('Invalid credentials');
      expect(error.code).toBe('HSM_AUTH_ERROR');
    });
  });
});

// ============================================================================
// HSM Service Tests
// ============================================================================

describe('HSMService', () => {
  let hsmService: HSMService;
  const validCredentials: HSMCredentials = {
    username: 'admin',
    password: 'securePassword123!'
  };

  beforeEach(() => {
    hsmService = new HSMService(mockDocClient as any, 'zalt-hsm-test');
  });

  afterEach(async () => {
    try {
      await hsmService.disconnect();
    } catch {
      // Ignore disconnect errors in cleanup
    }
  });

  // ==========================================================================
  // Initialization Tests
  // ==========================================================================

  describe('initializeHSM', () => {
    /**
     * **Validates: Requirements 27.1**
     * THE Zalt_Platform SHALL support AWS CloudHSM integration for dedicated HSM
     */
    it('should initialize HSM connection successfully', async () => {
      const clusterId = 'cluster-abc123';
      
      const config = await hsmService.initializeHSM(clusterId, validCredentials);
      
      expect(config.clusterId).toBe(clusterId);
      expect(config.provider).toBe('aws_cloudhsm');
      expect(config.status).toBe('connected');
      expect(hsmService.isConnected()).toBe(true);
    });

    it('should throw error for missing cluster ID', async () => {
      await expect(
        hsmService.initializeHSM('', validCredentials)
      ).rejects.toThrow(HSMConnectionError);
    });

    it('should throw error for missing credentials', async () => {
      await expect(
        hsmService.initializeHSM('cluster-123', { username: '', password: '' })
      ).rejects.toThrow(HSMAuthenticationError);
    });

    it('should throw error for invalid username format', async () => {
      await expect(
        hsmService.initializeHSM('cluster-123', { username: 'ab', password: 'pass' })
      ).rejects.toThrow(HSMAuthenticationError);
    });

    it('should throw error for invalid credentials', async () => {
      await expect(
        hsmService.initializeHSM('cluster-123', { username: 'invalid', password: 'pass' })
      ).rejects.toThrow(HSMConnectionError);
    });
  });

  // ==========================================================================
  // Key Generation Tests
  // ==========================================================================

  describe('generateKeyInHSM', () => {
    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
    });

    /**
     * **Validates: Requirements 27.1**
     * Key generation in HSM boundary
     */
    it('should generate RSA-2048 key in HSM', async () => {
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'test-rsa-key', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      
      expect(result.key.keyHandle).toMatch(/^hsm_key_/);
      expect(result.key.keyType).toBe('RSA_2048');
      expect(result.key.label).toBe('test-rsa-key');
      expect(result.key.status).toBe('active');
      expect(result.publicKey).toBeDefined();
      expect(result.publicKey).toContain('BEGIN PUBLIC KEY');
    });

    it('should generate RSA-4096 key in HSM', async () => {
      const result = await hsmService.generateKeyInHSM('RSA_4096', 'test-rsa-4096', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      
      expect(result.key.keyType).toBe('RSA_4096');
      expect(result.publicKey).toBeDefined();
    });

    it('should generate EC P-256 key in HSM', async () => {
      const result = await hsmService.generateKeyInHSM('EC_P256', 'test-ec-key', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      
      expect(result.key.keyType).toBe('EC_P256');
      expect(result.publicKey).toBeDefined();
    });

    it('should generate EC P-384 key in HSM', async () => {
      const result = await hsmService.generateKeyInHSM('EC_P384', 'test-ec-384', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      
      expect(result.key.keyType).toBe('EC_P384');
      expect(result.publicKey).toBeDefined();
    });

    it('should generate secp256k1 key in HSM', async () => {
      const result = await hsmService.generateKeyInHSM('EC_SECP256K1', 'test-secp256k1', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      
      expect(result.key.keyType).toBe('EC_SECP256K1');
      expect(result.publicKey).toBeDefined();
    });

    it('should generate AES-256 key in HSM', async () => {
      const result = await hsmService.generateKeyInHSM('AES_256', 'test-aes-key', {
        realmId: 'test-realm',
        keyUsage: ['encrypt', 'wrap']
      });
      
      expect(result.key.keyType).toBe('AES_256');
      expect(result.publicKey).toBeUndefined(); // Symmetric key has no public key
    });

    it('should throw error for invalid key type', async () => {
      await expect(
        hsmService.generateKeyInHSM('INVALID' as HSMKeyType, 'test-key')
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for empty label', async () => {
      await expect(
        hsmService.generateKeyInHSM('RSA_2048', '')
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error when HSM not initialized', async () => {
      const uninitializedService = new HSMService(mockDocClient as any, 'test');
      
      await expect(
        uninitializedService.generateKeyInHSM('RSA_2048', 'test-key')
      ).rejects.toThrow(HSMConnectionError);
    });

    it('should set default key usage to sign', async () => {
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'test-key');
      
      expect(result.key.keyUsage).toContain('sign');
    });

    it('should set extractable to false by default', async () => {
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'test-key');
      
      expect(result.key.extractable).toBe(false);
    });

    it('should allow setting extractable to true', async () => {
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'test-key', {
        extractable: true
      });
      
      expect(result.key.extractable).toBe(true);
    });
  });

  // ==========================================================================
  // Signing Tests
  // ==========================================================================

  describe('signWithHSM', () => {
    let signingKeyHandle: string;

    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'signing-key', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      signingKeyHandle = result.key.keyHandle;
    });

    /**
     * **Validates: Requirements 27.5**
     * WHEN HSM configured THEN THE Zalt_Platform SHALL perform all signing operations within HSM boundary
     */
    it('should sign message with RSA key', async () => {
      const message = Buffer.from('Hello, World!');
      
      const result = await hsmService.signWithHSM(signingKeyHandle, message);
      
      expect(result.signature).toBeDefined();
      expect(result.signature.length).toBeGreaterThan(0);
      expect(result.algorithm).toBe('RSA-SHA256');
      expect(result.keyHandle).toBe(signingKeyHandle);
      expect(result.timestamp).toBeDefined();
    });

    it('should sign message with EC key', async () => {
      const ecResult = await hsmService.generateKeyInHSM('EC_P256', 'ec-signing-key', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      const message = Buffer.from('Test message');
      
      const result = await hsmService.signWithHSM(ecResult.key.keyHandle, message);
      
      expect(result.signature).toBeDefined();
      expect(result.algorithm).toBe('ECDSA-SHA256');
    });

    it('should sign message with AES key (HMAC)', async () => {
      const aesResult = await hsmService.generateKeyInHSM('AES_256', 'hmac-key', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      const message = Buffer.from('Test message');
      
      const result = await hsmService.signWithHSM(aesResult.key.keyHandle, message);
      
      expect(result.signature).toBeDefined();
    });

    it('should throw error for non-existent key', async () => {
      const message = Buffer.from('Test');
      
      await expect(
        hsmService.signWithHSM('non-existent-key', message)
      ).rejects.toThrow(HSMKeyNotFoundError);
    });

    it('should throw error for empty key handle', async () => {
      const message = Buffer.from('Test');
      
      await expect(
        hsmService.signWithHSM('', message)
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for empty message', async () => {
      await expect(
        hsmService.signWithHSM(signingKeyHandle, Buffer.from(''))
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for key without sign permission', async () => {
      const encryptOnlyKey = await hsmService.generateKeyInHSM('AES_256', 'encrypt-only', {
        realmId: 'test-realm',
        keyUsage: ['encrypt']
      });
      const message = Buffer.from('Test');
      
      await expect(
        hsmService.signWithHSM(encryptOnlyKey.key.keyHandle, message)
      ).rejects.toThrow('Key is not authorized for signing');
    });

    it('should produce different signatures for different messages', async () => {
      const message1 = Buffer.from('Message 1');
      const message2 = Buffer.from('Message 2');
      
      const result1 = await hsmService.signWithHSM(signingKeyHandle, message1);
      const result2 = await hsmService.signWithHSM(signingKeyHandle, message2);
      
      expect(result1.signature).not.toBe(result2.signature);
    });

    it('should produce consistent signatures for same message', async () => {
      // Note: RSA signatures are deterministic, ECDSA are not
      // This test uses RSA
      const message = Buffer.from('Consistent message');
      
      const result1 = await hsmService.signWithHSM(signingKeyHandle, message);
      const result2 = await hsmService.signWithHSM(signingKeyHandle, message);
      
      // RSA-PKCS1 signatures are deterministic
      expect(result1.signature).toBe(result2.signature);
    });
  });

  // ==========================================================================
  // Verification Tests
  // ==========================================================================

  describe('verifyWithHSM', () => {
    let signingKeyHandle: string;

    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'verify-key', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      signingKeyHandle = result.key.keyHandle;
    });

    it('should verify valid signature', async () => {
      const message = Buffer.from('Test message');
      const signResult = await hsmService.signWithHSM(signingKeyHandle, message);
      
      const verifyResult = await hsmService.verifyWithHSM(
        signingKeyHandle,
        message,
        signResult.signature
      );
      
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.keyHandle).toBe(signingKeyHandle);
    });

    it('should reject invalid signature', async () => {
      const message = Buffer.from('Test message');
      const invalidSignature = Buffer.from('invalid').toString('base64');
      
      const result = await hsmService.verifyWithHSM(
        signingKeyHandle,
        message,
        invalidSignature
      );
      
      expect(result.valid).toBe(false);
    });

    it('should reject signature for different message', async () => {
      const message1 = Buffer.from('Original message');
      const message2 = Buffer.from('Different message');
      const signResult = await hsmService.signWithHSM(signingKeyHandle, message1);
      
      const verifyResult = await hsmService.verifyWithHSM(
        signingKeyHandle,
        message2,
        signResult.signature
      );
      
      expect(verifyResult.valid).toBe(false);
    });

    it('should verify EC signature', async () => {
      const ecKey = await hsmService.generateKeyInHSM('EC_P256', 'ec-verify', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      const message = Buffer.from('EC test');
      const signResult = await hsmService.signWithHSM(ecKey.key.keyHandle, message);
      
      const verifyResult = await hsmService.verifyWithHSM(
        ecKey.key.keyHandle,
        message,
        signResult.signature
      );
      
      expect(verifyResult.valid).toBe(true);
    });

    it('should verify HMAC signature', async () => {
      const aesKey = await hsmService.generateKeyInHSM('AES_256', 'hmac-verify', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      const message = Buffer.from('HMAC test');
      const signResult = await hsmService.signWithHSM(aesKey.key.keyHandle, message);
      
      const verifyResult = await hsmService.verifyWithHSM(
        aesKey.key.keyHandle,
        message,
        signResult.signature
      );
      
      expect(verifyResult.valid).toBe(true);
    });

    it('should throw error for non-existent key', async () => {
      await expect(
        hsmService.verifyWithHSM('non-existent', Buffer.from('test'), 'sig')
      ).rejects.toThrow(HSMKeyNotFoundError);
    });

    it('should throw error for empty key handle', async () => {
      await expect(
        hsmService.verifyWithHSM('', Buffer.from('test'), 'sig')
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for empty message', async () => {
      await expect(
        hsmService.verifyWithHSM(signingKeyHandle, Buffer.from(''), 'sig')
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for empty signature', async () => {
      await expect(
        hsmService.verifyWithHSM(signingKeyHandle, Buffer.from('test'), '')
      ).rejects.toThrow(HSMOperationError);
    });
  });

  // ==========================================================================
  // Key Backup and Recovery Tests
  // ==========================================================================

  describe('exportWrappedKey', () => {
    let dataKeyHandle: string;
    let wrappingKeyHandle: string;

    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      
      // Create a wrapping key
      const wrappingResult = await hsmService.generateKeyInHSM('AES_256', 'wrapping-key', {
        realmId: 'test-realm',
        keyUsage: ['wrap'],
        extractable: false
      });
      wrappingKeyHandle = wrappingResult.key.keyHandle;
      
      // Create a data key to export
      const dataResult = await hsmService.generateKeyInHSM('AES_256', 'data-key', {
        realmId: 'test-realm',
        keyUsage: ['encrypt'],
        extractable: true
      });
      dataKeyHandle = dataResult.key.keyHandle;
    });

    /**
     * **Validates: Requirements 27.6**
     * THE Zalt_Platform SHALL support HSM key backup and disaster recovery procedures
     */
    it('should export wrapped key for backup', async () => {
      const result = await hsmService.exportWrappedKey(dataKeyHandle, wrappingKeyHandle);
      
      expect(result.backupId).toMatch(/^hsm_backup_/);
      expect(result.wrappedKey).toBeDefined();
      expect(result.wrappedKey.length).toBeGreaterThan(0);
      expect(result.wrappingKeyHandle).toBe(wrappingKeyHandle);
      expect(result.keyType).toBe('AES_256');
      expect(result.checksum).toHaveLength(64);
      expect(result.timestamp).toBeDefined();
    });

    it('should export RSA key wrapped', async () => {
      const rsaKey = await hsmService.generateKeyInHSM('RSA_2048', 'rsa-export', {
        realmId: 'test-realm',
        keyUsage: ['sign'],
        extractable: true
      });
      
      const result = await hsmService.exportWrappedKey(rsaKey.key.keyHandle, wrappingKeyHandle);
      
      expect(result.keyType).toBe('RSA_2048');
      expect(result.wrappedKey).toBeDefined();
    });

    it('should throw error for non-extractable key', async () => {
      const nonExtractable = await hsmService.generateKeyInHSM('AES_256', 'non-extract', {
        realmId: 'test-realm',
        keyUsage: ['encrypt'],
        extractable: false
      });
      
      await expect(
        hsmService.exportWrappedKey(nonExtractable.key.keyHandle, wrappingKeyHandle)
      ).rejects.toThrow('Key is not extractable');
    });

    it('should throw error for non-existent key', async () => {
      await expect(
        hsmService.exportWrappedKey('non-existent', wrappingKeyHandle)
      ).rejects.toThrow(HSMKeyNotFoundError);
    });

    it('should throw error for non-existent wrapping key', async () => {
      await expect(
        hsmService.exportWrappedKey(dataKeyHandle, 'non-existent')
      ).rejects.toThrow(HSMKeyNotFoundError);
    });

    it('should throw error for wrapping key without wrap permission', async () => {
      const signOnlyKey = await hsmService.generateKeyInHSM('AES_256', 'sign-only', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      
      await expect(
        hsmService.exportWrappedKey(dataKeyHandle, signOnlyKey.key.keyHandle)
      ).rejects.toThrow('Wrapping key is not authorized for key wrapping');
    });

    it('should throw error for empty key handle', async () => {
      await expect(
        hsmService.exportWrappedKey('', wrappingKeyHandle)
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for empty wrapping key handle', async () => {
      await expect(
        hsmService.exportWrappedKey(dataKeyHandle, '')
      ).rejects.toThrow(HSMOperationError);
    });
  });

  describe('importWrappedKey', () => {
    let wrappingKeyHandle: string;
    let wrappedKeyData: string;
    let originalKeyType: HSMKeyType;

    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      
      // Create wrapping key
      const wrappingResult = await hsmService.generateKeyInHSM('AES_256', 'import-wrap-key', {
        realmId: 'test-realm',
        keyUsage: ['wrap']
      });
      wrappingKeyHandle = wrappingResult.key.keyHandle;
      
      // Create and export a key
      const dataKey = await hsmService.generateKeyInHSM('AES_256', 'export-for-import', {
        realmId: 'test-realm',
        keyUsage: ['encrypt'],
        extractable: true
      });
      
      const exportResult = await hsmService.exportWrappedKey(
        dataKey.key.keyHandle,
        wrappingKeyHandle
      );
      wrappedKeyData = exportResult.wrappedKey;
      originalKeyType = exportResult.keyType;
    });

    /**
     * **Validates: Requirements 27.6**
     * Key recovery from backup
     */
    it('should import wrapped key from backup', async () => {
      const result = await hsmService.importWrappedKey(
        wrappedKeyData,
        wrappingKeyHandle,
        {
          label: 'imported-key',
          keyType: originalKeyType,
          keyUsage: ['encrypt'],
          realmId: 'test-realm'
        }
      );
      
      expect(result.key.keyHandle).toMatch(/^hsm_key_/);
      expect(result.key.label).toBe('imported-key');
      expect(result.key.keyType).toBe(originalKeyType);
      expect(result.key.status).toBe('active');
      expect(result.key.extractable).toBe(false); // Imported keys not extractable
      expect(result.importedAt).toBeDefined();
    });

    it('should import RSA key from backup', async () => {
      // Export RSA key
      const rsaKey = await hsmService.generateKeyInHSM('RSA_2048', 'rsa-for-import', {
        realmId: 'test-realm',
        keyUsage: ['sign'],
        extractable: true
      });
      const rsaExport = await hsmService.exportWrappedKey(rsaKey.key.keyHandle, wrappingKeyHandle);
      
      const result = await hsmService.importWrappedKey(
        rsaExport.wrappedKey,
        wrappingKeyHandle,
        {
          label: 'imported-rsa',
          keyType: 'RSA_2048',
          keyUsage: ['sign'],
          realmId: 'test-realm'
        }
      );
      
      expect(result.key.keyType).toBe('RSA_2048');
    });

    it('should allow signing with imported RSA key', async () => {
      // Export RSA key for this test
      const rsaKey = await hsmService.generateKeyInHSM('RSA_2048', 'rsa-sign-import', {
        realmId: 'test-realm',
        keyUsage: ['sign'],
        extractable: true
      });
      const rsaExport = await hsmService.exportWrappedKey(rsaKey.key.keyHandle, wrappingKeyHandle);
      
      const result = await hsmService.importWrappedKey(
        rsaExport.wrappedKey,
        wrappingKeyHandle,
        {
          label: 'sign-import',
          keyType: 'RSA_2048',
          keyUsage: ['sign'],
          realmId: 'test-realm'
        }
      );
      
      // Verify the imported key works for signing
      const signResult = await hsmService.signWithHSM(
        result.key.keyHandle,
        Buffer.from('Test message')
      );
      
      expect(signResult.signature).toBeDefined();
    });

    it('should throw error for empty wrapped key', async () => {
      await expect(
        hsmService.importWrappedKey('', wrappingKeyHandle, {
          label: 'test',
          keyType: 'AES_256',
          keyUsage: ['encrypt'],
          realmId: 'test'
        })
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for empty wrapping key handle', async () => {
      await expect(
        hsmService.importWrappedKey(wrappedKeyData, '', {
          label: 'test',
          keyType: 'AES_256',
          keyUsage: ['encrypt'],
          realmId: 'test'
        })
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for empty label', async () => {
      await expect(
        hsmService.importWrappedKey(wrappedKeyData, wrappingKeyHandle, {
          label: '',
          keyType: 'AES_256',
          keyUsage: ['encrypt'],
          realmId: 'test'
        })
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for invalid key type', async () => {
      await expect(
        hsmService.importWrappedKey(wrappedKeyData, wrappingKeyHandle, {
          label: 'test',
          keyType: 'INVALID' as HSMKeyType,
          keyUsage: ['encrypt'],
          realmId: 'test'
        })
      ).rejects.toThrow(HSMOperationError);
    });

    it('should throw error for non-existent wrapping key', async () => {
      await expect(
        hsmService.importWrappedKey(wrappedKeyData, 'non-existent', {
          label: 'test',
          keyType: 'AES_256',
          keyUsage: ['encrypt'],
          realmId: 'test'
        })
      ).rejects.toThrow(HSMKeyNotFoundError);
    });
  });

  // ==========================================================================
  // Key Info and Management Tests
  // ==========================================================================

  describe('getKeyInfo', () => {
    let keyHandle: string;

    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'info-test-key', {
        realmId: 'test-realm',
        keyUsage: ['sign', 'encrypt']
      });
      keyHandle = result.key.keyHandle;
    });

    it('should return key information', async () => {
      const info = await hsmService.getKeyInfo(keyHandle);
      
      expect(info.keyHandle).toBe(keyHandle);
      expect(info.label).toBe('info-test-key');
      expect(info.keyType).toBe('RSA_2048');
      expect(info.keyUsage).toContain('sign');
      expect(info.keyUsage).toContain('encrypt');
      expect(info.status).toBe('active');
      expect(info.publicKey).toBeDefined();
    });

    it('should return public key for asymmetric keys', async () => {
      const info = await hsmService.getKeyInfo(keyHandle);
      
      expect(info.publicKey).toContain('BEGIN PUBLIC KEY');
    });

    it('should not return public key for symmetric keys', async () => {
      const aesKey = await hsmService.generateKeyInHSM('AES_256', 'aes-info', {
        realmId: 'test-realm',
        keyUsage: ['encrypt']
      });
      
      const info = await hsmService.getKeyInfo(aesKey.key.keyHandle);
      
      expect(info.publicKey).toBeUndefined();
    });

    it('should throw error for non-existent key', async () => {
      await expect(
        hsmService.getKeyInfo('non-existent')
      ).rejects.toThrow(HSMKeyNotFoundError);
    });

    it('should throw error for empty key handle', async () => {
      await expect(
        hsmService.getKeyInfo('')
      ).rejects.toThrow(HSMOperationError);
    });
  });

  describe('listKeys', () => {
    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
    });

    it('should list all keys for a realm', async () => {
      // Create multiple keys
      await hsmService.generateKeyInHSM('RSA_2048', 'key-1', { realmId: 'list-realm' });
      await hsmService.generateKeyInHSM('EC_P256', 'key-2', { realmId: 'list-realm' });
      await hsmService.generateKeyInHSM('AES_256', 'key-3', { realmId: 'list-realm' });
      
      const keys = await hsmService.listKeys('list-realm');
      
      expect(keys.length).toBe(3);
      expect(keys.map(k => k.label)).toContain('key-1');
      expect(keys.map(k => k.label)).toContain('key-2');
      expect(keys.map(k => k.label)).toContain('key-3');
    });

    it('should return empty array for realm with no keys', async () => {
      const keys = await hsmService.listKeys('empty-realm');
      
      expect(keys).toEqual([]);
    });

    it('should only return keys for specified realm', async () => {
      await hsmService.generateKeyInHSM('RSA_2048', 'realm-a-key', { realmId: 'realm-a' });
      await hsmService.generateKeyInHSM('RSA_2048', 'realm-b-key', { realmId: 'realm-b' });
      
      const keysA = await hsmService.listKeys('realm-a');
      const keysB = await hsmService.listKeys('realm-b');
      
      expect(keysA.length).toBe(1);
      expect(keysA[0].label).toBe('realm-a-key');
      expect(keysB.length).toBe(1);
      expect(keysB[0].label).toBe('realm-b-key');
    });
  });

  describe('disableKey', () => {
    let keyHandle: string;

    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'disable-test', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      keyHandle = result.key.keyHandle;
    });

    it('should disable a key', async () => {
      await hsmService.disableKey(keyHandle);
      
      const info = await hsmService.getKeyInfo(keyHandle);
      expect(info.status).toBe('disabled');
    });

    it('should prevent signing with disabled key', async () => {
      await hsmService.disableKey(keyHandle);
      
      await expect(
        hsmService.signWithHSM(keyHandle, Buffer.from('test'))
      ).rejects.toThrow('Key is not active');
    });

    it('should throw error for non-existent key', async () => {
      await expect(
        hsmService.disableKey('non-existent')
      ).rejects.toThrow(HSMKeyNotFoundError);
    });
  });

  describe('deleteKey', () => {
    let keyHandle: string;

    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      const result = await hsmService.generateKeyInHSM('RSA_2048', 'delete-test', {
        realmId: 'test-realm',
        keyUsage: ['sign']
      });
      keyHandle = result.key.keyHandle;
    });

    it('should mark key as pending deletion', async () => {
      await hsmService.deleteKey(keyHandle);
      
      const info = await hsmService.getKeyInfo(keyHandle);
      expect(info.status).toBe('pending_deletion');
    });

    it('should throw error for non-existent key', async () => {
      await expect(
        hsmService.deleteKey('non-existent')
      ).rejects.toThrow(HSMKeyNotFoundError);
    });
  });

  // ==========================================================================
  // Cluster Status Tests
  // ==========================================================================

  describe('getClusterStatus', () => {
    beforeEach(async () => {
      await hsmService.initializeHSM('cluster-status-test', validCredentials);
    });

    it('should return cluster status', async () => {
      const status = await hsmService.getClusterStatus();
      
      expect(status.clusterId).toBe('cluster-status-test');
      expect(status.status).toBe('connected');
      expect(status.hsmCount).toBeGreaterThan(0);
      expect(status.activeHsms).toBeGreaterThan(0);
      expect(status.keyCount).toBeGreaterThanOrEqual(0);
      expect(status.operationsPerSecond).toBeGreaterThan(0);
      expect(status.lastHealthCheck).toBeDefined();
    });

    it('should reflect key count', async () => {
      await hsmService.generateKeyInHSM('RSA_2048', 'count-key-1', { realmId: 'test' });
      await hsmService.generateKeyInHSM('RSA_2048', 'count-key-2', { realmId: 'test' });
      
      const status = await hsmService.getClusterStatus();
      
      expect(status.keyCount).toBe(2);
    });

    it('should throw error when not initialized', async () => {
      const uninitializedService = new HSMService(mockDocClient as any, 'test');
      
      await expect(
        uninitializedService.getClusterStatus()
      ).rejects.toThrow(HSMConnectionError);
    });
  });

  // ==========================================================================
  // Connection Management Tests
  // ==========================================================================

  describe('isConnected', () => {
    it('should return false before initialization', () => {
      expect(hsmService.isConnected()).toBe(false);
    });

    it('should return true after initialization', async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      
      expect(hsmService.isConnected()).toBe(true);
    });

    it('should return false after disconnect', async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      await hsmService.disconnect();
      
      expect(hsmService.isConnected()).toBe(false);
    });
  });

  describe('disconnect', () => {
    it('should disconnect from HSM', async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      
      await hsmService.disconnect();
      
      expect(hsmService.isConnected()).toBe(false);
    });

    it('should clear key store on disconnect', async () => {
      await hsmService.initializeHSM('cluster-test', validCredentials);
      await hsmService.generateKeyInHSM('RSA_2048', 'test-key', { realmId: 'test' });
      
      await hsmService.disconnect();
      
      // Re-initialize and check key count
      await hsmService.initializeHSM('cluster-test', validCredentials);
      const status = await hsmService.getClusterStatus();
      expect(status.keyCount).toBe(0);
    });

    it('should allow re-initialization after disconnect', async () => {
      await hsmService.initializeHSM('cluster-1', validCredentials);
      await hsmService.disconnect();
      
      const config = await hsmService.initializeHSM('cluster-2', validCredentials);
      
      expect(config.clusterId).toBe('cluster-2');
      expect(hsmService.isConnected()).toBe(true);
    });
  });
});
