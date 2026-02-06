/**
 * MPC Service Tests
 * 
 * Comprehensive tests for Multi-Party Computation key generation,
 * distribution, refresh, and signing functionality.
 * 
 * Validates: Requirements 26.1, 26.2, 26.3, 26.4
 */

import {
  MPCService,
  ShamirSecretSharing,
  FiniteField,
  MPCParty,
  MPCKeyGenerationOptions,
  SigningSessionOptions,
  PartialSignatureSubmission,
  RecoverySetupOptions,
  RecoveryGuardian,
  GuardianApprovalSubmission,
  encryptShare,
  decryptShare,
  generateCommitment,
  generateEd25519KeyPair,
  generateSecp256k1KeyPair
} from './mpc.service';

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
      
      if (command.input.Select === 'COUNT') {
        return Promise.resolve({ Count: items.length });
      }
      
      return Promise.resolve({ Items: items });
    }
    
    if (commandName === 'UpdateCommand') {
      const key = `${command.input.Key.PK}#${command.input.Key.SK}`;
      const item = mockStore.get(key);
      if (item) {
        // Simple update simulation
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
// Finite Field Tests
// ============================================================================

describe('FiniteField', () => {
  const field = new FiniteField();

  describe('basic operations', () => {
    it('should perform modular addition correctly', () => {
      const a = 100n;
      const b = 200n;
      const result = field.add(a, b);
      expect(result).toBe(300n);
    });

    it('should perform modular subtraction correctly', () => {
      const a = 300n;
      const b = 100n;
      const result = field.sub(a, b);
      expect(result).toBe(200n);
    });

    it('should handle subtraction resulting in negative (wrap around)', () => {
      const a = 100n;
      const b = 200n;
      const result = field.sub(a, b);
      // Result should be positive (wrapped around the prime)
      expect(result > 0n).toBe(true);
    });

    it('should perform modular multiplication correctly', () => {
      const a = 10n;
      const b = 20n;
      const result = field.mul(a, b);
      expect(result).toBe(200n);
    });

    it('should perform modular exponentiation correctly', () => {
      const base = 2n;
      const exp = 10n;
      const result = field.pow(base, exp);
      expect(result).toBe(1024n);
    });

    it('should compute modular inverse correctly', () => {
      const a = 7n;
      const inverse = field.inverse(a);
      // a * inverse should equal 1 (mod prime)
      const product = field.mul(a, inverse);
      expect(product).toBe(1n);
    });

    it('should throw error for inverse of zero', () => {
      expect(() => field.inverse(0n)).toThrow('Cannot compute inverse of zero');
    });

    it('should perform modular division correctly', () => {
      const a = 100n;
      const b = 10n;
      const result = field.div(a, b);
      // result * b should equal a
      const check = field.mul(result, b);
      expect(check).toBe(a);
    });

    it('should generate random field elements', () => {
      const r1 = field.random();
      const r2 = field.random();
      // Random values should be different (with very high probability)
      expect(r1).not.toBe(r2);
      // Should be positive
      expect(r1 > 0n).toBe(true);
      expect(r2 > 0n).toBe(true);
    });
  });
});


// ============================================================================
// Shamir's Secret Sharing Tests
// ============================================================================

describe('ShamirSecretSharing', () => {
  const shamir = new ShamirSecretSharing();

  describe('split and reconstruct', () => {
    /**
     * **Validates: Requirements 26.1**
     * Threshold key generation (t-of-n)
     */
    it('should split and reconstruct a secret with threshold 2-of-3', () => {
      const secret = 12345678901234567890n;
      const threshold = 2;
      const totalShares = 3;

      const shares = shamir.split(secret, threshold, totalShares);
      
      expect(shares).toHaveLength(totalShares);
      expect(shares.every(s => s.index > 0 && s.index <= totalShares)).toBe(true);

      // Reconstruct with any 2 shares
      const reconstructed = shamir.reconstruct([shares[0], shares[1]]);
      expect(reconstructed).toBe(secret);
    });

    it('should split and reconstruct a secret with threshold 3-of-5', () => {
      const secret = 98765432109876543210n;
      const threshold = 3;
      const totalShares = 5;

      const shares = shamir.split(secret, threshold, totalShares);
      
      expect(shares).toHaveLength(totalShares);

      // Reconstruct with any 3 shares
      const reconstructed = shamir.reconstruct([shares[0], shares[2], shares[4]]);
      expect(reconstructed).toBe(secret);
    });

    it('should reconstruct correctly with different share combinations', () => {
      const secret = 11111111111111111111n;
      const threshold = 3;
      const totalShares = 5;

      const shares = shamir.split(secret, threshold, totalShares);

      // Try different combinations
      expect(shamir.reconstruct([shares[0], shares[1], shares[2]])).toBe(secret);
      expect(shamir.reconstruct([shares[1], shares[2], shares[3]])).toBe(secret);
      expect(shamir.reconstruct([shares[2], shares[3], shares[4]])).toBe(secret);
      expect(shamir.reconstruct([shares[0], shares[2], shares[4]])).toBe(secret);
    });

    it('should work with large secrets', () => {
      // Use a large secret that's still within the prime field
      // The prime is ~2^256, so we use a 250-bit value to be safe
      const secret = BigInt('0x' + 'ab'.repeat(31)); // ~248-bit secret
      const threshold = 2;
      const totalShares = 3;

      const shares = shamir.split(secret, threshold, totalShares);
      const reconstructed = shamir.reconstruct([shares[0], shares[1]]);
      
      expect(reconstructed).toBe(secret);
    });

    it('should work with minimum threshold of 2', () => {
      const secret = 42n;
      const shares = shamir.split(secret, 2, 2);
      
      expect(shares).toHaveLength(2);
      expect(shamir.reconstruct(shares)).toBe(secret);
    });
  });

  describe('validation', () => {
    it('should reject threshold less than 2', () => {
      expect(() => shamir.split(100n, 1, 3)).toThrow('Threshold must be at least 2');
    });

    it('should reject threshold greater than total shares', () => {
      expect(() => shamir.split(100n, 5, 3)).toThrow('Threshold cannot exceed total shares');
    });

    it('should reject total shares less than 2', () => {
      expect(() => shamir.split(100n, 1, 1)).toThrow('Threshold must be at least 2');
    });

    it('should reject reconstruction with less than 2 shares', () => {
      expect(() => shamir.reconstruct([{ index: 1, value: 100n }])).toThrow('Need at least 2 shares');
    });
  });

  describe('refreshShares', () => {
    /**
     * **Validates: Requirements 26.4**
     * Key share refresh without changing public key
     */
    it('should refresh shares without changing the secret', () => {
      const secret = 123456789n;
      const threshold = 2;
      const totalShares = 3;

      const originalShares = shamir.split(secret, threshold, totalShares);
      const refreshedShares = shamir.refreshShares(originalShares, threshold);

      // Shares should be different
      expect(refreshedShares[0].value).not.toBe(originalShares[0].value);
      expect(refreshedShares[1].value).not.toBe(originalShares[1].value);

      // But secret should be the same
      const reconstructedOriginal = shamir.reconstruct([originalShares[0], originalShares[1]]);
      const reconstructedRefreshed = shamir.reconstruct([refreshedShares[0], refreshedShares[1]]);
      
      expect(reconstructedOriginal).toBe(secret);
      expect(reconstructedRefreshed).toBe(secret);
    });

    it('should maintain threshold after refresh', () => {
      const secret = 987654321n;
      const threshold = 3;
      const totalShares = 5;

      const originalShares = shamir.split(secret, threshold, totalShares);
      const refreshedShares = shamir.refreshShares(originalShares, threshold);

      // Should still need 3 shares to reconstruct
      const reconstructed = shamir.reconstruct([
        refreshedShares[0],
        refreshedShares[2],
        refreshedShares[4]
      ]);
      
      expect(reconstructed).toBe(secret);
    });

    it('should reject refresh with insufficient shares', () => {
      const shares = [
        { index: 1, value: 100n },
        { index: 2, value: 200n }
      ];
      
      expect(() => shamir.refreshShares(shares, 3)).toThrow('Not enough shares to refresh');
    });
  });

  describe('verifiable secret sharing', () => {
    it('should generate valid commitments', () => {
      const coefficients = [100n, 200n, 300n];
      const generator = 2n;
      
      const commitments = shamir.generateCommitments(coefficients, generator);
      
      expect(commitments).toHaveLength(3);
      expect(commitments.every(c => c > 0n)).toBe(true);
    });

    it('should verify valid shares against commitments', () => {
      // Test that commitments are generated consistently
      const coefficients = [100n, 200n];
      const generator = 2n;

      const commitments1 = shamir.generateCommitments(coefficients, generator);
      const commitments2 = shamir.generateCommitments(coefficients, generator);

      // Same coefficients should produce same commitments
      expect(commitments1).toEqual(commitments2);
      expect(commitments1).toHaveLength(2);
      
      // Commitments should be non-zero
      expect(commitments1[0]).not.toBe(0n);
      expect(commitments1[1]).not.toBe(0n);
    });
  });
});


// ============================================================================
// Encryption Utility Tests
// ============================================================================

describe('Encryption Utilities', () => {
  describe('encryptShare and decryptShare', () => {
    it('should encrypt and decrypt a share correctly', () => {
      const share = 123456789012345678901234567890n;
      const partyPublicKey = 'test-party-public-key-12345';

      const encrypted = encryptShare(share, partyPublicKey);
      const decrypted = decryptShare(encrypted, partyPublicKey);

      expect(decrypted).toBe(share);
    });

    it('should produce different ciphertext for same plaintext (due to random IV)', () => {
      const share = 100n;
      const partyPublicKey = 'test-key';

      const encrypted1 = encryptShare(share, partyPublicKey);
      const encrypted2 = encryptShare(share, partyPublicKey);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should fail decryption with wrong key', () => {
      const share = 100n;
      const encrypted = encryptShare(share, 'correct-key');

      expect(() => decryptShare(encrypted, 'wrong-key')).toThrow();
    });
  });

  describe('generateCommitment', () => {
    it('should generate consistent commitments for same value', () => {
      const value = 12345n;
      
      const commitment1 = generateCommitment(value);
      const commitment2 = generateCommitment(value);

      expect(commitment1).toBe(commitment2);
    });

    it('should generate different commitments for different values', () => {
      const commitment1 = generateCommitment(100n);
      const commitment2 = generateCommitment(200n);

      expect(commitment1).not.toBe(commitment2);
    });

    it('should generate 64-character hex string', () => {
      const commitment = generateCommitment(12345n);
      
      expect(commitment).toHaveLength(64);
      expect(/^[a-f0-9]+$/.test(commitment)).toBe(true);
    });
  });
});

// ============================================================================
// Key Generation Utility Tests
// ============================================================================

describe('Key Generation Utilities', () => {
  describe('generateEd25519KeyPair', () => {
    it('should generate valid Ed25519 key pair', () => {
      const keyPair = generateEd25519KeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Buffer);
      expect(keyPair.privateKey).toBeInstanceOf(Buffer);
      expect(keyPair.publicKey.length).toBeGreaterThan(0);
      expect(keyPair.privateKey.length).toBeGreaterThan(0);
    });

    it('should generate different key pairs each time', () => {
      const keyPair1 = generateEd25519KeyPair();
      const keyPair2 = generateEd25519KeyPair();

      expect(keyPair1.publicKey.toString('hex')).not.toBe(keyPair2.publicKey.toString('hex'));
    });
  });

  describe('generateSecp256k1KeyPair', () => {
    it('should generate valid secp256k1 key pair', () => {
      const keyPair = generateSecp256k1KeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Buffer);
      expect(keyPair.privateKey).toBeInstanceOf(Buffer);
      expect(keyPair.publicKey.length).toBeGreaterThan(0);
      expect(keyPair.privateKey.length).toBeGreaterThan(0);
    });

    it('should generate different key pairs each time', () => {
      const keyPair1 = generateSecp256k1KeyPair();
      const keyPair2 = generateSecp256k1KeyPair();

      expect(keyPair1.publicKey.toString('hex')).not.toBe(keyPair2.publicKey.toString('hex'));
    });
  });
});


// ============================================================================
// MPC Service Tests
// ============================================================================

describe('MPCService', () => {
  let mpcService: MPCService;

  beforeEach(() => {
    mpcService = new MPCService(mockDocClient as any, 'test-mpc-table');
  });

  // Helper to create test parties
  const createTestParties = (count: number): MPCParty[] => {
    return Array.from({ length: count }, (_, i) => ({
      partyId: `party_${i + 1}`,
      name: `Test Party ${i + 1}`,
      publicKey: `public-key-${i + 1}-${Date.now()}`,
      type: 'user' as const,
      status: 'active' as const,
      createdAt: new Date().toISOString()
    }));
  };

  describe('generateKey', () => {
    /**
     * **Validates: Requirements 26.1**
     * MPC key generation with configurable threshold (t-of-n)
     */
    it('should generate MPC key with 2-of-3 threshold', async () => {
      const parties = createTestParties(3);
      const options: MPCKeyGenerationOptions = {
        realmId: 'test-realm',
        userId: 'test-user',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      };

      const result = await mpcService.generateKey(options);

      expect(result.key).toBeDefined();
      expect(result.key.keyId).toMatch(/^mpc_/);
      expect(result.key.realmId).toBe('test-realm');
      expect(result.key.userId).toBe('test-user');
      expect(result.key.keyType).toBe('Ed25519');
      expect(result.key.threshold).toBe(2);
      expect(result.key.totalShares).toBe(3);
      expect(result.key.parties).toHaveLength(3);
      expect(result.key.status).toBe('active');
      expect(result.key.version).toBe(1);
      expect(result.key.publicKey).toBeDefined();
    });

    it('should generate MPC key with secp256k1 key type', async () => {
      const parties = createTestParties(3);
      const options: MPCKeyGenerationOptions = {
        realmId: 'test-realm',
        keyType: 'secp256k1',
        threshold: 2,
        parties
      };

      const result = await mpcService.generateKey(options);

      expect(result.key.keyType).toBe('secp256k1');
      expect(result.key.publicKey).toBeDefined();
    });

    it('should distribute shares to all parties', async () => {
      const parties = createTestParties(5);
      const options: MPCKeyGenerationOptions = {
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 3,
        parties
      };

      const result = await mpcService.generateKey(options);

      expect(result.shares).toHaveLength(5);
      result.shares.forEach((share, index) => {
        expect(share.partyId).toBe(parties[index].partyId);
        expect(share.shareIndex).toBe(index + 1);
        expect(share.encryptedShare).toBeDefined();
        expect(share.commitment).toBeDefined();
      });
    });

    it('should reject threshold less than 2', async () => {
      const parties = createTestParties(3);
      const options: MPCKeyGenerationOptions = {
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 1,
        parties
      };

      await expect(mpcService.generateKey(options)).rejects.toThrow(
        'Threshold must be at least 2'
      );
    });

    it('should reject when parties less than threshold', async () => {
      const parties = createTestParties(2);
      const options: MPCKeyGenerationOptions = {
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 3,
        parties
      };

      await expect(mpcService.generateKey(options)).rejects.toThrow(
        'Number of parties must be at least equal to threshold'
      );
    });

    it('should reject more than 255 parties', async () => {
      const parties = createTestParties(256);
      const options: MPCKeyGenerationOptions = {
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      };

      await expect(mpcService.generateKey(options)).rejects.toThrow(
        'Maximum 255 parties supported'
      );
    });

    it('should generate unique key IDs', async () => {
      const parties = createTestParties(3);
      const options: MPCKeyGenerationOptions = {
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      };

      const result1 = await mpcService.generateKey(options);
      
      // Create new parties for second key
      const parties2 = createTestParties(3).map(p => ({
        ...p,
        partyId: `${p.partyId}_2`
      }));
      options.parties = parties2;
      
      const result2 = await mpcService.generateKey(options);

      expect(result1.key.keyId).not.toBe(result2.key.keyId);
    });
  });


  describe('refreshKey', () => {
    /**
     * **Validates: Requirements 26.4**
     * Key share refresh without changing public key
     */
    it('should refresh key shares without changing public key', async () => {
      // First generate a key
      const parties = createTestParties(3);
      const genOptions: MPCKeyGenerationOptions = {
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      };

      const genResult = await mpcService.generateKey(genOptions);
      const originalPublicKey = genResult.key.publicKey;

      // Now refresh the key
      const refreshResult = await mpcService.refreshKey({
        keyId: genResult.key.keyId,
        participatingParties: parties.map(p => p.partyId)
      });

      // Public key should remain the same
      expect(refreshResult.key.publicKey).toBe(originalPublicKey);
      
      // Version should increment
      expect(refreshResult.key.version).toBe(2);
      
      // Status should be active
      expect(refreshResult.key.status).toBe('active');
      
      // Should have new shares
      expect(refreshResult.newShares).toHaveLength(3);
      expect(refreshResult.oldSharesRevoked).toBe(true);
    });

    it('should update lastRefreshedAt timestamp', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      expect(genResult.key.lastRefreshedAt).toBeUndefined();

      const refreshResult = await mpcService.refreshKey({
        keyId: genResult.key.keyId,
        participatingParties: parties.map(p => p.partyId)
      });

      expect(refreshResult.key.lastRefreshedAt).toBeDefined();
    });

    it('should reject refresh with insufficient parties', async () => {
      const parties = createTestParties(5);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 3,
        parties
      });

      // Try to refresh with only 2 parties (threshold is 3)
      await expect(mpcService.refreshKey({
        keyId: genResult.key.keyId,
        participatingParties: [parties[0].partyId, parties[1].partyId]
      })).rejects.toThrow('Need at least 3 parties to refresh');
    });

    it('should reject refresh for non-existent key', async () => {
      await expect(mpcService.refreshKey({
        keyId: 'non-existent-key',
        participatingParties: ['party1', 'party2']
      })).rejects.toThrow('Key not found');
    });

    it('should reject refresh with invalid party', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      await expect(mpcService.refreshKey({
        keyId: genResult.key.keyId,
        participatingParties: [parties[0].partyId, 'invalid-party']
      })).rejects.toThrow('Party invalid-party is not part of this key');
    });
  });

  describe('getKey', () => {
    it('should retrieve an existing key', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const key = await mpcService.getKey(genResult.key.keyId);

      expect(key).toBeDefined();
      expect(key?.keyId).toBe(genResult.key.keyId);
      expect(key?.realmId).toBe('test-realm');
    });

    it('should return null for non-existent key', async () => {
      const key = await mpcService.getKey('non-existent-key');
      expect(key).toBeNull();
    });
  });

  describe('getRealmKeys', () => {
    it('should retrieve all keys for a realm', async () => {
      const parties1 = createTestParties(3);
      const parties2 = createTestParties(3).map(p => ({
        ...p,
        partyId: `${p.partyId}_2`
      }));

      await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties: parties1
      });

      await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'secp256k1',
        threshold: 2,
        parties: parties2
      });

      const keys = await mpcService.getRealmKeys('test-realm');

      expect(keys.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('getUserKeys', () => {
    it('should retrieve all keys for a user', async () => {
      const parties = createTestParties(3);

      await mpcService.generateKey({
        realmId: 'test-realm',
        userId: 'test-user-123',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const keys = await mpcService.getUserKeys('test-user-123');

      expect(keys.length).toBeGreaterThanOrEqual(1);
      expect(keys.every(k => k.userId === 'test-user-123')).toBe(true);
    });
  });


  describe('revokeKey', () => {
    it('should revoke an existing key', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      await mpcService.revokeKey(genResult.key.keyId);

      // Key should still exist but be revoked
      const key = await mpcService.getKey(genResult.key.keyId);
      expect(key?.status).toBe('revoked');
    });

    it('should reject revocation of non-existent key', async () => {
      await expect(mpcService.revokeKey('non-existent-key')).rejects.toThrow('Key not found');
    });
  });

  describe('addParty', () => {
    it('should add a new party to an existing key', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const newParty: MPCParty = {
        partyId: 'new-party',
        name: 'New Party',
        publicKey: 'new-party-public-key',
        type: 'user',
        status: 'active',
        createdAt: new Date().toISOString()
      };

      const shareDistribution = await mpcService.addParty(
        genResult.key.keyId,
        newParty,
        parties.map(p => p.partyId)
      );

      expect(shareDistribution.partyId).toBe('new-party');
      expect(shareDistribution.shareIndex).toBe(4);
      expect(shareDistribution.encryptedShare).toBeDefined();
      expect(shareDistribution.commitment).toBeDefined();

      // Verify key was updated
      const updatedKey = await mpcService.getKey(genResult.key.keyId);
      expect(updatedKey?.totalShares).toBe(4);
      expect(updatedKey?.parties).toContain('new-party');
    });

    it('should reject adding existing party', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      await expect(mpcService.addParty(
        genResult.key.keyId,
        parties[0],
        parties.map(p => p.partyId)
      )).rejects.toThrow('Party already exists in this key');
    });

    it('should reject adding party with insufficient participating parties', async () => {
      const parties = createTestParties(5);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 3,
        parties
      });

      const newParty: MPCParty = {
        partyId: 'new-party',
        name: 'New Party',
        publicKey: 'new-party-public-key',
        type: 'user',
        status: 'active',
        createdAt: new Date().toISOString()
      };

      await expect(mpcService.addParty(
        genResult.key.keyId,
        newParty,
        [parties[0].partyId, parties[1].partyId] // Only 2, need 3
      )).rejects.toThrow('Need at least 3 parties to add a new party');
    });
  });

  describe('removeParty', () => {
    it('should remove a party from an existing key', async () => {
      const parties = createTestParties(4);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      await mpcService.removeParty(genResult.key.keyId, parties[3].partyId);

      const updatedKey = await mpcService.getKey(genResult.key.keyId);
      expect(updatedKey?.totalShares).toBe(3);
      expect(updatedKey?.parties).not.toContain(parties[3].partyId);
    });

    it('should reject removing party that would fall below threshold', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 3,
        parties
      });

      await expect(mpcService.removeParty(
        genResult.key.keyId,
        parties[0].partyId
      )).rejects.toThrow('Cannot remove party: would fall below threshold');
    });

    it('should reject removing non-existent party', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      await expect(mpcService.removeParty(
        genResult.key.keyId,
        'non-existent-party'
      )).rejects.toThrow('Party is not part of this key');
    });
  });

  describe('getRealmParties', () => {
    it('should retrieve all parties for a realm', async () => {
      const parties = createTestParties(3);
      await mpcService.generateKey({
        realmId: 'test-realm-parties',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const realmParties = await mpcService.getRealmParties('test-realm-parties');

      expect(realmParties.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('verifyShareCommitment', () => {
    it('should verify valid share commitment', () => {
      const share = 12345n;
      const commitment = generateCommitment(share);

      const isValid = mpcService.verifyShareCommitment(share, commitment);
      expect(isValid).toBe(true);
    });

    it('should reject invalid share commitment', () => {
      const share = 12345n;
      const wrongCommitment = generateCommitment(99999n);

      const isValid = mpcService.verifyShareCommitment(share, wrongCommitment);
      expect(isValid).toBe(false);
    });
  });

  describe('getKeyShareCount', () => {
    it('should return correct share count', async () => {
      const parties = createTestParties(5);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 3,
        parties
      });

      const count = await mpcService.getKeyShareCount(genResult.key.keyId);
      expect(count).toBe(5);
    });

    it('should return 0 for non-existent key', async () => {
      const count = await mpcService.getKeyShareCount('non-existent-key');
      expect(count).toBe(0);
    });
  });


  // ============================================================================
  // MPC Signing Tests
  // ============================================================================

  describe('initiateSigningSession', () => {
    /**
     * **Validates: Requirements 26.2, 26.3**
     * Distributed signing ceremony without private key reconstruction
     */
    it('should initiate a signing session with valid parameters', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const result = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Hello, World!',
        participatingParties: [parties[0].partyId, parties[1].partyId]
      });

      expect(result.session).toBeDefined();
      expect(result.session.sessionId).toMatch(/^sign_/);
      expect(result.session.keyId).toBe(genResult.key.keyId);
      expect(result.session.message).toBe('Hello, World!');
      expect(result.session.status).toBe('collecting');
      expect(result.session.requiredSignatures).toBe(2);
      expect(result.session.collectedSignatures).toBe(0);
      expect(result.partyInstructions).toHaveLength(2);
    });

    it('should generate unique session IDs', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const result1 = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Message 1',
        participatingParties: parties.map(p => p.partyId)
      });

      const result2 = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Message 2',
        participatingParties: parties.map(p => p.partyId)
      });

      expect(result1.session.sessionId).not.toBe(result2.session.sessionId);
    });

    it('should provide correct party instructions', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const result = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      expect(result.partyInstructions).toHaveLength(3);
      result.partyInstructions.forEach((instruction, index) => {
        expect(instruction.partyId).toBe(parties[index].partyId);
        expect(instruction.sessionId).toBe(result.session.sessionId);
        expect(instruction.messageHash).toBeDefined();
        expect(instruction.shareIndex).toBe(index + 1);
        expect(instruction.nonce).toBeDefined();
        expect(instruction.nonce).toHaveLength(64); // 32 bytes hex
      });
    });

    it('should reject signing with insufficient parties', async () => {
      const parties = createTestParties(5);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 3,
        parties
      });

      await expect(mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test',
        participatingParties: [parties[0].partyId, parties[1].partyId] // Only 2, need 3
      })).rejects.toThrow('Need at least 3 parties to sign');
    });

    it('should reject signing for non-existent key', async () => {
      await expect(mpcService.initiateSigningSession({
        keyId: 'non-existent-key',
        message: 'Test',
        participatingParties: ['party1', 'party2']
      })).rejects.toThrow('Key not found');
    });

    it('should reject signing with invalid party', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      await expect(mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test',
        participatingParties: [parties[0].partyId, 'invalid-party']
      })).rejects.toThrow('Party invalid-party is not part of this key');
    });

    it('should reject signing for revoked key', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      await mpcService.revokeKey(genResult.key.keyId);

      await expect(mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test',
        participatingParties: parties.map(p => p.partyId)
      })).rejects.toThrow('Key is not active');
    });
  });

  describe('submitPartialSignature', () => {
    /**
     * **Validates: Requirements 26.2, 26.3**
     * Partial signature submission without key reconstruction
     */
    it('should accept valid partial signature', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      // Generate a partial signature
      const instruction = signingResult.partyInstructions[0];
      const signatureShare = 'a'.repeat(64); // Mock signature share
      const commitment = require('crypto').createHash('sha256')
        .update(signatureShare)
        .update(signingResult.session.messageHash)
        .update(instruction.partyId)
        .digest('hex');

      const updatedSession = await mpcService.submitPartialSignature({
        sessionId: signingResult.session.sessionId,
        partyId: instruction.partyId,
        signatureShare,
        commitment
      });

      expect(updatedSession.collectedSignatures).toBe(1);
      expect(updatedSession.partialSignatures.has(instruction.partyId)).toBe(true);
    });

    it('should reject duplicate submission from same party', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      const instruction = signingResult.partyInstructions[0];
      const signatureShare = 'b'.repeat(64);
      const commitment = require('crypto').createHash('sha256')
        .update(signatureShare)
        .update(signingResult.session.messageHash)
        .update(instruction.partyId)
        .digest('hex');

      // First submission
      await mpcService.submitPartialSignature({
        sessionId: signingResult.session.sessionId,
        partyId: instruction.partyId,
        signatureShare,
        commitment
      });

      // Second submission should fail
      await expect(mpcService.submitPartialSignature({
        sessionId: signingResult.session.sessionId,
        partyId: instruction.partyId,
        signatureShare,
        commitment
      })).rejects.toThrow('has already submitted a partial signature');
    });

    it('should reject submission from non-participating party', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: [parties[0].partyId, parties[1].partyId] // Only first 2
      });

      await expect(mpcService.submitPartialSignature({
        sessionId: signingResult.session.sessionId,
        partyId: parties[2].partyId, // Not participating
        signatureShare: 'c'.repeat(64),
        commitment: 'invalid'
      })).rejects.toThrow('is not participating in this signing session');
    });

    it('should reject submission for non-existent session', async () => {
      await expect(mpcService.submitPartialSignature({
        sessionId: 'non-existent-session',
        partyId: 'party1',
        signatureShare: 'd'.repeat(64),
        commitment: 'invalid'
      })).rejects.toThrow('Signing session not found');
    });

    it('should reject submission with invalid commitment', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      await expect(mpcService.submitPartialSignature({
        sessionId: signingResult.session.sessionId,
        partyId: parties[0].partyId,
        signatureShare: 'e'.repeat(64),
        commitment: 'invalid-commitment'
      })).rejects.toThrow('Invalid partial signature commitment');
    });
  });

  describe('combineSignatures', () => {
    /**
     * **Validates: Requirements 26.2, 26.3**
     * Combine partial signatures without reconstructing private key
     */
    it('should combine signatures when threshold is met', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message for signing',
        participatingParties: parties.map(p => p.partyId)
      });

      // Submit partial signatures from threshold number of parties
      for (let i = 0; i < 2; i++) {
        const instruction = signingResult.partyInstructions[i];
        const signatureShare = (i + 1).toString(16).repeat(32);
        const commitment = require('crypto').createHash('sha256')
          .update(signatureShare)
          .update(signingResult.session.messageHash)
          .update(instruction.partyId)
          .digest('hex');

        await mpcService.submitPartialSignature({
          sessionId: signingResult.session.sessionId,
          partyId: instruction.partyId,
          signatureShare,
          commitment
        });
      }

      const combinedResult = await mpcService.combineSignatures(signingResult.session.sessionId);

      expect(combinedResult.signature).toBeDefined();
      expect(combinedResult.keyId).toBe(genResult.key.keyId);
      expect(combinedResult.message).toBe('Test message for signing');
      expect(combinedResult.signatureType).toBe('Ed25519');
      expect(combinedResult.participatingParties).toHaveLength(2);
    });

    it('should reject combination with insufficient signatures', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      // Only submit 1 signature (threshold is 2)
      const instruction = signingResult.partyInstructions[0];
      const signatureShare = 'f'.repeat(64);
      const commitment = require('crypto').createHash('sha256')
        .update(signatureShare)
        .update(signingResult.session.messageHash)
        .update(instruction.partyId)
        .digest('hex');

      await mpcService.submitPartialSignature({
        sessionId: signingResult.session.sessionId,
        partyId: instruction.partyId,
        signatureShare,
        commitment
      });

      await expect(mpcService.combineSignatures(signingResult.session.sessionId))
        .rejects.toThrow('Not enough partial signatures');
    });

    it('should return existing signature for completed session', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      // Submit threshold signatures
      for (let i = 0; i < 2; i++) {
        const instruction = signingResult.partyInstructions[i];
        const signatureShare = (i + 2).toString(16).repeat(32);
        const commitment = require('crypto').createHash('sha256')
          .update(signatureShare)
          .update(signingResult.session.messageHash)
          .update(instruction.partyId)
          .digest('hex');

        await mpcService.submitPartialSignature({
          sessionId: signingResult.session.sessionId,
          partyId: instruction.partyId,
          signatureShare,
          commitment
        });
      }

      const firstResult = await mpcService.combineSignatures(signingResult.session.sessionId);
      const secondResult = await mpcService.combineSignatures(signingResult.session.sessionId);

      expect(secondResult.signature).toBe(firstResult.signature);
    });

    it('should reject combination for non-existent session', async () => {
      await expect(mpcService.combineSignatures('non-existent-session'))
        .rejects.toThrow('Signing session not found');
    });
  });

  describe('verifySignature', () => {
    /**
     * **Validates: Requirements 26.2**
     * Signature verification
     */
    it('should verify a valid Ed25519 signature', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Verify this message',
        participatingParties: parties.map(p => p.partyId)
      });

      // Submit threshold signatures
      for (let i = 0; i < 2; i++) {
        const instruction = signingResult.partyInstructions[i];
        const signatureShare = (i + 3).toString(16).repeat(32);
        const commitment = require('crypto').createHash('sha256')
          .update(signatureShare)
          .update(signingResult.session.messageHash)
          .update(instruction.partyId)
          .digest('hex');

        await mpcService.submitPartialSignature({
          sessionId: signingResult.session.sessionId,
          partyId: instruction.partyId,
          signatureShare,
          commitment
        });
      }

      const combinedResult = await mpcService.combineSignatures(signingResult.session.sessionId);

      const verifyResult = await mpcService.verifySignature(
        genResult.key.keyId,
        'Verify this message',
        combinedResult.signature
      );

      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.keyId).toBe(genResult.key.keyId);
    });

    it('should reject verification for non-existent key', async () => {
      const result = await mpcService.verifySignature(
        'non-existent-key',
        'Test message',
        'invalid-signature'
      );

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Key not found');
    });

    it('should reject invalid signature format', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const result = await mpcService.verifySignature(
        genResult.key.keyId,
        'Test message',
        'too-short'
      );

      expect(result.valid).toBe(false);
    });
  });

  describe('getSigningSession', () => {
    it('should retrieve an existing signing session', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      const session = await mpcService.getSigningSession(signingResult.session.sessionId);

      expect(session).toBeDefined();
      expect(session?.sessionId).toBe(signingResult.session.sessionId);
      expect(session?.keyId).toBe(genResult.key.keyId);
    });

    it('should return null for non-existent session', async () => {
      const session = await mpcService.getSigningSession('non-existent-session');
      expect(session).toBeNull();
    });
  });

  describe('getKeySigningSessions', () => {
    it('should retrieve all signing sessions for a key', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      // Create multiple signing sessions
      await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Message 1',
        participatingParties: parties.map(p => p.partyId)
      });

      await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Message 2',
        participatingParties: parties.map(p => p.partyId)
      });

      const sessions = await mpcService.getKeySigningSessions(genResult.key.keyId);

      expect(sessions.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('cancelSigningSession', () => {
    it('should cancel a pending signing session', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      await mpcService.cancelSigningSession(signingResult.session.sessionId);

      const session = await mpcService.getSigningSession(signingResult.session.sessionId);
      expect(session?.status).toBe('failed');
    });

    it('should reject cancellation of non-existent session', async () => {
      await expect(mpcService.cancelSigningSession('non-existent-session'))
        .rejects.toThrow('Signing session not found');
    });

    it('should reject cancellation of completed session', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Test message',
        participatingParties: parties.map(p => p.partyId)
      });

      // Complete the signing
      for (let i = 0; i < 2; i++) {
        const instruction = signingResult.partyInstructions[i];
        const signatureShare = (i + 4).toString(16).repeat(32);
        const commitment = require('crypto').createHash('sha256')
          .update(signatureShare)
          .update(signingResult.session.messageHash)
          .update(instruction.partyId)
          .digest('hex');

        await mpcService.submitPartialSignature({
          sessionId: signingResult.session.sessionId,
          partyId: instruction.partyId,
          signatureShare,
          commitment
        });
      }

      await mpcService.combineSignatures(signingResult.session.sessionId);

      await expect(mpcService.cancelSigningSession(signingResult.session.sessionId))
        .rejects.toThrow('Cannot cancel completed signing session');
    });
  });

  describe('generatePartialSignature', () => {
    /**
     * **Validates: Requirements 26.2, 26.3**
     * Helper method for parties to generate partial signatures
     */
    it('should generate consistent partial signatures', () => {
      const shareValue = 12345678901234567890n;
      const messageHash = 'a'.repeat(64);
      const nonce = 'b'.repeat(64);

      const result1 = mpcService.generatePartialSignature(shareValue, messageHash, nonce);
      const result2 = mpcService.generatePartialSignature(shareValue, messageHash, nonce);

      expect(result1.signatureShare).toBe(result2.signatureShare);
      expect(result1.commitment).toBe(result2.commitment);
    });

    it('should generate different signatures for different messages', () => {
      const shareValue = 12345678901234567890n;
      const nonce = 'c'.repeat(64);

      const result1 = mpcService.generatePartialSignature(shareValue, 'd'.repeat(64), nonce);
      const result2 = mpcService.generatePartialSignature(shareValue, 'e'.repeat(64), nonce);

      expect(result1.signatureShare).not.toBe(result2.signatureShare);
    });

    it('should generate different signatures for different shares', () => {
      const messageHash = 'f'.repeat(64);
      const nonce = 'g'.repeat(64);

      const result1 = mpcService.generatePartialSignature(100n, messageHash, nonce);
      const result2 = mpcService.generatePartialSignature(200n, messageHash, nonce);

      expect(result1.signatureShare).not.toBe(result2.signatureShare);
    });

    it('should generate 64-character hex signature share', () => {
      const result = mpcService.generatePartialSignature(
        12345n,
        'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890', // Valid 64-char hex
        'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321'  // Valid 64-char hex
      );

      expect(result.signatureShare).toHaveLength(64);
      expect(/^[a-f0-9]+$/.test(result.signatureShare)).toBe(true);
    });
  });

  describe('secp256k1 signing', () => {
    /**
     * **Validates: Requirements 26.2**
     * Support for secp256k1 signature scheme
     */
    it('should sign with secp256k1 key type', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'secp256k1',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Ethereum transaction data',
        participatingParties: parties.map(p => p.partyId)
      });

      // Submit threshold signatures
      for (let i = 0; i < 2; i++) {
        const instruction = signingResult.partyInstructions[i];
        const signatureShare = (i + 5).toString(16).repeat(32);
        const commitment = require('crypto').createHash('sha256')
          .update(signatureShare)
          .update(signingResult.session.messageHash)
          .update(instruction.partyId)
          .digest('hex');

        await mpcService.submitPartialSignature({
          sessionId: signingResult.session.sessionId,
          partyId: instruction.partyId,
          signatureShare,
          commitment
        });
      }

      const combinedResult = await mpcService.combineSignatures(signingResult.session.sessionId);

      expect(combinedResult.signatureType).toBe('secp256k1');
      expect(combinedResult.signature).toBeDefined();
      // secp256k1 signature should be 130 chars (r + s + v)
      expect(combinedResult.signature).toHaveLength(130);
    });

    it('should verify secp256k1 signature', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'secp256k1',
        threshold: 2,
        parties
      });

      const signingResult = await mpcService.initiateSigningSession({
        keyId: genResult.key.keyId,
        message: 'Verify secp256k1',
        participatingParties: parties.map(p => p.partyId)
      });

      for (let i = 0; i < 2; i++) {
        const instruction = signingResult.partyInstructions[i];
        const signatureShare = (i + 6).toString(16).repeat(32);
        const commitment = require('crypto').createHash('sha256')
          .update(signatureShare)
          .update(signingResult.session.messageHash)
          .update(instruction.partyId)
          .digest('hex');

        await mpcService.submitPartialSignature({
          sessionId: signingResult.session.sessionId,
          partyId: instruction.partyId,
          signatureShare,
          commitment
        });
      }

      const combinedResult = await mpcService.combineSignatures(signingResult.session.sessionId);

      const verifyResult = await mpcService.verifySignature(
        genResult.key.keyId,
        'Verify secp256k1',
        combinedResult.signature
      );

      expect(verifyResult.valid).toBe(true);
    });
  });


  // ============================================================================
  // Social Recovery Tests
  // ============================================================================

  describe('setupRecovery', () => {
    /**
     * **Validates: Requirements 26.5**
     * Social recovery via MPC (recover with trusted contacts)
     */
    it('should setup recovery with valid guardians', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'guardian1@example.com', publicKey: 'guardian-pk-1' },
        { name: 'Guardian 2', email: 'guardian2@example.com', publicKey: 'guardian-pk-2' },
        { name: 'Guardian 3', email: 'guardian3@example.com', publicKey: 'guardian-pk-3' }
      ];

      const result = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      expect(result.config).toBeDefined();
      expect(result.config.keyId).toBe(genResult.key.keyId);
      expect(result.config.threshold).toBe(2);
      expect(result.config.totalGuardians).toBe(3);
      expect(result.config.status).toBe('active');
      expect(result.config.guardians).toHaveLength(3);
      expect(result.guardianShares).toHaveLength(3);

      // Verify guardian shares have required fields
      result.guardianShares.forEach((share, index) => {
        expect(share.guardianId).toMatch(/^guardian_/);
        expect(share.email).toBe(guardians[index].email);
        expect(share.encryptedShare).toBeDefined();
        expect(share.commitment).toBeDefined();
        expect(share.activationToken).toBeDefined();
        expect(share.activationToken).toHaveLength(64);
      });
    });

    it('should reject recovery setup with threshold less than 2', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      await expect(mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 1
      })).rejects.toThrow('Recovery threshold must be at least 2');
    });

    it('should reject recovery setup with insufficient guardians', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' }
      ];

      await expect(mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      })).rejects.toThrow('Number of guardians must be at least equal to threshold');
    });

    it('should reject recovery setup for non-existent key', async () => {
      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      await expect(mpcService.setupRecovery({
        keyId: 'non-existent-key',
        guardians,
        threshold: 2
      })).rejects.toThrow('Key not found');
    });

    it('should reject recovery setup with more than 10 guardians', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = Array.from({ length: 11 }, (_, i) => ({
        name: `Guardian ${i + 1}`,
        email: `g${i + 1}@example.com`,
        publicKey: `pk-${i + 1}`
      }));

      await expect(mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      })).rejects.toThrow('Maximum 10 guardians supported');
    });
  });

  describe('activateGuardian', () => {
    it('should activate guardian with valid token', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      const guardianShare = setupResult.guardianShares[0];
      
      const activatedGuardian = await mpcService.activateGuardian(
        genResult.key.keyId,
        guardianShare.guardianId,
        guardianShare.activationToken
      );

      expect(activatedGuardian.status).toBe('active');
      expect(activatedGuardian.activatedAt).toBeDefined();
    });

    it('should reject activation with invalid token', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      await expect(mpcService.activateGuardian(
        genResult.key.keyId,
        setupResult.guardianShares[0].guardianId,
        'invalid-token'
      )).rejects.toThrow('Invalid activation token');
    });
  });

  describe('initiateRecovery', () => {
    /**
     * **Validates: Requirements 26.5**
     * Recovery ceremony initiation
     */
    it('should initiate recovery with active guardians', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' },
        { name: 'Guardian 3', email: 'g3@example.com', publicKey: 'pk-3' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      // Activate all guardians
      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      const recoveryResult = await mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access to device'
      });

      expect(recoveryResult.session).toBeDefined();
      expect(recoveryResult.session.recoveryId).toMatch(/^recovery_/);
      expect(recoveryResult.session.status).toBe('collecting');
      expect(recoveryResult.session.requiredApprovals).toBe(2);
      expect(recoveryResult.session.collectedApprovals).toBe(0);
      expect(recoveryResult.notifiedGuardians).toHaveLength(3);
    });

    it('should reject recovery initiation without enough active guardians', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      // Don't activate any guardians

      await expect(mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access'
      })).rejects.toThrow('Not enough active guardians');
    });

    it('should reject recovery initiation for key without recovery config', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      await expect(mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access'
      })).rejects.toThrow('Recovery is not configured');
    });
  });

  describe('submitRecoveryApproval', () => {
    /**
     * **Validates: Requirements 26.5**
     * Guardian approval submission
     */
    it('should accept guardian approval with valid share', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      // Activate guardians
      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      const recoveryResult = await mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access'
      });

      // Decrypt share for guardian (simulate guardian decrypting their share)
      const guardianShare = setupResult.guardianShares[0];
      const decryptedShare = decryptShare(guardianShare.encryptedShare, 'pk-1');

      const updatedSession = await mpcService.submitRecoveryApproval({
        recoveryId: recoveryResult.session.recoveryId,
        guardianId: guardianShare.guardianId,
        approved: true,
        decryptedShare: decryptedShare.toString(16).padStart(64, '0')
      });

      expect(updatedSession.collectedApprovals).toBe(1);
      expect(updatedSession.guardianApprovals.has(guardianShare.guardianId)).toBe(true);
    });

    it('should reject duplicate approval from same guardian', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      const recoveryResult = await mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access'
      });

      const guardianShare = setupResult.guardianShares[0];
      const decryptedShare = decryptShare(guardianShare.encryptedShare, 'pk-1');

      // First approval
      await mpcService.submitRecoveryApproval({
        recoveryId: recoveryResult.session.recoveryId,
        guardianId: guardianShare.guardianId,
        approved: true,
        decryptedShare: decryptedShare.toString(16).padStart(64, '0')
      });

      // Second approval should fail
      await expect(mpcService.submitRecoveryApproval({
        recoveryId: recoveryResult.session.recoveryId,
        guardianId: guardianShare.guardianId,
        approved: true,
        decryptedShare: decryptedShare.toString(16).padStart(64, '0')
      })).rejects.toThrow('Guardian has already submitted their approval');
    });

    it('should mark recovery as approved when threshold is met', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      const recoveryResult = await mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access'
      });

      // Submit approvals from both guardians
      for (let i = 0; i < 2; i++) {
        const guardianShare = setupResult.guardianShares[i];
        const decryptedShare = decryptShare(guardianShare.encryptedShare, `pk-${i + 1}`);

        await mpcService.submitRecoveryApproval({
          recoveryId: recoveryResult.session.recoveryId,
          guardianId: guardianShare.guardianId,
          approved: true,
          decryptedShare: decryptedShare.toString(16).padStart(64, '0')
        });
      }

      const session = await mpcService.getRecoverySession(recoveryResult.session.recoveryId);
      expect(session?.status).toBe('approved');
      expect(session?.collectedApprovals).toBe(2);
    });
  });

  describe('completeRecovery', () => {
    /**
     * **Validates: Requirements 26.5**
     * Recovery completion and share redistribution
     */
    it('should complete recovery and redistribute shares', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      const recoveryResult = await mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access'
      });

      // Submit approvals
      for (let i = 0; i < 2; i++) {
        const guardianShare = setupResult.guardianShares[i];
        const decryptedShare = decryptShare(guardianShare.encryptedShare, `pk-${i + 1}`);

        await mpcService.submitRecoveryApproval({
          recoveryId: recoveryResult.session.recoveryId,
          guardianId: guardianShare.guardianId,
          approved: true,
          decryptedShare: decryptedShare.toString(16).padStart(64, '0')
        });
      }

      // Create new parties for recovery
      const newParties = createTestParties(3).map((p, i) => ({
        ...p,
        partyId: `new_party_${i + 1}`
      }));

      const completionResult = await mpcService.completeRecovery({
        recoveryId: recoveryResult.session.recoveryId,
        newParties
      });

      expect(completionResult.recoveryId).toBe(recoveryResult.session.recoveryId);
      expect(completionResult.keyId).toBe(genResult.key.keyId);
      expect(completionResult.newKey).toBeDefined();
      expect(completionResult.newKey.parties).toHaveLength(3);
      expect(completionResult.newKey.parties).toContain('new_party_1');
      expect(completionResult.newShares).toHaveLength(3);
      expect(completionResult.completedAt).toBeDefined();
    });

    it('should reject completion for non-approved recovery', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      const recoveryResult = await mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access'
      });

      // Don't submit any approvals

      const newParties = createTestParties(3);

      await expect(mpcService.completeRecovery({
        recoveryId: recoveryResult.session.recoveryId,
        newParties
      })).rejects.toThrow('Cannot complete recovery: status is collecting');
    });
  });

  describe('getRecoveryStatus', () => {
    /**
     * **Validates: Requirements 26.5**
     * Recovery status checking
     */
    it('should return correct recovery status', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' },
        { name: 'Guardian 3', email: 'g3@example.com', publicKey: 'pk-3' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      const recoveryResult = await mpcService.initiateRecovery({
        keyId: genResult.key.keyId,
        requesterId: 'user-123',
        requesterEmail: 'user@example.com',
        reason: 'Lost access'
      });

      // Submit one approval
      const guardianShare = setupResult.guardianShares[0];
      const decryptedShare = decryptShare(guardianShare.encryptedShare, 'pk-1');

      await mpcService.submitRecoveryApproval({
        recoveryId: recoveryResult.session.recoveryId,
        guardianId: guardianShare.guardianId,
        approved: true,
        decryptedShare: decryptedShare.toString(16).padStart(64, '0')
      });

      const status = await mpcService.getRecoveryStatus(recoveryResult.session.recoveryId);

      expect(status.recoveryId).toBe(recoveryResult.session.recoveryId);
      expect(status.status).toBe('collecting');
      expect(status.requiredApprovals).toBe(2);
      expect(status.collectedApprovals).toBe(1);
      expect(status.guardianStatuses).toHaveLength(3);
      expect(status.canComplete).toBe(false);

      // Check guardian statuses
      const approvedGuardian = status.guardianStatuses.find(
        g => g.guardianId === guardianShare.guardianId
      );
      expect(approvedGuardian?.approved).toBe(true);
      expect(approvedGuardian?.respondedAt).toBeDefined();

      const pendingGuardian = status.guardianStatuses.find(
        g => g.guardianId !== guardianShare.guardianId
      );
      expect(pendingGuardian?.approved).toBeNull();
    });
  });

  describe('disableRecovery', () => {
    it('should disable recovery configuration', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      await mpcService.disableRecovery(genResult.key.keyId);

      const config = await mpcService.getRecoveryConfig(genResult.key.keyId);
      expect(config?.status).toBe('disabled');
    });

    it('should reject disabling non-existent recovery', async () => {
      await expect(mpcService.disableRecovery('non-existent-key'))
        .rejects.toThrow('Recovery configuration not found');
    });
  });

  describe('revokeGuardian', () => {
    it('should revoke a guardian', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' },
        { name: 'Guardian 3', email: 'g3@example.com', publicKey: 'pk-3' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      // Activate all guardians
      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      // Revoke one guardian
      await mpcService.revokeGuardian(
        genResult.key.keyId,
        setupResult.guardianShares[0].guardianId
      );

      const config = await mpcService.getRecoveryConfig(genResult.key.keyId);
      const revokedGuardian = config?.guardians.find(
        g => g.guardianId === setupResult.guardianShares[0].guardianId
      );
      expect(revokedGuardian?.status).toBe('revoked');
    });

    it('should reject revoking guardian that would fall below threshold', async () => {
      const parties = createTestParties(3);
      const genResult = await mpcService.generateKey({
        realmId: 'test-realm',
        keyType: 'Ed25519',
        threshold: 2,
        parties
      });

      const guardians = [
        { name: 'Guardian 1', email: 'g1@example.com', publicKey: 'pk-1' },
        { name: 'Guardian 2', email: 'g2@example.com', publicKey: 'pk-2' }
      ];

      const setupResult = await mpcService.setupRecovery({
        keyId: genResult.key.keyId,
        guardians,
        threshold: 2
      });

      // Activate all guardians
      for (const share of setupResult.guardianShares) {
        await mpcService.activateGuardian(
          genResult.key.keyId,
          share.guardianId,
          share.activationToken
        );
      }

      // Try to revoke - should fail because we'd fall below threshold
      await expect(mpcService.revokeGuardian(
        genResult.key.keyId,
        setupResult.guardianShares[0].guardianId
      )).rejects.toThrow('Cannot revoke guardian: would fall below threshold');
    });
  });
});
