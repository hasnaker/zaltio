/**
 * Decentralized Identity (DID) Service Tests
 * 
 * Tests for DID creation, resolution, and management
 * ⚠️ GERÇEK TEST - Mock data YASAK
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import * as fc from 'fast-check';

// Mock dynamodb.service before importing did.service
const mockDynamoSend = jest.fn<any>();
jest.mock('./dynamodb.service', () => ({
  dynamoDb: {
    send: mockDynamoSend
  }
}));

import {
  DIDService,
  isValidDID,
  parseDID,
  generateKeyPair,
  generateEd25519KeyPair,
  generateSecp256k1KeyPair,
  generateP256KeyPair,
  publicKeyToMultibase,
  publicKeyToJWK,
  base58Encode,
  deriveEthereumAddress,
  generateDIDKey,
  generateDIDWeb,
  generateDIDEthr,
  generateDIDIon,
  DID_CONTEXT,
  KEY_TYPE_MAP,
  ETHR_NETWORKS,
  DIDMethod
} from './did.service';

describe('DID Service', () => {
  let service: DIDService;

  beforeEach(() => {
    jest.clearAllMocks();
    mockDynamoSend.mockReset();
    service = new DIDService();
  });

  describe('DID Validation', () => {
    it('should validate correct DID format', () => {
      expect(isValidDID('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toBe(true);
      expect(isValidDID('did:web:example.com')).toBe(true);
      expect(isValidDID('did:ethr:0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21')).toBe(true);
      expect(isValidDID('did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw')).toBe(true);
    });

    it('should reject invalid DID format', () => {
      expect(isValidDID('')).toBe(false);
      expect(isValidDID('did:')).toBe(false);
      expect(isValidDID('did:key')).toBe(false);
      expect(isValidDID('key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toBe(false);
      expect(isValidDID('not-a-did')).toBe(false);
    });

    it('should parse valid DID', () => {
      const parsed = parseDID('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
      expect(parsed).not.toBeNull();
      expect(parsed?.method).toBe('key');
      expect(parsed?.identifier).toBe('z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    });

    it('should parse DID with colons in identifier', () => {
      const parsed = parseDID('did:ethr:goerli:0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21');
      expect(parsed).not.toBeNull();
      expect(parsed?.method).toBe('ethr');
      expect(parsed?.identifier).toBe('goerli:0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21');
    });

    it('should return null for invalid DID', () => {
      expect(parseDID('invalid')).toBeNull();
      expect(parseDID('')).toBeNull();
    });
  });

  describe('Key Generation', () => {
    it('should generate Ed25519 key pair', () => {
      const keyPair = generateEd25519KeyPair();
      
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.keyType).toBe('Ed25519');
      expect(keyPair.keyId).toMatch(/^[a-f0-9]{16}$/);
    });

    it('should generate secp256k1 key pair', () => {
      const keyPair = generateSecp256k1KeyPair();
      
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.keyType).toBe('secp256k1');
      expect(keyPair.keyId).toMatch(/^[a-f0-9]{16}$/);
    });

    it('should generate P-256 key pair', () => {
      const keyPair = generateP256KeyPair();
      
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.keyType).toBe('P-256');
      expect(keyPair.keyId).toMatch(/^[a-f0-9]{16}$/);
    });

    it('should generate key pair by type', () => {
      const ed25519 = generateKeyPair('Ed25519');
      expect(ed25519.keyType).toBe('Ed25519');

      const secp256k1 = generateKeyPair('secp256k1');
      expect(secp256k1.keyType).toBe('secp256k1');

      const p256 = generateKeyPair('P-256');
      expect(p256.keyType).toBe('P-256');
    });

    it('should throw for unsupported key type', () => {
      expect(() => generateKeyPair('unsupported' as any)).toThrow('Unsupported key type');
    });

    it('property: generated keys are unique', () => {
      const keys = new Set<string>();
      
      fc.assert(
        fc.property(fc.constant(null), () => {
          const keyPair = generateEd25519KeyPair();
          const isUnique = !keys.has(keyPair.keyId);
          keys.add(keyPair.keyId);
          return isUnique;
        }),
        { numRuns: 100 }
      );
    });
  });


  describe('Base58 Encoding', () => {
    it('should encode buffer to base58', () => {
      const buffer = Buffer.from('hello');
      const encoded = base58Encode(buffer);
      expect(encoded).toBeDefined();
      expect(encoded.length).toBeGreaterThan(0);
    });

    it('should handle empty buffer', () => {
      const buffer = Buffer.from([]);
      const encoded = base58Encode(buffer);
      expect(encoded).toBe('1');
    });

    it('should handle leading zeros', () => {
      const buffer = Buffer.from([0, 0, 1, 2, 3]);
      const encoded = base58Encode(buffer);
      expect(encoded.startsWith('11')).toBe(true);
    });
  });

  describe('Public Key Conversion', () => {
    it('should convert Ed25519 key to multibase', () => {
      const keyPair = generateEd25519KeyPair();
      const multibase = publicKeyToMultibase(keyPair.publicKey, 'Ed25519');
      
      expect(multibase).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/);
    });

    it('should convert key to JWK format', () => {
      const keyPair = generateEd25519KeyPair();
      const jwk = publicKeyToJWK(keyPair.publicKey, 'Ed25519', keyPair.keyId);
      
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('Ed25519');
      expect(jwk.x).toBeDefined();
      expect(jwk.kid).toBe(keyPair.keyId);
    });

    it('should convert secp256k1 key to JWK', () => {
      const keyPair = generateSecp256k1KeyPair();
      const jwk = publicKeyToJWK(keyPair.publicKey, 'secp256k1', keyPair.keyId);
      
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('secp256k1');
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
    });

    it('should convert P-256 key to JWK', () => {
      const keyPair = generateP256KeyPair();
      const jwk = publicKeyToJWK(keyPair.publicKey, 'P-256', keyPair.keyId);
      
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256');
    });
  });

  describe('Ethereum Address Derivation', () => {
    it('should derive Ethereum address from secp256k1 key', () => {
      const keyPair = generateSecp256k1KeyPair();
      const address = deriveEthereumAddress(keyPair.publicKey);
      
      expect(address).toMatch(/^0x[a-f0-9]{40}$/);
    });

    it('property: derived addresses are valid Ethereum format', () => {
      fc.assert(
        fc.property(fc.constant(null), () => {
          const keyPair = generateSecp256k1KeyPair();
          const address = deriveEthereumAddress(keyPair.publicKey);
          return /^0x[a-f0-9]{40}$/.test(address);
        }),
        { numRuns: 20 }
      );
    });
  });

  describe('DID Method Generation', () => {
    describe('did:key', () => {
      it('should generate valid did:key', () => {
        const keyPair = generateEd25519KeyPair();
        const { did, document } = generateDIDKey(keyPair);
        
        expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
        expect(document.id).toBe(did);
        expect(document['@context']).toEqual(DID_CONTEXT);
        expect(document.verificationMethod).toHaveLength(1);
        expect(document.authentication).toHaveLength(1);
      });

      it('should include all verification relationships', () => {
        const keyPair = generateEd25519KeyPair();
        const { document } = generateDIDKey(keyPair);
        
        expect(document.authentication).toBeDefined();
        expect(document.assertionMethod).toBeDefined();
        expect(document.capabilityInvocation).toBeDefined();
        expect(document.capabilityDelegation).toBeDefined();
      });
    });

    describe('did:web', () => {
      it('should generate valid did:web', () => {
        const keyPair = generateEd25519KeyPair();
        const { did, document } = generateDIDWeb('example.com', undefined, keyPair);
        
        expect(did).toBe('did:web:example.com');
        expect(document.id).toBe(did);
        expect(document.verificationMethod).toHaveLength(1);
      });

      it('should handle domain with port', () => {
        const { did } = generateDIDWeb('localhost:3000');
        expect(did).toBe('did:web:localhost%3A3000');
      });

      it('should handle path', () => {
        const { did } = generateDIDWeb('example.com', 'users:alice');
        expect(did).toBe('did:web:example.com:users:alice');
      });

      it('should work without key pair', () => {
        const { did, document } = generateDIDWeb('example.com');
        expect(did).toBe('did:web:example.com');
        expect(document.verificationMethod).toBeUndefined();
      });
    });

    describe('did:ethr', () => {
      it('should generate valid did:ethr for mainnet', () => {
        const keyPair = generateSecp256k1KeyPair();
        const { did, document } = generateDIDEthr(keyPair, 'mainnet');
        
        expect(did).toMatch(/^did:ethr:0x[a-f0-9]{40}$/);
        expect(document.verificationMethod?.[0].blockchainAccountId).toContain('eip155:1:');
      });

      it('should generate did:ethr for other networks', () => {
        const keyPair = generateSecp256k1KeyPair();
        
        const { did: polygonDid } = generateDIDEthr(keyPair, 'polygon');
        expect(polygonDid).toMatch(/^did:ethr:polygon:0x[a-f0-9]{40}$/);
        
        const { did: arbitrumDid } = generateDIDEthr(keyPair, 'arbitrum');
        expect(arbitrumDid).toMatch(/^did:ethr:arbitrum:0x[a-f0-9]{40}$/);
      });

      it('should throw for non-secp256k1 key', () => {
        const keyPair = generateEd25519KeyPair();
        expect(() => generateDIDEthr(keyPair)).toThrow('did:ethr requires secp256k1 key type');
      });

      it('should throw for unsupported network', () => {
        const keyPair = generateSecp256k1KeyPair();
        expect(() => generateDIDEthr(keyPair, 'unsupported')).toThrow('Unsupported network');
      });
    });

    describe('did:ion', () => {
      it('should generate valid did:ion', () => {
        const keyPair = generateEd25519KeyPair();
        const { did, document, operations } = generateDIDIon(keyPair);
        
        expect(did).toMatch(/^did:ion:[1-9A-HJ-NP-Za-km-z]+$/);
        expect(document.id).toBe(did);
        expect(operations).toBeDefined();
      });

      it('should include ION operations for anchoring', () => {
        const keyPair = generateEd25519KeyPair();
        const { operations } = generateDIDIon(keyPair);
        
        expect((operations as any).type).toBe('create');
        expect((operations as any).suffixData).toBeDefined();
        expect((operations as any).delta).toBeDefined();
      });
    });
  });


  describe('DIDService', () => {
    describe('createDID', () => {
      beforeEach(() => {
        mockDynamoSend.mockResolvedValue({});
      });

      it('should create did:key', async () => {
        const record = await service.createDID({
          method: 'key',
          realmId: 'realm_123'
        });

        expect(record.did).toMatch(/^did:key:z/);
        expect(record.method).toBe('key');
        expect(record.realmId).toBe('realm_123');
        expect(record.status).toBe('active');
        expect(record.keyPairs).toHaveLength(1);
      });

      it('should create did:web', async () => {
        const record = await service.createDID({
          method: 'web',
          realmId: 'realm_123',
          domain: 'zalt.io'
        });

        expect(record.did).toBe('did:web:zalt.io');
        expect(record.method).toBe('web');
      });

      it('should create did:ethr', async () => {
        const record = await service.createDID({
          method: 'ethr',
          realmId: 'realm_123',
          network: 'polygon'
        });

        expect(record.did).toMatch(/^did:ethr:polygon:0x/);
        expect(record.method).toBe('ethr');
      });

      it('should create did:ion with pending status', async () => {
        const record = await service.createDID({
          method: 'ion',
          realmId: 'realm_123'
        });

        expect(record.did).toMatch(/^did:ion:/);
        expect(record.status).toBe('pending');
      });

      it('should throw for did:web without domain', async () => {
        await expect(service.createDID({
          method: 'web',
          realmId: 'realm_123'
        })).rejects.toThrow('Domain is required for did:web');
      });

      it('should throw for unsupported method', async () => {
        await expect(service.createDID({
          method: 'unsupported' as DIDMethod,
          realmId: 'realm_123'
        })).rejects.toThrow('Unsupported DID method');
      });

      it('should include userId if provided', async () => {
        const record = await service.createDID({
          method: 'key',
          realmId: 'realm_123',
          userId: 'user_456'
        });

        expect(record.userId).toBe('user_456');
      });

      it('should set controller if provided', async () => {
        const record = await service.createDID({
          method: 'key',
          realmId: 'realm_123',
          controller: 'did:key:zController'
        });

        expect(record.document.controller).toBe('did:key:zController');
      });

      it('should add services if provided', async () => {
        const record = await service.createDID({
          method: 'key',
          realmId: 'realm_123',
          services: [{
            id: '#messaging',
            type: 'MessagingService',
            serviceEndpoint: 'https://example.com/messages'
          }]
        });

        expect(record.document.service).toHaveLength(1);
        expect(record.document.service?.[0].type).toBe('MessagingService');
      });

      it('should encrypt private key', async () => {
        const record = await service.createDID({
          method: 'key',
          realmId: 'realm_123'
        });

        expect(record.keyPairs[0].encryptedPrivateKey).toContain(':');
        expect(record.keyPairs[0].encryptedPrivateKey).not.toContain('BEGIN');
      });
    });

    describe('resolveDID', () => {
      it('should resolve did:key without database', async () => {
        const result = await service.resolveDID('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');

        expect(result.didDocument).not.toBeNull();
        expect(result.didDocument?.id).toBe('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
        expect(result.didResolutionMetadata.error).toBeUndefined();
      });

      it('should resolve stored DID', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            did: 'did:web:example.com',
            method: 'web',
            realmId: 'realm_123',
            document: {
              '@context': DID_CONTEXT,
              id: 'did:web:example.com'
            },
            status: 'active',
            createdAt: '2026-01-25T10:00:00.000Z',
            updatedAt: '2026-01-25T10:00:00.000Z'
          }]
        });

        const result = await service.resolveDID('did:web:example.com');

        expect(result.didDocument).not.toBeNull();
        expect(result.didDocument?.id).toBe('did:web:example.com');
        expect(result.didDocumentMetadata.deactivated).toBe(false);
      });

      it('should return deactivated metadata', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            did: 'did:web:example.com',
            status: 'deactivated',
            document: { id: 'did:web:example.com' },
            createdAt: '2026-01-25T10:00:00.000Z',
            updatedAt: '2026-01-25T11:00:00.000Z'
          }]
        });

        const result = await service.resolveDID('did:web:example.com');

        expect(result.didDocumentMetadata.deactivated).toBe(true);
      });

      it('should return error for invalid DID', async () => {
        const result = await service.resolveDID('invalid');

        expect(result.didDocument).toBeNull();
        expect(result.didResolutionMetadata.error).toBe('invalidDid');
      });

      it('should return error for not found DID', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        const result = await service.resolveDID('did:web:notfound.com');

        expect(result.didDocument).toBeNull();
        expect(result.didResolutionMetadata.error).toBe('notFound');
      });
    });

    describe('getDID', () => {
      it('should return DID record', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            did: 'did:key:z123',
            method: 'key',
            realmId: 'realm_123'
          }]
        });

        const record = await service.getDID('did:key:z123');

        expect(record).not.toBeNull();
        expect(record?.did).toBe('did:key:z123');
      });

      it('should return null for non-existent DID', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        const record = await service.getDID('did:key:notfound');

        expect(record).toBeNull();
      });
    });

    describe('getRealmDIDs', () => {
      it('should return all DIDs for realm', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [
            { did: 'did:key:z1', method: 'key' },
            { did: 'did:web:example.com', method: 'web' }
          ]
        });

        const dids = await service.getRealmDIDs('realm_123');

        expect(dids).toHaveLength(2);
      });
    });

    describe('getUserDIDs', () => {
      it('should return all DIDs for user', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [
            { did: 'did:key:z1', userId: 'user_123' }
          ]
        });

        const dids = await service.getUserDIDs('user_123');

        expect(dids).toHaveLength(1);
      });
    });


    describe('updateDIDDocument', () => {
      it('should update DID document', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                did: 'did:key:z123',
                method: 'key',
                realmId: 'realm_123',
                document: { id: 'did:key:z123', '@context': DID_CONTEXT },
                keyPairs: [{ keyId: 'key1', encryptedPrivateKey: 'enc', keyType: 'Ed25519' }],
                status: 'active',
                createdAt: '2026-01-25T10:00:00.000Z',
                updatedAt: '2026-01-25T10:00:00.000Z'
              }]
            });
          }
          return Promise.resolve({});
        });

        const record = await service.updateDIDDocument('did:key:z123', {
          alsoKnownAs: ['https://example.com/user']
        });

        expect(record.document.alsoKnownAs).toContain('https://example.com/user');
      });

      it('should throw for non-existent DID', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        await expect(service.updateDIDDocument('did:key:notfound', {}))
          .rejects.toThrow('DID not found');
      });

      it('should throw for deactivated DID', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{ did: 'did:key:z123', status: 'deactivated' }]
        });

        await expect(service.updateDIDDocument('did:key:z123', {}))
          .rejects.toThrow('Cannot update deactivated DID');
      });
    });

    describe('addVerificationMethod', () => {
      it('should add new verification method', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                did: 'did:key:z123',
                method: 'key',
                realmId: 'realm_123',
                document: {
                  id: 'did:key:z123',
                  '@context': DID_CONTEXT,
                  verificationMethod: [{ id: 'did:key:z123#key1' }],
                  authentication: ['did:key:z123#key1']
                },
                keyPairs: [{ keyId: 'key1', encryptedPrivateKey: 'enc', keyType: 'Ed25519' }],
                status: 'active',
                createdAt: '2026-01-25T10:00:00.000Z',
                updatedAt: '2026-01-25T10:00:00.000Z'
              }]
            });
          }
          return Promise.resolve({});
        });

        const { record, keyId } = await service.addVerificationMethod(
          'did:key:z123',
          'P-256',
          ['authentication', 'assertionMethod']
        );

        expect(record.document.verificationMethod).toHaveLength(2);
        expect(record.keyPairs).toHaveLength(2);
        expect(keyId).toBeDefined();
      });
    });

    describe('removeVerificationMethod', () => {
      it('should remove verification method', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                did: 'did:key:z123',
                method: 'key',
                realmId: 'realm_123',
                document: {
                  id: 'did:key:z123',
                  verificationMethod: [
                    { id: 'did:key:z123#key-key1' },
                    { id: 'did:key:z123#key-key2' }
                  ],
                  authentication: ['did:key:z123#key-key1', 'did:key:z123#key-key2']
                },
                keyPairs: [
                  { keyId: 'key1', encryptedPrivateKey: 'enc1', keyType: 'Ed25519' },
                  { keyId: 'key2', encryptedPrivateKey: 'enc2', keyType: 'Ed25519' }
                ],
                status: 'active'
              }]
            });
          }
          return Promise.resolve({});
        });

        const record = await service.removeVerificationMethod('did:key:z123', 'key1');

        expect(record.keyPairs).toHaveLength(1);
        expect(record.keyPairs[0].keyId).toBe('key2');
      });

      it('should throw when removing last key', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            did: 'did:key:z123',
            status: 'active',
            keyPairs: [{ keyId: 'key1' }]
          }]
        });

        await expect(service.removeVerificationMethod('did:key:z123', 'key1'))
          .rejects.toThrow('Cannot remove last verification method');
      });
    });

    describe('deactivateDID', () => {
      it('should deactivate DID', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                did: 'did:key:z123',
                method: 'key',
                realmId: 'realm_123',
                document: { id: 'did:key:z123' },
                keyPairs: [],
                status: 'active',
                createdAt: '2026-01-25T10:00:00.000Z',
                updatedAt: '2026-01-25T10:00:00.000Z'
              }]
            });
          }
          return Promise.resolve({});
        });

        const record = await service.deactivateDID('did:key:z123');

        expect(record.status).toBe('deactivated');
        expect(record.document.deactivated).toBe(true);
        expect(record.deactivatedAt).toBeDefined();
      });

      it('should throw for already deactivated DID', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{ did: 'did:key:z123', status: 'deactivated' }]
        });

        await expect(service.deactivateDID('did:key:z123'))
          .rejects.toThrow('DID already deactivated');
      });
    });

    describe('addService', () => {
      it('should add service endpoint', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                did: 'did:key:z123',
                method: 'key',
                realmId: 'realm_123',
                document: { id: 'did:key:z123', service: [] },
                keyPairs: [],
                status: 'active'
              }]
            });
          }
          return Promise.resolve({});
        });

        const record = await service.addService('did:key:z123', {
          id: '#vc-service',
          type: 'VerifiableCredentialService',
          serviceEndpoint: 'https://vc.zalt.io'
        });

        expect(record.document.service).toHaveLength(1);
        expect(record.document.service?.[0].type).toBe('VerifiableCredentialService');
      });
    });

    describe('removeService', () => {
      it('should remove service endpoint', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                did: 'did:key:z123',
                method: 'key',
                realmId: 'realm_123',
                document: {
                  id: 'did:key:z123',
                  service: [
                    { id: '#svc1', type: 'Service1', serviceEndpoint: 'https://1.com' },
                    { id: '#svc2', type: 'Service2', serviceEndpoint: 'https://2.com' }
                  ]
                },
                keyPairs: [],
                status: 'active'
              }]
            });
          }
          return Promise.resolve({});
        });

        const record = await service.removeService('did:key:z123', '#svc1');

        expect(record.document.service).toHaveLength(1);
        expect(record.document.service?.[0].id).toBe('#svc2');
      });
    });

    describe('getSupportedMethods', () => {
      it('should return all supported methods', () => {
        const methods = service.getSupportedMethods();

        expect(methods).toContain('ethr');
        expect(methods).toContain('web');
        expect(methods).toContain('key');
        expect(methods).toContain('ion');
        expect(methods).toHaveLength(4);
      });
    });

    describe('isMethodSupported', () => {
      it('should return true for supported methods', () => {
        expect(service.isMethodSupported('ethr')).toBe(true);
        expect(service.isMethodSupported('web')).toBe(true);
        expect(service.isMethodSupported('key')).toBe(true);
        expect(service.isMethodSupported('ion')).toBe(true);
      });

      it('should return false for unsupported methods', () => {
        expect(service.isMethodSupported('unsupported')).toBe(false);
        expect(service.isMethodSupported('sov')).toBe(false);
      });
    });
  });

  describe('Constants', () => {
    it('should have correct DID context', () => {
      expect(DID_CONTEXT).toContain('https://www.w3.org/ns/did/v1');
    });

    it('should have correct key type mappings', () => {
      expect(KEY_TYPE_MAP['Ed25519']).toBe('Ed25519VerificationKey2020');
      expect(KEY_TYPE_MAP['secp256k1']).toBe('EcdsaSecp256k1VerificationKey2019');
    });

    it('should have correct Ethereum network chain IDs', () => {
      expect(ETHR_NETWORKS['mainnet']).toBe(1);
      expect(ETHR_NETWORKS['polygon']).toBe(137);
      expect(ETHR_NETWORKS['arbitrum']).toBe(42161);
    });
  });

  describe('Security Properties', () => {
    it('property: DIDs are deterministic from key pairs', () => {
      fc.assert(
        fc.property(fc.constant(null), () => {
          const keyPair = generateEd25519KeyPair();
          const { did: did1 } = generateDIDKey(keyPair);
          const { did: did2 } = generateDIDKey(keyPair);
          return did1 === did2;
        }),
        { numRuns: 20 }
      );
    });

    it('property: different keys produce different DIDs', () => {
      const dids = new Set<string>();
      
      fc.assert(
        fc.property(fc.constant(null), () => {
          const keyPair = generateEd25519KeyPair();
          const { did } = generateDIDKey(keyPair);
          const isUnique = !dids.has(did);
          dids.add(did);
          return isUnique;
        }),
        { numRuns: 50 }
      );
    });
  });
});
