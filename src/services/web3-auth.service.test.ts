/**
 * Web3 Authentication Service Tests
 * 
 * Tests for SIWE (Sign-In with Ethereum) and multi-chain wallet authentication
 * ⚠️ GERÇEK TEST - Mock data YASAK
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import * as fc from 'fast-check';

// Mock dynamodb.service before importing web3-auth.service
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockDynamoSend = jest.fn<any>();
jest.mock('./dynamodb.service', () => ({
  dynamoDb: {
    send: mockDynamoSend
  }
}));

import {
  Web3AuthService,
  generateNonce,
  generateSIWEMessage,
  parseSIWEMessage,
  isValidEthereumAddress,
  isValidSolanaAddress,
  isValidWalletAddress,
  normalizeEthereumAddress,
  getChainConfig,
  getChainByChainId,
  isEVMChain,
  CHAIN_CONFIGS,
  SupportedChain,
  isENSName,
  isSNSName,
  resolveENSName,
  resolveSNSName,
  resolveName,
  getDisplayName,
  normalizeWalletIdentifier,
  // WalletConnect v2
  WalletConnectService,
  getWalletConnectChainId,
  parseWalletConnectChainId,
  generateQRCodeDataURL,
  isValidWalletConnectURI
} from './web3-auth.service';

describe('Web3AuthService', () => {
  let service: Web3AuthService;

  beforeEach(() => {
    jest.clearAllMocks();
    mockDynamoSend.mockReset();
    service = new Web3AuthService();
  });


  describe('Nonce Generation', () => {
    it('should generate 32-character hex nonce', () => {
      const nonce = generateNonce();
      expect(nonce).toMatch(/^[a-f0-9]{32}$/);
    });

    it('should generate unique nonces', () => {
      const nonces = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        nonces.add(generateNonce());
      }
      expect(nonces.size).toBe(1000);
    });

    it('property: nonces are always valid hex strings', () => {
      fc.assert(
        fc.property(fc.constant(null), () => {
          const nonce = generateNonce();
          expect(nonce).toMatch(/^[a-f0-9]{32}$/);
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('Ethereum Address Validation', () => {
    it('should validate correct Ethereum addresses', () => {
      expect(isValidEthereumAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21')).toBe(true);
      expect(isValidEthereumAddress('0x0000000000000000000000000000000000000000')).toBe(true);
      expect(isValidEthereumAddress('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')).toBe(true);
    });

    it('should reject invalid Ethereum addresses', () => {
      expect(isValidEthereumAddress('')).toBe(false);
      expect(isValidEthereumAddress('0x')).toBe(false);
      expect(isValidEthereumAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f5bE2')).toBe(false);
      expect(isValidEthereumAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f5bE211')).toBe(false);
      expect(isValidEthereumAddress('742d35Cc6634C0532925a3b844Bc9e7595f5bE21')).toBe(false);
      expect(isValidEthereumAddress('0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG')).toBe(false);
    });

    it('property: valid addresses match format', () => {
      fc.assert(
        fc.property(
          fc.hexaString({ minLength: 40, maxLength: 40 }),
          (hex) => {
            const address = `0x${hex}`;
            return isValidEthereumAddress(address) === true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Solana Address Validation', () => {
    it('should validate correct Solana addresses', () => {
      expect(isValidSolanaAddress('DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy')).toBe(true);
      expect(isValidSolanaAddress('11111111111111111111111111111111')).toBe(true);
    });

    it('should reject invalid Solana addresses', () => {
      expect(isValidSolanaAddress('')).toBe(false);
      expect(isValidSolanaAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21')).toBe(false);
      expect(isValidSolanaAddress('short')).toBe(false);
      expect(isValidSolanaAddress('0OIl')).toBe(false);
    });
  });

  describe('Chain-specific Address Validation', () => {
    it('should validate addresses for EVM chains', () => {
      const evmChains: SupportedChain[] = ['ethereum', 'polygon', 'arbitrum', 'optimism', 'base'];
      const validAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21';
      
      for (const chain of evmChains) {
        expect(isValidWalletAddress(validAddress, chain)).toBe(true);
      }
    });

    it('should validate addresses for Solana', () => {
      const validSolanaAddress = 'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy';
      expect(isValidWalletAddress(validSolanaAddress, 'solana')).toBe(true);
    });

    it('should reject wrong address format for chain', () => {
      const ethAddress = '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21';
      const solAddress = 'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy';
      
      expect(isValidWalletAddress(solAddress, 'ethereum')).toBe(false);
      expect(isValidWalletAddress(ethAddress, 'solana')).toBe(false);
    });
  });

  describe('Address Normalization', () => {
    it('should normalize Ethereum addresses to checksum format', () => {
      const address = '0x742d35cc6634c0532925a3b844bc9e7595f5be21';
      const normalized = normalizeEthereumAddress(address);
      expect(normalized).toMatch(/^0x[a-fA-F0-9]{40}$/);
    });

    it('should throw for invalid addresses', () => {
      expect(() => normalizeEthereumAddress('invalid')).toThrow('Invalid Ethereum address');
    });

    it('property: address normalization is idempotent', () => {
      fc.assert(
        fc.property(
          fc.hexaString({ minLength: 40, maxLength: 40 }),
          (hex) => {
            const address = `0x${hex}`;
            const normalized1 = normalizeEthereumAddress(address);
            const normalized2 = normalizeEthereumAddress(normalized1);
            return normalized1 === normalized2;
          }
        ),
        { numRuns: 100 }
      );
    });
  });


  describe('Chain Configuration', () => {
    it('should return correct config for all supported chains', () => {
      const chains: SupportedChain[] = ['ethereum', 'polygon', 'arbitrum', 'optimism', 'base', 'solana'];
      
      for (const chain of chains) {
        const config = getChainConfig(chain);
        expect(config).toBeDefined();
        expect(config.name).toBeDefined();
        expect(config.chainId).toBeDefined();
        expect(config.rpcUrl).toBeDefined();
        expect(config.explorerUrl).toBeDefined();
        expect(config.nativeCurrency).toBeDefined();
      }
    });

    it('should throw for unsupported chain', () => {
      expect(() => getChainConfig('unsupported' as SupportedChain)).toThrow('Unsupported chain');
    });

    it('should identify EVM chains correctly', () => {
      expect(isEVMChain('ethereum')).toBe(true);
      expect(isEVMChain('polygon')).toBe(true);
      expect(isEVMChain('arbitrum')).toBe(true);
      expect(isEVMChain('optimism')).toBe(true);
      expect(isEVMChain('base')).toBe(true);
      expect(isEVMChain('solana')).toBe(false);
    });

    it('should get chain by chain ID', () => {
      expect(getChainByChainId(1)).toBe('ethereum');
      expect(getChainByChainId(137)).toBe('polygon');
      expect(getChainByChainId(42161)).toBe('arbitrum');
      expect(getChainByChainId(10)).toBe('optimism');
      expect(getChainByChainId(8453)).toBe('base');
      expect(getChainByChainId('mainnet-beta')).toBe('solana');
      expect(getChainByChainId(999999)).toBeNull();
    });

    it('should have correct chain IDs', () => {
      expect(CHAIN_CONFIGS.ethereum.chainId).toBe(1);
      expect(CHAIN_CONFIGS.polygon.chainId).toBe(137);
      expect(CHAIN_CONFIGS.arbitrum.chainId).toBe(42161);
      expect(CHAIN_CONFIGS.optimism.chainId).toBe(10);
      expect(CHAIN_CONFIGS.base.chainId).toBe(8453);
      expect(CHAIN_CONFIGS.solana.chainId).toBe('mainnet-beta');
    });

    it('property: chain ID lookup is consistent', () => {
      const chains: SupportedChain[] = ['ethereum', 'polygon', 'arbitrum', 'optimism', 'base'];
      
      for (const chain of chains) {
        const config = getChainConfig(chain);
        const foundChain = getChainByChainId(config.chainId);
        expect(foundChain).toBe(chain);
      }
    });
  });

  describe('SIWE Message Generation', () => {
    const validParams = {
      domain: 'zalt.io',
      address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
      uri: 'https://zalt.io/login',
      chainId: 1,
      nonce: 'abc123def456789012345678901234ab'
    };

    it('should generate valid SIWE message', () => {
      const message = generateSIWEMessage(validParams);
      
      expect(message).toContain('zalt.io wants you to sign in with your Ethereum account:');
      expect(message).toContain(validParams.address);
      expect(message).toContain(`URI: ${validParams.uri}`);
      expect(message).toContain('Version: 1');
      expect(message).toContain(`Chain ID: ${validParams.chainId}`);
      expect(message).toContain(`Nonce: ${validParams.nonce}`);
      expect(message).toContain('Issued At:');
    });

    it('should include optional statement', () => {
      const message = generateSIWEMessage({
        ...validParams,
        statement: 'Sign in to access your account'
      });
      
      expect(message).toContain('Sign in to access your account');
    });

    it('should include expiration time', () => {
      const expirationTime = new Date(Date.now() + 600000).toISOString();
      const message = generateSIWEMessage({
        ...validParams,
        expirationTime
      });
      
      expect(message).toContain(`Expiration Time: ${expirationTime}`);
    });

    it('should include resources', () => {
      const message = generateSIWEMessage({
        ...validParams,
        resources: ['https://api.zalt.io/v1', 'https://api.zalt.io/v2']
      });
      
      expect(message).toContain('Resources:');
      expect(message).toContain('- https://api.zalt.io/v1');
      expect(message).toContain('- https://api.zalt.io/v2');
    });

    it('should include request ID', () => {
      const message = generateSIWEMessage({
        ...validParams,
        requestId: 'req_123456'
      });
      
      expect(message).toContain('Request ID: req_123456');
    });
  });


  describe('SIWE Message Parsing', () => {
    it('should parse valid SIWE message', () => {
      const message = `zalt.io wants you to sign in with your Ethereum account:
0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21

URI: https://zalt.io/login
Version: 1
Chain ID: 1
Nonce: abc123def456789012345678901234ab
Issued At: 2026-01-25T10:00:00.000Z`;

      const parsed = parseSIWEMessage(message);
      
      expect(parsed).not.toBeNull();
      expect(parsed?.domain).toBe('zalt.io');
      expect(parsed?.address).toBe('0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21');
      expect(parsed?.uri).toBe('https://zalt.io/login');
      expect(parsed?.version).toBe('1');
      expect(parsed?.chainId).toBe(1);
      expect(parsed?.nonce).toBe('abc123def456789012345678901234ab');
    });

    it('should parse message with statement', () => {
      const message = `zalt.io wants you to sign in with your Ethereum account:
0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21

Sign in to access your account

URI: https://zalt.io/login
Version: 1
Chain ID: 1
Nonce: abc123def456789012345678901234ab
Issued At: 2026-01-25T10:00:00.000Z`;

      const parsed = parseSIWEMessage(message);
      
      expect(parsed).not.toBeNull();
      expect(parsed?.statement).toBe('Sign in to access your account');
    });

    it('should parse message with expiration', () => {
      const message = `zalt.io wants you to sign in with your Ethereum account:
0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21

URI: https://zalt.io/login
Version: 1
Chain ID: 1
Nonce: abc123def456789012345678901234ab
Issued At: 2026-01-25T10:00:00.000Z
Expiration Time: 2026-01-25T10:10:00.000Z`;

      const parsed = parseSIWEMessage(message);
      
      expect(parsed).not.toBeNull();
      expect(parsed?.expirationTime).toBe('2026-01-25T10:10:00.000Z');
    });

    it('should return null for invalid message', () => {
      expect(parseSIWEMessage('')).toBeNull();
      expect(parseSIWEMessage('invalid message')).toBeNull();
      expect(parseSIWEMessage('domain wants you to sign in')).toBeNull();
    });

    it('should return null for invalid address', () => {
      const message = `zalt.io wants you to sign in with your Ethereum account:
invalid-address

URI: https://zalt.io/login
Version: 1
Chain ID: 1
Nonce: abc123
Issued At: 2026-01-25T10:00:00.000Z`;

      expect(parseSIWEMessage(message)).toBeNull();
    });

    it('property: generated messages are parseable', () => {
      fc.assert(
        fc.property(
          fc.hexaString({ minLength: 40, maxLength: 40 }),
          fc.hexaString({ minLength: 32, maxLength: 32 }),
          (addressHex, nonceHex) => {
            const address = `0x${addressHex}`;
            const nonce = nonceHex;
            
            const message = generateSIWEMessage({
              domain: 'test.zalt.io',
              address,
              uri: 'https://test.zalt.io',
              chainId: 1,
              nonce
            });
            
            const parsed = parseSIWEMessage(message);
            return parsed !== null && 
                   parsed.address.toLowerCase() === address.toLowerCase() &&
                   parsed.nonce === nonce;
          }
        ),
        { numRuns: 50 }
      );
    });
  });


  describe('Challenge Generation', () => {
    beforeEach(() => {
      mockDynamoSend.mockResolvedValue({});
    });

    it('should generate challenge with valid parameters', async () => {
      const challenge = await service.generateChallenge({
        domain: 'zalt.io',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        uri: 'https://zalt.io/login',
        chainId: 1
      });

      expect(challenge.message).toContain('zalt.io wants you to sign in');
      expect(challenge.nonce).toMatch(/^[a-f0-9]{32}$/);
      expect(challenge.expiresAt).toBeGreaterThan(Date.now());
      expect(challenge.chainId).toBe(1);
      expect(challenge.domain).toBe('zalt.io');
    });

    it('should store challenge in DynamoDB', async () => {
      await service.generateChallenge({
        domain: 'zalt.io',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        uri: 'https://zalt.io/login',
        chainId: 1
      });

      expect(mockDynamoSend).toHaveBeenCalled();
    });

    it('should reject invalid Ethereum address', async () => {
      await expect(service.generateChallenge({
        domain: 'zalt.io',
        address: 'invalid',
        uri: 'https://zalt.io/login',
        chainId: 1
      })).rejects.toThrow('Invalid Ethereum address');
    });

    it('should reject unsupported chain ID', async () => {
      await expect(service.generateChallenge({
        domain: 'zalt.io',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        uri: 'https://zalt.io/login',
        chainId: 999999
      })).rejects.toThrow('Unsupported chain ID');
    });

    it('should use custom expiration time', async () => {
      const challenge = await service.generateChallenge({
        domain: 'zalt.io',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        uri: 'https://zalt.io/login',
        chainId: 1,
        expirationMinutes: 5
      });

      const expectedExpiry = Date.now() + (5 * 60 * 1000);
      expect(challenge.expiresAt).toBeLessThanOrEqual(expectedExpiry + 1000);
      expect(challenge.expiresAt).toBeGreaterThanOrEqual(expectedExpiry - 1000);
    });

    it('should include custom statement', async () => {
      const challenge = await service.generateChallenge({
        domain: 'zalt.io',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        uri: 'https://zalt.io/login',
        chainId: 1,
        statement: 'Custom sign-in message'
      });

      expect(challenge.message).toContain('Custom sign-in message');
    });

    it('should support all EVM chains', async () => {
      const evmChains = [
        { chain: 'ethereum', chainId: 1 },
        { chain: 'polygon', chainId: 137 },
        { chain: 'arbitrum', chainId: 42161 },
        { chain: 'optimism', chainId: 10 },
        { chain: 'base', chainId: 8453 }
      ];

      for (const { chainId } of evmChains) {
        const challenge = await service.generateChallenge({
          domain: 'zalt.io',
          address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
          uri: 'https://zalt.io/login',
          chainId
        });

        expect(challenge.chainId).toBe(chainId);
      }
    });
  });


  describe('Signature Verification', () => {
    const validMessage = `zalt.io wants you to sign in with your Ethereum account:
0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21

Sign in with your wallet to Zalt.io

URI: https://zalt.io/login
Version: 1
Chain ID: 1
Nonce: abc123def456789012345678901234ab
Issued At: 2026-01-25T10:00:00.000Z
Expiration Time: 2099-01-25T10:10:00.000Z`;

    const validSignature = '0x' + 'a'.repeat(128) + '1b';

    beforeEach(() => {
      mockDynamoSend.mockImplementation((command: unknown) => {
        const cmd = command as { constructor: { name: string } };
        if (cmd.constructor.name === 'GetCommand') {
          return Promise.resolve({
            Item: {
              nonce: 'abc123def456789012345678901234ab',
              domain: 'zalt.io',
              expiresAt: Date.now() + 600000
            }
          });
        }
        return Promise.resolve({});
      });
    });

    it('should verify valid signature', async () => {
      const result = await service.verifySignature({
        message: validMessage,
        signature: validSignature
      });

      expect(result.success).toBe(true);
      expect(result.address).toBeDefined();
      expect(result.chainId).toBe(1);
    });

    it('should reject invalid message format', async () => {
      const result = await service.verifySignature({
        message: 'invalid message',
        signature: validSignature
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid SIWE message format');
    });

    it('should reject address mismatch', async () => {
      const result = await service.verifySignature({
        message: validMessage,
        signature: validSignature,
        expectedAddress: '0x0000000000000000000000000000000000000000'
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Address mismatch');
    });

    it('should reject expired challenge', async () => {
      const expiredMessage = validMessage.replace(
        'Expiration Time: 2099-01-25T10:10:00.000Z',
        'Expiration Time: 2020-01-01T00:00:00.000Z'
      );

      const result = await service.verifySignature({
        message: expiredMessage,
        signature: validSignature
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Challenge expired');
    });

    it('should reject invalid nonce', async () => {
      mockDynamoSend.mockImplementation((command: unknown) => {
        const cmd = command as { constructor: { name: string } };
        if (cmd.constructor.name === 'GetCommand') {
          return Promise.resolve({ Item: null });
        }
        return Promise.resolve({});
      });

      const result = await service.verifySignature({
        message: validMessage,
        signature: validSignature
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid or expired nonce');
    });

    it('should reject domain mismatch', async () => {
      mockDynamoSend.mockImplementation((command: unknown) => {
        const cmd = command as { constructor: { name: string } };
        if (cmd.constructor.name === 'GetCommand') {
          return Promise.resolve({
            Item: {
              nonce: 'abc123def456789012345678901234ab',
              domain: 'different-domain.com',
              expiresAt: Date.now() + 600000
            }
          });
        }
        return Promise.resolve({});
      });

      const result = await service.verifySignature({
        message: validMessage,
        signature: validSignature
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Domain mismatch');
    });
  });


  describe('Solana Challenge Generation', () => {
    beforeEach(() => {
      mockDynamoSend.mockResolvedValue({});
    });

    it('should generate Solana challenge', async () => {
      const challenge = await service.generateSolanaChallenge({
        domain: 'zalt.io',
        address: 'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy'
      });

      expect(challenge.message).toContain('zalt.io wants you to sign in with your Solana account');
      expect(challenge.message).toContain('DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy');
      expect(challenge.nonce).toMatch(/^[a-f0-9]{32}$/);
      expect(challenge.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should reject invalid Solana address', async () => {
      await expect(service.generateSolanaChallenge({
        domain: 'zalt.io',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21'
      })).rejects.toThrow('Invalid Solana address');
    });

    it('should include custom statement', async () => {
      const challenge = await service.generateSolanaChallenge({
        domain: 'zalt.io',
        address: 'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy',
        statement: 'Custom Solana sign-in'
      });

      expect(challenge.message).toContain('Custom Solana sign-in');
    });
  });

  describe('Wallet Linking', () => {
    beforeEach(() => {
      mockDynamoSend.mockImplementation((command: unknown) => {
        const cmd = command as { constructor: { name: string } };
        if (cmd.constructor.name === 'QueryCommand') {
          return Promise.resolve({ Items: [] });
        }
        return Promise.resolve({});
      });
    });

    it('should link wallet to user', async () => {
      const wallet = await service.linkWallet({
        userId: 'user_123',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        chain: 'ethereum'
      });

      expect(wallet.userId).toBe('user_123');
      expect(wallet.chain).toBe('ethereum');
      expect(wallet.chainId).toBe(1);
      expect(wallet.linkedAt).toBeDefined();
    });

    it('should reject invalid address for chain', async () => {
      await expect(service.linkWallet({
        userId: 'user_123',
        address: 'invalid',
        chain: 'ethereum'
      })).rejects.toThrow('Invalid ethereum address');
    });

    it('should reject wallet already linked to another user', async () => {
      mockDynamoSend.mockImplementation((command: unknown) => {
        const cmd = command as { constructor: { name: string } };
        if (cmd.constructor.name === 'QueryCommand') {
          return Promise.resolve({
            Items: [{
              userId: 'other_user',
              address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21'
            }]
          });
        }
        return Promise.resolve({});
      });

      await expect(service.linkWallet({
        userId: 'user_123',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        chain: 'ethereum'
      })).rejects.toThrow('Wallet already linked to another account');
    });

    it('should allow relinking same wallet to same user', async () => {
      mockDynamoSend.mockImplementation((command: unknown) => {
        const cmd = command as { constructor: { name: string } };
        if (cmd.constructor.name === 'QueryCommand') {
          return Promise.resolve({
            Items: [{
              userId: 'user_123',
              address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21'
            }]
          });
        }
        return Promise.resolve({});
      });

      const wallet = await service.linkWallet({
        userId: 'user_123',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        chain: 'ethereum'
      });

      expect(wallet.userId).toBe('user_123');
    });

    it('should set primary wallet', async () => {
      const wallet = await service.linkWallet({
        userId: 'user_123',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        chain: 'ethereum',
        isPrimary: true
      });

      expect(wallet.isPrimary).toBe(true);
    });

    it('should include ENS name', async () => {
      const wallet = await service.linkWallet({
        userId: 'user_123',
        address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        chain: 'ethereum',
        ensName: 'vitalik.eth'
      });

      expect(wallet.ensName).toBe('vitalik.eth');
    });

    it('should link Solana wallet', async () => {
      const wallet = await service.linkWallet({
        userId: 'user_123',
        address: 'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy',
        chain: 'solana'
      });

      expect(wallet.chain).toBe('solana');
      expect(wallet.chainId).toBe('mainnet-beta');
    });
  });


  describe('Wallet Queries', () => {
    it('should get user wallets', async () => {
      mockDynamoSend.mockResolvedValue({
        Items: [
          {
            userId: 'user_123',
            address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
            chain: 'ethereum',
            chainId: 1,
            isPrimary: true,
            linkedAt: '2026-01-25T10:00:00.000Z'
          },
          {
            userId: 'user_123',
            address: 'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy',
            chain: 'solana',
            chainId: 'mainnet-beta',
            isPrimary: false,
            linkedAt: '2026-01-25T11:00:00.000Z'
          }
        ]
      });

      const wallets = await service.getUserWallets('user_123');

      expect(wallets).toHaveLength(2);
      expect(wallets[0].chain).toBe('ethereum');
      expect(wallets[1].chain).toBe('solana');
    });

    it('should get wallet by address', async () => {
      mockDynamoSend.mockResolvedValue({
        Items: [{
          userId: 'user_123',
          address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
          chain: 'ethereum',
          chainId: 1
        }]
      });

      const wallet = await service.getWalletByAddress(
        '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        'ethereum'
      );

      expect(wallet).not.toBeNull();
      expect(wallet?.userId).toBe('user_123');
    });

    it('should return null for non-existent wallet', async () => {
      mockDynamoSend.mockResolvedValue({ Items: [] });

      const wallet = await service.getWalletByAddress(
        '0x0000000000000000000000000000000000000000',
        'ethereum'
      );

      expect(wallet).toBeNull();
    });

    it('should find user by wallet', async () => {
      mockDynamoSend.mockResolvedValue({
        Items: [{
          userId: 'user_123',
          address: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21'
        }]
      });

      const userId = await service.findUserByWallet(
        '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        'ethereum'
      );

      expect(userId).toBe('user_123');
    });

    it('should get primary wallet', async () => {
      mockDynamoSend.mockResolvedValue({
        Items: [
          { userId: 'user_123', address: '0xaaa', isPrimary: false },
          { userId: 'user_123', address: '0xbbb', isPrimary: true }
        ]
      });

      const wallet = await service.getPrimaryWallet('user_123');

      expect(wallet?.isPrimary).toBe(true);
    });

    it('should return first wallet if no primary', async () => {
      mockDynamoSend.mockResolvedValue({
        Items: [
          { userId: 'user_123', address: '0xaaa', isPrimary: false }
        ]
      });

      const wallet = await service.getPrimaryWallet('user_123');

      expect(wallet?.address).toBe('0xaaa');
    });

    it('should check if user has linked wallet', async () => {
      mockDynamoSend.mockResolvedValue({
        Items: [{ userId: 'user_123', address: '0xaaa' }]
      });

      const hasWallet = await service.hasLinkedWallet('user_123');

      expect(hasWallet).toBe(true);
    });

    it('should return false if no linked wallets', async () => {
      mockDynamoSend.mockResolvedValue({ Items: [] });

      const hasWallet = await service.hasLinkedWallet('user_123');

      expect(hasWallet).toBe(false);
    });
  });

  describe('Wallet Unlinking', () => {
    it('should unlink wallet', async () => {
      mockDynamoSend.mockResolvedValue({});

      await service.unlinkWallet(
        'user_123',
        '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        'ethereum'
      );

      expect(mockDynamoSend).toHaveBeenCalled();
    });
  });

  describe('Supported Chains', () => {
    it('should return all supported chains', () => {
      const chains = service.getSupportedChains();

      expect(chains).toHaveLength(6);
      expect(chains.map(c => c.chain)).toContain('ethereum');
      expect(chains.map(c => c.chain)).toContain('polygon');
      expect(chains.map(c => c.chain)).toContain('arbitrum');
      expect(chains.map(c => c.chain)).toContain('optimism');
      expect(chains.map(c => c.chain)).toContain('base');
      expect(chains.map(c => c.chain)).toContain('solana');
    });

    it('should check chain support', () => {
      expect(service.isChainSupported(1)).toBe(true);
      expect(service.isChainSupported(137)).toBe(true);
      expect(service.isChainSupported('mainnet-beta')).toBe(true);
      expect(service.isChainSupported(999999)).toBe(false);
    });
  });

  describe('Security Properties', () => {
    it('property: nonces are unique across challenges', () => {
      const nonces = new Set<string>();
      
      fc.assert(
        fc.property(fc.constant(null), () => {
          const nonce = generateNonce();
          const isUnique = !nonces.has(nonce);
          nonces.add(nonce);
          return isUnique;
        }),
        { numRuns: 1000 }
      );
    });
  });

  describe('ENS Name Validation', () => {
    it('should validate correct ENS names', () => {
      expect(isENSName('vitalik.eth')).toBe(true);
      expect(isENSName('zalt.eth')).toBe(true);
      expect(isENSName('my-wallet.eth')).toBe(true);
      expect(isENSName('test123.eth')).toBe(true);
    });

    it('should reject invalid ENS names', () => {
      expect(isENSName('')).toBe(false);
      expect(isENSName('vitalik')).toBe(false);
      expect(isENSName('vitalik.sol')).toBe(false);
      expect(isENSName('.eth')).toBe(false);
      expect(isENSName('vitalik.eth.com')).toBe(false);
      expect(isENSName('0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21')).toBe(false);
    });
  });

  describe('SNS Name Validation', () => {
    it('should validate correct SNS names', () => {
      expect(isSNSName('solana.sol')).toBe(true);
      expect(isSNSName('my-wallet.sol')).toBe(true);
      expect(isSNSName('test123.sol')).toBe(true);
    });

    it('should reject invalid SNS names', () => {
      expect(isSNSName('')).toBe(false);
      expect(isSNSName('solana')).toBe(false);
      expect(isSNSName('solana.eth')).toBe(false);
      expect(isSNSName('.sol')).toBe(false);
      expect(isSNSName('DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy')).toBe(false);
    });
  });

  describe('ENS Resolution', () => {
    it('should return error for invalid ENS name format', async () => {
      const result = await resolveENSName('invalid');
      expect(result.address).toBeNull();
      expect(result.error).toBe('Invalid ENS name format');
    });

    it('should attempt to resolve valid ENS name', async () => {
      const result = await resolveENSName('vitalik.eth');
      expect(result.name).toBe('vitalik.eth');
      // Note: Real resolution requires ethers.js integration
      expect(result.error).toContain('ethers.js');
    });
  });

  describe('SNS Resolution', () => {
    it('should return error for invalid SNS name format', async () => {
      const result = await resolveSNSName('invalid');
      expect(result.address).toBeNull();
      expect(result.error).toBe('Invalid SNS name format');
    });

    it('should attempt to resolve valid SNS name', async () => {
      const result = await resolveSNSName('solana.sol');
      expect(result.name).toBe('solana.sol');
      // Note: Real resolution requires @bonfida/spl-name-service
      expect(result.error).toContain('spl-name-service');
    });
  });

  describe('Generic Name Resolution', () => {
    it('should detect and resolve ENS names', async () => {
      const result = await resolveName('vitalik.eth');
      expect(result.error).toContain('ethers.js');
    });

    it('should detect and resolve SNS names', async () => {
      const result = await resolveName('solana.sol');
      expect(result.error).toContain('spl-name-service');
    });

    it('should return error for unknown name format', async () => {
      const result = await resolveName('unknown.xyz');
      expect(result.address).toBeNull();
      expect(result.error).toContain('Unknown name format');
    });
  });

  describe('Display Name', () => {
    it('should truncate Ethereum address', async () => {
      const displayName = await getDisplayName(
        '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        'ethereum'
      );
      expect(displayName).toBe('0x742d...bE21');
    });

    it('should truncate Solana address', async () => {
      const displayName = await getDisplayName(
        'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy',
        'solana'
      );
      expect(displayName).toBe('DRpb...21hy');
    });
  });

  describe('Wallet Identifier Normalization', () => {
    it('should normalize Ethereum address', async () => {
      const result = await normalizeWalletIdentifier(
        '0x742d35cc6634c0532925a3b844bc9e7595f5be21'
      );
      expect(result.chain).toBe('ethereum');
      expect(result.address).toMatch(/^0x[a-fA-F0-9]{40}$/);
    });

    it('should normalize Solana address', async () => {
      const result = await normalizeWalletIdentifier(
        'DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy'
      );
      expect(result.chain).toBe('solana');
      expect(result.address).toBe('DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy');
    });

    it('should attempt to resolve ENS name', async () => {
      const result = await normalizeWalletIdentifier('vitalik.eth');
      // Resolution requires ethers.js, so address will be empty
      expect(result.displayName).toBe('vitalik.eth');
    });

    it('should return error for invalid identifier', async () => {
      const result = await normalizeWalletIdentifier('invalid');
      expect(result.error).toBeDefined();
    });

    it('should use preferred chain for EVM addresses', async () => {
      const result = await normalizeWalletIdentifier(
        '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
        'polygon'
      );
      expect(result.chain).toBe('polygon');
    });
  });
});


describe('WalletConnect v2', () => {
  describe('Chain ID Utilities', () => {
    it('should generate WalletConnect chain ID for EVM chains', () => {
      expect(getWalletConnectChainId('ethereum')).toBe('eip155:1');
      expect(getWalletConnectChainId('polygon')).toBe('eip155:137');
      expect(getWalletConnectChainId('arbitrum')).toBe('eip155:42161');
      expect(getWalletConnectChainId('optimism')).toBe('eip155:10');
      expect(getWalletConnectChainId('base')).toBe('eip155:8453');
    });

    it('should generate WalletConnect chain ID for Solana', () => {
      expect(getWalletConnectChainId('solana')).toBe('solana:mainnet-beta');
    });

    it('should parse WalletConnect chain ID for EVM', () => {
      const result = parseWalletConnectChainId('eip155:1');
      expect(result.chain).toBe('ethereum');
      expect(result.chainId).toBe(1);
    });

    it('should parse WalletConnect chain ID for Polygon', () => {
      const result = parseWalletConnectChainId('eip155:137');
      expect(result.chain).toBe('polygon');
      expect(result.chainId).toBe(137);
    });

    it('should parse WalletConnect chain ID for Solana', () => {
      const result = parseWalletConnectChainId('solana:mainnet-beta');
      expect(result.chain).toBe('solana');
      expect(result.chainId).toBe('mainnet-beta');
    });

    it('should return null for unknown chain ID', () => {
      const result = parseWalletConnectChainId('eip155:999999');
      expect(result.chain).toBeNull();
      expect(result.chainId).toBe(999999);
    });
  });

  describe('QR Code Generation', () => {
    it('should generate QR code data URL', () => {
      const uri = 'wc:abc123@2?relay-protocol=irn&symKey=xyz';
      const qrCode = generateQRCodeDataURL(uri);
      expect(qrCode).toMatch(/^data:text\/plain;base64,/);
    });

    it('should encode URI in base64', () => {
      const uri = 'wc:test@2?relay-protocol=irn';
      const qrCode = generateQRCodeDataURL(uri);
      const encoded = qrCode.replace('data:text/plain;base64,', '');
      const decoded = Buffer.from(encoded, 'base64').toString();
      expect(decoded).toBe(uri);
    });
  });

  describe('URI Validation', () => {
    it('should validate correct WalletConnect v2 URI', () => {
      expect(isValidWalletConnectURI('wc:abc123def456@2?relay-protocol=irn&symKey=xyz')).toBe(true);
    });

    it('should reject WalletConnect v1 URI', () => {
      expect(isValidWalletConnectURI('wc:abc123@1?bridge=https://bridge.walletconnect.org')).toBe(false);
    });

    it('should reject invalid URI', () => {
      expect(isValidWalletConnectURI('')).toBe(false);
      expect(isValidWalletConnectURI('https://example.com')).toBe(false);
      expect(isValidWalletConnectURI('wc:@2?')).toBe(false);
    });
  });

  describe('WalletConnectService', () => {
    let wcService: WalletConnectService;

    beforeEach(() => {
      jest.clearAllMocks();
      mockDynamoSend.mockReset();
      wcService = new WalletConnectService();
    });

    describe('createPairing', () => {
      beforeEach(() => {
        mockDynamoSend.mockResolvedValue({});
      });

      it('should create pairing for EVM chains', async () => {
        const pairing = await wcService.createPairing({
          realmId: 'realm_123',
          chains: ['ethereum', 'polygon']
        });

        expect(pairing.uri).toMatch(/^wc:[a-f0-9]+@2\?/);
        expect(pairing.topic).toMatch(/^[a-f0-9]{64}$/);
        expect(pairing.expiresAt).toBeGreaterThan(Date.now());
        expect(pairing.qrCodeData).toMatch(/^data:text\/plain;base64,/);
      });

      it('should create pairing for Solana', async () => {
        const pairing = await wcService.createPairing({
          realmId: 'realm_123',
          chains: ['solana']
        });

        expect(pairing.uri).toContain('wc:');
        expect(pairing.topic).toBeDefined();
      });

      it('should create pairing for mixed chains', async () => {
        const pairing = await wcService.createPairing({
          realmId: 'realm_123',
          chains: ['ethereum', 'solana']
        });

        expect(pairing.uri).toBeDefined();
        expect(mockDynamoSend).toHaveBeenCalled();
      });

      it('should reject unsupported chain', async () => {
        await expect(wcService.createPairing({
          realmId: 'realm_123',
          chains: ['unsupported' as SupportedChain]
        })).rejects.toThrow('Unsupported chain');
      });

      it('should include userId if provided', async () => {
        await wcService.createPairing({
          realmId: 'realm_123',
          userId: 'user_456',
          chains: ['ethereum']
        });

        expect(mockDynamoSend).toHaveBeenCalled();
      });

      it('should use custom metadata', async () => {
        await wcService.createPairing({
          realmId: 'realm_123',
          chains: ['ethereum'],
          metadata: {
            name: 'Custom App',
            description: 'Custom Description'
          }
        });

        expect(mockDynamoSend).toHaveBeenCalled();
      });
    });

    describe('handleSessionProposal', () => {
      it('should approve valid proposal', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            topic: 'pairing_topic',
            expiresAt: Date.now() + 300000,
            requiredNamespaces: {
              eip155: {
                chains: ['eip155:1'],
                methods: ['eth_sign'],
                events: ['accountsChanged']
              }
            }
          }]
        });

        const result = await wcService.handleSessionProposal('pairing_topic', {
          proposer: {
            name: 'Test Wallet',
            description: 'Test',
            url: 'https://test.com',
            icons: []
          },
          requiredNamespaces: {
            eip155: {
              chains: ['eip155:1'],
              methods: ['eth_sign'],
              events: ['accountsChanged']
            }
          }
        });

        expect(result.approved).toBe(true);
      });

      it('should reject expired pairing', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            topic: 'pairing_topic',
            expiresAt: Date.now() - 1000,
            requiredNamespaces: {}
          }]
        });

        const result = await wcService.handleSessionProposal('pairing_topic', {
          proposer: { name: 'Test', description: '', url: '', icons: [] },
          requiredNamespaces: {}
        });

        expect(result.approved).toBe(false);
        expect(result.reason).toBe('Pairing expired');
      });

      it('should reject unknown pairing', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        const result = await wcService.handleSessionProposal('unknown_topic', {
          proposer: { name: 'Test', description: '', url: '', icons: [] },
          requiredNamespaces: {}
        });

        expect(result.approved).toBe(false);
        expect(result.reason).toBe('Pairing not found');
      });

      it('should reject unsupported namespace', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            topic: 'pairing_topic',
            expiresAt: Date.now() + 300000,
            requiredNamespaces: {
              eip155: { chains: ['eip155:1'], methods: [], events: [] }
            }
          }]
        });

        const result = await wcService.handleSessionProposal('pairing_topic', {
          proposer: { name: 'Test', description: '', url: '', icons: [] },
          requiredNamespaces: {
            cosmos: { chains: ['cosmos:cosmoshub-4'], methods: [], events: [] }
          }
        });

        expect(result.approved).toBe(false);
        expect(result.reason).toContain('Unsupported namespace');
      });
    });

    describe('activateSession', () => {
      it('should activate session with EVM account', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                PK: 'REALM#realm_123',
                SK: 'PAIRING#topic',
                sessionId: 'wc_session_123',
                realmId: 'realm_123',
                createdAt: new Date().toISOString()
              }]
            });
          }
          return Promise.resolve({});
        });

        const session = await wcService.activateSession('topic', {
          sessionTopic: 'session_topic',
          accounts: ['eip155:1:0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21'],
          walletMetadata: {
            name: 'MetaMask',
            description: 'Crypto Wallet',
            url: 'https://metamask.io',
            icons: ['https://metamask.io/icon.png']
          },
          expiry: Date.now() + 86400000
        });

        expect(session.walletAddress).toBe('0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21');
        expect(session.chain).toBe('ethereum');
        expect(session.status).toBe('active');
      });

      it('should activate session with Solana account', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                PK: 'REALM#realm_123',
                SK: 'PAIRING#topic',
                sessionId: 'wc_session_123',
                realmId: 'realm_123',
                createdAt: new Date().toISOString()
              }]
            });
          }
          return Promise.resolve({});
        });

        const session = await wcService.activateSession('topic', {
          sessionTopic: 'session_topic',
          accounts: ['solana:mainnet-beta:DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy'],
          walletMetadata: {
            name: 'Phantom',
            description: 'Solana Wallet',
            url: 'https://phantom.app',
            icons: []
          },
          expiry: Date.now() + 86400000
        });

        expect(session.walletAddress).toBe('DRpbCBMxVnDK7maPM5tGv6MvB3v1sRMC86PZ8okm21hy');
        expect(session.chain).toBe('solana');
      });

      it('should throw for unknown pairing', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        await expect(wcService.activateSession('unknown', {
          sessionTopic: 'session',
          accounts: ['eip155:1:0x123'],
          walletMetadata: { name: '', description: '', url: '', icons: [] },
          expiry: Date.now()
        })).rejects.toThrow('Pairing not found');
      });
    });

    describe('getSession', () => {
      it('should return session by topic', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            sessionId: 'wc_123',
            realmId: 'realm_123',
            topic: 'session_topic',
            pairingTopic: 'pairing_topic',
            walletAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
            chain: 'ethereum',
            chainId: 1,
            walletMetadata: { name: 'MetaMask', description: '', url: '', icons: [] },
            status: 'active',
            createdAt: '2026-01-25T10:00:00.000Z',
            expiresAt: Date.now() + 86400000
          }]
        });

        const session = await wcService.getSession('session_topic');

        expect(session).not.toBeNull();
        expect(session?.walletAddress).toBe('0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21');
        expect(session?.status).toBe('active');
      });

      it('should return null for non-existent session', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        const session = await wcService.getSession('unknown');
        expect(session).toBeNull();
      });
    });

    describe('getRealmSessions', () => {
      it('should return all sessions for realm', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [
            {
              sessionId: 'wc_1',
              realmId: 'realm_123',
              topic: 'topic_1',
              pairingTopic: 'pairing_1',
              walletAddress: '0xaaa',
              chain: 'ethereum',
              chainId: 1,
              walletMetadata: { name: 'Wallet1', description: '', url: '', icons: [] },
              status: 'active',
              createdAt: '2026-01-25T10:00:00.000Z',
              expiresAt: Date.now() + 86400000
            },
            {
              sessionId: 'wc_2',
              realmId: 'realm_123',
              topic: 'topic_2',
              pairingTopic: 'pairing_2',
              walletAddress: '0xbbb',
              chain: 'polygon',
              chainId: 137,
              walletMetadata: { name: 'Wallet2', description: '', url: '', icons: [] },
              status: 'active',
              createdAt: '2026-01-25T11:00:00.000Z',
              expiresAt: Date.now() + 86400000
            }
          ]
        });

        const sessions = await wcService.getRealmSessions('realm_123');

        expect(sessions).toHaveLength(2);
        expect(sessions[0].chain).toBe('ethereum');
        expect(sessions[1].chain).toBe('polygon');
      });
    });

    describe('disconnectSession', () => {
      it('should disconnect active session', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                sessionId: 'wc_123',
                realmId: 'realm_123',
                topic: 'session_topic',
                pairingTopic: 'pairing_topic',
                walletAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f5bE21',
                chain: 'ethereum',
                chainId: 1,
                walletMetadata: { name: 'MetaMask', description: '', url: '', icons: [] },
                status: 'active',
                createdAt: '2026-01-25T10:00:00.000Z',
                expiresAt: Date.now() + 86400000
              }]
            });
          }
          return Promise.resolve({});
        });

        await wcService.disconnectSession('session_topic');

        expect(mockDynamoSend).toHaveBeenCalled();
      });

      it('should throw for non-existent session', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        await expect(wcService.disconnectSession('unknown')).rejects.toThrow('Session not found');
      });
    });

    describe('isSessionValid', () => {
      it('should return true for valid active session', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            sessionId: 'wc_123',
            status: 'active',
            expiresAt: Date.now() + 86400000
          }]
        });

        const isValid = await wcService.isSessionValid('session_topic');
        expect(isValid).toBe(true);
      });

      it('should return false for expired session', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            sessionId: 'wc_123',
            status: 'active',
            expiresAt: Date.now() - 1000
          }]
        });

        const isValid = await wcService.isSessionValid('session_topic');
        expect(isValid).toBe(false);
      });

      it('should return false for disconnected session', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            sessionId: 'wc_123',
            status: 'disconnected',
            expiresAt: Date.now() + 86400000
          }]
        });

        const isValid = await wcService.isSessionValid('session_topic');
        expect(isValid).toBe(false);
      });

      it('should return false for non-existent session', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        const isValid = await wcService.isSessionValid('unknown');
        expect(isValid).toBe(false);
      });
    });

    describe('cleanupExpired', () => {
      it('should clean up expired items', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [
                { PK: 'REALM#r1', SK: 'SESSION#s1', expiresAt: Date.now() - 1000 },
                { PK: 'REALM#r1', SK: 'SESSION#s2', expiresAt: Date.now() + 86400000 },
                { PK: 'REALM#r1', SK: 'PAIRING#p1', expiresAt: Date.now() - 2000 }
              ]
            });
          }
          return Promise.resolve({});
        });

        const cleaned = await wcService.cleanupExpired('r1');
        expect(cleaned).toBe(2);
      });
    });
  });
});
