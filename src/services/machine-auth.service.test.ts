/**
 * Machine Auth Service Tests
 * Tests for M2M authentication service
 * 
 * Validates: Requirements 1.3, 1.4, 1.5, 1.6 (M2M Authentication)
 */

// Mock repository
const mockCreateMachine = jest.fn();
const mockGetMachineById = jest.fn();
const mockGetMachineByClientId = jest.fn();
const mockAuthenticateMachine = jest.fn();
const mockListMachinesByRealm = jest.fn();
const mockUpdateMachine = jest.fn();
const mockRotateCredentials = jest.fn();
const mockDeleteMachine = jest.fn();
const mockMachineHasScope = jest.fn();

jest.mock('../repositories/machine.repository', () => ({
  createMachine: (...args: unknown[]) => mockCreateMachine(...args),
  getMachineById: (...args: unknown[]) => mockGetMachineById(...args),
  getMachineByClientId: (...args: unknown[]) => mockGetMachineByClientId(...args),
  authenticateMachine: (...args: unknown[]) => mockAuthenticateMachine(...args),
  listMachinesByRealm: (...args: unknown[]) => mockListMachinesByRealm(...args),
  updateMachine: (...args: unknown[]) => mockUpdateMachine(...args),
  rotateCredentials: (...args: unknown[]) => mockRotateCredentials(...args),
  deleteMachine: (...args: unknown[]) => mockDeleteMachine(...args),
  machineHasScope: (...args: unknown[]) => mockMachineHasScope(...args)
}));

// Mock jsonwebtoken
const mockJwtSign = jest.fn().mockReturnValue('mock_jwt_token');
const mockJwtVerify = jest.fn();

class MockTokenExpiredError extends Error {
  constructor() {
    super('Token expired');
    this.name = 'TokenExpiredError';
  }
}

class MockJsonWebTokenError extends Error {
  constructor() {
    super('Invalid token');
    this.name = 'JsonWebTokenError';
  }
}

jest.mock('jsonwebtoken', () => ({
  sign: (...args: unknown[]) => mockJwtSign(...args),
  verify: (...args: unknown[]) => mockJwtVerify(...args),
  TokenExpiredError: MockTokenExpiredError,
  JsonWebTokenError: MockJsonWebTokenError
}));

import { MachineAuthService, MachineAuthError } from './machine-auth.service';
import { Machine, MachineStatus } from '../models/machine.model';

describe('MachineAuthService', () => {
  let service: MachineAuthService;
  
  const mockRealmId = 'realm_test123';
  const mockMachineId = 'machine_abc123';
  const mockClientId = 'zalt_m2m_abc123def456789012345678';  // 24 hex chars after prefix
  const mockClientSecret = 'test_secret_12345';
  
  const mockMachine: Machine = {
    id: mockMachineId,
    realm_id: mockRealmId,
    name: 'Test Machine',
    client_id: mockClientId,
    client_secret_hash: 'hashed_secret',
    scopes: ['read:users', 'write:sessions'],
    allowed_targets: [],
    status: 'active' as MachineStatus,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z'
  };
  
  beforeEach(() => {
    jest.clearAllMocks();
    service = new MachineAuthService();
  });
  
  describe('createMachine', () => {
    it('should create a machine with valid scopes', async () => {
      const mockResult = {
        machine: {
          id: mockMachineId,
          realm_id: mockRealmId,
          name: 'Test Machine',
          client_id: mockClientId,
          scopes: ['read:users'],
          allowed_targets: [],
          status: 'active',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z'
        },
        client_secret: mockClientSecret
      };
      
      mockCreateMachine.mockResolvedValueOnce(mockResult);
      
      const result = await service.createMachine({
        realm_id: mockRealmId,
        name: 'Test Machine',
        scopes: ['read:users'],
        created_by: 'admin_123'
      });
      
      expect(result.machine.name).toBe('Test Machine');
      expect(result.client_secret).toBe(mockClientSecret);
      expect(mockCreateMachine).toHaveBeenCalled();
    });
    
    it('should reject invalid scopes', async () => {
      await expect(
        service.createMachine({
          realm_id: mockRealmId,
          name: 'Test Machine',
          scopes: ['invalid:scope', 'bad:scope']
        })
      ).rejects.toThrow(MachineAuthError);
      
      expect(mockCreateMachine).not.toHaveBeenCalled();
    });
  });
  
  describe('authenticateMachine', () => {
    it('should authenticate valid credentials and return token', async () => {
      mockAuthenticateMachine.mockResolvedValueOnce(mockMachine);
      
      const result = await service.authenticateMachine({
        client_id: mockClientId,
        client_secret: mockClientSecret
      });
      
      expect(result.access_token).toBe('mock_jwt_token');
      expect(result.token_type).toBe('Bearer');
      expect(result.expires_in).toBe(3600);
      expect(result.scope).toBe('read:users write:sessions');
      expect(mockJwtSign).toHaveBeenCalled();
    });
    
    it('should reject invalid client ID format', async () => {
      await expect(
        service.authenticateMachine({
          client_id: 'invalid_format',
          client_secret: mockClientSecret
        })
      ).rejects.toThrow(MachineAuthError);
      
      expect(mockAuthenticateMachine).not.toHaveBeenCalled();
    });
    
    it('should reject invalid credentials', async () => {
      mockAuthenticateMachine.mockResolvedValueOnce(null);
      
      await expect(
        service.authenticateMachine({
          client_id: mockClientId,
          client_secret: 'wrong_secret'
        })
      ).rejects.toThrow(MachineAuthError);
    });
    
    it('should allow requesting subset of scopes', async () => {
      mockAuthenticateMachine.mockResolvedValueOnce(mockMachine);
      
      const result = await service.authenticateMachine({
        client_id: mockClientId,
        client_secret: mockClientSecret,
        scopes: ['read:users']  // Subset of machine's scopes
      });
      
      expect(result.scope).toBe('read:users');
    });
    
    it('should reject requesting scopes beyond machine permissions', async () => {
      mockAuthenticateMachine.mockResolvedValueOnce(mockMachine);
      
      await expect(
        service.authenticateMachine({
          client_id: mockClientId,
          client_secret: mockClientSecret,
          scopes: ['admin:all']  // Not in machine's scopes
        })
      ).rejects.toThrow(MachineAuthError);
    });
  });
  
  describe('validateM2MToken', () => {
    it('should validate valid M2M token', async () => {
      const mockPayload = {
        machine_id: mockMachineId,
        realm_id: mockRealmId,
        scopes: ['read:users'],
        target_machines: [],
        type: 'm2m',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: 'https://api.zalt.io',
        jti: 'unique_id'
      };
      
      mockJwtVerify.mockReturnValueOnce(mockPayload);
      
      const result = await service.validateM2MToken('valid_token');
      
      expect(result.machine_id).toBe(mockMachineId);
      expect(result.type).toBe('m2m');
    });
    
    it('should reject expired token', async () => {
      mockJwtVerify.mockImplementationOnce(() => {
        throw new MockTokenExpiredError();
      });
      
      await expect(
        service.validateM2MToken('expired_token')
      ).rejects.toThrow(MachineAuthError);
    });
    
    it('should reject invalid token', async () => {
      mockJwtVerify.mockImplementationOnce(() => {
        throw new MockJsonWebTokenError();
      });
      
      await expect(
        service.validateM2MToken('invalid_token')
      ).rejects.toThrow(MachineAuthError);
    });
    
    it('should reject non-M2M token type', async () => {
      const mockPayload = {
        type: 'user',  // Not m2m
        iat: Math.floor(Date.now() / 1000)
      };
      
      mockJwtVerify.mockReturnValueOnce(mockPayload);
      
      await expect(
        service.validateM2MToken('user_token')
      ).rejects.toThrow(MachineAuthError);
    });
  });
  
  describe('rotateCredentials', () => {
    it('should rotate credentials and return new secret', async () => {
      mockRotateCredentials.mockResolvedValueOnce({
        clientId: mockClientId,
        clientSecret: 'new_secret_12345'
      });
      
      const result = await service.rotateCredentials(
        mockRealmId,
        mockMachineId,
        'admin_123'
      );
      
      expect(result.clientId).toBe(mockClientId);
      expect(result.clientSecret).toBe('new_secret_12345');
    });
    
    it('should throw error for non-existent machine', async () => {
      mockRotateCredentials.mockResolvedValueOnce(null);
      
      await expect(
        service.rotateCredentials(mockRealmId, 'nonexistent', 'admin_123')
      ).rejects.toThrow(MachineAuthError);
    });
  });
  
  describe('listMachines', () => {
    it('should return all machines in realm', async () => {
      const mockMachines = [
        { id: 'machine_1', name: 'Machine 1' },
        { id: 'machine_2', name: 'Machine 2' }
      ];
      
      mockListMachinesByRealm.mockResolvedValueOnce(mockMachines);
      
      const result = await service.listMachines(mockRealmId);
      
      expect(result).toHaveLength(2);
      expect(mockListMachinesByRealm).toHaveBeenCalledWith(mockRealmId);
    });
  });
  
  describe('getMachine', () => {
    it('should return machine by ID', async () => {
      mockGetMachineById.mockResolvedValueOnce(mockMachine);
      
      const result = await service.getMachine(mockRealmId, mockMachineId);
      
      expect(result?.id).toBe(mockMachineId);
      expect(mockGetMachineById).toHaveBeenCalledWith(mockRealmId, mockMachineId);
    });
    
    it('should return null for non-existent machine', async () => {
      mockGetMachineById.mockResolvedValueOnce(null);
      
      const result = await service.getMachine(mockRealmId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });
  
  describe('updateMachine', () => {
    it('should update machine configuration', async () => {
      const updatedMachine = { ...mockMachine, name: 'Updated Machine' };
      mockUpdateMachine.mockResolvedValueOnce(updatedMachine);
      
      const result = await service.updateMachine(
        mockRealmId,
        mockMachineId,
        { name: 'Updated Machine' },
        'admin_123'
      );
      
      expect(result?.name).toBe('Updated Machine');
    });
    
    it('should reject invalid scopes in update', async () => {
      await expect(
        service.updateMachine(
          mockRealmId,
          mockMachineId,
          { scopes: ['invalid:scope'] },
          'admin_123'
        )
      ).rejects.toThrow(MachineAuthError);
      
      expect(mockUpdateMachine).not.toHaveBeenCalled();
    });
  });
  
  describe('deleteMachine', () => {
    it('should delete machine', async () => {
      mockDeleteMachine.mockResolvedValueOnce(true);
      
      const result = await service.deleteMachine(
        mockRealmId,
        mockMachineId,
        'admin_123'
      );
      
      expect(result).toBe(true);
    });
    
    it('should return false for non-existent machine', async () => {
      mockDeleteMachine.mockResolvedValueOnce(false);
      
      const result = await service.deleteMachine(
        mockRealmId,
        'nonexistent',
        'admin_123'
      );
      
      expect(result).toBe(false);
    });
  });
  
  describe('checkScope', () => {
    it('should delegate to repository machineHasScope', () => {
      mockMachineHasScope.mockReturnValueOnce(true);
      
      const result = service.checkScope(mockMachine, 'read:users');
      
      expect(result).toBe(true);
      expect(mockMachineHasScope).toHaveBeenCalledWith(mockMachine, 'read:users');
    });
  });
});

describe('MachineAuthError', () => {
  it('should create error with code and message', () => {
    const error = new MachineAuthError('TEST_CODE', 'Test message');
    
    expect(error.code).toBe('TEST_CODE');
    expect(error.message).toBe('Test message');
    expect(error.name).toBe('MachineAuthError');
  });
});
