/**
 * Machine Repository Tests
 * Tests for M2M machine CRUD operations
 * 
 * Validates: Requirements 1.1, 1.2 (M2M Authentication)
 */

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  }
}));

// Mock password utils
const mockHashPassword = jest.fn().mockResolvedValue('hashed_secret');
const mockVerifyPassword = jest.fn().mockResolvedValue(true);
jest.mock('../utils/password', () => ({
  hashPassword: (...args: unknown[]) => mockHashPassword(...args),
  verifyPassword: (...args: unknown[]) => mockVerifyPassword(...args)
}));

// Import after mocks
import {
  createMachine,
  getMachineById,
  getMachineByClientId,
  authenticateMachine,
  listMachinesByRealm,
  updateMachine,
  rotateCredentials,
  deleteMachine,
  countMachinesByRealm,
  machineHasScope,
  machineCanCallTarget
} from './machine.repository';
import { Machine, MachineStatus } from '../models/machine.model';

describe('Machine Repository', () => {
  const mockRealmId = 'realm_test123';
  const mockMachineId = 'machine_abc123def456';
  const mockClientId = 'zalt_m2m_abc123def456789012';
  
  beforeEach(() => {
    mockSend.mockReset();
    mockHashPassword.mockClear();
    mockVerifyPassword.mockClear();
  });
  
  describe('createMachine', () => {
    it('should create a new machine with generated credentials', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        realm_id: mockRealmId,
        name: 'Test Machine',
        description: 'A test machine for M2M auth',
        scopes: ['read:users', 'write:sessions'],
        allowed_targets: [],
        created_by: 'admin_123'
      };
      
      const result = await createMachine(input);
      
      // Verify machine was created
      expect(result.machine).toBeDefined();
      expect(result.machine.name).toBe('Test Machine');
      expect(result.machine.realm_id).toBe(mockRealmId);
      expect(result.machine.scopes).toEqual(['read:users', 'write:sessions']);
      expect(result.machine.status).toBe('active');
      
      // Verify client ID format
      expect(result.machine.client_id).toMatch(/^zalt_m2m_[a-f0-9]{24}$/);
      
      // Verify client secret is returned (only once)
      expect(result.client_secret).toBeDefined();
      expect(result.client_secret.length).toBeGreaterThan(32);
      
      // Verify password was hashed
      expect(mockHashPassword).toHaveBeenCalled();
      
      // Verify DynamoDB put was called
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should set default rate limit if not provided', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        realm_id: mockRealmId,
        name: 'Test Machine',
        scopes: ['read:users']
      };
      
      const result = await createMachine(input);
      
      expect(result.machine.rate_limit).toBe(1000);
    });
    
    it('should generate unique machine ID', async () => {
      mockSend.mockResolvedValue({});
      
      const input = {
        realm_id: mockRealmId,
        name: 'Test Machine',
        scopes: ['read:users']
      };
      
      const result1 = await createMachine(input);
      const result2 = await createMachine(input);
      
      expect(result1.machine.id).not.toBe(result2.machine.id);
      expect(result1.machine.client_id).not.toBe(result2.machine.client_id);
    });
  });
  
  describe('getMachineById', () => {
    it('should return machine when found', async () => {
      const mockMachine = {
        id: mockMachineId,
        realm_id: mockRealmId,
        name: 'Test Machine',
        client_id: mockClientId,
        client_secret_hash: 'hashed',
        scopes: ['read:users'],
        allowed_targets: [],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Item: mockMachine
      });
      
      const result = await getMachineById(mockRealmId, mockMachineId);
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockMachineId);
      expect(result?.name).toBe('Test Machine');
    });
    
    it('should return null when machine not found', async () => {
      mockSend.mockResolvedValueOnce({
        Item: undefined
      });
      
      const result = await getMachineById(mockRealmId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });
  
  describe('getMachineByClientId', () => {
    it('should return machine when found by client ID', async () => {
      const mockMachine = {
        id: mockMachineId,
        realm_id: mockRealmId,
        name: 'Test Machine',
        client_id: mockClientId,
        client_secret_hash: 'hashed',
        scopes: ['read:users'],
        allowed_targets: [],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockMachine]
      });
      
      const result = await getMachineByClientId(mockClientId);
      
      expect(result).toBeDefined();
      expect(result?.client_id).toBe(mockClientId);
    });
    
    it('should return null when client ID not found', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getMachineByClientId('invalid_client_id');
      
      expect(result).toBeNull();
    });
  });
  
  describe('authenticateMachine', () => {
    const mockMachine = {
      id: mockMachineId,
      realm_id: mockRealmId,
      name: 'Test Machine',
      client_id: mockClientId,
      client_secret_hash: 'hashed_secret',
      scopes: ['read:users'],
      allowed_targets: [],
      status: 'active' as MachineStatus,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z'
    };
    
    it('should authenticate valid credentials', async () => {
      mockSend
        .mockResolvedValueOnce({ Items: [mockMachine] })
        .mockResolvedValueOnce({}); // updateLastUsed
      
      mockVerifyPassword.mockResolvedValueOnce(true);
      
      const result = await authenticateMachine(mockClientId, 'valid_secret');
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockMachineId);
      expect(mockVerifyPassword).toHaveBeenCalledWith('valid_secret', 'hashed_secret');
    });
    
    it('should reject invalid credentials', async () => {
      mockSend.mockResolvedValueOnce({
        Items: [mockMachine]
      });
      
      mockVerifyPassword.mockResolvedValueOnce(false);
      
      const result = await authenticateMachine(mockClientId, 'wrong_secret');
      
      expect(result).toBeNull();
    });
    
    it('should reject disabled machine', async () => {
      const disabledMachine = { ...mockMachine, status: 'disabled' as MachineStatus };
      
      mockSend.mockResolvedValueOnce({
        Items: [disabledMachine]
      });
      
      const result = await authenticateMachine(mockClientId, 'valid_secret');
      
      expect(result).toBeNull();
      expect(mockVerifyPassword).not.toHaveBeenCalled();
    });
    
    it('should reject non-existent machine', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await authenticateMachine('nonexistent', 'secret');
      
      expect(result).toBeNull();
    });
  });
  
  describe('listMachinesByRealm', () => {
    it('should return all active machines in realm', async () => {
      const mockMachines = [
        {
          id: 'machine_1',
          realm_id: mockRealmId,
          name: 'Machine 1',
          client_id: 'zalt_m2m_1',
          scopes: ['read:users'],
          allowed_targets: [],
          status: 'active',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z'
        },
        {
          id: 'machine_2',
          realm_id: mockRealmId,
          name: 'Machine 2',
          client_id: 'zalt_m2m_2',
          scopes: ['write:sessions'],
          allowed_targets: [],
          status: 'active',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockMachines
      });
      
      const result = await listMachinesByRealm(mockRealmId);
      
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe('Machine 1');
      expect(result[1].name).toBe('Machine 2');
    });
    
    it('should return empty array when no machines', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await listMachinesByRealm(mockRealmId);
      
      expect(result).toEqual([]);
    });
  });
  
  describe('updateMachine', () => {
    it('should update machine configuration', async () => {
      const updatedMachine = {
        id: mockMachineId,
        realm_id: mockRealmId,
        name: 'Updated Machine',
        client_id: mockClientId,
        client_secret_hash: 'hashed',
        scopes: ['read:users', 'write:users'],
        allowed_targets: ['machine_target'],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-02-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedMachine
      });
      
      const result = await updateMachine(mockRealmId, mockMachineId, {
        name: 'Updated Machine',
        scopes: ['read:users', 'write:users'],
        allowed_targets: ['machine_target']
      });
      
      expect(result).toBeDefined();
      expect(result?.name).toBe('Updated Machine');
      expect(result?.scopes).toContain('write:users');
    });
    
    it('should return null when machine not found', async () => {
      mockSend.mockResolvedValueOnce({
        Attributes: undefined
      });
      
      const result = await updateMachine(mockRealmId, 'nonexistent', {
        name: 'Updated'
      });
      
      expect(result).toBeNull();
    });
  });
  
  describe('rotateCredentials', () => {
    it('should generate new client secret', async () => {
      const mockMachine = {
        id: mockMachineId,
        realm_id: mockRealmId,
        name: 'Test Machine',
        client_id: mockClientId,
        client_secret_hash: 'old_hash',
        scopes: ['read:users'],
        allowed_targets: [],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend
        .mockResolvedValueOnce({ Item: mockMachine })
        .mockResolvedValueOnce({}); // update
      
      const result = await rotateCredentials(mockRealmId, mockMachineId);
      
      expect(result).toBeDefined();
      expect(result?.clientId).toBe(mockClientId);
      expect(result?.clientSecret).toBeDefined();
      expect(result?.clientSecret.length).toBeGreaterThan(32);
      expect(mockHashPassword).toHaveBeenCalled();
    });
    
    it('should return null for disabled machine', async () => {
      const disabledMachine = {
        id: mockMachineId,
        realm_id: mockRealmId,
        name: 'Test',
        client_id: mockClientId,
        client_secret_hash: 'hash',
        scopes: [],
        allowed_targets: [],
        status: 'disabled' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Item: disabledMachine
      });
      
      const result = await rotateCredentials(mockRealmId, mockMachineId);
      
      expect(result).toBeNull();
    });
    
    it('should return null for non-existent machine', async () => {
      mockSend.mockResolvedValueOnce({
        Item: undefined
      });
      
      const result = await rotateCredentials(mockRealmId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });
  
  describe('deleteMachine', () => {
    it('should soft delete machine', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const result = await deleteMachine(mockRealmId, mockMachineId);
      
      expect(result).toBe(true);
      expect(mockSend).toHaveBeenCalled();
    });
    
    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
      
      const result = await deleteMachine(mockRealmId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });
  
  describe('countMachinesByRealm', () => {
    it('should return count of machines', async () => {
      mockSend.mockResolvedValueOnce({
        Count: 5
      });
      
      const result = await countMachinesByRealm(mockRealmId);
      
      expect(result).toBe(5);
    });
    
    it('should return 0 when no machines', async () => {
      mockSend.mockResolvedValueOnce({
        Count: 0
      });
      
      const result = await countMachinesByRealm(mockRealmId);
      
      expect(result).toBe(0);
    });
  });
  
  describe('machineHasScope', () => {
    it('should return true when machine has scope', () => {
      const machine = {
        id: 'machine_test',
        realm_id: 'realm_test',
        name: 'Test',
        client_id: 'zalt_m2m_test',
        client_secret_hash: 'hash',
        scopes: ['read:users', 'write:sessions'],
        allowed_targets: [],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      } as Machine;
      
      expect(machineHasScope(machine, 'read:users')).toBe(true);
      expect(machineHasScope(machine, 'write:sessions')).toBe(true);
    });
    
    it('should return false when machine lacks scope', () => {
      const machine = {
        id: 'machine_test',
        realm_id: 'realm_test',
        name: 'Test',
        client_id: 'zalt_m2m_test',
        client_secret_hash: 'hash',
        scopes: ['read:users'],
        allowed_targets: [],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      } as Machine;
      
      expect(machineHasScope(machine, 'write:users')).toBe(false);
    });
    
    it('should return true for admin:all scope', () => {
      const machine = {
        id: 'machine_test',
        realm_id: 'realm_test',
        name: 'Test',
        client_id: 'zalt_m2m_test',
        client_secret_hash: 'hash',
        scopes: ['admin:all'],
        allowed_targets: [],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      } as Machine;
      
      expect(machineHasScope(machine, 'read:users')).toBe(true);
      expect(machineHasScope(machine, 'write:sessions')).toBe(true);
      expect(machineHasScope(machine, 'delete:users')).toBe(true);
    });
  });
  
  describe('machineCanCallTarget', () => {
    it('should return true when target is allowed', () => {
      const machine = {
        id: 'machine_test',
        realm_id: 'realm_test',
        name: 'Test',
        client_id: 'zalt_m2m_test',
        client_secret_hash: 'hash',
        scopes: [],
        allowed_targets: ['machine_a', 'machine_b'],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      } as Machine;
      
      expect(machineCanCallTarget(machine, 'machine_a')).toBe(true);
      expect(machineCanCallTarget(machine, 'machine_b')).toBe(true);
    });
    
    it('should return false when target not allowed', () => {
      const machine = {
        id: 'machine_test',
        realm_id: 'realm_test',
        name: 'Test',
        client_id: 'zalt_m2m_test',
        client_secret_hash: 'hash',
        scopes: [],
        allowed_targets: ['machine_a'],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      } as Machine;
      
      expect(machineCanCallTarget(machine, 'machine_c')).toBe(false);
    });
    
    it('should return true when allowed_targets is empty (allow all)', () => {
      const machine = {
        id: 'machine_test',
        realm_id: 'realm_test',
        name: 'Test',
        client_id: 'zalt_m2m_test',
        client_secret_hash: 'hash',
        scopes: [],
        allowed_targets: [],
        status: 'active' as MachineStatus,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z'
      } as Machine;
      
      expect(machineCanCallTarget(machine, 'any_machine')).toBe(true);
    });
  });
});

describe('Machine Model Utilities', () => {
  // Import model utilities
  const { isValidClientId, isValidScope, validateScopes, scopesAllowed, CLIENT_ID_PREFIX } = require('../models/machine.model');
  
  describe('isValidClientId', () => {
    it('should return true for valid client ID', () => {
      expect(isValidClientId('zalt_m2m_abc123def456789012345678')).toBe(true);
    });
    
    it('should return false for invalid prefix', () => {
      expect(isValidClientId('invalid_abc123def456789012345678')).toBe(false);
    });
    
    it('should return false for wrong length', () => {
      expect(isValidClientId('zalt_m2m_short')).toBe(false);
    });
  });
  
  describe('isValidScope', () => {
    it('should return true for valid scopes', () => {
      expect(isValidScope('read:users')).toBe(true);
      expect(isValidScope('write:sessions')).toBe(true);
      expect(isValidScope('admin:all')).toBe(true);
    });
    
    it('should return false for invalid scopes', () => {
      expect(isValidScope('invalid:scope')).toBe(false);
      expect(isValidScope('random')).toBe(false);
    });
  });
  
  describe('validateScopes', () => {
    it('should return valid true for all valid scopes', () => {
      const result = validateScopes(['read:users', 'write:sessions']);
      expect(result.valid).toBe(true);
      expect(result.invalid).toHaveLength(0);
    });
    
    it('should return invalid scopes', () => {
      const result = validateScopes(['read:users', 'invalid:scope', 'bad']);
      expect(result.valid).toBe(false);
      expect(result.invalid).toContain('invalid:scope');
      expect(result.invalid).toContain('bad');
    });
  });
  
  describe('scopesAllowed', () => {
    it('should return true when requested scopes are subset', () => {
      expect(scopesAllowed(['read:users'], ['read:users', 'write:users'])).toBe(true);
    });
    
    it('should return false when requested scope not in allowed', () => {
      expect(scopesAllowed(['delete:users'], ['read:users'])).toBe(false);
    });
    
    it('should return true for admin:all', () => {
      expect(scopesAllowed(['read:users', 'delete:users'], ['admin:all'])).toBe(true);
    });
  });
});
