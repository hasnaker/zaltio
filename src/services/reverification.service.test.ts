/**
 * Reverification Service Tests
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5 (Reverification)
 */

import {
  ReverificationService,
  ReverificationError,
  ReverificationLevel,
  SessionReverification,
  REVERIFICATION_LEVEL_HIERARCHY,
  DEFAULT_REVERIFICATION_VALIDITY
} from './reverification.service';
import {
  matchEndpoint,
  findReverificationRequirement,
  proofTypeToLevel,
  getValidityMinutes,
  levelSatisfiesRequirement,
  isReverificationValid,
  reverificationSatisfiesRequirement,
  isValidReverificationLevel
} from '../models/reverification.model';

describe('ReverificationService', () => {
  let service: ReverificationService;
  
  beforeEach(() => {
    service = new ReverificationService();
  });
  
  describe('Model Utilities', () => {
    describe('levelSatisfiesRequirement', () => {
      it('should return true when levels are equal', () => {
        expect(levelSatisfiesRequirement('password', 'password')).toBe(true);
        expect(levelSatisfiesRequirement('mfa', 'mfa')).toBe(true);
        expect(levelSatisfiesRequirement('webauthn', 'webauthn')).toBe(true);
      });
      
      it('should return true when current level is higher', () => {
        expect(levelSatisfiesRequirement('mfa', 'password')).toBe(true);
        expect(levelSatisfiesRequirement('webauthn', 'password')).toBe(true);
        expect(levelSatisfiesRequirement('webauthn', 'mfa')).toBe(true);
      });
      
      it('should return false when current level is lower', () => {
        expect(levelSatisfiesRequirement('password', 'mfa')).toBe(false);
        expect(levelSatisfiesRequirement('password', 'webauthn')).toBe(false);
        expect(levelSatisfiesRequirement('mfa', 'webauthn')).toBe(false);
      });
      
      it('should return false for invalid levels', () => {
        expect(levelSatisfiesRequirement('invalid' as ReverificationLevel, 'password')).toBe(false);
        expect(levelSatisfiesRequirement('password', 'invalid' as ReverificationLevel)).toBe(false);
      });
    });
    
    describe('isReverificationValid', () => {
      it('should return true for non-expired reverification', () => {
        const reverification: SessionReverification = {
          sessionId: 'session-123',
          level: 'password',
          verifiedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString()
        };
        
        expect(isReverificationValid(reverification)).toBe(true);
      });
      
      it('should return false for expired reverification', () => {
        const reverification: SessionReverification = {
          sessionId: 'session-123',
          level: 'password',
          verifiedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
          expiresAt: new Date(Date.now() - 10 * 60 * 1000).toISOString()
        };
        
        expect(isReverificationValid(reverification)).toBe(false);
      });
    });
    
    describe('reverificationSatisfiesRequirement', () => {
      it('should return false for null reverification', () => {
        expect(reverificationSatisfiesRequirement(null, 'password')).toBe(false);
        expect(reverificationSatisfiesRequirement(undefined, 'password')).toBe(false);
      });
      
      it('should return false for expired reverification', () => {
        const reverification: SessionReverification = {
          sessionId: 'session-123',
          level: 'mfa',
          verifiedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
          expiresAt: new Date(Date.now() - 10 * 60 * 1000).toISOString()
        };
        
        expect(reverificationSatisfiesRequirement(reverification, 'password')).toBe(false);
      });
      
      it('should return true for valid reverification with sufficient level', () => {
        const reverification: SessionReverification = {
          sessionId: 'session-123',
          level: 'mfa',
          verifiedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString()
        };
        
        expect(reverificationSatisfiesRequirement(reverification, 'password')).toBe(true);
        expect(reverificationSatisfiesRequirement(reverification, 'mfa')).toBe(true);
      });
      
      it('should return false for valid reverification with insufficient level', () => {
        const reverification: SessionReverification = {
          sessionId: 'session-123',
          level: 'password',
          verifiedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString()
        };
        
        expect(reverificationSatisfiesRequirement(reverification, 'mfa')).toBe(false);
        expect(reverificationSatisfiesRequirement(reverification, 'webauthn')).toBe(false);
      });
    });
    
    describe('isValidReverificationLevel', () => {
      it('should return true for valid levels', () => {
        expect(isValidReverificationLevel('password')).toBe(true);
        expect(isValidReverificationLevel('mfa')).toBe(true);
        expect(isValidReverificationLevel('webauthn')).toBe(true);
      });
      
      it('should return false for invalid levels', () => {
        expect(isValidReverificationLevel('invalid')).toBe(false);
        expect(isValidReverificationLevel('')).toBe(false);
        expect(isValidReverificationLevel('PASSWORD')).toBe(false);
      });
    });
    
    describe('proofTypeToLevel', () => {
      it('should map password to password level', () => {
        expect(proofTypeToLevel('password')).toBe('password');
      });
      
      it('should map totp to mfa level', () => {
        expect(proofTypeToLevel('totp')).toBe('mfa');
      });
      
      it('should map backup_code to mfa level', () => {
        expect(proofTypeToLevel('backup_code')).toBe('mfa');
      });
      
      it('should map webauthn to webauthn level', () => {
        expect(proofTypeToLevel('webauthn')).toBe('webauthn');
      });
    });
    
    describe('getValidityMinutes', () => {
      it('should return default validity for each level', () => {
        expect(getValidityMinutes('password')).toBe(DEFAULT_REVERIFICATION_VALIDITY.password);
        expect(getValidityMinutes('mfa')).toBe(DEFAULT_REVERIFICATION_VALIDITY.mfa);
        expect(getValidityMinutes('webauthn')).toBe(DEFAULT_REVERIFICATION_VALIDITY.webauthn);
      });
      
      it('should return custom validity when provided', () => {
        expect(getValidityMinutes('password', 5)).toBe(5);
        expect(getValidityMinutes('mfa', 20)).toBe(20);
      });
      
      it('should ignore invalid custom validity', () => {
        expect(getValidityMinutes('password', 0)).toBe(DEFAULT_REVERIFICATION_VALIDITY.password);
        expect(getValidityMinutes('password', -5)).toBe(DEFAULT_REVERIFICATION_VALIDITY.password);
      });
    });
    
    describe('matchEndpoint', () => {
      it('should match exact endpoints', () => {
        expect(matchEndpoint('/me/password', '/me/password')).toBe(true);
        expect(matchEndpoint('/api-keys', '/api-keys')).toBe(true);
      });
      
      it('should not match different endpoints', () => {
        expect(matchEndpoint('/me/password', '/me/email')).toBe(false);
        expect(matchEndpoint('/api-keys', '/api-keys/123')).toBe(false);
      });
      
      it('should match wildcard patterns', () => {
        expect(matchEndpoint('/api-keys/*', '/api-keys/123')).toBe(true);
        expect(matchEndpoint('/organizations/*/members', '/organizations/org-123/members')).toBe(true);
        expect(matchEndpoint('/organizations/*/members/*/remove', '/organizations/org-123/members/user-456/remove')).toBe(true);
      });
      
      it('should not match partial wildcards', () => {
        expect(matchEndpoint('/api-keys/*', '/api-keys')).toBe(false);
        expect(matchEndpoint('/api-keys/*', '/api-keys/123/extra')).toBe(false);
      });
    });
    
    describe('findReverificationRequirement', () => {
      it('should find requirement for exact endpoint', () => {
        const req = findReverificationRequirement('/me/password', 'PUT');
        expect(req).not.toBeNull();
        expect(req?.level).toBe('password');
      });
      
      it('should find requirement for wildcard endpoint', () => {
        const req = findReverificationRequirement('/api-keys/key-123', 'DELETE');
        expect(req).not.toBeNull();
        expect(req?.level).toBe('password');
      });
      
      it('should return null for non-protected endpoint', () => {
        const req = findReverificationRequirement('/users', 'GET');
        expect(req).toBeNull();
      });
      
      it('should return null for wrong method', () => {
        const req = findReverificationRequirement('/me/password', 'GET');
        expect(req).toBeNull();
      });
    });
  });
  
  describe('Service Methods', () => {
    describe('requireReverification', () => {
      it('should mark session as requiring reverification', async () => {
        await service.requireReverification('session-123', 'mfa');
        
        // Check that reverification is not yet complete
        const result = await service.checkReverification('session-123', 'mfa');
        expect(result).toBe(false);
      });
    });
    
    describe('checkReverification', () => {
      it('should return false when no reverification exists', async () => {
        const result = await service.checkReverification('session-123', 'password');
        expect(result).toBe(false);
      });
      
      it('should return true after completing reverification', async () => {
        await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'password', value: 'test-password' }
        );
        
        const result = await service.checkReverification('session-123', 'password');
        expect(result).toBe(true);
      });
      
      it('should return true when level is higher than required', async () => {
        await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'totp', value: '123456' }
        );
        
        const result = await service.checkReverification('session-123', 'password');
        expect(result).toBe(true);
      });
      
      it('should return false when level is lower than required', async () => {
        await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'password', value: 'test-password' }
        );
        
        const result = await service.checkReverification('session-123', 'mfa');
        expect(result).toBe(false);
      });
    });
    
    describe('completeReverification', () => {
      it('should complete reverification with password proof', async () => {
        const result = await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'password', value: 'test-password' }
        );
        
        expect(result.sessionId).toBe('session-123');
        expect(result.level).toBe('password');
        expect(result.method).toBe('password');
        expect(new Date(result.expiresAt).getTime()).toBeGreaterThan(Date.now());
      });
      
      it('should complete reverification with MFA proof', async () => {
        const result = await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'totp', value: '123456' }
        );
        
        expect(result.level).toBe('mfa');
        expect(result.method).toBe('totp');
      });
      
      it('should complete reverification with WebAuthn proof', async () => {
        const result = await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'webauthn', value: 'assertion-data', challenge: 'challenge-123' }
        );
        
        expect(result.level).toBe('webauthn');
        expect(result.method).toBe('webauthn');
      });
      
      it('should complete reverification with backup code', async () => {
        const result = await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'backup_code', value: 'ABCD1234EFGH' }
        );
        
        expect(result.level).toBe('mfa');
        expect(result.method).toBe('backup_code');
      });
      
      it('should use custom validity when provided', async () => {
        const result = await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'password', value: 'test-password' },
          { validityMinutes: 5 }
        );
        
        const expectedExpiry = Date.now() + 5 * 60 * 1000;
        const actualExpiry = new Date(result.expiresAt).getTime();
        
        // Allow 1 second tolerance
        expect(Math.abs(actualExpiry - expectedExpiry)).toBeLessThan(1000);
      });
      
      it('should reject empty password', async () => {
        await expect(
          service.completeReverification(
            'session-123',
            'user-456',
            { type: 'password', value: '' }
          )
        ).rejects.toThrow(ReverificationError);
      });
      
      it('should reject invalid TOTP format', async () => {
        await expect(
          service.completeReverification(
            'session-123',
            'user-456',
            { type: 'totp', value: '12345' } // Should be 6 digits
          )
        ).rejects.toThrow(ReverificationError);
      });
      
      it('should reject WebAuthn without challenge', async () => {
        await expect(
          service.completeReverification(
            'session-123',
            'user-456',
            { type: 'webauthn', value: 'assertion-data' }
          )
        ).rejects.toThrow(ReverificationError);
      });
      
      it('should reject short backup code', async () => {
        await expect(
          service.completeReverification(
            'session-123',
            'user-456',
            { type: 'backup_code', value: 'ABC' }
          )
        ).rejects.toThrow(ReverificationError);
      });
    });
    
    describe('getRequiredLevel', () => {
      it('should return config for protected endpoint', () => {
        const config = service.getRequiredLevel('/me/password', 'PUT');
        
        expect(config).not.toBeNull();
        expect(config?.level).toBe('password');
        expect(config?.validityMinutes).toBeGreaterThan(0);
      });
      
      it('should return null for non-protected endpoint', () => {
        const config = service.getRequiredLevel('/users', 'GET');
        
        expect(config).toBeNull();
      });
      
      it('should return config for MFA disable endpoint', () => {
        const config = service.getRequiredLevel('/mfa/disable', 'POST');
        
        expect(config).not.toBeNull();
        expect(config?.level).toBe('mfa');
      });
      
      it('should return config for organization delete endpoint', () => {
        const config = service.getRequiredLevel('/organizations/org-123/delete', 'DELETE');
        
        expect(config).not.toBeNull();
        expect(config?.level).toBe('webauthn');
      });
    });
    
    describe('getReverificationStatus', () => {
      it('should return status for session with reverification', async () => {
        await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'totp', value: '123456' }
        );
        
        const status = await service.getReverificationStatus('session-123');
        
        expect(status.hasReverification).toBe(true);
        expect(status.isValid).toBe(true);
        expect(status.reverification?.level).toBe('mfa');
      });
      
      it('should return status for session without reverification', async () => {
        const status = await service.getReverificationStatus('session-new');
        
        expect(status.hasReverification).toBe(false);
        expect(status.isValid).toBe(false);
        expect(status.reverification).toBeNull();
      });
      
      it('should include required level when provided', async () => {
        const status = await service.getReverificationStatus('session-123', 'webauthn');
        
        expect(status.requiredLevel).toBe('webauthn');
      });
    });
    
    describe('clearReverification', () => {
      it('should clear reverification from session', async () => {
        await service.completeReverification(
          'session-123',
          'user-456',
          { type: 'password', value: 'test-password' }
        );
        
        // Verify it exists
        let result = await service.checkReverification('session-123', 'password');
        expect(result).toBe(true);
        
        // Clear it
        await service.clearReverification('session-123');
        
        // Verify it's gone
        result = await service.checkReverification('session-123', 'password');
        expect(result).toBe(false);
      });
    });
    
    describe('levelSatisfies', () => {
      it('should return true for equal levels', () => {
        expect(service.levelSatisfies('password', 'password')).toBe(true);
        expect(service.levelSatisfies('mfa', 'mfa')).toBe(true);
        expect(service.levelSatisfies('webauthn', 'webauthn')).toBe(true);
      });
      
      it('should return true for higher levels', () => {
        expect(service.levelSatisfies('mfa', 'password')).toBe(true);
        expect(service.levelSatisfies('webauthn', 'password')).toBe(true);
        expect(service.levelSatisfies('webauthn', 'mfa')).toBe(true);
      });
      
      it('should return false for lower levels', () => {
        expect(service.levelSatisfies('password', 'mfa')).toBe(false);
        expect(service.levelSatisfies('password', 'webauthn')).toBe(false);
        expect(service.levelSatisfies('mfa', 'webauthn')).toBe(false);
      });
    });
    
    describe('getLevelIndex', () => {
      it('should return correct indices', () => {
        expect(service.getLevelIndex('password')).toBe(0);
        expect(service.getLevelIndex('mfa')).toBe(1);
        expect(service.getLevelIndex('webauthn')).toBe(2);
      });
      
      it('should return -1 for invalid level', () => {
        expect(service.getLevelIndex('invalid' as ReverificationLevel)).toBe(-1);
      });
    });
  });
  
  describe('Level Hierarchy', () => {
    it('should have correct hierarchy order', () => {
      expect(REVERIFICATION_LEVEL_HIERARCHY).toEqual(['password', 'mfa', 'webauthn']);
    });
    
    it('should have default validity for all levels', () => {
      expect(DEFAULT_REVERIFICATION_VALIDITY.password).toBe(10);
      expect(DEFAULT_REVERIFICATION_VALIDITY.mfa).toBe(15);
      expect(DEFAULT_REVERIFICATION_VALIDITY.webauthn).toBe(30);
    });
  });
});
