/**
 * Session Task Integration Service Tests
 * 
 * Tests for the session task integration with login flow.
 * Validates: Requirements 4.3, 4.4, 4.5 (Session Tasks)
 */

// Mock functions - defined before jest.mock()
const mockCreateTask = jest.fn();
const mockGetUserMemberships = jest.fn();
const mockGetOrganization = jest.fn();
const mockGetEffectiveMfaConfig = jest.fn();
const mockCheckMfaSetupRequired = jest.fn();

// Mock dependencies
jest.mock('./session-tasks.service', () => ({
  sessionTasksService: {
    createTask: (...args: unknown[]) => mockCreateTask(...args)
  }
}));

jest.mock('../repositories/membership.repository', () => ({
  getUserMemberships: (...args: unknown[]) => mockGetUserMemberships(...args)
}));

jest.mock('../repositories/organization.repository', () => ({
  getOrganization: (...args: unknown[]) => mockGetOrganization(...args)
}));

jest.mock('./realm.service', () => ({
  getEffectiveMfaConfig: (...args: unknown[]) => mockGetEffectiveMfaConfig(...args),
  checkMfaSetupRequired: (...args: unknown[]) => mockCheckMfaSetupRequired(...args)
}));

// Import after mocks
import { SessionTaskIntegrationService } from './session-task-integration.service';
import { User } from '../models/user.model';
import { SessionTask } from '../models/session-task.model';

describe('SessionTaskIntegrationService', () => {
  let service: SessionTaskIntegrationService;
  const now = new Date().toISOString();
  
  const mockUser: User = {
    id: 'user_123',
    realm_id: 'realm_test',
    email: 'test@example.com',
    email_verified: true,
    password_hash: 'hashed_password',
    profile: { metadata: {} },
    created_at: now,
    updated_at: now,
    last_login: now,
    status: 'active',
    mfa_enabled: false
  };
  
  const mockSessionId = 'session_abc123';
  const mockRealmId = 'realm_test';
  
  beforeEach(() => {
    service = new SessionTaskIntegrationService();
    jest.clearAllMocks();
    
    mockGetUserMemberships.mockResolvedValue([]);
    mockGetOrganization.mockResolvedValue(null);
    mockGetEffectiveMfaConfig.mockResolvedValue({
      policy: 'optional',
      allowed_methods: ['totp', 'webauthn'],
      grace_period_hours: 72,
      remember_device_days: 30,
      require_webauthn_for_sensitive: false
    });
    mockCheckMfaSetupRequired.mockResolvedValue({ required: false });
  });
  
  describe('evaluateAndCreateTasks', () => {
    it('should return empty tasks when no conditions are met', async () => {
      const result = await service.evaluateAndCreateTasks({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result.tasks).toHaveLength(0);
      expect(result.hasBlockingTasks).toBe(false);
      expect(result.requiresAction).toBe(false);
    });
    
    it('should create reset_password task when password is compromised', async () => {
      const mockTask: SessionTask = {
        id: 'task_1',
        session_id: mockSessionId,
        user_id: mockUser.id,
        realm_id: mockRealmId,
        type: 'reset_password',
        status: 'pending',
        created_at: now,
        priority: 1,
        blocking: true,
        metadata: { reason: 'compromised' }
      };
      
      mockCreateTask.mockResolvedValueOnce(mockTask);
      
      const result = await service.evaluateAndCreateTasks({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId,
        passwordCompromised: true
      });
      
      expect(result.tasks).toHaveLength(1);
      expect(result.tasks[0].type).toBe('reset_password');
      expect(result.hasBlockingTasks).toBe(true);
    });
    
    it('should create setup_mfa task when MFA required but not enabled', async () => {
      mockGetEffectiveMfaConfig.mockResolvedValue({
        policy: 'required',
        allowed_methods: ['totp', 'webauthn'],
        grace_period_hours: 72,
        remember_device_days: 30,
        require_webauthn_for_sensitive: false
      });
      
      mockCheckMfaSetupRequired.mockResolvedValue({
        required: true,
        message: 'MFA setup required'
      });
      
      const mockTask: SessionTask = {
        id: 'task_2',
        session_id: mockSessionId,
        user_id: mockUser.id,
        realm_id: mockRealmId,
        type: 'setup_mfa',
        status: 'pending',
        created_at: now,
        priority: 2,
        blocking: true
      };
      
      mockCreateTask.mockResolvedValueOnce(mockTask);
      
      const result = await service.evaluateAndCreateTasks({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result.tasks).toHaveLength(1);
      expect(result.tasks[0].type).toBe('setup_mfa');
    });
    
    it('should NOT create setup_mfa task when user has MFA enabled', async () => {
      const userWithMfa: User = { ...mockUser, mfa_enabled: true };
      
      mockGetEffectiveMfaConfig.mockResolvedValue({
        policy: 'required',
        allowed_methods: ['totp', 'webauthn'],
        grace_period_hours: 72,
        remember_device_days: 30,
        require_webauthn_for_sensitive: false
      });
      
      const result = await service.evaluateAndCreateTasks({
        user: userWithMfa,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result.tasks).toHaveLength(0);
    });
    
    it('should create choose_organization task for multi-org user', async () => {
      mockGetUserMemberships.mockResolvedValue([
        { user_id: mockUser.id, org_id: 'org_1', realm_id: mockRealmId, role_ids: ['admin'], direct_permissions: [], is_default: false, status: 'active', created_at: now, updated_at: now },
        { user_id: mockUser.id, org_id: 'org_2', realm_id: mockRealmId, role_ids: ['member'], direct_permissions: [], is_default: false, status: 'active', created_at: now, updated_at: now }
      ]);
      
      mockGetOrganization
        .mockResolvedValueOnce({ id: 'org_1', realm_id: mockRealmId, name: 'Org One', slug: 'org-one', status: 'active', member_count: 10, settings: {}, created_at: now, updated_at: now })
        .mockResolvedValueOnce({ id: 'org_2', realm_id: mockRealmId, name: 'Org Two', slug: 'org-two', status: 'active', member_count: 5, settings: {}, created_at: now, updated_at: now });
      
      const mockTask: SessionTask = {
        id: 'task_3',
        session_id: mockSessionId,
        user_id: mockUser.id,
        realm_id: mockRealmId,
        type: 'choose_organization',
        status: 'pending',
        created_at: now,
        priority: 4,
        blocking: true
      };
      
      mockCreateTask.mockResolvedValueOnce(mockTask);
      
      const result = await service.evaluateAndCreateTasks({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result.tasks).toHaveLength(1);
      expect(result.tasks[0].type).toBe('choose_organization');
    });
    
    it('should NOT create choose_organization task with default org', async () => {
      mockGetUserMemberships.mockResolvedValue([
        { user_id: mockUser.id, org_id: 'org_1', realm_id: mockRealmId, role_ids: ['admin'], direct_permissions: [], is_default: true, status: 'active', created_at: now, updated_at: now },
        { user_id: mockUser.id, org_id: 'org_2', realm_id: mockRealmId, role_ids: ['member'], direct_permissions: [], is_default: false, status: 'active', created_at: now, updated_at: now }
      ]);
      
      const result = await service.evaluateAndCreateTasks({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result.tasks).toHaveLength(0);
    });
    
    it('should handle TASK_ALREADY_EXISTS error gracefully', async () => {
      const error = new Error('TASK_ALREADY_EXISTS');
      mockCreateTask.mockRejectedValueOnce(error);
      
      const result = await service.evaluateAndCreateTasks({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId,
        passwordCompromised: true
      });
      
      expect(result.tasks).toHaveLength(0);
    });
  });
  
  describe('evaluatePasswordReset', () => {
    it('should return null when password is not compromised', async () => {
      const result = await service.evaluatePasswordReset({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result).toBeNull();
    });
  });
  
  describe('evaluateMfaSetup', () => {
    it('should return null when MFA policy is optional', async () => {
      const result = await service.evaluateMfaSetup({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result).toBeNull();
    });
  });
  
  describe('evaluateOrganizationSelection', () => {
    it('should return null when user has no memberships', async () => {
      mockGetUserMemberships.mockResolvedValue([]);
      
      const result = await service.evaluateOrganizationSelection({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result).toBeNull();
    });
  });
  
  describe('evaluateTermsAcceptance', () => {
    it('should return null when no terms version set', async () => {
      const result = await service.evaluateTermsAcceptance({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId
      });
      
      expect(result).toBeNull();
    });
    
    it('should create task when terms not accepted', async () => {
      const mockTask: SessionTask = {
        id: 'task_4',
        session_id: mockSessionId,
        user_id: mockUser.id,
        realm_id: mockRealmId,
        type: 'accept_terms',
        status: 'pending',
        created_at: now,
        priority: 3,
        blocking: true
      };
      
      mockCreateTask.mockResolvedValueOnce(mockTask);
      
      const result = await service.evaluateTermsAcceptance({
        user: mockUser,
        sessionId: mockSessionId,
        realmId: mockRealmId,
        termsVersion: '1.0',
        currentTermsVersion: '2.0'
      });
      
      expect(result).not.toBeNull();
      expect(result?.type).toBe('accept_terms');
    });
  });
});
