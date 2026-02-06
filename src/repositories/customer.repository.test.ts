/**
 * Customer Repository Tests
 * Tests DynamoDB operations for platform customers
 * 
 * Validates: Requirements 1.2, 1.5 (Customer account system)
 */

import { PLAN_LIMITS } from '../models/customer.model';

// Mock uuid
jest.mock('uuid', () => ({
  v4: jest.fn().mockReturnValue('12345678-1234-1234-1234-123456789012')
}));

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  },
  TableNames: {
    CUSTOMERS: 'zalt-customers',
    API_KEYS: 'zalt-api-keys',
    USAGE: 'zalt-usage'
  }
}));

// Mock password hashing
jest.mock('../utils/password', () => ({
  hashPassword: jest.fn().mockResolvedValue('$argon2id$v=19$m=32768,t=5,p=2$mock_hash')
}));

// Import after mocks
import {
  createCustomer,
  getCustomerById,
  getCustomerByEmail,
  updateCustomer,
  recordLoginAttempt,
  lockCustomerAccount,
  verifyCustomerEmail,
  emailExists
} from './customer.repository';

describe('Customer Repository', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createCustomer', () => {
    it('should create a new customer with free plan by default', async () => {
      mockSend.mockResolvedValueOnce({});

      const customer = await createCustomer({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      });

      expect(customer.id).toMatch(/^customer_[a-z0-9]{24}$/);
      expect(customer.email).toBe('test@company.com');
      expect(customer.profile.company_name).toBe('Test Company');
      expect(customer.billing.plan).toBe('free');
      expect(customer.usage_limits).toEqual(PLAN_LIMITS.free);
      expect(customer.status).toBe('pending_verification');
      expect(customer.email_verified).toBe(false);
    });

    it('should create customer with specified plan', async () => {
      mockSend.mockResolvedValueOnce({});

      const customer = await createCustomer({
        email: 'enterprise@company.com',
        password: 'SecurePass123!',
        company_name: 'Enterprise Corp',
        plan: 'enterprise'
      });

      expect(customer.billing.plan).toBe('enterprise');
      expect(customer.usage_limits).toEqual(PLAN_LIMITS.enterprise);
    });

    it('should normalize email to lowercase', async () => {
      mockSend.mockResolvedValueOnce({});

      const customer = await createCustomer({
        email: 'TEST@COMPANY.COM',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      });

      expect(customer.email).toBe('test@company.com');
    });

    it('should hash password with Argon2id', async () => {
      mockSend.mockResolvedValueOnce({});

      const customer = await createCustomer({
        email: 'test@company.com',
        password: 'SecurePass123!',
        company_name: 'Test Company'
      });

      expect(customer.password_hash).toContain('$argon2id$');
    });
  });

  describe('getCustomerById', () => {
    it('should return customer when found', async () => {
      const mockCustomer = {
        pk: 'CUSTOMER#customer_abc123',
        id: 'customer_abc123',
        email: 'test@company.com',
        profile: { company_name: 'Test Company' },
        billing: { plan: 'free' },
        status: 'active'
      };

      mockSend.mockResolvedValueOnce({ Item: mockCustomer });

      const customer = await getCustomerById('customer_abc123');

      expect(customer).not.toBeNull();
      expect(customer?.id).toBe('customer_abc123');
      expect(customer?.email).toBe('test@company.com');
    });

    it('should return null when customer not found', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const customer = await getCustomerById('nonexistent');

      expect(customer).toBeNull();
    });
  });

  describe('getCustomerByEmail', () => {
    it('should return customer when found by email', async () => {
      const mockCustomer = {
        pk: 'CUSTOMER#customer_abc123',
        id: 'customer_abc123',
        email: 'test@company.com',
        profile: { company_name: 'Test Company' }
      };

      mockSend.mockResolvedValueOnce({ Items: [mockCustomer] });

      const customer = await getCustomerByEmail('test@company.com');

      expect(customer).not.toBeNull();
      expect(customer?.email).toBe('test@company.com');
    });

    it('should return null when email not found', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const customer = await getCustomerByEmail('nonexistent@company.com');

      expect(customer).toBeNull();
    });
  });

  describe('updateCustomer', () => {
    it('should update customer fields', async () => {
      const updatedCustomer = {
        pk: 'CUSTOMER#customer_abc123',
        id: 'customer_abc123',
        email: 'test@company.com',
        status: 'active',
        updated_at: new Date().toISOString()
      };

      mockSend.mockResolvedValueOnce({ Attributes: updatedCustomer });

      const customer = await updateCustomer('customer_abc123', { status: 'active' });

      expect(customer?.status).toBe('active');
    });
  });

  describe('recordLoginAttempt', () => {
    it('should reset failed attempts on successful login', async () => {
      mockSend.mockResolvedValueOnce({});

      await recordLoginAttempt('customer_abc123', true);

      expect(mockSend).toHaveBeenCalledTimes(1);
      const command = mockSend.mock.calls[0][0];
      expect(command.input.UpdateExpression).toContain('failed_login_attempts = :zero');
      expect(command.input.UpdateExpression).toContain('last_login_at');
    });

    it('should increment failed attempts on failed login', async () => {
      mockSend.mockResolvedValueOnce({});

      await recordLoginAttempt('customer_abc123', false);

      expect(mockSend).toHaveBeenCalledTimes(1);
      const command = mockSend.mock.calls[0][0];
      expect(command.input.UpdateExpression).toContain('failed_login_attempts');
      expect(command.input.UpdateExpression).toContain('+ :one');
    });
  });

  describe('lockCustomerAccount', () => {
    it('should set locked_until timestamp', async () => {
      mockSend.mockResolvedValueOnce({});

      await lockCustomerAccount('customer_abc123', 30);

      expect(mockSend).toHaveBeenCalledTimes(1);
      const command = mockSend.mock.calls[0][0];
      expect(command.input.UpdateExpression).toContain('locked_until');
    });
  });

  describe('verifyCustomerEmail', () => {
    it('should set email_verified to true and status to active', async () => {
      const verifiedCustomer = {
        pk: 'CUSTOMER#customer_abc123',
        id: 'customer_abc123',
        email_verified: true,
        status: 'active'
      };

      mockSend.mockResolvedValueOnce({ Attributes: verifiedCustomer });

      const customer = await verifyCustomerEmail('customer_abc123');

      expect(customer?.email_verified).toBe(true);
      expect(customer?.status).toBe('active');
    });
  });

  describe('emailExists', () => {
    it('should return true when email exists', async () => {
      mockSend.mockResolvedValueOnce({ 
        Items: [{ id: 'customer_abc123', email: 'test@company.com' }] 
      });

      const exists = await emailExists('test@company.com');

      expect(exists).toBe(true);
    });

    it('should return false when email does not exist', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const exists = await emailExists('nonexistent@company.com');

      expect(exists).toBe(false);
    });
  });

  describe('Plan Limits', () => {
    it('should have correct free plan limits', () => {
      expect(PLAN_LIMITS.free.max_mau).toBe(1000);
      expect(PLAN_LIMITS.free.max_realms).toBe(1);
      expect(PLAN_LIMITS.free.sso_enabled).toBe(false);
    });

    it('should have correct pro plan limits', () => {
      expect(PLAN_LIMITS.pro.max_mau).toBe(10000);
      expect(PLAN_LIMITS.pro.max_realms).toBe(5);
      expect(PLAN_LIMITS.pro.sso_enabled).toBe(true);
    });

    it('should have unlimited enterprise plan', () => {
      expect(PLAN_LIMITS.enterprise.max_mau).toBe(-1);
      expect(PLAN_LIMITS.enterprise.max_realms).toBe(-1);
      expect(PLAN_LIMITS.enterprise.audit_logs_days).toBe(365);
    });
  });
});
