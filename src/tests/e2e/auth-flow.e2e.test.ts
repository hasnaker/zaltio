/**
 * E2E Tests: Core Authentication Flow
 * 
 * Tests the complete authentication lifecycle:
 * Register → Verify Email → Login → Refresh → Logout
 * 
 * @e2e-test
 * @phase Phase 1 Checkpoint
 */

import { 
  E2EApiClient, 
  generateTestUser, 
  E2E_CONFIG,
  E2EAssertions,
  wait
} from './setup';
import { 
  registerAndLogin, 
  measureResponseTime,
  generateDeviceFingerprint 
} from './helpers';

describe('E2E: Core Authentication Flow', () => {
  let client: E2EApiClient;

  beforeAll(() => {
    client = new E2EApiClient(E2E_CONFIG.apiEndpoint);
  });

  describe('User Registration', () => {
    it('should register a new user successfully', async () => {
      const user = generateTestUser();
      
      const { result, durationMs } = await measureResponseTime(() => 
        client.register(user)
      );

      expect(result.status).toBe(201);
      expect(result.data.user_id).toBeDefined();
      expect(E2EAssertions.isValidUUID(result.data.user_id)).toBe(true);
      expect(durationMs).toBeLessThan(5000); // Should complete within 5s
    });

    it('should reject duplicate email in same realm', async () => {
      const user = generateTestUser();
      
      // First registration
      await client.register(user);
      
      // Second registration with same email
      const result = await client.register(user);
      
      expect(result.status).toBe(409); // Conflict
    });

    it('should reject weak passwords', async () => {
      const user = generateTestUser({ password: 'weak' });
      
      const result = await client.register(user);
      
      expect(result.status).toBe(400);
    });

    it('should reject invalid email format', async () => {
      const user = generateTestUser({ email: 'not-an-email' });
      
      const result = await client.register(user);
      
      expect(result.status).toBe(400);
    });
  });

  describe('User Login', () => {
    it('should login with valid credentials', async () => {
      const user = generateTestUser();
      await client.register(user);

      const { result, durationMs } = await measureResponseTime(() =>
        client.login(user.email, user.password, user.realm_id)
      );

      expect(result.status).toBe(200);
      expect(result.data.access_token).toBeDefined();
      expect(result.data.refresh_token).toBeDefined();
      expect(result.data.expires_in).toBeGreaterThan(0);
      expect(E2EAssertions.isValidJWT(result.data.access_token)).toBe(true);
      expect(durationMs).toBeLessThan(3000);
    });

    it('should reject invalid password without revealing user existence', async () => {
      const user = generateTestUser();
      await client.register(user);

      const result = await client.login(user.email, 'WrongPassword!123', user.realm_id);

      expect(result.status).toBe(401);
      // Should NOT reveal that user exists - generic message
      expect(JSON.stringify(result.data)).toContain('Invalid credentials');
    });

    it('should reject non-existent user without revealing non-existence', async () => {
      const result = await client.login(
        'nonexistent@test.zalt.io',
        'SomePassword!123',
        E2E_CONFIG.testRealmId
      );

      expect(result.status).toBe(401);
      // Same message as invalid password - no email enumeration
      expect(JSON.stringify(result.data)).toContain('Invalid credentials');
    });
  });

  describe('Token Refresh', () => {
    it('should refresh tokens successfully', async () => {
      const { refreshToken } = await registerAndLogin(client);

      const result = await client.refresh(refreshToken);

      expect(result.status).toBe(200);
      expect(result.data.access_token).toBeDefined();
      expect(result.data.refresh_token).toBeDefined();
      expect(E2EAssertions.isValidJWT(result.data.access_token)).toBe(true);
    });

    it('should rotate refresh token on each use', async () => {
      const { refreshToken: oldToken } = await registerAndLogin(client);

      const result = await client.refresh(oldToken);
      const newToken = result.data.refresh_token;

      expect(newToken).not.toBe(oldToken);
    });

    it('should support 30-second grace period for old token', async () => {
      const { refreshToken: oldToken } = await registerAndLogin(client);

      // First refresh
      const first = await client.refresh(oldToken);
      expect(first.status).toBe(200);

      // Immediate second refresh with OLD token (within grace period)
      const second = await client.refresh(oldToken);
      expect(second.status).toBe(200);

      // Should return SAME tokens (idempotent)
      expect(second.data.access_token).toBe(first.data.access_token);
      expect(second.data.refresh_token).toBe(first.data.refresh_token);
    });

    it('should reject invalid refresh token', async () => {
      const result = await client.refresh('invalid-token');

      expect(result.status).toBe(401);
    });
  });

  describe('Get Current User', () => {
    it('should return user info with valid token', async () => {
      const { user, accessToken } = await registerAndLogin(client);

      const result = await client.getMe(accessToken);

      expect(result.status).toBe(200);
      expect(result.data.email).toBe(user.email);
      expect(result.data.realm_id).toBe(user.realm_id);
      // Password should NEVER be returned
      expect(JSON.stringify(result.data)).not.toContain('password');
    });

    it('should reject expired/invalid token', async () => {
      const result = await client.getMe('invalid-token');

      expect(result.status).toBe(401);
    });
  });

  describe('Logout', () => {
    it('should invalidate session on logout', async () => {
      const { accessToken, refreshToken } = await registerAndLogin(client);

      // Logout
      const logoutResult = await client.logout(accessToken);
      expect(logoutResult.status).toBe(200);

      // Try to use refresh token - should fail
      const refreshResult = await client.refresh(refreshToken);
      expect(refreshResult.status).toBe(401);
    });

    it('should logout from all devices when requested', async () => {
      const user = generateTestUser();
      await client.register(user);

      // Login from "device 1"
      const login1 = await client.login(user.email, user.password, user.realm_id, 
        generateDeviceFingerprint({ userAgent: 'Device1' }));
      
      // Login from "device 2"
      const login2 = await client.login(user.email, user.password, user.realm_id,
        generateDeviceFingerprint({ userAgent: 'Device2' }));

      // Logout from all devices using device 1's token
      await client.logout(login1.data.access_token, true);

      // Both refresh tokens should be invalid
      const refresh1 = await client.refresh(login1.data.refresh_token);
      const refresh2 = await client.refresh(login2.data.refresh_token);

      expect(refresh1.status).toBe(401);
      expect(refresh2.status).toBe(401);
    });
  });

  describe('Full Psychologist Flow (Clinisyn Use Case)', () => {
    it('should complete full authentication lifecycle', async () => {
      // 1. Psychologist registers
      const psychologist = generateTestUser({
        profile: {
          first_name: 'Dr. Ayşe',
          last_name: 'Yılmaz'
        }
      });
      
      const registerResult = await client.register(psychologist);
      expect(registerResult.status).toBe(201);
      
      // 2. Psychologist logs in
      const loginResult = await client.login(
        psychologist.email,
        psychologist.password,
        psychologist.realm_id
      );
      expect(loginResult.status).toBe(200);
      
      const { access_token, refresh_token } = loginResult.data;
      
      // 3. Psychologist accesses their profile
      const meResult = await client.getMe(access_token);
      expect(meResult.status).toBe(200);
      expect(meResult.data.profile).toBeDefined();
      
      // 4. Token expires, psychologist refreshes
      const refreshResult = await client.refresh(refresh_token);
      expect(refreshResult.status).toBe(200);
      
      // 5. Psychologist logs out at end of day
      const logoutResult = await client.logout(refreshResult.data.access_token);
      expect(logoutResult.status).toBe(200);
      
      // 6. Old tokens no longer work
      const oldTokenResult = await client.getMe(access_token);
      expect(oldTokenResult.status).toBe(401);
    });
  });
});
