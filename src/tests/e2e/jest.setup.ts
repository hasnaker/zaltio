/**
 * Jest E2E Setup for Zalt.io Authentication Platform
 * 
 * Global setup and teardown for E2E tests
 */

import { E2E_CONFIG } from './setup';

// Increase timeout for E2E tests
jest.setTimeout(E2E_CONFIG.setupTimeout);

// Global setup before all tests
beforeAll(async () => {
  console.log('🚀 Starting E2E Test Suite');
  console.log(`📡 API Endpoint: ${E2E_CONFIG.apiEndpoint}`);
  console.log(`🏠 Test Realm: ${E2E_CONFIG.testRealmId}`);
  
  // Verify API is reachable
  try {
    const response = await fetch(`${E2E_CONFIG.apiEndpoint}/health`);
    if (!response.ok) {
      console.warn('⚠️ Health check returned non-200 status');
    } else {
      console.log('✅ API is reachable');
    }
  } catch (error) {
    console.warn('⚠️ Could not reach API - tests may fail');
    console.warn('   Make sure the API is running: npm run sam:local');
  }
});

// Global teardown after all tests
afterAll(async () => {
  console.log('🧹 E2E Test Suite Complete');
  // Cleanup would happen here in a real implementation
});

// Custom matchers for E2E tests
expect.extend({
  toBeValidJWT(received: string) {
    const parts = received.split('.');
    const pass = parts.length === 3 && parts.every(p => /^[A-Za-z0-9_-]+$/.test(p));
    
    return {
      pass,
      message: () => pass
        ? `expected ${received} not to be a valid JWT`
        : `expected ${received} to be a valid JWT (3 base64url parts separated by dots)`
    };
  },
  
  toBeValidUUID(received: string) {
    const pass = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(received);
    
    return {
      pass,
      message: () => pass
        ? `expected ${received} not to be a valid UUID`
        : `expected ${received} to be a valid UUID`
    };
  },
  
  toRespondWithin(received: number, maxMs: number) {
    const pass = received < maxMs;
    
    return {
      pass,
      message: () => pass
        ? `expected response time ${received}ms to exceed ${maxMs}ms`
        : `expected response time ${received}ms to be within ${maxMs}ms`
    };
  }
});

// TypeScript declarations for custom matchers
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidJWT(): R;
      toBeValidUUID(): R;
      toRespondWithin(maxMs: number): R;
    }
  }
}
