/**
 * Jest E2E Configuration for Zalt.io Authentication Platform
 * 
 * Separate config for E2E tests that run against actual API endpoints
 */

module.exports = {
  displayName: 'e2e',
  preset: 'ts-jest',
  testEnvironment: 'node',
  
  // Only run E2E tests
  testMatch: ['**/tests/e2e/**/*.e2e.test.ts'],
  
  // Longer timeouts for E2E tests
  testTimeout: 60000,
  
  // Setup file for global configuration
  setupFilesAfterEnv: ['<rootDir>/src/tests/e2e/jest.setup.ts'],
  
  // Module paths
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    // Mock uuid for ESM compatibility
    '^uuid$': require.resolve('uuid')
  },
  
  // Transform TypeScript and ESM modules
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: 'tsconfig.json'
    }]
  },
  
  // Transform uuid ESM module
  transformIgnorePatterns: [
    'node_modules/(?!(uuid)/)'
  ],
  
  // Coverage settings for E2E
  collectCoverageFrom: [
    'src/handlers/**/*.ts',
    'src/services/**/*.ts',
    '!src/**/*.test.ts',
    '!src/**/*.d.ts'
  ],
  
  // Verbose output for E2E
  verbose: true,
  
  // Run tests sequentially (important for E2E)
  maxWorkers: 1,
  
  // Global variables
  globals: {
    'E2E_API_ENDPOINT': process.env.E2E_API_ENDPOINT || 'http://localhost:3000',
    'E2E_TEST_REALM': process.env.E2E_TEST_REALM || 'e2e-test-realm'
  }
};
