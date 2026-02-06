/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.test.ts',
    '!src/**/*.d.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  verbose: true,
  transformIgnorePatterns: [
    'node_modules/(?!(uuid)/)'
  ],
  moduleNameMapper: {
    '^uuid$': require.resolve('uuid'),
    '^(\\.\\./)+sdk$': '<rootDir>/src/sdk/index.ts',
    '^(\\.\\./)+sdk/(.*)$': '<rootDir>/src/sdk/$2'
  }
};
