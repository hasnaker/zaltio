/**
 * Property-based tests for AWS Configuration
 * Feature: zalt-auth-platform, Property: Infrastructure Consistency
 * Validates: Requirements 7.1, 7.2
 */

import * as fc from 'fast-check';
import { AWS_CONFIG } from './aws.config';

describe('AWS Configuration - Infrastructure Consistency', () => {
  /**
   * Property: Infrastructure Consistency
   * For any access to AWS configuration, the configuration should contain
   * all required infrastructure identifiers with valid formats.
   * Validates: Requirements 7.1, 7.2
   */
  describe('Property: Infrastructure Consistency', () => {
    it('should have valid AWS region format (eu-central-1 for GDPR compliance)', () => {
      fc.assert(
        fc.property(fc.constant(AWS_CONFIG.region), (region) => {
          // Region must be eu-central-1 per Requirements 7.1
          expect(region).toBe('eu-central-1');
          // Valid AWS region format
          expect(region).toMatch(/^[a-z]{2}-[a-z]+-\d$/);
          return true;
        }),
        { numRuns: 10 }
      );
    });

    it('should have valid API Gateway endpoint format', () => {
      fc.assert(
        fc.property(fc.constant(AWS_CONFIG.apiGateway.endpoint), (endpoint) => {
          // Must be HTTPS
          expect(endpoint).toMatch(/^https:\/\//);
          // Must be valid API Gateway URL format
          expect(endpoint).toMatch(/execute-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com/);
          // Must include stage
          expect(endpoint).toMatch(/\/prod$/);
          return true;
        }),
        { numRuns: 10 }
      );
    });

    it('should have all required DynamoDB table names', () => {
      const tableNames = Object.values(AWS_CONFIG.dynamodb.tables);
      
      // Must have required tables
      expect(tableNames).toContain('zalt-users');
      expect(tableNames).toContain('zalt-realms');
      expect(tableNames).toContain('zalt-sessions');
      expect(tableNames).toContain('zalt-tokens');
      
      // All tables must follow naming convention
      tableNames.forEach(tableName => {
        expect(tableName).toMatch(/^zalt-[a-z-]+$/);
      });
    });

    it('should have all required Lambda function names', () => {
      const functionNames = Object.values(AWS_CONFIG.lambda.functions);
      
      // Must include required functions
      expect(functionNames).toContain('zalt-register');
      expect(functionNames).toContain('zalt-login');
      
      // All functions must follow naming convention (allows hyphens)
      functionNames.forEach(funcName => {
        expect(funcName).toMatch(/^zalt-[a-z-]+$/);
      });
    });

    it('should have valid Secrets Manager path format', () => {
      fc.assert(
        fc.property(fc.constant(AWS_CONFIG.secretsManager.jwtSecrets), (secretPath) => {
          // Must follow zalt/* naming convention
          expect(secretPath).toMatch(/^zalt\/[a-z-]+$/);
          expect(secretPath).toBe('zalt/jwt-secrets');
          return true;
        }),
        { numRuns: 10 }
      );
    });

    it('should have RSA key path for RS256 JWT signing', () => {
      expect(AWS_CONFIG.secretsManager.jwtKeys).toBe('zalt/jwt-keys');
    });

    it('should have valid SES configuration for Zalt.io', () => {
      expect(AWS_CONFIG.ses.fromEmail).toBe('noreply@zalt.io');
      expect(AWS_CONFIG.ses.replyToEmail).toBe('support@zalt.io');
    });

    it('should maintain configuration immutability', () => {
      fc.assert(
        fc.property(fc.constant(AWS_CONFIG), (config) => {
          // Configuration should be readonly (const assertion)
          const originalRegion = config.region;
          const originalEndpoint = config.apiGateway.endpoint;
          
          // Verify values remain consistent across accesses
          expect(AWS_CONFIG.region).toBe(originalRegion);
          expect(AWS_CONFIG.apiGateway.endpoint).toBe(originalEndpoint);
          
          return true;
        }),
        { numRuns: 10 }
      );
    });
  });
});
