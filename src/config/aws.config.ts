/**
 * AWS Configuration for Zalt.io Auth Platform
 * Contains all AWS resource identifiers and configuration
 */

export const AWS_CONFIG = {
  region: 'eu-central-1',
  
  apiGateway: {
    endpoint: 'https://65tnchimfk.execute-api.eu-central-1.amazonaws.com/prod'
  },
  
  dynamodb: {
    // Core tables (deployed)
    tables: {
      users: 'zalt-users',
      realms: 'zalt-realms',
      sessions: 'zalt-sessions'
    },
    // Platform tables (SaaS customers)
    platformTables: {
      customers: 'zalt-customers',  // B2B customers (companies using Zalt)
      apiKeys: 'zalt-api-keys',     // API keys for SDK authentication
      usage: 'zalt-usage'           // Usage tracking per customer
    },
    // Extended tables (AWS Kiro created for health check)
    extendedTables: {
      tokens: 'zalt-tokens',        // Email verification, password reset tokens
      documents: 'zalt-documents',  // Document verification records
      audit: 'zalt-audit',          // Security audit logs (HIPAA: 6 years retention)
      devices: 'zalt-devices',      // Device fingerprinting
      mfa: 'zalt-mfa',              // MFA configurations
      webauthn: 'zalt-webauthn'     // WebAuthn credentials
    }
  },
  
  lambda: {
    functions: {
      register: 'zalt-register',
      login: 'zalt-login',
      verifyEmail: 'zalt-verify-email',
      forgotPassword: 'zalt-forgot-password',
      resetPassword: 'zalt-reset-password',
      mfaSetup: 'zalt-mfa-setup',
      mfaVerify: 'zalt-mfa-verify'
    }
  },
  
  secretsManager: {
    jwtSecrets: 'zalt/jwt-secrets',      // Legacy symmetric (deprecated)
    jwtKeys: 'zalt/jwt-keys',            // RSA key pair for RS256
    oauthProviders: 'zalt/oauth-providers', // Google, Apple, etc.
    encryptionKey: 'zalt/encryption-key'   // AES-256 for field encryption
  },
  
  kms: {
    masterKeyAlias: 'alias/zalt-master',  // Data encryption key
    jwtSigningKeyAlias: 'alias/zalt-jwt-signing',  // JWT signing key (RSA 4096-bit)
    jwtSigningKeyId: 'fa16a08f-aa50-4113-af73-155a31d13d49',
    // Used for:
    // 1. DynamoDB SSE (masterKeyAlias)
    // 2. JWT signing (jwtSigningKeyAlias) - FIPS 140-2 Level 3
    // 3. Envelope encryption for sensitive data (TOTP secrets, etc.)
  },
  
  ses: {
    fromEmail: 'noreply@zalt.io',
    replyToEmail: 'support@zalt.io'
  },
  
  s3: {
    documentsBucket: 'zalt-auth-documents'
  }
} as const;

export type AWSConfig = typeof AWS_CONFIG;
