/**
 * API Gateway Configuration for HSD Auth Platform
 * Validates: Requirements 2.1, 5.3
 * 
 * Configures API Gateway endpoints at api.auth.hsdcore.com
 * with CORS configuration for HSD domains
 */

import { AWS_CONFIG } from './aws.config';

/**
 * Allowed origins for CORS configuration
 * Includes all HSD domains, Zalt.io, Clinisyn and development environments
 */
export const ALLOWED_ORIGINS = [
  // HSD Core domains
  'https://auth.hsdcore.com',
  'https://dashboard.auth.hsdcore.com',
  'https://api.auth.hsdcore.com',
  'https://portal.hsdcore.com',
  'https://chat.hsdcore.com',
  'https://tasks.hsdcore.com',
  'https://docs.hsdcore.com',
  'https://crm.hsdcore.com',
  
  // Zalt.io domains
  'https://zalt.io',
  'https://www.zalt.io',
  'https://api.zalt.io',
  'https://dashboard.zalt.io',
  'https://app.zalt.io',
  
  // Clinisyn Production
  'https://clinisyn.com',
  'https://www.clinisyn.com',
  'https://app.clinisyn.com',
  'https://portal.clinisyn.com',
  'https://admin.clinisyn.com',
  'https://student.clinisyn.com',
  
  // Clinisyn Staging
  'https://staging.clinisyn.com',
  'https://staging-app.clinisyn.com',
  'https://staging-portal.clinisyn.com',
  'https://staging-admin.clinisyn.com',
  
  // Tediyat domains
  'https://tediyat.com',
  'https://www.tediyat.com',
  'https://app.tediyat.com',
  'https://staging.tediyat.com',
  'https://staging-app.tediyat.com',
  
  // Development environments
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5173',
  'http://localhost:8080'
] as const;

/**
 * Allowed HTTP methods for CORS
 */
export const ALLOWED_METHODS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS'
] as const;

/**
 * Allowed headers for CORS
 */
export const ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'X-Requested-With',
  'X-Request-ID',
  'X-Realm-ID',
  'Accept',
  'Origin'
] as const;

/**
 * Exposed headers in CORS responses
 */
export const EXPOSED_HEADERS = [
  'X-Request-ID',
  'X-RateLimit-Limit',
  'X-RateLimit-Remaining',
  'X-RateLimit-Reset',
  'Retry-After'
] as const;

/**
 * API Gateway configuration
 */
export const API_GATEWAY_CONFIG = {
  endpoint: AWS_CONFIG.apiGateway.endpoint,
  basePath: '/prod',
  
  // Domain configuration
  domains: {
    api: 'api.auth.hsdcore.com',
    dashboard: 'dashboard.auth.hsdcore.com',
    main: 'auth.hsdcore.com'
  },
  
  // CORS configuration
  cors: {
    allowedOrigins: ALLOWED_ORIGINS,
    allowedMethods: ALLOWED_METHODS,
    allowedHeaders: ALLOWED_HEADERS,
    exposedHeaders: EXPOSED_HEADERS,
    maxAge: 86400, // 24 hours
    credentials: true
  },
  
  // Rate limiting defaults
  rateLimit: {
    defaultLimit: 1000, // requests per minute
    burstLimit: 100
  },
  
  // Request/Response transformation
  transformation: {
    requestContentType: 'application/json',
    responseContentType: 'application/json'
  }
} as const;

export type APIGatewayConfig = typeof API_GATEWAY_CONFIG;
export type AllowedOrigin = typeof ALLOWED_ORIGINS[number];
export type AllowedMethod = typeof ALLOWED_METHODS[number];
export type AllowedHeader = typeof ALLOWED_HEADERS[number];
