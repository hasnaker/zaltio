/**
 * CORS Middleware for HSD Auth Platform
 * Validates: Requirements 2.1, 5.3
 * 
 * Implements CORS configuration for HSD domains
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  API_GATEWAY_CONFIG,
  ALLOWED_ORIGINS,
  ALLOWED_METHODS,
  ALLOWED_HEADERS,
  EXPOSED_HEADERS
} from '../config/api-gateway.config';

/**
 * CORS headers type
 */
export interface CORSHeaders {
  'Access-Control-Allow-Origin': string;
  'Access-Control-Allow-Methods': string;
  'Access-Control-Allow-Headers': string;
  'Access-Control-Expose-Headers': string;
  'Access-Control-Max-Age': string;
  'Access-Control-Allow-Credentials': string;
  'Vary': string;
}

/**
 * Check if an origin is allowed
 */
export function isOriginAllowed(origin: string | undefined): boolean {
  if (!origin) return false;
  
  // Check exact match
  if ((ALLOWED_ORIGINS as readonly string[]).includes(origin)) {
    return true;
  }
  
  // Check wildcard patterns for HSD subdomains
  const hsdPattern = /^https:\/\/[a-z0-9-]+\.hsdcore\.com$/;
  if (hsdPattern.test(origin)) {
    return true;
  }
  
  // Check wildcard patterns for Clinisyn subdomains
  const clinsynPattern = /^https:\/\/[a-z0-9-]+\.clinisyn\.com$/;
  if (clinsynPattern.test(origin)) {
    return true;
  }
  
  // Check wildcard patterns for Zalt.io subdomains
  const zaltPattern = /^https:\/\/[a-z0-9-]+\.zalt\.io$/;
  if (zaltPattern.test(origin)) {
    return true;
  }
  
  // Check wildcard patterns for Tediyat subdomains
  const tediyatPattern = /^https:\/\/[a-z0-9-]+\.tediyat\.com$/;
  if (tediyatPattern.test(origin)) {
    return true;
  }
  
  return false;
}

/**
 * Get the allowed origin for CORS response
 * Returns the request origin if allowed, otherwise returns the first allowed origin
 */
export function getAllowedOrigin(requestOrigin: string | undefined): string {
  if (requestOrigin && isOriginAllowed(requestOrigin)) {
    return requestOrigin;
  }
  return ALLOWED_ORIGINS[0];
}

/**
 * Generate CORS headers for a request
 */
export function getCORSHeaders(event: APIGatewayProxyEvent): CORSHeaders {
  const requestOrigin = event.headers?.Origin || event.headers?.origin;
  const allowedOrigin = getAllowedOrigin(requestOrigin);
  
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': ALLOWED_METHODS.join(', '),
    'Access-Control-Allow-Headers': ALLOWED_HEADERS.join(', '),
    'Access-Control-Expose-Headers': EXPOSED_HEADERS.join(', '),
    'Access-Control-Max-Age': String(API_GATEWAY_CONFIG.cors.maxAge),
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin'
  };
}

/**
 * Generate minimal CORS headers (for non-preflight requests)
 */
export function getMinimalCORSHeaders(event: APIGatewayProxyEvent): Pick<CORSHeaders, 'Access-Control-Allow-Origin' | 'Access-Control-Allow-Credentials' | 'Vary'> {
  const requestOrigin = event.headers?.Origin || event.headers?.origin;
  const allowedOrigin = getAllowedOrigin(requestOrigin);
  
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin'
  };
}

/**
 * Check if request is a CORS preflight request
 */
export function isPreflightRequest(event: APIGatewayProxyEvent): boolean {
  return (
    event.httpMethod === 'OPTIONS' &&
    !!event.headers?.['Access-Control-Request-Method']
  );
}
