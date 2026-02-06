/**
 * Security Headers Middleware for Zalt.io Auth Platform
 * Task 6.5: Security Headers
 * 
 * SECURITY HEADERS:
 * - Strict-Transport-Security (HSTS)
 * - X-Content-Type-Options
 * - X-Frame-Options
 * - Content-Security-Policy (CSP)
 * - X-XSS-Protection
 * - Referrer-Policy
 * - Permissions-Policy
 * 
 * COMPLIANCE:
 * - OWASP Security Headers
 * - HIPAA data protection
 * - PCI DSS requirements
 */

import { APIGatewayProxyResult } from 'aws-lambda';

/**
 * Security header configuration
 */
export interface SecurityHeadersConfig {
  // HSTS
  hstsMaxAge: number;
  hstsIncludeSubDomains: boolean;
  hstsPreload: boolean;
  
  // Frame options
  frameOptions: 'DENY' | 'SAMEORIGIN';
  
  // Content type
  contentTypeNosniff: boolean;
  
  // XSS protection
  xssProtection: boolean;
  xssProtectionMode: 'block' | '1';
  
  // CSP
  cspEnabled: boolean;
  cspDirectives: Record<string, string[]>;
  
  // Referrer
  referrerPolicy: string;
  
  // Permissions
  permissionsPolicy: Record<string, string[]>;
  
  // CORS
  corsEnabled: boolean;
  corsOrigins: string[];
  corsMethods: string[];
  corsHeaders: string[];
  corsMaxAge: number;
}

/**
 * Default security headers configuration
 */
export const DEFAULT_SECURITY_CONFIG: SecurityHeadersConfig = {
  // HSTS: 1 year, include subdomains, preload
  hstsMaxAge: 31536000, // 1 year in seconds
  hstsIncludeSubDomains: true,
  hstsPreload: true,
  
  // Prevent clickjacking
  frameOptions: 'DENY',
  
  // Prevent MIME type sniffing
  contentTypeNosniff: true,
  
  // XSS protection (legacy, but still useful)
  xssProtection: true,
  xssProtectionMode: 'block',
  
  // Content Security Policy
  cspEnabled: true,
  cspDirectives: {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'https:'],
    'font-src': ["'self'"],
    'connect-src': ["'self'", 'https://api.zalt.io'],
    'frame-ancestors': ["'none'"],
    'form-action': ["'self'"],
    'base-uri': ["'self'"],
    'object-src': ["'none'"]
  },
  
  // Referrer policy
  referrerPolicy: 'strict-origin-when-cross-origin',
  
  // Permissions policy (formerly Feature-Policy)
  permissionsPolicy: {
    'accelerometer': [],
    'camera': [],
    'geolocation': [],
    'gyroscope': [],
    'magnetometer': [],
    'microphone': [],
    'payment': [],
    'usb': []
  },
  
  // CORS
  corsEnabled: true,
  corsOrigins: ['*'], // Configure per realm in production
  corsMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  corsHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  corsMaxAge: 86400 // 24 hours
};

/**
 * Build HSTS header value
 */
export function buildHSTSHeader(config: SecurityHeadersConfig): string {
  let value = `max-age=${config.hstsMaxAge}`;
  
  if (config.hstsIncludeSubDomains) {
    value += '; includeSubDomains';
  }
  
  if (config.hstsPreload) {
    value += '; preload';
  }
  
  return value;
}

/**
 * Build CSP header value
 */
export function buildCSPHeader(directives: Record<string, string[]>): string {
  return Object.entries(directives)
    .map(([directive, values]) => `${directive} ${values.join(' ')}`)
    .join('; ');
}

/**
 * Build Permissions-Policy header value
 */
export function buildPermissionsPolicyHeader(policies: Record<string, string[]>): string {
  return Object.entries(policies)
    .map(([feature, allowlist]) => {
      if (allowlist.length === 0) {
        return `${feature}=()`;
      }
      return `${feature}=(${allowlist.join(' ')})`;
    })
    .join(', ');
}

/**
 * Build XSS Protection header value
 */
export function buildXSSProtectionHeader(config: SecurityHeadersConfig): string {
  if (!config.xssProtection) {
    return '0';
  }
  
  if (config.xssProtectionMode === 'block') {
    return '1; mode=block';
  }
  
  return '1';
}

/**
 * Generate all security headers
 */
export function generateSecurityHeaders(
  config: SecurityHeadersConfig = DEFAULT_SECURITY_CONFIG
): Record<string, string> {
  const headers: Record<string, string> = {};
  
  // HSTS
  headers['Strict-Transport-Security'] = buildHSTSHeader(config);
  
  // Content type options
  if (config.contentTypeNosniff) {
    headers['X-Content-Type-Options'] = 'nosniff';
  }
  
  // Frame options
  headers['X-Frame-Options'] = config.frameOptions;
  
  // XSS protection
  headers['X-XSS-Protection'] = buildXSSProtectionHeader(config);
  
  // CSP
  if (config.cspEnabled) {
    headers['Content-Security-Policy'] = buildCSPHeader(config.cspDirectives);
  }
  
  // Referrer policy
  headers['Referrer-Policy'] = config.referrerPolicy;
  
  // Permissions policy
  headers['Permissions-Policy'] = buildPermissionsPolicyHeader(config.permissionsPolicy);
  
  // Additional security headers
  headers['X-DNS-Prefetch-Control'] = 'off';
  headers['X-Download-Options'] = 'noopen';
  headers['X-Permitted-Cross-Domain-Policies'] = 'none';
  
  return headers;
}

/**
 * Generate CORS headers
 */
export function generateCORSHeaders(
  origin: string | undefined,
  config: SecurityHeadersConfig = DEFAULT_SECURITY_CONFIG
): Record<string, string> {
  if (!config.corsEnabled) {
    return {};
  }
  
  const headers: Record<string, string> = {};
  
  // Check if origin is allowed
  const allowedOrigin = config.corsOrigins.includes('*') 
    ? '*' 
    : config.corsOrigins.includes(origin || '') 
      ? origin! 
      : '';
  
  if (allowedOrigin) {
    headers['Access-Control-Allow-Origin'] = allowedOrigin;
    headers['Access-Control-Allow-Methods'] = config.corsMethods.join(', ');
    headers['Access-Control-Allow-Headers'] = config.corsHeaders.join(', ');
    headers['Access-Control-Max-Age'] = config.corsMaxAge.toString();
    
    if (allowedOrigin !== '*') {
      headers['Access-Control-Allow-Credentials'] = 'true';
      headers['Vary'] = 'Origin';
    }
  }
  
  return headers;
}

/**
 * Apply security headers to API Gateway response
 */
export function applySecurityHeaders(
  response: APIGatewayProxyResult,
  origin?: string,
  config: SecurityHeadersConfig = DEFAULT_SECURITY_CONFIG
): APIGatewayProxyResult {
  const securityHeaders = generateSecurityHeaders(config);
  const corsHeaders = generateCORSHeaders(origin, config);
  
  return {
    ...response,
    headers: {
      ...response.headers,
      ...securityHeaders,
      ...corsHeaders
    }
  };
}

/**
 * Create secure response with all headers
 */
export function createSecureResponse(
  statusCode: number,
  body: unknown,
  origin?: string,
  config: SecurityHeadersConfig = DEFAULT_SECURITY_CONFIG
): APIGatewayProxyResult {
  const securityHeaders = generateSecurityHeaders(config);
  const corsHeaders = generateCORSHeaders(origin, config);
  
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      ...securityHeaders,
      ...corsHeaders
    },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  };
}

/**
 * Create secure error response
 */
export function createSecureErrorResponse(
  statusCode: number,
  code: string,
  message: string,
  origin?: string,
  config: SecurityHeadersConfig = DEFAULT_SECURITY_CONFIG
): APIGatewayProxyResult {
  return createSecureResponse(
    statusCode,
    {
      error: {
        code,
        message,
        timestamp: new Date().toISOString()
      }
    },
    origin,
    config
  );
}

/**
 * Validate security headers in response
 */
export function validateSecurityHeaders(
  headers: Record<string, string>
): { valid: boolean; missing: string[]; warnings: string[] } {
  const requiredHeaders = [
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Referrer-Policy'
  ];
  
  const recommendedHeaders = [
    'Content-Security-Policy',
    'Permissions-Policy'
  ];
  
  const missing: string[] = [];
  const warnings: string[] = [];
  
  // Check required headers
  for (const header of requiredHeaders) {
    if (!headers[header]) {
      missing.push(header);
    }
  }
  
  // Check recommended headers
  for (const header of recommendedHeaders) {
    if (!headers[header]) {
      warnings.push(`Missing recommended header: ${header}`);
    }
  }
  
  // Validate HSTS max-age
  const hsts = headers['Strict-Transport-Security'];
  if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge < 31536000) {
        warnings.push('HSTS max-age should be at least 1 year (31536000 seconds)');
      }
    }
  }
  
  return {
    valid: missing.length === 0,
    missing,
    warnings
  };
}

/**
 * Get realm-specific security config
 */
export function getRealmSecurityConfig(
  realmId: string,
  realmSettings?: { cors_origins?: string[] }
): SecurityHeadersConfig {
  const config = { ...DEFAULT_SECURITY_CONFIG };
  
  // Apply realm-specific CORS origins
  if (realmSettings?.cors_origins) {
    config.corsOrigins = realmSettings.cors_origins;
  }
  
  return config;
}

/**
 * Security headers for API responses
 */
export const API_SECURITY_HEADERS = generateSecurityHeaders(DEFAULT_SECURITY_CONFIG);

/**
 * Check if request origin is allowed against a list
 */
export function isOriginInAllowedList(
  origin: string | undefined,
  allowedOrigins: string[]
): boolean {
  if (!origin) return false;
  if (allowedOrigins.includes('*')) return true;
  return allowedOrigins.includes(origin);
}
