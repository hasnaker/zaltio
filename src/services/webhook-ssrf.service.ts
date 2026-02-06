/**
 * Webhook SSRF Protection Service for Zalt.io Auth Platform
 * Task 6.12: Webhook SSRF Protection
 * 
 * SECURITY CRITICAL:
 * - Prevents Server-Side Request Forgery attacks
 * - Blocks requests to internal/private networks
 * - Blocks AWS metadata endpoint
 * - Enforces HTTPS only
 * - Prevents DNS rebinding attacks
 */

import * as dns from 'dns';
import { promisify } from 'util';

const dnsLookup = promisify(dns.lookup);

/**
 * SSRF protection configuration
 */
export interface SSRFProtectionConfig {
  // Allow HTTP (not recommended)
  allowHttp: boolean;
  
  // Allow localhost
  allowLocalhost: boolean;
  
  // Allow private IPs
  allowPrivateIPs: boolean;
  
  // Allow link-local IPs
  allowLinkLocal: boolean;
  
  // Allowed domains (whitelist)
  allowedDomains: string[];
  
  // Blocked domains (blacklist)
  blockedDomains: string[];
  
  // Maximum redirects to follow
  maxRedirects: number;
  
  // Request timeout (ms)
  timeout: number;
}

/**
 * Default SSRF protection configuration
 */
export const DEFAULT_SSRF_CONFIG: SSRFProtectionConfig = {
  allowHttp: false,
  allowLocalhost: false,
  allowPrivateIPs: false,
  allowLinkLocal: false,
  allowedDomains: [],
  blockedDomains: [],
  maxRedirects: 3,
  timeout: 10000
};

/**
 * URL validation result
 */
export interface URLValidationResult {
  valid: boolean;
  error?: string;
  errorCode?: 'INVALID_URL' | 'HTTP_NOT_ALLOWED' | 'LOCALHOST_BLOCKED' | 
              'PRIVATE_IP_BLOCKED' | 'LINK_LOCAL_BLOCKED' | 'AWS_METADATA_BLOCKED' |
              'DOMAIN_BLOCKED' | 'DNS_REBINDING' | 'DOMAIN_NOT_ALLOWED';
  resolvedIP?: string;
}

/**
 * Private IP ranges (RFC 1918)
 */
const PRIVATE_IP_RANGES = [
  { start: '10.0.0.0', end: '10.255.255.255' },
  { start: '172.16.0.0', end: '172.31.255.255' },
  { start: '192.168.0.0', end: '192.168.255.255' }
];

/**
 * Link-local IP ranges
 */
const LINK_LOCAL_RANGES = [
  { start: '169.254.0.0', end: '169.254.255.255' }, // IPv4 link-local
  { start: '127.0.0.0', end: '127.255.255.255' }    // Loopback
];

/**
 * AWS metadata IP
 */
const AWS_METADATA_IP = '169.254.169.254';

/**
 * Convert IP to number for comparison
 * Uses unsigned arithmetic to avoid JavaScript's signed 32-bit integer overflow
 */
export function ipToNumber(ip: string): number {
  const parts = ip.split('.').map(Number);
  // Use >>> 0 to convert to unsigned 32-bit integer, avoiding negative numbers
  return ((parts[0] * 16777216) + (parts[1] * 65536) + (parts[2] * 256) + parts[3]) >>> 0;
}

/**
 * Check if IP is in range
 */
export function isIPInRange(ip: string, start: string, end: string): boolean {
  const ipNum = ipToNumber(ip);
  const startNum = ipToNumber(start);
  const endNum = ipToNumber(end);
  return ipNum >= startNum && ipNum <= endNum;
}

/**
 * Check if IP is private
 */
export function isPrivateIP(ip: string): boolean {
  return PRIVATE_IP_RANGES.some(range => isIPInRange(ip, range.start, range.end));
}

/**
 * Check if IP is link-local
 */
export function isLinkLocalIP(ip: string): boolean {
  return LINK_LOCAL_RANGES.some(range => isIPInRange(ip, range.start, range.end));
}

/**
 * Check if IP is localhost
 */
export function isLocalhostIP(ip: string): boolean {
  return ip === '127.0.0.1' || ip.startsWith('127.');
}

/**
 * Check if IP is AWS metadata endpoint
 */
export function isAWSMetadataIP(ip: string): boolean {
  return ip === AWS_METADATA_IP;
}

/**
 * Check if hostname is localhost
 */
export function isLocalhostHostname(hostname: string): boolean {
  const lowercaseHostname = hostname.toLowerCase();
  return lowercaseHostname === 'localhost' ||
         lowercaseHostname === 'localhost.localdomain' ||
         lowercaseHostname.endsWith('.localhost');
}

/**
 * Check if hostname is internal
 */
export function isInternalHostname(hostname: string): boolean {
  const lowercaseHostname = hostname.toLowerCase();
  return lowercaseHostname.endsWith('.internal') ||
         lowercaseHostname.endsWith('.local') ||
         lowercaseHostname.endsWith('.corp') ||
         lowercaseHostname.endsWith('.lan') ||
         lowercaseHostname === 'metadata' ||
         lowercaseHostname === 'metadata.google.internal';
}

/**
 * Parse and validate URL format
 */
export function parseURL(urlString: string): { valid: boolean; parsed?: URL; error?: string } {
  try {
    const parsed = new URL(urlString);
    return { valid: true, parsed };
  } catch (e) {
    return { valid: false, error: 'Invalid URL format' };
  }
}

/**
 * Validate URL protocol
 */
export function validateProtocol(
  protocol: string,
  config: SSRFProtectionConfig = DEFAULT_SSRF_CONFIG
): URLValidationResult {
  if (protocol === 'https:') {
    return { valid: true };
  }

  if (protocol === 'http:' && config.allowHttp) {
    return { valid: true };
  }

  return {
    valid: false,
    error: 'Only HTTPS URLs are allowed',
    errorCode: 'HTTP_NOT_ALLOWED'
  };
}

/**
 * Validate hostname
 */
export function validateHostname(
  hostname: string,
  config: SSRFProtectionConfig = DEFAULT_SSRF_CONFIG
): URLValidationResult {
  // Check localhost
  if (isLocalhostHostname(hostname)) {
    if (!config.allowLocalhost) {
      return {
        valid: false,
        error: 'Localhost URLs are not allowed',
        errorCode: 'LOCALHOST_BLOCKED'
      };
    }
  }

  // Check internal hostnames
  if (isInternalHostname(hostname)) {
    return {
      valid: false,
      error: 'Internal hostnames are not allowed',
      errorCode: 'DOMAIN_BLOCKED'
    };
  }

  // Check blocked domains
  if (config.blockedDomains.length > 0) {
    const lowercaseHostname = hostname.toLowerCase();
    for (const blocked of config.blockedDomains) {
      if (lowercaseHostname === blocked.toLowerCase() ||
          lowercaseHostname.endsWith('.' + blocked.toLowerCase())) {
        return {
          valid: false,
          error: `Domain '${hostname}' is blocked`,
          errorCode: 'DOMAIN_BLOCKED'
        };
      }
    }
  }

  // Check allowed domains (whitelist mode)
  if (config.allowedDomains.length > 0) {
    const lowercaseHostname = hostname.toLowerCase();
    const isAllowed = config.allowedDomains.some(allowed => {
      const lowercaseAllowed = allowed.toLowerCase();
      return lowercaseHostname === lowercaseAllowed ||
             lowercaseHostname.endsWith('.' + lowercaseAllowed);
    });

    if (!isAllowed) {
      return {
        valid: false,
        error: `Domain '${hostname}' is not in the allowed list`,
        errorCode: 'DOMAIN_NOT_ALLOWED'
      };
    }
  }

  return { valid: true };
}

/**
 * Validate resolved IP address
 */
export function validateIP(
  ip: string,
  config: SSRFProtectionConfig = DEFAULT_SSRF_CONFIG
): URLValidationResult {
  // Check AWS metadata
  if (isAWSMetadataIP(ip)) {
    return {
      valid: false,
      error: 'AWS metadata endpoint is blocked',
      errorCode: 'AWS_METADATA_BLOCKED',
      resolvedIP: ip
    };
  }

  // Check localhost
  if (isLocalhostIP(ip)) {
    if (!config.allowLocalhost) {
      return {
        valid: false,
        error: 'Localhost IPs are not allowed',
        errorCode: 'LOCALHOST_BLOCKED',
        resolvedIP: ip
      };
    }
  }

  // Check link-local
  if (isLinkLocalIP(ip)) {
    if (!config.allowLinkLocal) {
      return {
        valid: false,
        error: 'Link-local IPs are not allowed',
        errorCode: 'LINK_LOCAL_BLOCKED',
        resolvedIP: ip
      };
    }
  }

  // Check private IPs
  if (isPrivateIP(ip)) {
    if (!config.allowPrivateIPs) {
      return {
        valid: false,
        error: 'Private IPs are not allowed',
        errorCode: 'PRIVATE_IP_BLOCKED',
        resolvedIP: ip
      };
    }
  }

  return { valid: true, resolvedIP: ip };
}

/**
 * Resolve hostname to IP and validate
 */
export async function resolveAndValidate(
  hostname: string,
  config: SSRFProtectionConfig = DEFAULT_SSRF_CONFIG
): Promise<URLValidationResult> {
  try {
    // Check if hostname is already an IP
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
      return validateIP(hostname, config);
    }

    // Resolve hostname
    const { address } = await dnsLookup(hostname);
    
    // Validate resolved IP
    const ipResult = validateIP(address, config);
    if (!ipResult.valid) {
      // DNS rebinding detection
      return {
        ...ipResult,
        errorCode: 'DNS_REBINDING',
        error: `DNS rebinding detected: ${hostname} resolved to blocked IP ${address}`
      };
    }

    return { valid: true, resolvedIP: address };
  } catch (error) {
    return {
      valid: false,
      error: `Failed to resolve hostname: ${hostname}`,
      errorCode: 'INVALID_URL'
    };
  }
}

/**
 * Full URL validation for webhook
 */
export async function validateWebhookURL(
  urlString: string,
  config: SSRFProtectionConfig = DEFAULT_SSRF_CONFIG
): Promise<URLValidationResult> {
  // Parse URL
  const parseResult = parseURL(urlString);
  if (!parseResult.valid || !parseResult.parsed) {
    return {
      valid: false,
      error: parseResult.error || 'Invalid URL',
      errorCode: 'INVALID_URL'
    };
  }

  const parsed = parseResult.parsed;

  // Validate protocol
  const protocolResult = validateProtocol(parsed.protocol, config);
  if (!protocolResult.valid) {
    return protocolResult;
  }

  // Validate hostname
  const hostnameResult = validateHostname(parsed.hostname, config);
  if (!hostnameResult.valid) {
    return hostnameResult;
  }

  // Resolve and validate IP
  const resolveResult = await resolveAndValidate(parsed.hostname, config);
  if (!resolveResult.valid) {
    return resolveResult;
  }

  return { valid: true, resolvedIP: resolveResult.resolvedIP };
}

/**
 * Validate webhook URL synchronously (without DNS resolution)
 * Use for quick validation before async resolution
 */
export function validateWebhookURLSync(
  urlString: string,
  config: SSRFProtectionConfig = DEFAULT_SSRF_CONFIG
): URLValidationResult {
  // Parse URL
  const parseResult = parseURL(urlString);
  if (!parseResult.valid || !parseResult.parsed) {
    return {
      valid: false,
      error: parseResult.error || 'Invalid URL',
      errorCode: 'INVALID_URL'
    };
  }

  const parsed = parseResult.parsed;

  // Validate protocol
  const protocolResult = validateProtocol(parsed.protocol, config);
  if (!protocolResult.valid) {
    return protocolResult;
  }

  // Validate hostname
  const hostnameResult = validateHostname(parsed.hostname, config);
  if (!hostnameResult.valid) {
    return hostnameResult;
  }

  // Check if hostname is an IP
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipRegex.test(parsed.hostname)) {
    return validateIP(parsed.hostname, config);
  }

  return { valid: true };
}

/**
 * Create safe webhook request options
 */
export function createSafeRequestOptions(
  urlString: string,
  config: SSRFProtectionConfig = DEFAULT_SSRF_CONFIG
): {
  url: string;
  timeout: number;
  maxRedirects: number;
  followRedirect: boolean;
} {
  return {
    url: urlString,
    timeout: config.timeout,
    maxRedirects: config.maxRedirects,
    followRedirect: config.maxRedirects > 0
  };
}
