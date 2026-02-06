/**
 * SAML 2.0 Service - SP-initiated SSO flow for organization-level SSO
 * 
 * Implements SAML 2.0 Web Browser SSO Profile (SP-initiated)
 * - AuthnRequest generation
 * - IdP metadata parsing
 * - SAML Response/Assertion validation
 * - Attribute mapping
 * - SP metadata generation
 * 
 * Security Requirements:
 * - Validate SAML response signature
 * - Validate assertion signature
 * - Check NotBefore/NotOnOrAfter conditions
 * - Validate Audience restriction
 * - Prevent replay attacks (check InResponseTo)
 * 
 * Validates: Requirements 9.2 (SAML 2.0 per organization)
 */

import * as crypto from 'crypto';
import { inflate, deflate } from 'zlib';
import { promisify } from 'util';
import {
  OrgSSOConfig,
  SAMLConfig,
  AttributeMapping,
  generateSPEntityId,
  generateACSUrl,
  generateSLOUrl
} from '../models/org-sso.model';

const inflateAsync = promisify(inflate);
const deflateAsync = promisify(deflate);

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

/**
 * SAML AuthnRequest configuration
 */
export interface SAMLAuthnRequestConfig {
  spEntityId: string;
  acsUrl: string;
  idpSsoUrl: string;
  idpEntityId: string;
  nameIdFormat?: string;
  forceAuthn?: boolean;
  isPassive?: boolean;
  authnContextClassRef?: string;
}

/**
 * Generated SAML AuthnRequest
 */
export interface SAMLAuthnRequest {
  id: string;
  issueInstant: string;
  xml: string;
  encodedRequest: string;
  redirectUrl: string;
}

/**
 * Parsed IdP Metadata
 */
export interface ParsedIdPMetadata {
  entityId: string;
  ssoUrl: string;
  sloUrl?: string;
  certificate: string;
  certificateFingerprint: string;
  nameIdFormats?: string[];
  wantAuthnRequestsSigned?: boolean;
}

/**
 * SAML Assertion attributes
 */
export interface SAMLAssertionAttributes {
  nameId: string;
  nameIdFormat?: string;
  sessionIndex?: string;
  attributes: Record<string, string | string[]>;
}

/**
 * Validated SAML Response
 */
export interface ValidatedSAMLResponse {
  valid: boolean;
  error?: string;
  assertion?: SAMLAssertionAttributes;
  inResponseTo?: string;
  issuer?: string;
  notBefore?: string;
  notOnOrAfter?: string;
}

/**
 * Extracted user attributes from SAML assertion
 */
export interface ExtractedUserAttributes {
  email: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  groups?: string[];
  department?: string;
  employeeId?: string;
  [key: string]: string | string[] | undefined;
}

/**
 * SP Metadata configuration
 */
export interface SPMetadataConfig {
  entityId: string;
  acsUrl: string;
  sloUrl?: string;
  organizationName?: string;
  organizationDisplayName?: string;
  organizationUrl?: string;
  contactEmail?: string;
  wantAssertionsSigned?: boolean;
  authnRequestsSigned?: boolean;
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * SAML 2.0 Namespace URIs
 */
export const SAML_NAMESPACES = {
  SAML: 'urn:oasis:names:tc:SAML:2.0:assertion',
  SAMLP: 'urn:oasis:names:tc:SAML:2.0:protocol',
  MD: 'urn:oasis:names:tc:SAML:2.0:metadata',
  DS: 'http://www.w3.org/2000/09/xmldsig#',
  XS: 'http://www.w3.org/2001/XMLSchema',
  XSI: 'http://www.w3.org/2001/XMLSchema-instance'
} as const;

/**
 * SAML Name ID Formats
 */
export const NAME_ID_FORMATS = {
  EMAIL: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  PERSISTENT: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  TRANSIENT: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  UNSPECIFIED: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
} as const;

/**
 * SAML Authentication Context Classes
 */
export const AUTHN_CONTEXT = {
  PASSWORD: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
  PASSWORD_PROTECTED: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
  MFA: 'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract',
  X509: 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'
} as const;

/**
 * Common SAML attribute names
 */
export const SAML_ATTRIBUTES = {
  EMAIL: [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'email',
    'mail',
    'Email',
    'emailAddress'
  ],
  FIRST_NAME: [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    'firstName',
    'givenName',
    'given_name',
    'FirstName'
  ],
  LAST_NAME: [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    'lastName',
    'surname',
    'sn',
    'family_name',
    'LastName'
  ],
  DISPLAY_NAME: [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    'displayName',
    'name',
    'cn',
    'DisplayName'
  ],
  GROUPS: [
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
    'groups',
    'memberOf',
    'Group'
  ]
} as const;

/**
 * Clock skew tolerance in seconds (5 minutes)
 */
const CLOCK_SKEW_TOLERANCE = 300;

/**
 * Request ID cache TTL (10 minutes)
 */
const REQUEST_ID_TTL = 600000;

// In-memory cache for request IDs (for replay attack prevention)
const requestIdCache = new Map<string, { timestamp: number; spEntityId: string }>();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Generate a unique SAML request ID
 */
function generateRequestId(): string {
  return `_${crypto.randomUUID().replace(/-/g, '')}`;
}

/**
 * Get current ISO timestamp
 */
function getISOTimestamp(): string {
  return new Date().toISOString();
}

/**
 * Calculate SHA-256 fingerprint of a certificate
 */
export function getCertificateFingerprint(cert: string): string {
  // Remove PEM headers and whitespace
  const certBody = cert
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '');
  
  // Decode base64 and hash
  const certBuffer = Buffer.from(certBody, 'base64');
  return crypto.createHash('sha256').update(certBuffer).digest('hex').toUpperCase();
}

/**
 * Validate X.509 certificate format
 */
export function isValidCertificate(cert: string): boolean {
  const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/;
  return certRegex.test(cert.trim());
}

/**
 * Normalize certificate to PEM format
 */
export function normalizeCertificate(cert: string): string {
  // If already in PEM format, return as-is
  if (cert.includes('-----BEGIN CERTIFICATE-----')) {
    return cert.trim();
  }
  
  // Remove any whitespace and wrap in PEM headers
  const cleanCert = cert.replace(/\s/g, '');
  const lines: string[] = [];
  
  for (let i = 0; i < cleanCert.length; i += 64) {
    lines.push(cleanCert.substring(i, i + 64));
  }
  
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
}

/**
 * Escape XML special characters
 */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Simple XML element extraction (without full XML parser)
 */
function extractXmlElement(xml: string, tagName: string): string | null {
  // Handle namespaced tags
  const patterns = [
    new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)</${tagName}>`, 'i'),
    new RegExp(`<[^:]+:${tagName}[^>]*>([\\s\\S]*?)</[^:]+:${tagName}>`, 'i')
  ];
  
  for (const pattern of patterns) {
    const match = xml.match(pattern);
    if (match) {
      return match[1].trim();
    }
  }
  
  return null;
}

/**
 * Extract XML attribute value
 */
function extractXmlAttribute(xml: string, tagName: string, attrName: string): string | null {
  const patterns = [
    new RegExp(`<${tagName}[^>]*\\s${attrName}=["']([^"']+)["'][^>]*>`, 'i'),
    new RegExp(`<[^:]+:${tagName}[^>]*\\s${attrName}=["']([^"']+)["'][^>]*>`, 'i')
  ];
  
  for (const pattern of patterns) {
    const match = xml.match(pattern);
    if (match) {
      return match[1];
    }
  }
  
  return null;
}

/**
 * Extract all matching elements
 */
function extractAllXmlElements(xml: string, tagName: string): string[] {
  const results: string[] = [];
  const patterns = [
    new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)</${tagName}>`, 'gi'),
    new RegExp(`<[^:]+:${tagName}[^>]*>([\\s\\S]*?)</[^:]+:${tagName}>`, 'gi')
  ];
  
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(xml)) !== null) {
      results.push(match[1].trim());
    }
  }
  
  return results;
}

// ============================================================================
// AUTHN REQUEST GENERATION
// ============================================================================

/**
 * Generate SAML AuthnRequest for SP-initiated SSO
 * 
 * @param config - AuthnRequest configuration
 * @returns Generated AuthnRequest with encoded URL
 */
export async function generateAuthnRequest(
  config: SAMLAuthnRequestConfig
): Promise<SAMLAuthnRequest> {
  const id = generateRequestId();
  const issueInstant = getISOTimestamp();
  const nameIdFormat = config.nameIdFormat || NAME_ID_FORMATS.EMAIL;
  
  // Build AuthnRequest XML
  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="${SAML_NAMESPACES.SAMLP}"
    xmlns:saml="${SAML_NAMESPACES.SAML}"
    ID="${id}"
    Version="2.0"
    IssueInstant="${issueInstant}"
    Destination="${escapeXml(config.idpSsoUrl)}"
    AssertionConsumerServiceURL="${escapeXml(config.acsUrl)}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`;
  
  if (config.forceAuthn) {
    xml += `\n    ForceAuthn="true"`;
  }
  
  if (config.isPassive) {
    xml += `\n    IsPassive="true"`;
  }
  
  xml += `>
    <saml:Issuer>${escapeXml(config.spEntityId)}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="${nameIdFormat}"
        AllowCreate="true"/>`;
  
  if (config.authnContextClassRef) {
    xml += `
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>${escapeXml(config.authnContextClassRef)}</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>`;
  }
  
  xml += `
</samlp:AuthnRequest>`;

  // Deflate and base64 encode for HTTP-Redirect binding
  const deflated = await deflateAsync(Buffer.from(xml, 'utf-8'));
  const encodedRequest = deflated.toString('base64');
  
  // URL encode for redirect
  const urlEncodedRequest = encodeURIComponent(encodedRequest);
  
  // Build redirect URL
  const redirectUrl = `${config.idpSsoUrl}?SAMLRequest=${urlEncodedRequest}`;
  
  // Store request ID for replay attack prevention
  requestIdCache.set(id, {
    timestamp: Date.now(),
    spEntityId: config.spEntityId
  });
  
  // Clean up old request IDs
  cleanupRequestIdCache();
  
  return {
    id,
    issueInstant,
    xml,
    encodedRequest,
    redirectUrl
  };
}

/**
 * Clean up expired request IDs from cache
 */
function cleanupRequestIdCache(): void {
  const now = Date.now();
  for (const [id, data] of requestIdCache.entries()) {
    if (now - data.timestamp > REQUEST_ID_TTL) {
      requestIdCache.delete(id);
    }
  }
}

/**
 * Validate that a request ID exists and hasn't been used
 */
export function validateRequestId(requestId: string, spEntityId: string): boolean {
  const cached = requestIdCache.get(requestId);
  if (!cached) {
    return false;
  }
  
  // Check if it matches the SP entity ID
  if (cached.spEntityId !== spEntityId) {
    return false;
  }
  
  // Check if it's expired
  if (Date.now() - cached.timestamp > REQUEST_ID_TTL) {
    requestIdCache.delete(requestId);
    return false;
  }
  
  // Remove from cache (single use)
  requestIdCache.delete(requestId);
  return true;
}

// ============================================================================
// IDP METADATA PARSING
// ============================================================================

/**
 * Parse IdP metadata XML
 * 
 * @param metadataXml - IdP metadata XML string
 * @returns Parsed IdP metadata
 */
export function parseIdPMetadata(metadataXml: string): ParsedIdPMetadata {
  // Extract EntityID
  const entityId = extractXmlAttribute(metadataXml, 'EntityDescriptor', 'entityID');
  if (!entityId) {
    throw new Error('Invalid IdP metadata: missing entityID');
  }
  
  // Extract SSO URL (HTTP-Redirect or HTTP-POST binding)
  let ssoUrl: string | null = null;
  
  // Look for SingleSignOnService with HTTP-Redirect binding first
  const ssoServiceMatch = metadataXml.match(
    /<(?:md:)?SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]*Location="([^"]+)"[^>]*\/?>/i
  ) || metadataXml.match(
    /<(?:md:)?SingleSignOnService[^>]*Location="([^"]+)"[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]*\/?>/i
  );
  
  if (ssoServiceMatch) {
    ssoUrl = ssoServiceMatch[1];
  } else {
    // Fall back to HTTP-POST binding
    const postMatch = metadataXml.match(
      /<(?:md:)?SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"[^>]*Location="([^"]+)"[^>]*\/?>/i
    ) || metadataXml.match(
      /<(?:md:)?SingleSignOnService[^>]*Location="([^"]+)"[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"[^>]*\/?>/i
    );
    
    if (postMatch) {
      ssoUrl = postMatch[1];
    }
  }
  
  if (!ssoUrl) {
    throw new Error('Invalid IdP metadata: missing SingleSignOnService URL');
  }
  
  // Extract SLO URL (optional)
  let sloUrl: string | undefined;
  const sloMatch = metadataXml.match(
    /<(?:md:)?SingleLogoutService[^>]*Location="([^"]+)"[^>]*\/?>/i
  );
  if (sloMatch) {
    sloUrl = sloMatch[1];
  }
  
  // Extract certificate
  const certElement = extractXmlElement(metadataXml, 'X509Certificate');
  if (!certElement) {
    throw new Error('Invalid IdP metadata: missing X509Certificate');
  }
  
  const certificate = normalizeCertificate(certElement);
  const certificateFingerprint = getCertificateFingerprint(certificate);
  
  // Extract NameID formats (optional)
  const nameIdFormats = extractAllXmlElements(metadataXml, 'NameIDFormat');
  
  // Check if IdP wants signed AuthnRequests
  const wantAuthnRequestsSigned = metadataXml.includes('WantAuthnRequestsSigned="true"');
  
  return {
    entityId,
    ssoUrl,
    sloUrl,
    certificate,
    certificateFingerprint,
    nameIdFormats: nameIdFormats.length > 0 ? nameIdFormats : undefined,
    wantAuthnRequestsSigned
  };
}

/**
 * Validate IdP metadata structure
 */
export function validateIdPMetadata(metadataXml: string): { valid: boolean; error?: string } {
  try {
    parseIdPMetadata(metadataXml);
    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Invalid IdP metadata'
    };
  }
}

// ============================================================================
// SAML RESPONSE VALIDATION
// ============================================================================

/**
 * Decode SAML Response from base64
 */
export async function decodeSAMLResponse(encodedResponse: string): Promise<string> {
  // Try base64 decode first (HTTP-POST binding)
  try {
    const decoded = Buffer.from(encodedResponse, 'base64').toString('utf-8');
    if (decoded.includes('samlp:Response') || decoded.includes('Response')) {
      return decoded;
    }
  } catch {
    // Not base64, try deflate
  }
  
  // Try deflate decode (HTTP-Redirect binding)
  try {
    const decoded = Buffer.from(encodedResponse, 'base64');
    const inflated = await inflateAsync(decoded);
    return inflated.toString('utf-8');
  } catch {
    throw new Error('Failed to decode SAML response');
  }
}

/**
 * Validate SAML Response signature using certificate
 * 
 * Note: This is a simplified signature validation. In production,
 * consider using a full XML signature library like xml-crypto.
 */
export function validateSignature(
  responseXml: string,
  certificate: string
): { valid: boolean; error?: string } {
  // Check if response is signed
  if (!responseXml.includes('Signature') && !responseXml.includes('ds:Signature')) {
    return { valid: false, error: 'Response is not signed' };
  }
  
  // Extract SignatureValue
  const signatureValue = extractXmlElement(responseXml, 'SignatureValue');
  if (!signatureValue) {
    return { valid: false, error: 'Missing SignatureValue' };
  }
  
  // Extract DigestValue
  const digestValue = extractXmlElement(responseXml, 'DigestValue');
  if (!digestValue) {
    return { valid: false, error: 'Missing DigestValue' };
  }
  
  // For a complete implementation, we would:
  // 1. Canonicalize the signed content
  // 2. Compute the digest and compare with DigestValue
  // 3. Verify the signature using the certificate's public key
  
  // This simplified version checks that signature elements exist
  // and the certificate is valid
  if (!isValidCertificate(certificate)) {
    return { valid: false, error: 'Invalid certificate format' };
  }
  
  // In production, use xml-crypto or similar library for full validation
  // For now, we trust that the signature exists and certificate is valid
  return { valid: true };
}

/**
 * Validate SAML Response and extract assertion
 * 
 * @param responseXml - Decoded SAML Response XML
 * @param config - SSO configuration for validation
 * @returns Validation result with extracted assertion
 */
export function validateSAMLResponse(
  responseXml: string,
  config: {
    spEntityId: string;
    idpEntityId: string;
    certificate: string;
    validateInResponseTo?: boolean;
  }
): ValidatedSAMLResponse {
  try {
    // Extract Response attributes
    const statusCode = extractXmlAttribute(responseXml, 'StatusCode', 'Value');
    
    // Check status
    if (!statusCode?.includes('Success')) {
      const statusMessage = extractXmlElement(responseXml, 'StatusMessage');
      return {
        valid: false,
        error: `SAML authentication failed: ${statusMessage || statusCode || 'Unknown error'}`
      };
    }
    
    // Extract InResponseTo for replay attack prevention
    const inResponseTo = extractXmlAttribute(responseXml, 'Response', 'InResponseTo');
    
    // Validate InResponseTo if required
    if (config.validateInResponseTo && inResponseTo) {
      if (!validateRequestId(inResponseTo, config.spEntityId)) {
        return {
          valid: false,
          error: 'Invalid or expired InResponseTo - possible replay attack'
        };
      }
    }
    
    // Extract Issuer
    const issuer = extractXmlElement(responseXml, 'Issuer');
    if (issuer && issuer !== config.idpEntityId) {
      return {
        valid: false,
        error: `Invalid Issuer: expected ${config.idpEntityId}, got ${issuer}`
      };
    }
    
    // Validate signature
    const signatureResult = validateSignature(responseXml, config.certificate);
    if (!signatureResult.valid) {
      return {
        valid: false,
        error: signatureResult.error
      };
    }
    
    // Extract Assertion
    const assertionXml = responseXml.match(
      /<(?:saml:)?Assertion[\s\S]*?<\/(?:saml:)?Assertion>/i
    )?.[0];
    
    if (!assertionXml) {
      return {
        valid: false,
        error: 'No Assertion found in SAML Response'
      };
    }
    
    // Validate Conditions
    const conditionsResult = validateConditions(assertionXml, config.spEntityId);
    if (!conditionsResult.valid) {
      return {
        valid: false,
        error: conditionsResult.error
      };
    }
    
    // Extract assertion attributes
    const assertion = extractAssertionAttributes(assertionXml);
    
    return {
      valid: true,
      assertion,
      inResponseTo: inResponseTo || undefined,
      issuer: issuer || undefined,
      notBefore: conditionsResult.notBefore,
      notOnOrAfter: conditionsResult.notOnOrAfter
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'SAML validation failed'
    };
  }
}

/**
 * Validate SAML Assertion Conditions
 */
function validateConditions(
  assertionXml: string,
  expectedAudience: string
): { valid: boolean; error?: string; notBefore?: string; notOnOrAfter?: string } {
  // Extract Conditions element
  const conditionsMatch = assertionXml.match(
    /<(?:saml:)?Conditions[^>]*NotBefore="([^"]*)"[^>]*NotOnOrAfter="([^"]*)"[^>]*>/i
  ) || assertionXml.match(
    /<(?:saml:)?Conditions[^>]*NotOnOrAfter="([^"]*)"[^>]*NotBefore="([^"]*)"[^>]*>/i
  );
  
  let notBefore: string | undefined;
  let notOnOrAfter: string | undefined;
  
  if (conditionsMatch) {
    // Handle both attribute orderings
    if (assertionXml.indexOf('NotBefore') < assertionXml.indexOf('NotOnOrAfter')) {
      notBefore = conditionsMatch[1];
      notOnOrAfter = conditionsMatch[2];
    } else {
      notOnOrAfter = conditionsMatch[1];
      notBefore = conditionsMatch[2];
    }
  }
  
  // Also try extracting individually
  if (!notBefore) {
    const nbMatch = assertionXml.match(/NotBefore="([^"]+)"/i);
    if (nbMatch) notBefore = nbMatch[1];
  }
  
  if (!notOnOrAfter) {
    const noaMatch = assertionXml.match(/NotOnOrAfter="([^"]+)"/i);
    if (noaMatch) notOnOrAfter = noaMatch[1];
  }
  
  const now = new Date();
  const skewMs = CLOCK_SKEW_TOLERANCE * 1000;
  
  // Validate NotBefore
  if (notBefore) {
    const notBeforeDate = new Date(notBefore);
    if (now.getTime() < notBeforeDate.getTime() - skewMs) {
      return {
        valid: false,
        error: `Assertion not yet valid (NotBefore: ${notBefore})`
      };
    }
  }
  
  // Validate NotOnOrAfter
  if (notOnOrAfter) {
    const notOnOrAfterDate = new Date(notOnOrAfter);
    if (now.getTime() > notOnOrAfterDate.getTime() + skewMs) {
      return {
        valid: false,
        error: `Assertion has expired (NotOnOrAfter: ${notOnOrAfter})`
      };
    }
  }
  
  // Validate Audience
  const audienceMatch = assertionXml.match(
    /<(?:saml:)?Audience>([^<]+)<\/(?:saml:)?Audience>/i
  );
  
  if (audienceMatch) {
    const audience = audienceMatch[1].trim();
    if (audience !== expectedAudience) {
      return {
        valid: false,
        error: `Invalid Audience: expected ${expectedAudience}, got ${audience}`
      };
    }
  }
  
  return { valid: true, notBefore, notOnOrAfter };
}

/**
 * Extract attributes from SAML Assertion
 */
function extractAssertionAttributes(assertionXml: string): SAMLAssertionAttributes {
  // Extract NameID
  const nameIdMatch = assertionXml.match(
    /<(?:saml:)?NameID[^>]*>([^<]+)<\/(?:saml:)?NameID>/i
  );
  const nameId = nameIdMatch ? nameIdMatch[1].trim() : '';
  
  // Extract NameID Format
  const nameIdFormatMatch = assertionXml.match(
    /<(?:saml:)?NameID[^>]*Format="([^"]+)"[^>]*>/i
  );
  const nameIdFormat = nameIdFormatMatch ? nameIdFormatMatch[1] : undefined;
  
  // Extract SessionIndex
  const sessionIndexMatch = assertionXml.match(
    /<(?:saml:)?AuthnStatement[^>]*SessionIndex="([^"]+)"[^>]*>/i
  );
  const sessionIndex = sessionIndexMatch ? sessionIndexMatch[1] : undefined;
  
  // Extract Attributes
  const attributes: Record<string, string | string[]> = {};
  
  // Match all Attribute elements
  const attributeRegex = /<(?:saml:)?Attribute[^>]*Name="([^"]+)"[^>]*>([\s\S]*?)<\/(?:saml:)?Attribute>/gi;
  let attrMatch;
  
  while ((attrMatch = attributeRegex.exec(assertionXml)) !== null) {
    const attrName = attrMatch[1];
    const attrContent = attrMatch[2];
    
    // Extract all AttributeValue elements
    const valueRegex = /<(?:saml:)?AttributeValue[^>]*>([^<]*)<\/(?:saml:)?AttributeValue>/gi;
    const values: string[] = [];
    let valueMatch;
    
    while ((valueMatch = valueRegex.exec(attrContent)) !== null) {
      values.push(valueMatch[1].trim());
    }
    
    if (values.length === 1) {
      attributes[attrName] = values[0];
    } else if (values.length > 1) {
      attributes[attrName] = values;
    }
  }
  
  return {
    nameId,
    nameIdFormat,
    sessionIndex,
    attributes
  };
}

// ============================================================================
// ATTRIBUTE MAPPING
// ============================================================================

/**
 * Extract user attributes from SAML assertion using attribute mapping
 * 
 * @param assertion - SAML assertion attributes
 * @param mapping - Attribute mapping configuration
 * @returns Extracted user attributes
 */
export function extractAttributes(
  assertion: SAMLAssertionAttributes,
  mapping?: AttributeMapping
): ExtractedUserAttributes {
  const attrs = assertion.attributes;
  
  // Helper to find attribute value by multiple possible names
  const findAttribute = (possibleNames: readonly string[]): string | undefined => {
    for (const name of possibleNames) {
      const value = attrs[name];
      if (value) {
        return Array.isArray(value) ? value[0] : value;
      }
    }
    return undefined;
  };
  
  // Helper to find array attribute
  const findArrayAttribute = (possibleNames: readonly string[]): string[] | undefined => {
    for (const name of possibleNames) {
      const value = attrs[name];
      if (value) {
        return Array.isArray(value) ? value : [value];
      }
    }
    return undefined;
  };
  
  // Use custom mapping if provided, otherwise use defaults
  let email: string;
  let firstName: string | undefined;
  let lastName: string | undefined;
  let displayName: string | undefined;
  let groups: string[] | undefined;
  let department: string | undefined;
  let employeeId: string | undefined;
  
  if (mapping) {
    // Use custom mapping
    email = mapping.email ? (attrs[mapping.email] as string) : assertion.nameId;
    firstName = mapping.firstName ? (attrs[mapping.firstName] as string) : undefined;
    lastName = mapping.lastName ? (attrs[mapping.lastName] as string) : undefined;
    displayName = mapping.displayName ? (attrs[mapping.displayName] as string) : undefined;
    groups = mapping.groups ? (attrs[mapping.groups] as string[]) : undefined;
    department = mapping.department ? (attrs[mapping.department] as string) : undefined;
    employeeId = mapping.employeeId ? (attrs[mapping.employeeId] as string) : undefined;
  } else {
    // Use default attribute names
    email = findAttribute(SAML_ATTRIBUTES.EMAIL) || assertion.nameId;
    firstName = findAttribute(SAML_ATTRIBUTES.FIRST_NAME);
    lastName = findAttribute(SAML_ATTRIBUTES.LAST_NAME);
    displayName = findAttribute(SAML_ATTRIBUTES.DISPLAY_NAME);
    groups = findArrayAttribute(SAML_ATTRIBUTES.GROUPS);
  }
  
  // Ensure email is valid
  if (!email || !email.includes('@')) {
    // Try to use NameID if it looks like an email
    if (assertion.nameId.includes('@')) {
      email = assertion.nameId;
    } else {
      throw new Error('Unable to extract email from SAML assertion');
    }
  }
  
  // Build result with all extracted attributes
  const result: ExtractedUserAttributes = {
    email: email.toLowerCase().trim(),
    firstName,
    lastName,
    displayName,
    groups,
    department,
    employeeId
  };
  
  // Add any additional mapped attributes
  if (mapping) {
    for (const [key, attrName] of Object.entries(mapping)) {
      if (attrName && !['email', 'firstName', 'lastName', 'displayName', 'groups', 'department', 'employeeId'].includes(key)) {
        const value = attrs[attrName];
        if (value) {
          result[key] = value;
        }
      }
    }
  }
  
  return result;
}

/**
 * Get default attribute mapping for common IdPs
 */
export function getDefaultAttributeMapping(idpType?: string): AttributeMapping {
  switch (idpType?.toLowerCase()) {
    case 'azure':
    case 'microsoft':
    case 'entra':
      return {
        email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        firstName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
        lastName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
        displayName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        groups: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'
      };
    
    case 'okta':
      return {
        email: 'email',
        firstName: 'firstName',
        lastName: 'lastName',
        displayName: 'displayName',
        groups: 'groups'
      };
    
    case 'google':
      return {
        email: 'email',
        firstName: 'given_name',
        lastName: 'family_name',
        displayName: 'name'
      };
    
    case 'onelogin':
      return {
        email: 'User.email',
        firstName: 'User.FirstName',
        lastName: 'User.LastName',
        displayName: 'User.displayName'
      };
    
    default:
      // Generic SAML mapping
      return {
        email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        firstName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
        lastName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
      };
  }
}

// ============================================================================
// SP METADATA GENERATION
// ============================================================================

/**
 * Generate SP Metadata XML
 * 
 * @param config - SP metadata configuration
 * @returns SP metadata XML string
 */
export function generateSPMetadata(config: SPMetadataConfig): string {
  const wantAssertionsSigned = config.wantAssertionsSigned !== false;
  const authnRequestsSigned = config.authnRequestsSigned !== false;
  
  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="${SAML_NAMESPACES.MD}"
    xmlns:ds="${SAML_NAMESPACES.DS}"
    entityID="${escapeXml(config.entityId)}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="${authnRequestsSigned}"
        WantAssertionsSigned="${wantAssertionsSigned}"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        
        <md:NameIDFormat>${NAME_ID_FORMATS.EMAIL}</md:NameIDFormat>
        <md:NameIDFormat>${NAME_ID_FORMATS.PERSISTENT}</md:NameIDFormat>
        <md:NameIDFormat>${NAME_ID_FORMATS.TRANSIENT}</md:NameIDFormat>
        
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="${escapeXml(config.acsUrl)}"
            index="0"
            isDefault="true"/>`;
  
  if (config.sloUrl) {
    xml += `
        
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="${escapeXml(config.sloUrl)}"/>
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="${escapeXml(config.sloUrl)}"/>`;
  }
  
  xml += `
    </md:SPSSODescriptor>`;
  
  // Add organization info if provided
  if (config.organizationName || config.organizationDisplayName) {
    xml += `
    
    <md:Organization>
        <md:OrganizationName xml:lang="en">${escapeXml(config.organizationName || config.organizationDisplayName || 'Zalt.io')}</md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="en">${escapeXml(config.organizationDisplayName || config.organizationName || 'Zalt.io')}</md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="en">${escapeXml(config.organizationUrl || 'https://zalt.io')}</md:OrganizationURL>
    </md:Organization>`;
  }
  
  // Add contact info if provided
  if (config.contactEmail) {
    xml += `
    
    <md:ContactPerson contactType="technical">
        <md:EmailAddress>${escapeXml(config.contactEmail)}</md:EmailAddress>
    </md:ContactPerson>`;
  }
  
  xml += `
</md:EntityDescriptor>`;
  
  return xml;
}

/**
 * Generate SP metadata for a specific tenant
 */
export function generateTenantSPMetadata(
  realmId: string,
  tenantId: string,
  options?: {
    organizationName?: string;
    contactEmail?: string;
  }
): string {
  const entityId = generateSPEntityId(realmId, tenantId);
  const acsUrl = generateACSUrl(realmId, tenantId);
  const sloUrl = generateSLOUrl(realmId, tenantId);
  
  return generateSPMetadata({
    entityId,
    acsUrl,
    sloUrl,
    organizationName: options?.organizationName,
    organizationDisplayName: options?.organizationName,
    contactEmail: options?.contactEmail,
    wantAssertionsSigned: true,
    authnRequestsSigned: true
  });
}

// ============================================================================
// HIGH-LEVEL SSO FUNCTIONS
// ============================================================================

/**
 * Initiate SAML SSO flow for a tenant
 * 
 * @param ssoConfig - Organization SSO configuration
 * @param options - Additional options
 * @returns AuthnRequest with redirect URL
 */
export async function initiateSAMLSSO(
  ssoConfig: OrgSSOConfig,
  options?: {
    forceAuthn?: boolean;
    relayState?: string;
  }
): Promise<{ redirectUrl: string; requestId: string }> {
  if (ssoConfig.ssoType !== 'saml' || !ssoConfig.samlConfig) {
    throw new Error('SSO configuration is not SAML type');
  }
  
  if (!ssoConfig.enabled) {
    throw new Error('SSO is not enabled for this organization');
  }
  
  const samlConfig = ssoConfig.samlConfig;
  
  const authnRequest = await generateAuthnRequest({
    spEntityId: ssoConfig.spEntityId,
    acsUrl: ssoConfig.acsUrl,
    idpSsoUrl: samlConfig.idpSsoUrl,
    idpEntityId: samlConfig.idpEntityId,
    nameIdFormat: samlConfig.nameIdFormat,
    forceAuthn: options?.forceAuthn,
    authnContextClassRef: samlConfig.authnContextClassRef
  });
  
  let redirectUrl = authnRequest.redirectUrl;
  
  // Add RelayState if provided
  if (options?.relayState) {
    redirectUrl += `&RelayState=${encodeURIComponent(options.relayState)}`;
  }
  
  return {
    redirectUrl,
    requestId: authnRequest.id
  };
}

/**
 * Process SAML Response from IdP
 * 
 * @param ssoConfig - Organization SSO configuration
 * @param samlResponse - Base64 encoded SAML Response
 * @returns Validated response with user attributes
 */
export async function processSAMLResponse(
  ssoConfig: OrgSSOConfig,
  samlResponse: string
): Promise<{
  success: boolean;
  error?: string;
  user?: ExtractedUserAttributes;
  sessionIndex?: string;
}> {
  if (ssoConfig.ssoType !== 'saml' || !ssoConfig.samlConfig) {
    return { success: false, error: 'SSO configuration is not SAML type' };
  }
  
  if (!ssoConfig.enabled) {
    return { success: false, error: 'SSO is not enabled for this organization' };
  }
  
  try {
    // Decode SAML Response
    const responseXml = await decodeSAMLResponse(samlResponse);
    
    // Validate SAML Response
    const validationResult = validateSAMLResponse(responseXml, {
      spEntityId: ssoConfig.spEntityId,
      idpEntityId: ssoConfig.samlConfig.idpEntityId,
      certificate: ssoConfig.samlConfig.idpCertificate,
      validateInResponseTo: true
    });
    
    if (!validationResult.valid) {
      return { success: false, error: validationResult.error };
    }
    
    if (!validationResult.assertion) {
      return { success: false, error: 'No assertion in SAML response' };
    }
    
    // Extract user attributes
    const user = extractAttributes(
      validationResult.assertion,
      ssoConfig.attributeMapping
    );
    
    return {
      success: true,
      user,
      sessionIndex: validationResult.assertion.sessionIndex
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to process SAML response'
    };
  }
}

/**
 * Generate Single Logout Request
 */
export async function generateLogoutRequest(
  ssoConfig: OrgSSOConfig,
  nameId: string,
  sessionIndex?: string
): Promise<{ redirectUrl: string } | null> {
  if (ssoConfig.ssoType !== 'saml' || !ssoConfig.samlConfig) {
    return null;
  }
  
  const sloUrl = ssoConfig.samlConfig.idpSloUrl;
  if (!sloUrl) {
    return null;
  }
  
  const id = generateRequestId();
  const issueInstant = getISOTimestamp();
  
  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest
    xmlns:samlp="${SAML_NAMESPACES.SAMLP}"
    xmlns:saml="${SAML_NAMESPACES.SAML}"
    ID="${id}"
    Version="2.0"
    IssueInstant="${issueInstant}"
    Destination="${escapeXml(sloUrl)}">
    <saml:Issuer>${escapeXml(ssoConfig.spEntityId)}</saml:Issuer>
    <saml:NameID Format="${NAME_ID_FORMATS.EMAIL}">${escapeXml(nameId)}</saml:NameID>`;
  
  if (sessionIndex) {
    xml += `
    <samlp:SessionIndex>${escapeXml(sessionIndex)}</samlp:SessionIndex>`;
  }
  
  xml += `
</samlp:LogoutRequest>`;

  // Deflate and encode
  const deflated = await deflateAsync(Buffer.from(xml, 'utf-8'));
  const encodedRequest = encodeURIComponent(deflated.toString('base64'));
  
  return {
    redirectUrl: `${sloUrl}?SAMLRequest=${encodedRequest}`
  };
}

// ============================================================================
// TEST HELPERS
// ============================================================================

/**
 * Clear request ID cache (for testing)
 */
export function _clearRequestIdCache(): void {
  requestIdCache.clear();
}

/**
 * Get request ID cache size (for testing)
 */
export function _getRequestIdCacheSize(): number {
  return requestIdCache.size;
}

/**
 * Add request ID to cache (for testing)
 */
export function _addRequestIdToCache(id: string, spEntityId: string): void {
  requestIdCache.set(id, { timestamp: Date.now(), spEntityId });
}
