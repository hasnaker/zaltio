/**
 * SAML 2.0 Service Tests
 * 
 * Tests for:
 * - AuthnRequest generation
 * - IdP metadata parsing
 * - SAML Response validation
 * - Attribute mapping
 * - SP metadata generation
 * 
 * Validates: Requirements 9.2 (SAML 2.0 per organization)
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

import {
  generateAuthnRequest,
  parseIdPMetadata,
  validateIdPMetadata,
  validateSAMLResponse,
  decodeSAMLResponse,
  extractAttributes,
  generateSPMetadata,
  generateTenantSPMetadata,
  getDefaultAttributeMapping,
  getCertificateFingerprint,
  isValidCertificate,
  normalizeCertificate,
  validateRequestId,
  NAME_ID_FORMATS,
  SAML_NAMESPACES,
  _clearRequestIdCache,
  _addRequestIdToCache,
  SAMLAssertionAttributes
} from './saml.service';

// ============================================================================
// TEST DATA
// ============================================================================

// Real X.509 certificate for testing (self-signed, not for production)
const TEST_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P2dG5jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7VvNrDp8XT5TCtWqS5iL8WvNxPz8LHmHFhKmRz5xBgJmqLhJGzrhlvnKOsN8t
ZrHYwEGAtWvOKAaFEIplvgl8o8c/2aU+h3xPzZCrJvQBpt9bdUKH3KHfvQWRstaD
ykY8ODGQN5XZmLlzlhIf5HBCB1mL5hBtA3p8wv8LRBDGplnLOBCL1iF8dYRi5bTw
lDnC9Xzn8BQPZLH4vnbkPqKvsB8D2wvHFbILsVj5E8raFNZKpRL+HzfrAeJAdTnG
u8QG5xzZE7xr1YDJX8ckp0aGTSYHoxIxVgYvLvMZEd5xvNawVu7XqMJa8EjP15X8
cGPLgcJYcNgqfcbG8XhfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGqBhBhBvLmk
qPkT2K8F5bPTfvTf7gNqZrZnTc8FVfIyXETgsBgSRfaF4/WBi5LJEu7U8kkdCyGn
sqqM5HhNLTCPr8w8JvzBtDU0gw3X8bKl7kNi5zzKOgKr7lBVo9GKELI6dnXp0Cvx
N9c1CjitwpTvPvM7/vOYGNwE8bLSCyb9sLdzdrxCp6PWlZz5K7T7XEVPLB8sM8z8
sofpgtPP7GZaxJFgfCniq7o3D/XhfR8h4QOnTHGXYPzYd4F1mWfAsuTbBgApGLRW
yE/JYBrjRpbre1Pxebix5JAhHpE5gJsolhGajqEAZTSAx8nt2qL8ILTv/5D8Xhsf
VYHhMwPMQy4=
-----END CERTIFICATE-----`;

const TEST_CERTIFICATE_RAW = `MIICpDCCAYwCCQDU+pQ4P2dG5jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7VvNrDp8XT5TCtWqS5iL8WvNxPz8LHmHFhKmRz5xBgJmqLhJGzrhlvnKOsN8t
ZrHYwEGAtWvOKAaFEIplvgl8o8c/2aU+h3xPzZCrJvQBpt9bdUKH3KHfvQWRstaD
ykY8ODGQN5XZmLlzlhIf5HBCB1mL5hBtA3p8wv8LRBDGplnLOBCL1iF8dYRi5bTw
lDnC9Xzn8BQPZLH4vnbkPqKvsB8D2wvHFbILsVj5E8raFNZKpRL+HzfrAeJAdTnG
u8QG5xzZE7xr1YDJX8ckp0aGTSYHoxIxVgYvLvMZEd5xvNawVu7XqMJa8EjP15X8
cGPLgcJYcNgqfcbG8XhfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGqBhBhBvLmk
qPkT2K8F5bPTfvTf7gNqZrZnTc8FVfIyXETgsBgSRfaF4/WBi5LJEu7U8kkdCyGn
sqqM5HhNLTCPr8w8JvzBtDU0gw3X8bKl7kNi5zzKOgKr7lBVo9GKELI6dnXp0Cvx
N9c1CjitwpTvPvM7/vOYGNwE8bLSCyb9sLdzdrxCp6PWlZz5K7T7XEVPLB8sM8z8
sofpgtPP7GZaxJFgfCniq7o3D/XhfR8h4QOnTHGXYPzYd4F1mWfAsuTbBgApGLRW
yE/JYBrjRpbre1Pxebix5JAhHpE5gJsolhGajqEAZTSAx8nt2qL8ILTv/5D8Xhsf
VYHhMwPMQy4=`;

// Sample IdP Metadata XML
const SAMPLE_IDP_METADATA = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${TEST_CERTIFICATE_RAW}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/post"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;

// Sample SAML Response (simplified for testing)
function createSampleSAMLResponse(options: {
  statusCode?: string;
  issuer?: string;
  audience?: string;
  nameId?: string;
  notBefore?: string;
  notOnOrAfter?: string;
  inResponseTo?: string;
  attributes?: Record<string, string>;
} = {}): string {
  const now = new Date();
  const notBefore = options.notBefore || new Date(now.getTime() - 60000).toISOString();
  const notOnOrAfter = options.notOnOrAfter || new Date(now.getTime() + 300000).toISOString();
  const statusCode = options.statusCode || 'urn:oasis:names:tc:SAML:2.0:status:Success';
  const issuer = options.issuer || 'https://idp.example.com';
  const audience = options.audience || 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456';
  const nameId = options.nameId || 'user@example.com';
  const inResponseTo = options.inResponseTo ? `InResponseTo="${options.inResponseTo}"` : '';
  
  let attributeStatements = '';
  if (options.attributes) {
    const attrs = Object.entries(options.attributes)
      .map(([name, value]) => `
        <saml:Attribute Name="${name}">
          <saml:AttributeValue>${value}</saml:AttributeValue>
        </saml:Attribute>`)
      .join('');
    attributeStatements = `<saml:AttributeStatement>${attrs}</saml:AttributeStatement>`;
  }
  
  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response_123"
                Version="2.0"
                IssueInstant="${now.toISOString()}"
                ${inResponseTo}>
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="${statusCode}"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion_456" Version="2.0" IssueInstant="${now.toISOString()}">
    <saml:Issuer>${issuer}</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_assertion_456">
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>abc123</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>signature_value_here</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
      <saml:AudienceRestriction>
        <saml:Audience>${audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="_session_789">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    ${attributeStatements}
  </saml:Assertion>
</samlp:Response>`;
}

// ============================================================================
// TESTS
// ============================================================================

describe('SAML Service', () => {
  beforeEach(() => {
    _clearRequestIdCache();
  });
  
  afterEach(() => {
    _clearRequestIdCache();
  });

  describe('Certificate Utilities', () => {
    it('should validate PEM certificate format', () => {
      expect(isValidCertificate(TEST_CERTIFICATE)).toBe(true);
    });
    
    it('should reject invalid certificate format', () => {
      expect(isValidCertificate('not a certificate')).toBe(false);
      expect(isValidCertificate('')).toBe(false);
    });
    
    it('should normalize raw certificate to PEM format', () => {
      const normalized = normalizeCertificate(TEST_CERTIFICATE_RAW);
      expect(normalized).toContain('-----BEGIN CERTIFICATE-----');
      expect(normalized).toContain('-----END CERTIFICATE-----');
      expect(isValidCertificate(normalized)).toBe(true);
    });
    
    it('should return PEM certificate unchanged', () => {
      const normalized = normalizeCertificate(TEST_CERTIFICATE);
      expect(normalized).toBe(TEST_CERTIFICATE.trim());
    });
    
    it('should calculate certificate fingerprint', () => {
      const fingerprint = getCertificateFingerprint(TEST_CERTIFICATE);
      expect(fingerprint).toMatch(/^[A-F0-9]{64}$/);
    });
    
    it('should return consistent fingerprint for same certificate', () => {
      const fp1 = getCertificateFingerprint(TEST_CERTIFICATE);
      const fp2 = getCertificateFingerprint(TEST_CERTIFICATE);
      expect(fp1).toBe(fp2);
    });
  });

  describe('AuthnRequest Generation', () => {
    it('should generate valid AuthnRequest', async () => {
      const config = {
        spEntityId: 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456',
        acsUrl: 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456/acs',
        idpSsoUrl: 'https://idp.example.com/sso',
        idpEntityId: 'https://idp.example.com'
      };
      
      const request = await generateAuthnRequest(config);
      
      expect(request.id).toMatch(/^_[a-f0-9]+$/);
      expect(request.issueInstant).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(request.xml).toContain('AuthnRequest');
      expect(request.xml).toContain(config.spEntityId);
      expect(request.xml).toContain(config.acsUrl);
      expect(request.encodedRequest).toBeTruthy();
      expect(request.redirectUrl).toContain(config.idpSsoUrl);
      expect(request.redirectUrl).toContain('SAMLRequest=');
    });
    
    it('should include ForceAuthn when specified', async () => {
      const config = {
        spEntityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        idpSsoUrl: 'https://idp.example.com/sso',
        idpEntityId: 'https://idp.example.com',
        forceAuthn: true
      };
      
      const request = await generateAuthnRequest(config);
      expect(request.xml).toContain('ForceAuthn="true"');
    });
    
    it('should include custom NameIDFormat', async () => {
      const config = {
        spEntityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        idpSsoUrl: 'https://idp.example.com/sso',
        idpEntityId: 'https://idp.example.com',
        nameIdFormat: NAME_ID_FORMATS.PERSISTENT
      };
      
      const request = await generateAuthnRequest(config);
      expect(request.xml).toContain(NAME_ID_FORMATS.PERSISTENT);
    });
    
    it('should store request ID for replay prevention', async () => {
      const config = {
        spEntityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        idpSsoUrl: 'https://idp.example.com/sso',
        idpEntityId: 'https://idp.example.com'
      };
      
      const request = await generateAuthnRequest(config);
      
      // Request ID should be valid once
      expect(validateRequestId(request.id, config.spEntityId)).toBe(true);
      
      // Request ID should be invalid after use (single use)
      expect(validateRequestId(request.id, config.spEntityId)).toBe(false);
    });
  });

  describe('IdP Metadata Parsing', () => {
    it('should parse valid IdP metadata', () => {
      const metadata = parseIdPMetadata(SAMPLE_IDP_METADATA);
      
      expect(metadata.entityId).toBe('https://idp.example.com');
      expect(metadata.ssoUrl).toBe('https://idp.example.com/sso');
      expect(metadata.sloUrl).toBe('https://idp.example.com/slo');
      expect(metadata.certificate).toContain('-----BEGIN CERTIFICATE-----');
      expect(metadata.certificateFingerprint).toMatch(/^[A-F0-9]{64}$/);
      expect(metadata.wantAuthnRequestsSigned).toBe(true);
    });
    
    it('should extract NameID formats', () => {
      const metadata = parseIdPMetadata(SAMPLE_IDP_METADATA);
      
      expect(metadata.nameIdFormats).toBeDefined();
      expect(metadata.nameIdFormats).toContain(NAME_ID_FORMATS.EMAIL);
      expect(metadata.nameIdFormats).toContain(NAME_ID_FORMATS.PERSISTENT);
    });
    
    it('should throw error for missing entityID', () => {
      const invalidMetadata = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"></md:EntityDescriptor>';
      
      expect(() => parseIdPMetadata(invalidMetadata)).toThrow('missing entityID');
    });
    
    it('should validate IdP metadata structure', () => {
      const result = validateIdPMetadata(SAMPLE_IDP_METADATA);
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });
    
    it('should return error for invalid metadata', () => {
      const result = validateIdPMetadata('invalid xml');
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('SAML Response Validation', () => {
    const spEntityId = 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456';
    const idpEntityId = 'https://idp.example.com';
    
    it('should validate successful SAML response', () => {
      const responseXml = createSampleSAMLResponse({
        audience: spEntityId,
        issuer: idpEntityId
      });
      
      const result = validateSAMLResponse(responseXml, {
        spEntityId,
        idpEntityId,
        certificate: TEST_CERTIFICATE,
        validateInResponseTo: false
      });
      
      expect(result.valid).toBe(true);
      expect(result.assertion).toBeDefined();
      expect(result.assertion?.nameId).toBe('user@example.com');
    });
    
    it('should reject failed SAML response', () => {
      const responseXml = createSampleSAMLResponse({
        statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
        audience: spEntityId
      });
      
      const result = validateSAMLResponse(responseXml, {
        spEntityId,
        idpEntityId,
        certificate: TEST_CERTIFICATE
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('authentication failed');
    });
    
    it('should reject response with wrong issuer', () => {
      const responseXml = createSampleSAMLResponse({
        issuer: 'https://wrong-idp.example.com',
        audience: spEntityId
      });
      
      const result = validateSAMLResponse(responseXml, {
        spEntityId,
        idpEntityId,
        certificate: TEST_CERTIFICATE
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid Issuer');
    });
    
    it('should reject response with wrong audience', () => {
      const responseXml = createSampleSAMLResponse({
        audience: 'https://wrong-sp.example.com',
        issuer: idpEntityId
      });
      
      const result = validateSAMLResponse(responseXml, {
        spEntityId,
        idpEntityId,
        certificate: TEST_CERTIFICATE
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Invalid Audience');
    });
    
    it('should reject expired assertion', () => {
      const pastDate = new Date(Date.now() - 600000).toISOString(); // 10 minutes ago
      const responseXml = createSampleSAMLResponse({
        notOnOrAfter: pastDate,
        audience: spEntityId,
        issuer: idpEntityId
      });
      
      const result = validateSAMLResponse(responseXml, {
        spEntityId,
        idpEntityId,
        certificate: TEST_CERTIFICATE
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });
    
    it('should validate InResponseTo for replay prevention', () => {
      const requestId = '_test_request_123';
      _addRequestIdToCache(requestId, spEntityId);
      
      const responseXml = createSampleSAMLResponse({
        inResponseTo: requestId,
        audience: spEntityId,
        issuer: idpEntityId
      });
      
      const result = validateSAMLResponse(responseXml, {
        spEntityId,
        idpEntityId,
        certificate: TEST_CERTIFICATE,
        validateInResponseTo: true
      });
      
      expect(result.valid).toBe(true);
      expect(result.inResponseTo).toBe(requestId);
    });
    
    it('should reject replay attack (reused InResponseTo)', () => {
      const requestId = '_test_request_456';
      // Don't add to cache - simulating replay
      
      const responseXml = createSampleSAMLResponse({
        inResponseTo: requestId,
        audience: spEntityId,
        issuer: idpEntityId
      });
      
      const result = validateSAMLResponse(responseXml, {
        spEntityId,
        idpEntityId,
        certificate: TEST_CERTIFICATE,
        validateInResponseTo: true
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('replay attack');
    });
    
    it('should extract session index from assertion', () => {
      const responseXml = createSampleSAMLResponse({
        audience: spEntityId,
        issuer: idpEntityId
      });
      
      const result = validateSAMLResponse(responseXml, {
        spEntityId,
        idpEntityId,
        certificate: TEST_CERTIFICATE
      });
      
      expect(result.valid).toBe(true);
      expect(result.assertion?.sessionIndex).toBe('_session_789');
    });
  });

  describe('Attribute Extraction', () => {
    it('should extract attributes from assertion', () => {
      const assertion: SAMLAssertionAttributes = {
        nameId: 'user@example.com',
        nameIdFormat: NAME_ID_FORMATS.EMAIL,
        sessionIndex: '_session_123',
        attributes: {
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'user@example.com',
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'John',
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'Doe'
        }
      };
      
      const extracted = extractAttributes(assertion);
      
      expect(extracted.email).toBe('user@example.com');
      expect(extracted.firstName).toBe('John');
      expect(extracted.lastName).toBe('Doe');
    });
    
    it('should use NameID as email fallback', () => {
      const assertion: SAMLAssertionAttributes = {
        nameId: 'user@example.com',
        attributes: {}
      };
      
      const extracted = extractAttributes(assertion);
      expect(extracted.email).toBe('user@example.com');
    });
    
    it('should extract groups as array', () => {
      const assertion: SAMLAssertionAttributes = {
        nameId: 'user@example.com',
        attributes: {
          'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups': ['admin', 'users']
        }
      };
      
      const extracted = extractAttributes(assertion);
      expect(extracted.groups).toEqual(['admin', 'users']);
    });
    
    it('should use custom attribute mapping', () => {
      const assertion: SAMLAssertionAttributes = {
        nameId: 'user@example.com',
        attributes: {
          'custom_email': 'custom@example.com',
          'custom_first': 'Jane',
          'custom_last': 'Smith'
        }
      };
      
      const mapping = {
        email: 'custom_email',
        firstName: 'custom_first',
        lastName: 'custom_last'
      };
      
      const extracted = extractAttributes(assertion, mapping);
      
      expect(extracted.email).toBe('custom@example.com');
      expect(extracted.firstName).toBe('Jane');
      expect(extracted.lastName).toBe('Smith');
    });
    
    it('should normalize email to lowercase', () => {
      const assertion: SAMLAssertionAttributes = {
        nameId: 'USER@EXAMPLE.COM',
        attributes: {}
      };
      
      const extracted = extractAttributes(assertion);
      expect(extracted.email).toBe('user@example.com');
    });
    
    it('should throw error if no valid email found', () => {
      const assertion: SAMLAssertionAttributes = {
        nameId: 'not-an-email',
        attributes: {}
      };
      
      expect(() => extractAttributes(assertion)).toThrow('Unable to extract email');
    });
  });

  describe('Default Attribute Mappings', () => {
    it('should return Azure/Microsoft mapping', () => {
      const mapping = getDefaultAttributeMapping('azure');
      expect(mapping.email).toContain('emailaddress');
      expect(mapping.groups).toContain('groups');
    });
    
    it('should return Okta mapping', () => {
      const mapping = getDefaultAttributeMapping('okta');
      expect(mapping.email).toBe('email');
      expect(mapping.firstName).toBe('firstName');
    });
    
    it('should return Google mapping', () => {
      const mapping = getDefaultAttributeMapping('google');
      expect(mapping.email).toBe('email');
      expect(mapping.firstName).toBe('given_name');
    });
    
    it('should return generic mapping for unknown IdP', () => {
      const mapping = getDefaultAttributeMapping('unknown');
      expect(mapping.email).toContain('emailaddress');
    });
    
    it('should return generic mapping when no IdP specified', () => {
      const mapping = getDefaultAttributeMapping();
      expect(mapping.email).toBeDefined();
    });
  });

  describe('SP Metadata Generation', () => {
    it('should generate valid SP metadata', () => {
      const metadata = generateSPMetadata({
        entityId: 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456',
        acsUrl: 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456/acs',
        sloUrl: 'https://api.zalt.io/v1/sso/saml/realm_123/tenant_456/slo'
      });
      
      expect(metadata).toContain('EntityDescriptor');
      expect(metadata).toContain('SPSSODescriptor');
      expect(metadata).toContain('AssertionConsumerService');
      expect(metadata).toContain('https://api.zalt.io/v1/sso/saml/realm_123/tenant_456');
    });
    
    it('should include SLO endpoint when provided', () => {
      const metadata = generateSPMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        sloUrl: 'https://sp.example.com/slo'
      });
      
      expect(metadata).toContain('SingleLogoutService');
      expect(metadata).toContain('https://sp.example.com/slo');
    });
    
    it('should not include SLO when not provided', () => {
      const metadata = generateSPMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs'
      });
      
      expect(metadata).not.toContain('SingleLogoutService');
    });
    
    it('should include organization info when provided', () => {
      const metadata = generateSPMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        organizationName: 'Acme Corp',
        organizationDisplayName: 'Acme Corporation',
        organizationUrl: 'https://acme.com'
      });
      
      expect(metadata).toContain('Organization');
      expect(metadata).toContain('Acme Corp');
      expect(metadata).toContain('Acme Corporation');
      expect(metadata).toContain('https://acme.com');
    });
    
    it('should include contact info when provided', () => {
      const metadata = generateSPMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        contactEmail: 'admin@example.com'
      });
      
      expect(metadata).toContain('ContactPerson');
      expect(metadata).toContain('admin@example.com');
    });
    
    it('should include NameID formats', () => {
      const metadata = generateSPMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs'
      });
      
      expect(metadata).toContain('NameIDFormat');
      expect(metadata).toContain(NAME_ID_FORMATS.EMAIL);
      expect(metadata).toContain(NAME_ID_FORMATS.PERSISTENT);
    });
    
    it('should set WantAssertionsSigned attribute', () => {
      const metadata = generateSPMetadata({
        entityId: 'https://sp.example.com',
        acsUrl: 'https://sp.example.com/acs',
        wantAssertionsSigned: true
      });
      
      expect(metadata).toContain('WantAssertionsSigned="true"');
    });
    
    it('should generate tenant-specific SP metadata', () => {
      const metadata = generateTenantSPMetadata('realm_123', 'tenant_456', {
        organizationName: 'Test Org'
      });
      
      expect(metadata).toContain('realm_123');
      expect(metadata).toContain('tenant_456');
      expect(metadata).toContain('Test Org');
    });
  });

  describe('SAML Response Decoding', () => {
    it('should decode base64 encoded response', async () => {
      const originalXml = createSampleSAMLResponse();
      const encoded = Buffer.from(originalXml).toString('base64');
      
      const decoded = await decodeSAMLResponse(encoded);
      
      expect(decoded).toContain('samlp:Response');
    });
    
    it('should throw error for invalid encoding', async () => {
      await expect(decodeSAMLResponse('not-valid-base64!!!')).rejects.toThrow();
    });
  });

  describe('Request ID Validation', () => {
    it('should validate request ID from cache', () => {
      const requestId = '_test_request_789';
      const spEntityId = 'https://sp.example.com';
      
      _addRequestIdToCache(requestId, spEntityId);
      
      expect(validateRequestId(requestId, spEntityId)).toBe(true);
    });
    
    it('should reject request ID with wrong SP entity ID', () => {
      const requestId = '_test_request_abc';
      
      _addRequestIdToCache(requestId, 'https://sp1.example.com');
      
      expect(validateRequestId(requestId, 'https://sp2.example.com')).toBe(false);
    });
    
    it('should reject unknown request ID', () => {
      expect(validateRequestId('_unknown_request', 'https://sp.example.com')).toBe(false);
    });
    
    it('should consume request ID (single use)', () => {
      const requestId = '_single_use_request';
      const spEntityId = 'https://sp.example.com';
      
      _addRequestIdToCache(requestId, spEntityId);
      
      // First validation should succeed
      expect(validateRequestId(requestId, spEntityId)).toBe(true);
      
      // Second validation should fail (already consumed)
      expect(validateRequestId(requestId, spEntityId)).toBe(false);
    });
  });
});
