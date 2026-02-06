/**
 * Verifiable Credentials (VC) Service for Zalt.io
 * 
 * Implements W3C Verifiable Credentials Data Model 1.1:
 * - Issue VCs with customer DID
 * - Verify VC signatures
 * - Revocation registry
 * - Credential status management
 * 
 * Security considerations:
 * - Cryptographic signatures using issuer DID keys
 * - Revocation checking before verification
 * - Expiration validation
 * - Schema validation
 */

import crypto from 'crypto';
import { DynamoDBDocumentClient, GetCommand, PutCommand, DeleteCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from './dynamodb.service';
import { DIDService, isValidDID } from './did.service';

// ============================================================================
// VC Types and Interfaces
// ============================================================================

/**
 * Verifiable Credential structure (W3C VC Data Model 1.1)
 */
export interface VerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string | { id: string; name?: string };
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
  credentialSchema?: CredentialSchema | CredentialSchema[];
  proof?: Proof;
}

/**
 * Credential Subject - the entity the credential is about
 */
export interface CredentialSubject {
  id?: string;
  [key: string]: unknown;
}

/**
 * Credential Status for revocation checking
 */
export interface CredentialStatus {
  id: string;
  type: string;
  revocationListIndex?: string;
  revocationListCredential?: string;
}

/**
 * Credential Schema reference
 */
export interface CredentialSchema {
  id: string;
  type: string;
}

/**
 * Cryptographic Proof
 */
export interface Proof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  challenge?: string;
  domain?: string;
  nonce?: string;
}

/**
 * Verifiable Presentation structure
 */
export interface VerifiablePresentation {
  '@context': string[];
  id?: string;
  type: string[];
  holder?: string;
  verifiableCredential: VerifiableCredential[];
  proof?: Proof;
}

/**
 * VC Issuance Request
 */
export interface VCIssuanceRequest {
  issuerDid: string;
  issuerKeyId: string;
  subjectDid?: string;
  credentialType: string;
  claims: Record<string, unknown>;
  expirationDate?: string;
  schemaId?: string;
}

/**
 * VC Verification Result
 */
export interface VCVerificationResult {
  valid: boolean;
  checks: {
    signature: boolean;
    expiration: boolean;
    revocation: boolean;
    schema?: boolean;
  };
  errors: string[];
  warnings: string[];
}

/**
 * VC Record stored in database
 */
export interface VCRecord {
  vcId: string;
  issuerDid: string;
  subjectDid?: string;
  credentialType: string;
  credential: VerifiableCredential;
  status: 'active' | 'revoked' | 'expired';
  realmId: string;
  issuedAt: string;
  expiresAt?: string;
  revokedAt?: string;
  revocationReason?: string;
}

/**
 * Revocation Registry Entry
 */
export interface RevocationEntry {
  vcId: string;
  issuerDid: string;
  revokedAt: string;
  reason: string;
}

// ============================================================================
// VC Constants
// ============================================================================

/**
 * W3C VC Context URLs
 */
export const VC_CONTEXT = [
  'https://www.w3.org/2018/credentials/v1',
  'https://www.w3.org/2018/credentials/examples/v1'
];

/**
 * Supported credential types
 */
export const CREDENTIAL_TYPES = {
  IDENTITY: 'IdentityCredential',
  KYC: 'KYCCredential',
  EMPLOYMENT: 'EmploymentCredential',
  EDUCATION: 'EducationCredential',
  MEMBERSHIP: 'MembershipCredential',
  HEALTHCARE: 'HealthcareCredential',
  AGE_VERIFICATION: 'AgeVerificationCredential',
  ADDRESS: 'AddressCredential'
} as const;

/**
 * Proof types
 */
export const PROOF_TYPES = {
  ED25519: 'Ed25519Signature2020',
  SECP256K1: 'EcdsaSecp256k1Signature2019',
  JWS: 'JsonWebSignature2020'
} as const;

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate unique VC ID
 */
export function generateVCId(): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomBytes(8).toString('hex');
  return `vc:zalt:${timestamp}-${random}`;
}

/**
 * Validate VC structure
 */
export function isValidVC(vc: unknown): vc is VerifiableCredential {
  if (!vc || typeof vc !== 'object') return false;
  
  const credential = vc as Record<string, unknown>;
  
  // Required fields
  if (!credential['@context'] || !Array.isArray(credential['@context'])) return false;
  if (!credential.type || !Array.isArray(credential.type)) return false;
  if (!credential.issuer) return false;
  if (!credential.issuanceDate || typeof credential.issuanceDate !== 'string') return false;
  if (!credential.credentialSubject) return false;
  
  // Type must include VerifiableCredential
  if (!credential.type.includes('VerifiableCredential')) return false;
  
  return true;
}

/**
 * Get issuer DID from credential
 */
export function getIssuerDid(vc: VerifiableCredential): string {
  if (typeof vc.issuer === 'string') {
    return vc.issuer;
  }
  return vc.issuer.id;
}

/**
 * Check if credential is expired
 */
export function isCredentialExpired(vc: VerifiableCredential): boolean {
  if (!vc.expirationDate) return false;
  return new Date(vc.expirationDate) < new Date();
}

/**
 * Create canonical JSON for signing
 */
export function canonicalize(obj: unknown): string {
  // Simple JSON canonicalization (in production, use json-canonicalize library)
  return JSON.stringify(obj, Object.keys(obj as object).sort());
}


// ============================================================================
// VC Service Class
// ============================================================================

/**
 * Verifiable Credentials Service
 */
export class VCService {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;
  private revocationTableName: string;
  private didService: DIDService;

  constructor(
    docClient?: DynamoDBDocumentClient,
    tableName?: string,
    revocationTableName?: string,
    didService?: DIDService
  ) {
    this.docClient = docClient || dynamoDb;
    this.tableName = tableName || process.env.VC_TABLE || 'zalt-credentials';
    this.revocationTableName = revocationTableName || process.env.REVOCATION_TABLE || 'zalt-revocations';
    this.didService = didService || new DIDService();
  }

  /**
   * Issue a new Verifiable Credential
   */
  async issueCredential(request: VCIssuanceRequest, realmId: string): Promise<VerifiableCredential> {
    const {
      issuerDid,
      issuerKeyId,
      subjectDid,
      credentialType,
      claims,
      expirationDate,
      schemaId
    } = request;

    // Validate issuer DID
    if (!isValidDID(issuerDid)) {
      throw new Error('Invalid issuer DID');
    }

    // Get issuer DID record
    const issuerRecord = await this.didService.getDID(issuerDid);
    if (!issuerRecord) {
      throw new Error('Issuer DID not found');
    }

    if (issuerRecord.status !== 'active') {
      throw new Error('Issuer DID is not active');
    }

    // Generate VC ID
    const vcId = generateVCId();
    const issuanceDate = new Date().toISOString();

    // Build credential subject
    const credentialSubject: CredentialSubject = {
      ...claims
    };
    
    if (subjectDid) {
      credentialSubject.id = subjectDid;
    }

    // Build credential
    const credential: VerifiableCredential = {
      '@context': VC_CONTEXT,
      id: vcId,
      type: ['VerifiableCredential', credentialType],
      issuer: issuerDid,
      issuanceDate,
      credentialSubject
    };

    // Add expiration if provided
    if (expirationDate) {
      credential.expirationDate = expirationDate;
    }

    // Add schema if provided
    if (schemaId) {
      credential.credentialSchema = {
        id: schemaId,
        type: 'JsonSchemaValidator2018'
      };
    }

    // Add credential status for revocation
    credential.credentialStatus = {
      id: `${vcId}#status`,
      type: 'RevocationList2020Status',
      revocationListCredential: `https://api.zalt.io/v1/revocations/${realmId}`
    };

    // Sign the credential
    const proof = await this.createProof(credential, issuerDid, issuerKeyId);
    credential.proof = proof;

    // Store credential
    const record: VCRecord = {
      vcId,
      issuerDid,
      subjectDid,
      credentialType,
      credential,
      status: 'active',
      realmId,
      issuedAt: issuanceDate,
      expiresAt: expirationDate
    };

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        PK: `REALM#${realmId}`,
        SK: `VC#${vcId}`,
        GSI1PK: `VC#${vcId}`,
        GSI1SK: `REALM#${realmId}`,
        GSI2PK: `ISSUER#${issuerDid}`,
        GSI2SK: `VC#${vcId}`,
        GSI3PK: subjectDid ? `SUBJECT#${subjectDid}` : 'SUBJECT#none',
        GSI3SK: `VC#${vcId}`,
        ...record
      }
    }));

    return credential;
  }

  /**
   * Create cryptographic proof for credential
   */
  private async createProof(
    credential: Omit<VerifiableCredential, 'proof'>,
    issuerDid: string,
    keyId: string
  ): Promise<Proof> {
    const created = new Date().toISOString();
    
    // Create data to sign (credential without proof)
    const dataToSign = canonicalize(credential);
    
    // Sign with issuer's key
    const signature = await this.didService.signWithDID(issuerDid, keyId, dataToSign);

    return {
      type: PROOF_TYPES.ED25519,
      created,
      verificationMethod: `${issuerDid}#key-${keyId}`,
      proofPurpose: 'assertionMethod',
      proofValue: signature
    };
  }

  /**
   * Verify a Verifiable Credential
   */
  async verifyCredential(credential: VerifiableCredential): Promise<VCVerificationResult> {
    const result: VCVerificationResult = {
      valid: true,
      checks: {
        signature: false,
        expiration: false,
        revocation: false
      },
      errors: [],
      warnings: []
    };

    // Validate structure
    if (!isValidVC(credential)) {
      result.valid = false;
      result.errors.push('Invalid credential structure');
      return result;
    }

    // Check expiration
    if (credential.expirationDate) {
      const isExpired = isCredentialExpired(credential);
      result.checks.expiration = !isExpired;
      if (isExpired) {
        result.valid = false;
        result.errors.push('Credential has expired');
      }
    } else {
      result.checks.expiration = true;
      result.warnings.push('Credential has no expiration date');
    }

    // Check revocation
    const isRevoked = await this.isCredentialRevoked(credential.id);
    result.checks.revocation = !isRevoked;
    if (isRevoked) {
      result.valid = false;
      result.errors.push('Credential has been revoked');
    }

    // Verify signature
    if (credential.proof) {
      try {
        const issuerDid = getIssuerDid(credential);
        
        // Extract key ID from verification method
        const keyIdMatch = credential.proof.verificationMethod.match(/#key-(.+)$/);
        const keyId = keyIdMatch ? keyIdMatch[1] : '';

        // Create data that was signed
        const { proof, ...credentialWithoutProof } = credential;
        const dataToVerify = canonicalize(credentialWithoutProof);

        // Verify signature
        const isValidSignature = await this.didService.verifyWithDID(
          issuerDid,
          keyId,
          dataToVerify,
          proof.proofValue
        );

        result.checks.signature = isValidSignature;
        if (!isValidSignature) {
          result.valid = false;
          result.errors.push('Invalid signature');
        }
      } catch (error) {
        result.valid = false;
        result.checks.signature = false;
        result.errors.push(`Signature verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    } else {
      result.valid = false;
      result.checks.signature = false;
      result.errors.push('Credential has no proof');
    }

    return result;
  }


  /**
   * Revoke a credential
   */
  async revokeCredential(vcId: string, reason: string, realmId: string): Promise<void> {
    // Get credential record
    const record = await this.getCredential(vcId);
    if (!record) {
      throw new Error('Credential not found');
    }

    if (record.status === 'revoked') {
      throw new Error('Credential already revoked');
    }

    const revokedAt = new Date().toISOString();

    // Update credential status
    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        PK: `REALM#${realmId}`,
        SK: `VC#${vcId}`,
        GSI1PK: `VC#${vcId}`,
        GSI1SK: `REALM#${realmId}`,
        GSI2PK: `ISSUER#${record.issuerDid}`,
        GSI2SK: `VC#${vcId}`,
        GSI3PK: record.subjectDid ? `SUBJECT#${record.subjectDid}` : 'SUBJECT#none',
        GSI3SK: `VC#${vcId}`,
        ...record,
        status: 'revoked',
        revokedAt,
        revocationReason: reason
      }
    }));

    // Add to revocation registry
    await this.docClient.send(new PutCommand({
      TableName: this.revocationTableName,
      Item: {
        PK: `VC#${vcId}`,
        SK: `REVOCATION`,
        vcId,
        issuerDid: record.issuerDid,
        revokedAt,
        reason,
        ttl: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60) // Keep for 1 year
      }
    }));
  }

  /**
   * Check if credential is revoked
   */
  async isCredentialRevoked(vcId: string): Promise<boolean> {
    const result = await this.docClient.send(new GetCommand({
      TableName: this.revocationTableName,
      Key: {
        PK: `VC#${vcId}`,
        SK: 'REVOCATION'
      }
    }));

    return !!result.Item;
  }

  /**
   * Get credential by ID
   */
  async getCredential(vcId: string): Promise<VCRecord | null> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI1',
      KeyConditionExpression: 'GSI1PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `VC#${vcId}`
      }
    }));

    if (!result.Items || result.Items.length === 0) {
      return null;
    }

    return result.Items[0] as VCRecord;
  }

  /**
   * Get all credentials issued by a DID
   */
  async getCredentialsByIssuer(issuerDid: string): Promise<VCRecord[]> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI2',
      KeyConditionExpression: 'GSI2PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `ISSUER#${issuerDid}`
      }
    }));

    return (result.Items || []) as VCRecord[];
  }

  /**
   * Get all credentials for a subject
   */
  async getCredentialsBySubject(subjectDid: string): Promise<VCRecord[]> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI3',
      KeyConditionExpression: 'GSI3PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `SUBJECT#${subjectDid}`
      }
    }));

    return (result.Items || []) as VCRecord[];
  }

  /**
   * Get all credentials in a realm
   */
  async getRealmCredentials(realmId: string): Promise<VCRecord[]> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `REALM#${realmId}`,
        ':sk': 'VC#'
      }
    }));

    return (result.Items || []) as VCRecord[];
  }

  /**
   * Delete a credential (permanent)
   */
  async deleteCredential(vcId: string, realmId: string): Promise<void> {
    await this.docClient.send(new DeleteCommand({
      TableName: this.tableName,
      Key: {
        PK: `REALM#${realmId}`,
        SK: `VC#${vcId}`
      }
    }));
  }

  /**
   * Create a Verifiable Presentation
   */
  async createPresentation(
    credentials: VerifiableCredential[],
    holderDid: string,
    holderKeyId: string,
    options?: {
      challenge?: string;
      domain?: string;
    }
  ): Promise<VerifiablePresentation> {
    const presentation: VerifiablePresentation = {
      '@context': VC_CONTEXT,
      id: `vp:zalt:${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`,
      type: ['VerifiablePresentation'],
      holder: holderDid,
      verifiableCredential: credentials
    };

    // Create proof
    const created = new Date().toISOString();
    const dataToSign = canonicalize({ ...presentation, proof: undefined });
    const signature = await this.didService.signWithDID(holderDid, holderKeyId, dataToSign);

    presentation.proof = {
      type: PROOF_TYPES.ED25519,
      created,
      verificationMethod: `${holderDid}#key-${holderKeyId}`,
      proofPurpose: 'authentication',
      proofValue: signature,
      challenge: options?.challenge,
      domain: options?.domain
    };

    return presentation;
  }

  /**
   * Verify a Verifiable Presentation
   */
  async verifyPresentation(
    presentation: VerifiablePresentation,
    options?: {
      challenge?: string;
      domain?: string;
    }
  ): Promise<VCVerificationResult> {
    const result: VCVerificationResult = {
      valid: true,
      checks: {
        signature: false,
        expiration: true,
        revocation: true
      },
      errors: [],
      warnings: []
    };

    // Validate structure
    if (!presentation['@context'] || !presentation.type?.includes('VerifiablePresentation')) {
      result.valid = false;
      result.errors.push('Invalid presentation structure');
      return result;
    }

    // Verify challenge if required
    if (options?.challenge && presentation.proof?.challenge !== options.challenge) {
      result.valid = false;
      result.errors.push('Challenge mismatch');
    }

    // Verify domain if required
    if (options?.domain && presentation.proof?.domain !== options.domain) {
      result.valid = false;
      result.errors.push('Domain mismatch');
    }

    // Verify presentation signature
    if (presentation.proof && presentation.holder) {
      try {
        const keyIdMatch = presentation.proof.verificationMethod.match(/#key-(.+)$/);
        const keyId = keyIdMatch ? keyIdMatch[1] : '';

        const { proof, ...presentationWithoutProof } = presentation;
        const dataToVerify = canonicalize(presentationWithoutProof);

        const isValidSignature = await this.didService.verifyWithDID(
          presentation.holder,
          keyId,
          dataToVerify,
          proof.proofValue
        );

        result.checks.signature = isValidSignature;
        if (!isValidSignature) {
          result.valid = false;
          result.errors.push('Invalid presentation signature');
        }
      } catch (error) {
        result.valid = false;
        result.checks.signature = false;
        result.errors.push(`Presentation signature verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }

    // Verify each credential
    for (const credential of presentation.verifiableCredential) {
      const credResult = await this.verifyCredential(credential);
      if (!credResult.valid) {
        result.valid = false;
        result.errors.push(...credResult.errors.map(e => `Credential ${credential.id}: ${e}`));
      }
      result.warnings.push(...credResult.warnings.map(w => `Credential ${credential.id}: ${w}`));
    }

    return result;
  }

  /**
   * Get supported credential types
   */
  getSupportedTypes(): string[] {
    return Object.values(CREDENTIAL_TYPES);
  }
}

// ============================================================================
// VC Templates - Pre-defined credential schemas
// ============================================================================

/**
 * KYC Credential Claims
 */
export interface KYCCredentialClaims {
  // Personal Information
  fullName: string;
  dateOfBirth: string; // ISO 8601 date
  nationality: string; // ISO 3166-1 alpha-2
  
  // Document Information
  documentType: 'passport' | 'national_id' | 'drivers_license';
  documentNumber: string;
  documentExpiry: string; // ISO 8601 date
  documentCountry: string; // ISO 3166-1 alpha-2
  
  // Verification Details
  verificationLevel: 'basic' | 'standard' | 'enhanced';
  verificationDate: string; // ISO 8601 datetime
  verificationMethod: 'document' | 'biometric' | 'video' | 'in_person';
  
  // Risk Assessment
  riskScore?: number; // 0-100
  amlCheck?: boolean;
  pep?: boolean; // Politically Exposed Person
  sanctionsCheck?: boolean;
  
  // Address (optional)
  address?: {
    street: string;
    city: string;
    state?: string;
    postalCode: string;
    country: string; // ISO 3166-1 alpha-2
  };
}

/**
 * Employment Credential Claims
 */
export interface EmploymentCredentialClaims {
  // Employee Information
  employeeName: string;
  employeeId?: string;
  
  // Employer Information
  employerName: string;
  employerDid?: string;
  employerAddress?: string;
  employerCountry: string; // ISO 3166-1 alpha-2
  
  // Position Details
  jobTitle: string;
  department?: string;
  employmentType: 'full_time' | 'part_time' | 'contract' | 'intern' | 'freelance';
  startDate: string; // ISO 8601 date
  endDate?: string; // ISO 8601 date (null if current)
  
  // Compensation (optional, privacy-sensitive)
  salaryRange?: string; // e.g., "50000-75000 USD"
  currency?: string; // ISO 4217
  
  // Verification
  verifiedBy: string; // HR representative name or ID
  verificationDate: string; // ISO 8601 datetime
  
  // Additional
  responsibilities?: string[];
  skills?: string[];
}

/**
 * Education Credential Claims
 */
export interface EducationCredentialClaims {
  // Student Information
  studentName: string;
  studentId?: string;
  dateOfBirth?: string; // ISO 8601 date
  
  // Institution Information
  institutionName: string;
  institutionDid?: string;
  institutionCountry: string; // ISO 3166-1 alpha-2
  institutionType: 'university' | 'college' | 'high_school' | 'vocational' | 'online' | 'certification_body';
  
  // Degree/Certificate Details
  credentialType: 'degree' | 'diploma' | 'certificate' | 'course_completion' | 'professional_certification';
  credentialName: string; // e.g., "Bachelor of Science in Computer Science"
  fieldOfStudy: string;
  level?: 'associate' | 'bachelor' | 'master' | 'doctorate' | 'professional' | 'certificate';
  
  // Dates
  enrollmentDate?: string; // ISO 8601 date
  graduationDate?: string; // ISO 8601 date
  issueDate: string; // ISO 8601 date
  expiryDate?: string; // For certifications that expire
  
  // Academic Performance (optional)
  gpa?: number;
  gpaScale?: number; // e.g., 4.0
  honors?: string; // e.g., "Cum Laude", "Magna Cum Laude"
  
  // Verification
  registrarName?: string;
  verificationDate: string; // ISO 8601 datetime
  
  // Additional
  courses?: string[];
  achievements?: string[];
}

/**
 * Healthcare Credential Claims (HIPAA-compliant)
 */
export interface HealthcareCredentialClaims {
  // Provider Information
  providerName: string;
  providerId: string; // NPI or equivalent
  providerType: 'physician' | 'nurse' | 'therapist' | 'pharmacist' | 'technician' | 'administrator';
  
  // License Information
  licenseNumber: string;
  licenseState: string;
  licenseCountry: string;
  licenseType: string;
  licenseIssueDate: string;
  licenseExpiryDate: string;
  
  // Specializations
  specializations?: string[];
  boardCertifications?: string[];
  
  // Facility (optional)
  facilityName?: string;
  facilityId?: string;
  
  // Verification
  verificationDate: string;
  verifiedBy: string;
}

/**
 * VC Template Definition
 */
export interface VCTemplate {
  id: string;
  name: string;
  description: string;
  credentialType: string;
  schemaUrl: string;
  requiredFields: string[];
  optionalFields: string[];
  defaultExpiry?: string; // ISO 8601 duration (e.g., "P1Y" for 1 year)
  context: string[];
}

/**
 * Pre-defined VC Templates
 */
export const VC_TEMPLATES: Record<string, VCTemplate> = {
  KYC: {
    id: 'template:zalt:kyc:v1',
    name: 'KYC Credential',
    description: 'Know Your Customer verification credential for identity verification',
    credentialType: CREDENTIAL_TYPES.KYC,
    schemaUrl: 'https://schema.zalt.io/credentials/kyc/v1',
    requiredFields: [
      'fullName',
      'dateOfBirth',
      'nationality',
      'documentType',
      'documentNumber',
      'documentExpiry',
      'documentCountry',
      'verificationLevel',
      'verificationDate',
      'verificationMethod'
    ],
    optionalFields: [
      'riskScore',
      'amlCheck',
      'pep',
      'sanctionsCheck',
      'address'
    ],
    defaultExpiry: 'P1Y', // 1 year
    context: [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.zalt.io/credentials/kyc/v1'
    ]
  },
  
  EMPLOYMENT: {
    id: 'template:zalt:employment:v1',
    name: 'Employment Credential',
    description: 'Employment verification credential for proof of employment',
    credentialType: CREDENTIAL_TYPES.EMPLOYMENT,
    schemaUrl: 'https://schema.zalt.io/credentials/employment/v1',
    requiredFields: [
      'employeeName',
      'employerName',
      'employerCountry',
      'jobTitle',
      'employmentType',
      'startDate',
      'verifiedBy',
      'verificationDate'
    ],
    optionalFields: [
      'employeeId',
      'employerDid',
      'employerAddress',
      'department',
      'endDate',
      'salaryRange',
      'currency',
      'responsibilities',
      'skills'
    ],
    defaultExpiry: 'P2Y', // 2 years
    context: [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.zalt.io/credentials/employment/v1'
    ]
  },
  
  EDUCATION: {
    id: 'template:zalt:education:v1',
    name: 'Education Credential',
    description: 'Educational achievement credential for degrees, diplomas, and certifications',
    credentialType: CREDENTIAL_TYPES.EDUCATION,
    schemaUrl: 'https://schema.zalt.io/credentials/education/v1',
    requiredFields: [
      'studentName',
      'institutionName',
      'institutionCountry',
      'institutionType',
      'credentialType',
      'credentialName',
      'fieldOfStudy',
      'issueDate',
      'verificationDate'
    ],
    optionalFields: [
      'studentId',
      'dateOfBirth',
      'institutionDid',
      'level',
      'enrollmentDate',
      'graduationDate',
      'expiryDate',
      'gpa',
      'gpaScale',
      'honors',
      'registrarName',
      'courses',
      'achievements'
    ],
    context: [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.zalt.io/credentials/education/v1'
    ]
  },
  
  HEALTHCARE: {
    id: 'template:zalt:healthcare:v1',
    name: 'Healthcare Provider Credential',
    description: 'Healthcare provider license and certification credential (HIPAA-compliant)',
    credentialType: CREDENTIAL_TYPES.HEALTHCARE,
    schemaUrl: 'https://schema.zalt.io/credentials/healthcare/v1',
    requiredFields: [
      'providerName',
      'providerId',
      'providerType',
      'licenseNumber',
      'licenseState',
      'licenseCountry',
      'licenseType',
      'licenseIssueDate',
      'licenseExpiryDate',
      'verificationDate',
      'verifiedBy'
    ],
    optionalFields: [
      'specializations',
      'boardCertifications',
      'facilityName',
      'facilityId'
    ],
    defaultExpiry: 'P1Y', // 1 year (licenses typically need annual renewal)
    context: [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.zalt.io/credentials/healthcare/v1'
    ]
  }
};

/**
 * Template validation result
 */
export interface TemplateValidationResult {
  valid: boolean;
  missingRequired: string[];
  invalidFields: string[];
  warnings: string[];
}

/**
 * Validate claims against a template
 */
export function validateClaimsAgainstTemplate(
  templateId: string,
  claims: Record<string, unknown>
): TemplateValidationResult {
  const result: TemplateValidationResult = {
    valid: true,
    missingRequired: [],
    invalidFields: [],
    warnings: []
  };

  const template = VC_TEMPLATES[templateId];
  if (!template) {
    result.valid = false;
    result.invalidFields.push(`Unknown template: ${templateId}`);
    return result;
  }

  // Check required fields
  for (const field of template.requiredFields) {
    if (claims[field] === undefined || claims[field] === null || claims[field] === '') {
      result.missingRequired.push(field);
      result.valid = false;
    }
  }

  // Check for unknown fields
  const allKnownFields = [...template.requiredFields, ...template.optionalFields];
  for (const field of Object.keys(claims)) {
    if (!allKnownFields.includes(field)) {
      result.warnings.push(`Unknown field: ${field}`);
    }
  }

  return result;
}

/**
 * Get expiry date from template default
 */
export function getExpiryFromTemplate(templateId: string): string | undefined {
  const template = VC_TEMPLATES[templateId];
  if (!template?.defaultExpiry) return undefined;

  // Parse ISO 8601 duration and add to current date
  const duration = template.defaultExpiry;
  const now = new Date();

  // Simple duration parser for P{n}Y, P{n}M, P{n}D formats
  const yearMatch = duration.match(/P(\d+)Y/);
  const monthMatch = duration.match(/P(\d+)M/);
  const dayMatch = duration.match(/P(\d+)D/);

  if (yearMatch) {
    now.setFullYear(now.getFullYear() + parseInt(yearMatch[1]));
  }
  if (monthMatch) {
    now.setMonth(now.getMonth() + parseInt(monthMatch[1]));
  }
  if (dayMatch) {
    now.setDate(now.getDate() + parseInt(dayMatch[1]));
  }

  return now.toISOString();
}

/**
 * VC Template Service - extends VCService with template support
 */
export class VCTemplateService extends VCService {
  /**
   * Issue credential from template
   */
  async issueFromTemplate(
    templateId: string,
    issuerDid: string,
    issuerKeyId: string,
    subjectDid: string | undefined,
    claims: Record<string, unknown>,
    realmId: string,
    options?: {
      expirationDate?: string;
      skipValidation?: boolean;
    }
  ): Promise<VerifiableCredential> {
    const template = VC_TEMPLATES[templateId];
    if (!template) {
      throw new Error(`Unknown template: ${templateId}`);
    }

    // Validate claims unless skipped
    if (!options?.skipValidation) {
      const validation = validateClaimsAgainstTemplate(templateId, claims);
      if (!validation.valid) {
        throw new Error(`Template validation failed: Missing required fields: ${validation.missingRequired.join(', ')}`);
      }
    }

    // Determine expiration
    const expirationDate = options?.expirationDate || getExpiryFromTemplate(templateId);

    // Issue credential
    return this.issueCredential({
      issuerDid,
      issuerKeyId,
      subjectDid,
      credentialType: template.credentialType,
      claims,
      expirationDate,
      schemaId: template.schemaUrl
    }, realmId);
  }

  /**
   * Issue KYC credential
   */
  async issueKYCCredential(
    issuerDid: string,
    issuerKeyId: string,
    subjectDid: string,
    claims: KYCCredentialClaims,
    realmId: string
  ): Promise<VerifiableCredential> {
    return this.issueFromTemplate('KYC', issuerDid, issuerKeyId, subjectDid, claims as unknown as Record<string, unknown>, realmId);
  }

  /**
   * Issue Employment credential
   */
  async issueEmploymentCredential(
    issuerDid: string,
    issuerKeyId: string,
    subjectDid: string,
    claims: EmploymentCredentialClaims,
    realmId: string
  ): Promise<VerifiableCredential> {
    return this.issueFromTemplate('EMPLOYMENT', issuerDid, issuerKeyId, subjectDid, claims as unknown as Record<string, unknown>, realmId);
  }

  /**
   * Issue Education credential
   */
  async issueEducationCredential(
    issuerDid: string,
    issuerKeyId: string,
    subjectDid: string,
    claims: EducationCredentialClaims,
    realmId: string
  ): Promise<VerifiableCredential> {
    return this.issueFromTemplate('EDUCATION', issuerDid, issuerKeyId, subjectDid, claims as unknown as Record<string, unknown>, realmId);
  }

  /**
   * Issue Healthcare credential (HIPAA-compliant)
   */
  async issueHealthcareCredential(
    issuerDid: string,
    issuerKeyId: string,
    subjectDid: string,
    claims: HealthcareCredentialClaims,
    realmId: string
  ): Promise<VerifiableCredential> {
    return this.issueFromTemplate('HEALTHCARE', issuerDid, issuerKeyId, subjectDid, claims as unknown as Record<string, unknown>, realmId);
  }

  /**
   * Get all available templates
   */
  getTemplates(): VCTemplate[] {
    return Object.values(VC_TEMPLATES);
  }

  /**
   * Get template by ID
   */
  getTemplate(templateId: string): VCTemplate | undefined {
    return VC_TEMPLATES[templateId];
  }

  /**
   * Validate claims for a template
   */
  validateClaims(templateId: string, claims: Record<string, unknown>): TemplateValidationResult {
    return validateClaimsAgainstTemplate(templateId, claims);
  }
}

// Export template service singleton
export const vcTemplateService = new VCTemplateService();

// Export singleton instance
export const vcService = new VCService();
