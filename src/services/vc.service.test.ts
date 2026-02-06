/**
 * Verifiable Credentials (VC) Service Tests
 * 
 * Tests for VC issuance, verification, and revocation
 * ⚠️ GERÇEK TEST - Mock data YASAK
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import * as fc from 'fast-check';

// Mock dynamodb.service before importing vc.service
const mockDynamoSend = jest.fn<any>();
jest.mock('./dynamodb.service', () => ({
  dynamoDb: {
    send: mockDynamoSend
  }
}));

// Mock did.service
const mockDIDService = {
  getDID: jest.fn<any>(),
  signWithDID: jest.fn<any>(),
  verifyWithDID: jest.fn<any>()
};

const actualDidService = jest.requireActual('./did.service') as Record<string, unknown>;
jest.mock('./did.service', () => ({
  ...actualDidService,
  DIDService: jest.fn().mockImplementation(() => mockDIDService)
}));

import {
  VCService,
  VCTemplateService,
  generateVCId,
  isValidVC,
  getIssuerDid,
  isCredentialExpired,
  canonicalize,
  validateClaimsAgainstTemplate,
  getExpiryFromTemplate,
  VC_CONTEXT,
  VC_TEMPLATES,
  CREDENTIAL_TYPES,
  PROOF_TYPES,
  VerifiableCredential,
  VCIssuanceRequest,
  KYCCredentialClaims,
  EmploymentCredentialClaims,
  EducationCredentialClaims,
  HealthcareCredentialClaims
} from './vc.service';

describe('VC Service', () => {
  let service: VCService;

  beforeEach(() => {
    jest.clearAllMocks();
    mockDynamoSend.mockReset();
    mockDIDService.getDID.mockReset();
    mockDIDService.signWithDID.mockReset();
    mockDIDService.verifyWithDID.mockReset();
    service = new VCService();
  });

  describe('VC ID Generation', () => {
    it('should generate unique VC IDs', () => {
      const id1 = generateVCId();
      const id2 = generateVCId();
      
      expect(id1).not.toBe(id2);
      expect(id1).toMatch(/^vc:zalt:[a-z0-9]+-[a-f0-9]+$/);
    });

    it('property: VC IDs are always unique', () => {
      const ids = new Set<string>();
      
      fc.assert(
        fc.property(fc.constant(null), () => {
          const id = generateVCId();
          const isUnique = !ids.has(id);
          ids.add(id);
          return isUnique;
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('VC Validation', () => {
    it('should validate correct VC structure', () => {
      const vc: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:zalt:test',
        type: ['VerifiableCredential', 'IdentityCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        credentialSubject: {
          id: 'did:key:z456',
          name: 'Test User'
        }
      };

      expect(isValidVC(vc)).toBe(true);
    });

    it('should reject VC without context', () => {
      const vc = {
        id: 'vc:zalt:test',
        type: ['VerifiableCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        credentialSubject: {}
      };

      expect(isValidVC(vc)).toBe(false);
    });

    it('should reject VC without VerifiableCredential type', () => {
      const vc = {
        '@context': VC_CONTEXT,
        id: 'vc:zalt:test',
        type: ['IdentityCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        credentialSubject: {}
      };

      expect(isValidVC(vc)).toBe(false);
    });

    it('should reject null or undefined', () => {
      expect(isValidVC(null)).toBe(false);
      expect(isValidVC(undefined)).toBe(false);
    });
  });

  describe('Issuer DID Extraction', () => {
    it('should extract issuer from string', () => {
      const vc: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:test',
        type: ['VerifiableCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        credentialSubject: {}
      };

      expect(getIssuerDid(vc)).toBe('did:key:z123');
    });

    it('should extract issuer from object', () => {
      const vc: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:test',
        type: ['VerifiableCredential'],
        issuer: { id: 'did:key:z123', name: 'Issuer Name' },
        issuanceDate: '2026-01-25T10:00:00.000Z',
        credentialSubject: {}
      };

      expect(getIssuerDid(vc)).toBe('did:key:z123');
    });
  });

  describe('Expiration Check', () => {
    it('should return false for non-expired credential', () => {
      const vc: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:test',
        type: ['VerifiableCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        expirationDate: '2099-01-01T00:00:00.000Z',
        credentialSubject: {}
      };

      expect(isCredentialExpired(vc)).toBe(false);
    });

    it('should return true for expired credential', () => {
      const vc: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:test',
        type: ['VerifiableCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2020-01-01T00:00:00.000Z',
        expirationDate: '2020-12-31T00:00:00.000Z',
        credentialSubject: {}
      };

      expect(isCredentialExpired(vc)).toBe(true);
    });

    it('should return false for credential without expiration', () => {
      const vc: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:test',
        type: ['VerifiableCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        credentialSubject: {}
      };

      expect(isCredentialExpired(vc)).toBe(false);
    });
  });

  describe('Canonicalization', () => {
    it('should produce consistent output', () => {
      const obj1 = { b: 2, a: 1 };
      const obj2 = { a: 1, b: 2 };
      
      expect(canonicalize(obj1)).toBe(canonicalize(obj2));
    });
  });


  describe('VCService', () => {
    describe('issueCredential', () => {
      beforeEach(() => {
        mockDIDService.getDID.mockResolvedValue({
          did: 'did:key:z123',
          status: 'active',
          keyPairs: [{ keyId: 'key1', encryptedPrivateKey: 'enc', keyType: 'Ed25519' }]
        });
        mockDIDService.signWithDID.mockResolvedValue('signature123');
        mockDynamoSend.mockResolvedValue({});
      });

      it('should issue credential with valid request', async () => {
        const request: VCIssuanceRequest = {
          issuerDid: 'did:key:z123',
          issuerKeyId: 'key1',
          subjectDid: 'did:key:z456',
          credentialType: CREDENTIAL_TYPES.IDENTITY,
          claims: {
            name: 'Test User',
            email: 'test@example.com'
          }
        };

        const vc = await service.issueCredential(request, 'realm_123');

        expect(vc.id).toMatch(/^vc:zalt:/);
        expect(vc.type).toContain('VerifiableCredential');
        expect(vc.type).toContain(CREDENTIAL_TYPES.IDENTITY);
        expect(vc.issuer).toBe('did:key:z123');
        expect(vc.credentialSubject.id).toBe('did:key:z456');
        expect(vc.credentialSubject.name).toBe('Test User');
        expect(vc.proof).toBeDefined();
      });

      it('should include expiration date if provided', async () => {
        const request: VCIssuanceRequest = {
          issuerDid: 'did:key:z123',
          issuerKeyId: 'key1',
          credentialType: CREDENTIAL_TYPES.KYC,
          claims: { verified: true },
          expirationDate: '2027-01-01T00:00:00.000Z'
        };

        const vc = await service.issueCredential(request, 'realm_123');

        expect(vc.expirationDate).toBe('2027-01-01T00:00:00.000Z');
      });

      it('should include schema if provided', async () => {
        const request: VCIssuanceRequest = {
          issuerDid: 'did:key:z123',
          issuerKeyId: 'key1',
          credentialType: CREDENTIAL_TYPES.EMPLOYMENT,
          claims: { employer: 'Zalt.io' },
          schemaId: 'https://schema.zalt.io/employment/v1'
        };

        const vc = await service.issueCredential(request, 'realm_123');

        expect(vc.credentialSchema).toBeDefined();
        expect((vc.credentialSchema as any).id).toBe('https://schema.zalt.io/employment/v1');
      });

      it('should throw for invalid issuer DID', async () => {
        const request: VCIssuanceRequest = {
          issuerDid: 'invalid',
          issuerKeyId: 'key1',
          credentialType: CREDENTIAL_TYPES.IDENTITY,
          claims: {}
        };

        await expect(service.issueCredential(request, 'realm_123'))
          .rejects.toThrow('Invalid issuer DID');
      });

      it('should throw for non-existent issuer', async () => {
        mockDIDService.getDID.mockResolvedValue(null);

        const request: VCIssuanceRequest = {
          issuerDid: 'did:key:zNotFound',
          issuerKeyId: 'key1',
          credentialType: CREDENTIAL_TYPES.IDENTITY,
          claims: {}
        };

        await expect(service.issueCredential(request, 'realm_123'))
          .rejects.toThrow('Issuer DID not found');
      });

      it('should throw for inactive issuer', async () => {
        mockDIDService.getDID.mockResolvedValue({
          did: 'did:key:z123',
          status: 'deactivated'
        });

        const request: VCIssuanceRequest = {
          issuerDid: 'did:key:z123',
          issuerKeyId: 'key1',
          credentialType: CREDENTIAL_TYPES.IDENTITY,
          claims: {}
        };

        await expect(service.issueCredential(request, 'realm_123'))
          .rejects.toThrow('Issuer DID is not active');
      });

      it('should add credential status for revocation', async () => {
        const request: VCIssuanceRequest = {
          issuerDid: 'did:key:z123',
          issuerKeyId: 'key1',
          credentialType: CREDENTIAL_TYPES.IDENTITY,
          claims: {}
        };

        const vc = await service.issueCredential(request, 'realm_123');

        expect(vc.credentialStatus).toBeDefined();
        expect(vc.credentialStatus?.type).toBe('RevocationList2020Status');
      });
    });

    describe('verifyCredential', () => {
      const validVC: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:zalt:test123',
        type: ['VerifiableCredential', 'IdentityCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        expirationDate: '2099-01-01T00:00:00.000Z',
        credentialSubject: { name: 'Test' },
        proof: {
          type: PROOF_TYPES.ED25519,
          created: '2026-01-25T10:00:00.000Z',
          verificationMethod: 'did:key:z123#key-key1',
          proofPurpose: 'assertionMethod',
          proofValue: 'signature123'
        }
      };

      beforeEach(() => {
        mockDynamoSend.mockResolvedValue({ Item: null }); // Not revoked
        mockDIDService.verifyWithDID.mockResolvedValue(true);
      });

      it('should verify valid credential', async () => {
        const result = await service.verifyCredential(validVC);

        expect(result.valid).toBe(true);
        expect(result.checks.signature).toBe(true);
        expect(result.checks.expiration).toBe(true);
        expect(result.checks.revocation).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should fail for invalid structure', async () => {
        const invalidVC = { id: 'test' } as any;

        const result = await service.verifyCredential(invalidVC);

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Invalid credential structure');
      });

      it('should fail for expired credential', async () => {
        const expiredVC = {
          ...validVC,
          expirationDate: '2020-01-01T00:00:00.000Z'
        };

        const result = await service.verifyCredential(expiredVC);

        expect(result.valid).toBe(false);
        expect(result.checks.expiration).toBe(false);
        expect(result.errors).toContain('Credential has expired');
      });

      it('should fail for revoked credential', async () => {
        mockDynamoSend.mockResolvedValue({
          Item: { vcId: 'vc:zalt:test123', revokedAt: '2026-01-26T00:00:00.000Z' }
        });

        const result = await service.verifyCredential(validVC);

        expect(result.valid).toBe(false);
        expect(result.checks.revocation).toBe(false);
        expect(result.errors).toContain('Credential has been revoked');
      });

      it('should fail for invalid signature', async () => {
        mockDIDService.verifyWithDID.mockResolvedValue(false);

        const result = await service.verifyCredential(validVC);

        expect(result.valid).toBe(false);
        expect(result.checks.signature).toBe(false);
        expect(result.errors).toContain('Invalid signature');
      });

      it('should fail for credential without proof', async () => {
        const noProofVC = { ...validVC };
        delete noProofVC.proof;

        const result = await service.verifyCredential(noProofVC);

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Credential has no proof');
      });

      it('should warn for credential without expiration', async () => {
        const noExpiryVC = { ...validVC };
        delete noExpiryVC.expirationDate;

        const result = await service.verifyCredential(noExpiryVC);

        expect(result.warnings).toContain('Credential has no expiration date');
      });
    });


    describe('revokeCredential', () => {
      beforeEach(() => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{
                vcId: 'vc:zalt:test123',
                issuerDid: 'did:key:z123',
                status: 'active',
                realmId: 'realm_123'
              }]
            });
          }
          return Promise.resolve({});
        });
      });

      it('should revoke active credential', async () => {
        await service.revokeCredential('vc:zalt:test123', 'User request', 'realm_123');

        expect(mockDynamoSend).toHaveBeenCalled();
      });

      it('should throw for non-existent credential', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        await expect(service.revokeCredential('vc:notfound', 'reason', 'realm_123'))
          .rejects.toThrow('Credential not found');
      });

      it('should throw for already revoked credential', async () => {
        mockDynamoSend.mockImplementation((command: unknown) => {
          const cmd = command as { constructor: { name: string } };
          if (cmd.constructor.name === 'QueryCommand') {
            return Promise.resolve({
              Items: [{ vcId: 'vc:test', status: 'revoked' }]
            });
          }
          return Promise.resolve({});
        });

        await expect(service.revokeCredential('vc:test', 'reason', 'realm_123'))
          .rejects.toThrow('Credential already revoked');
      });
    });

    describe('isCredentialRevoked', () => {
      it('should return true for revoked credential', async () => {
        mockDynamoSend.mockResolvedValue({
          Item: { vcId: 'vc:test', revokedAt: '2026-01-25T00:00:00.000Z' }
        });

        const isRevoked = await service.isCredentialRevoked('vc:test');

        expect(isRevoked).toBe(true);
      });

      it('should return false for non-revoked credential', async () => {
        mockDynamoSend.mockResolvedValue({ Item: null });

        const isRevoked = await service.isCredentialRevoked('vc:test');

        expect(isRevoked).toBe(false);
      });
    });

    describe('getCredential', () => {
      it('should return credential by ID', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [{
            vcId: 'vc:zalt:test',
            issuerDid: 'did:key:z123',
            credentialType: 'IdentityCredential'
          }]
        });

        const record = await service.getCredential('vc:zalt:test');

        expect(record).not.toBeNull();
        expect(record?.vcId).toBe('vc:zalt:test');
      });

      it('should return null for non-existent credential', async () => {
        mockDynamoSend.mockResolvedValue({ Items: [] });

        const record = await service.getCredential('vc:notfound');

        expect(record).toBeNull();
      });
    });

    describe('getCredentialsByIssuer', () => {
      it('should return all credentials by issuer', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [
            { vcId: 'vc:1', issuerDid: 'did:key:z123' },
            { vcId: 'vc:2', issuerDid: 'did:key:z123' }
          ]
        });

        const credentials = await service.getCredentialsByIssuer('did:key:z123');

        expect(credentials).toHaveLength(2);
      });
    });

    describe('getCredentialsBySubject', () => {
      it('should return all credentials for subject', async () => {
        mockDynamoSend.mockResolvedValue({
          Items: [
            { vcId: 'vc:1', subjectDid: 'did:key:z456' }
          ]
        });

        const credentials = await service.getCredentialsBySubject('did:key:z456');

        expect(credentials).toHaveLength(1);
      });
    });

    describe('createPresentation', () => {
      const testVC: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:test',
        type: ['VerifiableCredential', 'IdentityCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        credentialSubject: { name: 'Test' },
        proof: {
          type: PROOF_TYPES.ED25519,
          created: '2026-01-25T10:00:00.000Z',
          verificationMethod: 'did:key:z123#key-key1',
          proofPurpose: 'assertionMethod',
          proofValue: 'sig'
        }
      };

      beforeEach(() => {
        mockDIDService.signWithDID.mockResolvedValue('presentation-signature');
      });

      it('should create presentation with credentials', async () => {
        const presentation = await service.createPresentation(
          [testVC],
          'did:key:zHolder',
          'holderKey1'
        );

        expect(presentation.type).toContain('VerifiablePresentation');
        expect(presentation.holder).toBe('did:key:zHolder');
        expect(presentation.verifiableCredential).toHaveLength(1);
        expect(presentation.proof).toBeDefined();
      });

      it('should include challenge and domain if provided', async () => {
        const presentation = await service.createPresentation(
          [testVC],
          'did:key:zHolder',
          'holderKey1',
          { challenge: 'challenge123', domain: 'https://verifier.com' }
        );

        expect(presentation.proof?.challenge).toBe('challenge123');
        expect(presentation.proof?.domain).toBe('https://verifier.com');
      });
    });

    describe('verifyPresentation', () => {
      const testVC: VerifiableCredential = {
        '@context': VC_CONTEXT,
        id: 'vc:test',
        type: ['VerifiableCredential', 'IdentityCredential'],
        issuer: 'did:key:z123',
        issuanceDate: '2026-01-25T10:00:00.000Z',
        expirationDate: '2099-01-01T00:00:00.000Z',
        credentialSubject: { name: 'Test' },
        proof: {
          type: PROOF_TYPES.ED25519,
          created: '2026-01-25T10:00:00.000Z',
          verificationMethod: 'did:key:z123#key-key1',
          proofPurpose: 'assertionMethod',
          proofValue: 'sig'
        }
      };

      beforeEach(() => {
        mockDynamoSend.mockResolvedValue({ Item: null }); // Not revoked
        mockDIDService.verifyWithDID.mockResolvedValue(true);
      });

      it('should verify valid presentation', async () => {
        const presentation = {
          '@context': VC_CONTEXT,
          id: 'vp:test',
          type: ['VerifiablePresentation'],
          holder: 'did:key:zHolder',
          verifiableCredential: [testVC],
          proof: {
            type: PROOF_TYPES.ED25519,
            created: '2026-01-25T10:00:00.000Z',
            verificationMethod: 'did:key:zHolder#key-key1',
            proofPurpose: 'authentication',
            proofValue: 'presentation-sig'
          }
        };

        const result = await service.verifyPresentation(presentation);

        expect(result.valid).toBe(true);
      });

      it('should fail for invalid structure', async () => {
        const invalidPresentation = {
          type: ['NotAPresentation'],
          verifiableCredential: []
        } as any;

        const result = await service.verifyPresentation(invalidPresentation);

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Invalid presentation structure');
      });

      it('should fail for challenge mismatch', async () => {
        const presentation = {
          '@context': VC_CONTEXT,
          type: ['VerifiablePresentation'],
          holder: 'did:key:zHolder',
          verifiableCredential: [testVC],
          proof: {
            type: PROOF_TYPES.ED25519,
            created: '2026-01-25T10:00:00.000Z',
            verificationMethod: 'did:key:zHolder#key-key1',
            proofPurpose: 'authentication',
            proofValue: 'sig',
            challenge: 'wrong-challenge'
          }
        };

        const result = await service.verifyPresentation(presentation, {
          challenge: 'expected-challenge'
        });

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Challenge mismatch');
      });
    });

    describe('getSupportedTypes', () => {
      it('should return all supported credential types', () => {
        const types = service.getSupportedTypes();

        expect(types).toContain(CREDENTIAL_TYPES.IDENTITY);
        expect(types).toContain(CREDENTIAL_TYPES.KYC);
        expect(types).toContain(CREDENTIAL_TYPES.EMPLOYMENT);
        expect(types).toContain(CREDENTIAL_TYPES.EDUCATION);
        expect(types).toContain(CREDENTIAL_TYPES.HEALTHCARE);
      });
    });
  });

  describe('Constants', () => {
    it('should have correct VC context', () => {
      expect(VC_CONTEXT).toContain('https://www.w3.org/2018/credentials/v1');
    });

    it('should have correct credential types', () => {
      expect(CREDENTIAL_TYPES.IDENTITY).toBe('IdentityCredential');
      expect(CREDENTIAL_TYPES.KYC).toBe('KYCCredential');
      expect(CREDENTIAL_TYPES.HEALTHCARE).toBe('HealthcareCredential');
    });

    it('should have correct proof types', () => {
      expect(PROOF_TYPES.ED25519).toBe('Ed25519Signature2020');
      expect(PROOF_TYPES.SECP256K1).toBe('EcdsaSecp256k1Signature2019');
    });
  });

  // ============================================================================
  // VC Templates Tests
  // ============================================================================

  describe('VC Templates', () => {
    describe('Template Definitions', () => {
      it('should have KYC template', () => {
        expect(VC_TEMPLATES.KYC).toBeDefined();
        expect(VC_TEMPLATES.KYC.credentialType).toBe(CREDENTIAL_TYPES.KYC);
        expect(VC_TEMPLATES.KYC.requiredFields).toContain('fullName');
        expect(VC_TEMPLATES.KYC.requiredFields).toContain('dateOfBirth');
        expect(VC_TEMPLATES.KYC.requiredFields).toContain('documentType');
      });

      it('should have Employment template', () => {
        expect(VC_TEMPLATES.EMPLOYMENT).toBeDefined();
        expect(VC_TEMPLATES.EMPLOYMENT.credentialType).toBe(CREDENTIAL_TYPES.EMPLOYMENT);
        expect(VC_TEMPLATES.EMPLOYMENT.requiredFields).toContain('employeeName');
        expect(VC_TEMPLATES.EMPLOYMENT.requiredFields).toContain('employerName');
        expect(VC_TEMPLATES.EMPLOYMENT.requiredFields).toContain('jobTitle');
      });

      it('should have Education template', () => {
        expect(VC_TEMPLATES.EDUCATION).toBeDefined();
        expect(VC_TEMPLATES.EDUCATION.credentialType).toBe(CREDENTIAL_TYPES.EDUCATION);
        expect(VC_TEMPLATES.EDUCATION.requiredFields).toContain('studentName');
        expect(VC_TEMPLATES.EDUCATION.requiredFields).toContain('institutionName');
        expect(VC_TEMPLATES.EDUCATION.requiredFields).toContain('credentialName');
      });

      it('should have Healthcare template', () => {
        expect(VC_TEMPLATES.HEALTHCARE).toBeDefined();
        expect(VC_TEMPLATES.HEALTHCARE.credentialType).toBe(CREDENTIAL_TYPES.HEALTHCARE);
        expect(VC_TEMPLATES.HEALTHCARE.requiredFields).toContain('providerName');
        expect(VC_TEMPLATES.HEALTHCARE.requiredFields).toContain('licenseNumber');
      });
    });

    describe('validateClaimsAgainstTemplate', () => {
      it('should validate valid KYC claims', () => {
        const claims: KYCCredentialClaims = {
          fullName: 'John Doe',
          dateOfBirth: '1990-01-15',
          nationality: 'US',
          documentType: 'passport',
          documentNumber: 'AB123456',
          documentExpiry: '2030-01-15',
          documentCountry: 'US',
          verificationLevel: 'enhanced',
          verificationDate: '2026-01-25T10:00:00.000Z',
          verificationMethod: 'biometric'
        };

        const result = validateClaimsAgainstTemplate('KYC', claims as unknown as Record<string, unknown>);

        expect(result.valid).toBe(true);
        expect(result.missingRequired).toHaveLength(0);
      });

      it('should reject KYC claims with missing required fields', () => {
        const claims = {
          fullName: 'John Doe',
          dateOfBirth: '1990-01-15'
          // Missing many required fields
        };

        const result = validateClaimsAgainstTemplate('KYC', claims);

        expect(result.valid).toBe(false);
        expect(result.missingRequired).toContain('nationality');
        expect(result.missingRequired).toContain('documentType');
      });

      it('should validate valid Employment claims', () => {
        const claims: EmploymentCredentialClaims = {
          employeeName: 'Jane Smith',
          employerName: 'Zalt.io',
          employerCountry: 'US',
          jobTitle: 'Senior Engineer',
          employmentType: 'full_time',
          startDate: '2024-01-01',
          verifiedBy: 'HR Department',
          verificationDate: '2026-01-25T10:00:00.000Z'
        };

        const result = validateClaimsAgainstTemplate('EMPLOYMENT', claims as unknown as Record<string, unknown>);

        expect(result.valid).toBe(true);
        expect(result.missingRequired).toHaveLength(0);
      });

      it('should validate valid Education claims', () => {
        const claims: EducationCredentialClaims = {
          studentName: 'Alice Johnson',
          institutionName: 'MIT',
          institutionCountry: 'US',
          institutionType: 'university',
          credentialType: 'degree',
          credentialName: 'Bachelor of Science in Computer Science',
          fieldOfStudy: 'Computer Science',
          issueDate: '2024-05-15',
          verificationDate: '2026-01-25T10:00:00.000Z'
        };

        const result = validateClaimsAgainstTemplate('EDUCATION', claims as unknown as Record<string, unknown>);

        expect(result.valid).toBe(true);
        expect(result.missingRequired).toHaveLength(0);
      });

      it('should validate valid Healthcare claims', () => {
        const claims: HealthcareCredentialClaims = {
          providerName: 'Dr. Smith',
          providerId: '1234567890',
          providerType: 'physician',
          licenseNumber: 'MD12345',
          licenseState: 'CA',
          licenseCountry: 'US',
          licenseType: 'Medical Doctor',
          licenseIssueDate: '2020-01-01',
          licenseExpiryDate: '2027-01-01',
          verificationDate: '2026-01-25T10:00:00.000Z',
          verifiedBy: 'Medical Board of California'
        };

        const result = validateClaimsAgainstTemplate('HEALTHCARE', claims as unknown as Record<string, unknown>);

        expect(result.valid).toBe(true);
        expect(result.missingRequired).toHaveLength(0);
      });

      it('should return error for unknown template', () => {
        const result = validateClaimsAgainstTemplate('UNKNOWN', {});

        expect(result.valid).toBe(false);
        expect(result.invalidFields).toContain('Unknown template: UNKNOWN');
      });

      it('should warn about unknown fields', () => {
        const claims = {
          fullName: 'John Doe',
          dateOfBirth: '1990-01-15',
          nationality: 'US',
          documentType: 'passport',
          documentNumber: 'AB123456',
          documentExpiry: '2030-01-15',
          documentCountry: 'US',
          verificationLevel: 'enhanced',
          verificationDate: '2026-01-25T10:00:00.000Z',
          verificationMethod: 'biometric',
          unknownField: 'some value'
        };

        const result = validateClaimsAgainstTemplate('KYC', claims);

        expect(result.valid).toBe(true);
        expect(result.warnings).toContain('Unknown field: unknownField');
      });
    });

    describe('getExpiryFromTemplate', () => {
      it('should return expiry date for KYC template (1 year)', () => {
        const expiry = getExpiryFromTemplate('KYC');
        
        expect(expiry).toBeDefined();
        const expiryDate = new Date(expiry!);
        const now = new Date();
        const oneYearFromNow = new Date(now.setFullYear(now.getFullYear() + 1));
        
        // Should be approximately 1 year from now (within 1 day tolerance)
        expect(Math.abs(expiryDate.getTime() - oneYearFromNow.getTime())).toBeLessThan(86400000);
      });

      it('should return expiry date for Employment template (2 years)', () => {
        const expiry = getExpiryFromTemplate('EMPLOYMENT');
        
        expect(expiry).toBeDefined();
        const expiryDate = new Date(expiry!);
        const now = new Date();
        const twoYearsFromNow = new Date(now.setFullYear(now.getFullYear() + 2));
        
        expect(Math.abs(expiryDate.getTime() - twoYearsFromNow.getTime())).toBeLessThan(86400000);
      });

      it('should return undefined for Education template (no default expiry)', () => {
        const expiry = getExpiryFromTemplate('EDUCATION');
        
        // Education credentials typically don't expire
        expect(expiry).toBeUndefined();
      });

      it('should return undefined for unknown template', () => {
        const expiry = getExpiryFromTemplate('UNKNOWN');
        
        expect(expiry).toBeUndefined();
      });
    });

    describe('VCTemplateService', () => {
      let templateService: VCTemplateService;

      beforeEach(() => {
        jest.clearAllMocks();
        mockDynamoSend.mockReset();
        mockDIDService.getDID.mockReset();
        mockDIDService.signWithDID.mockReset();
        mockDIDService.verifyWithDID.mockReset();
        templateService = new VCTemplateService();
      });

      describe('getTemplates', () => {
        it('should return all templates', () => {
          const templates = templateService.getTemplates();

          expect(templates.length).toBeGreaterThanOrEqual(4);
          expect(templates.map(t => t.id)).toContain('template:zalt:kyc:v1');
          expect(templates.map(t => t.id)).toContain('template:zalt:employment:v1');
          expect(templates.map(t => t.id)).toContain('template:zalt:education:v1');
          expect(templates.map(t => t.id)).toContain('template:zalt:healthcare:v1');
        });
      });

      describe('getTemplate', () => {
        it('should return specific template', () => {
          const template = templateService.getTemplate('KYC');

          expect(template).toBeDefined();
          expect(template?.name).toBe('KYC Credential');
        });

        it('should return undefined for unknown template', () => {
          const template = templateService.getTemplate('UNKNOWN');

          expect(template).toBeUndefined();
        });
      });

      describe('validateClaims', () => {
        it('should validate claims using template', () => {
          const result = templateService.validateClaims('KYC', {
            fullName: 'Test',
            dateOfBirth: '1990-01-01'
          });

          expect(result.valid).toBe(false);
          expect(result.missingRequired.length).toBeGreaterThan(0);
        });
      });

      describe('issueFromTemplate', () => {
        beforeEach(() => {
          mockDIDService.getDID.mockResolvedValue({
            did: 'did:key:z123',
            status: 'active',
            keyPairs: [{ keyId: 'key1', encryptedPrivateKey: 'enc', keyType: 'Ed25519' }]
          });
          mockDIDService.signWithDID.mockResolvedValue('signature123');
          mockDynamoSend.mockResolvedValue({});
        });

        it('should issue credential from KYC template', async () => {
          const claims: KYCCredentialClaims = {
            fullName: 'John Doe',
            dateOfBirth: '1990-01-15',
            nationality: 'US',
            documentType: 'passport',
            documentNumber: 'AB123456',
            documentExpiry: '2030-01-15',
            documentCountry: 'US',
            verificationLevel: 'enhanced',
            verificationDate: '2026-01-25T10:00:00.000Z',
            verificationMethod: 'biometric'
          };

          const vc = await templateService.issueFromTemplate(
            'KYC',
            'did:key:z123',
            'key1',
            'did:key:zSubject',
            claims as unknown as Record<string, unknown>,
            'realm_123'
          );

          expect(vc.type).toContain('VerifiableCredential');
          expect(vc.type).toContain(CREDENTIAL_TYPES.KYC);
          expect(vc.credentialSubject.fullName).toBe('John Doe');
        });

        it('should throw for unknown template', async () => {
          await expect(templateService.issueFromTemplate(
            'UNKNOWN',
            'did:key:z123',
            'key1',
            'did:key:zSubject',
            {},
            'realm_123'
          )).rejects.toThrow('Unknown template: UNKNOWN');
        });

        it('should throw for invalid claims', async () => {
          await expect(templateService.issueFromTemplate(
            'KYC',
            'did:key:z123',
            'key1',
            'did:key:zSubject',
            { fullName: 'Test' }, // Missing required fields
            'realm_123'
          )).rejects.toThrow('Template validation failed');
        });

        it('should skip validation if requested', async () => {
          const vc = await templateService.issueFromTemplate(
            'KYC',
            'did:key:z123',
            'key1',
            'did:key:zSubject',
            { fullName: 'Test' }, // Missing required fields
            'realm_123',
            { skipValidation: true }
          );

          expect(vc).toBeDefined();
        });
      });

      describe('issueKYCCredential', () => {
        beforeEach(() => {
          mockDIDService.getDID.mockResolvedValue({
            did: 'did:key:z123',
            status: 'active',
            keyPairs: [{ keyId: 'key1' }]
          });
          mockDIDService.signWithDID.mockResolvedValue('sig');
          mockDynamoSend.mockResolvedValue({});
        });

        it('should issue KYC credential', async () => {
          const claims: KYCCredentialClaims = {
            fullName: 'John Doe',
            dateOfBirth: '1990-01-15',
            nationality: 'US',
            documentType: 'passport',
            documentNumber: 'AB123456',
            documentExpiry: '2030-01-15',
            documentCountry: 'US',
            verificationLevel: 'standard',
            verificationDate: '2026-01-25T10:00:00.000Z',
            verificationMethod: 'document'
          };

          const vc = await templateService.issueKYCCredential(
            'did:key:z123',
            'key1',
            'did:key:zSubject',
            claims,
            'realm_123'
          );

          expect(vc.type).toContain(CREDENTIAL_TYPES.KYC);
        });
      });

      describe('issueEmploymentCredential', () => {
        beforeEach(() => {
          mockDIDService.getDID.mockResolvedValue({
            did: 'did:key:z123',
            status: 'active',
            keyPairs: [{ keyId: 'key1' }]
          });
          mockDIDService.signWithDID.mockResolvedValue('sig');
          mockDynamoSend.mockResolvedValue({});
        });

        it('should issue Employment credential', async () => {
          const claims: EmploymentCredentialClaims = {
            employeeName: 'Jane Smith',
            employerName: 'Zalt.io',
            employerCountry: 'US',
            jobTitle: 'Engineer',
            employmentType: 'full_time',
            startDate: '2024-01-01',
            verifiedBy: 'HR',
            verificationDate: '2026-01-25T10:00:00.000Z'
          };

          const vc = await templateService.issueEmploymentCredential(
            'did:key:z123',
            'key1',
            'did:key:zSubject',
            claims,
            'realm_123'
          );

          expect(vc.type).toContain(CREDENTIAL_TYPES.EMPLOYMENT);
        });
      });

      describe('issueEducationCredential', () => {
        beforeEach(() => {
          mockDIDService.getDID.mockResolvedValue({
            did: 'did:key:z123',
            status: 'active',
            keyPairs: [{ keyId: 'key1' }]
          });
          mockDIDService.signWithDID.mockResolvedValue('sig');
          mockDynamoSend.mockResolvedValue({});
        });

        it('should issue Education credential', async () => {
          const claims: EducationCredentialClaims = {
            studentName: 'Alice Johnson',
            institutionName: 'MIT',
            institutionCountry: 'US',
            institutionType: 'university',
            credentialType: 'degree',
            credentialName: 'BS Computer Science',
            fieldOfStudy: 'Computer Science',
            issueDate: '2024-05-15',
            verificationDate: '2026-01-25T10:00:00.000Z'
          };

          const vc = await templateService.issueEducationCredential(
            'did:key:z123',
            'key1',
            'did:key:zSubject',
            claims,
            'realm_123'
          );

          expect(vc.type).toContain(CREDENTIAL_TYPES.EDUCATION);
        });
      });

      describe('issueHealthcareCredential', () => {
        beforeEach(() => {
          mockDIDService.getDID.mockResolvedValue({
            did: 'did:key:z123',
            status: 'active',
            keyPairs: [{ keyId: 'key1' }]
          });
          mockDIDService.signWithDID.mockResolvedValue('sig');
          mockDynamoSend.mockResolvedValue({});
        });

        it('should issue Healthcare credential (HIPAA-compliant)', async () => {
          const claims: HealthcareCredentialClaims = {
            providerName: 'Dr. Smith',
            providerId: '1234567890',
            providerType: 'physician',
            licenseNumber: 'MD12345',
            licenseState: 'CA',
            licenseCountry: 'US',
            licenseType: 'Medical Doctor',
            licenseIssueDate: '2020-01-01',
            licenseExpiryDate: '2027-01-01',
            verificationDate: '2026-01-25T10:00:00.000Z',
            verifiedBy: 'Medical Board'
          };

          const vc = await templateService.issueHealthcareCredential(
            'did:key:z123',
            'key1',
            'did:key:zSubject',
            claims,
            'realm_123'
          );

          expect(vc.type).toContain(CREDENTIAL_TYPES.HEALTHCARE);
        });
      });
    });
  });
});
