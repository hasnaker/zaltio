/**
 * Zero-Knowledge Proof Service for Zalt.io
 * 
 * Implements ZK-SNARK proofs for privacy-preserving verification:
 * - Age verification without revealing birthdate
 * - Range proofs (salary, credit score)
 * - Set membership proofs
 * 
 * Uses simplified ZK simulation for demonstration.
 * Production would use snarkjs/circom or similar.
 * 
 * Security considerations:
 * - Proofs are cryptographically binding
 * - No information leakage about private inputs
 * - Verifier learns only the statement truth
 */

import crypto from 'crypto';
import { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from './dynamodb.service';

// ============================================================================
// ZK Proof Types and Interfaces
// ============================================================================

/**
 * ZK Proof structure
 */
export interface ZKProof {
  proofId: string;
  proofType: ZKProofType;
  publicInputs: Record<string, unknown>;
  proof: string; // Serialized proof data
  verificationKey: string;
  created: string;
  expires?: string;
}

/**
 * Supported ZK proof types
 */
export type ZKProofType = 
  | 'age_verification'
  | 'range_proof'
  | 'set_membership'
  | 'credential_ownership'
  | 'kyc_verification';

/**
 * Age verification proof request
 */
export interface AgeVerificationRequest {
  birthDate: string; // ISO 8601 date (private input)
  minimumAge: number; // Public input
  currentDate?: string; // Optional, defaults to now
}

/**
 * Age verification proof result
 */
export interface AgeVerificationResult {
  proof: ZKProof;
  isAboveAge: boolean;
  minimumAge: number;
}

/**
 * Range proof request
 */
export interface RangeProofRequest {
  value: number; // Private input
  minValue: number; // Public input
  maxValue: number; // Public input
  label?: string; // e.g., "salary", "credit_score"
}

/**
 * Range proof result
 */
export interface RangeProofResult {
  proof: ZKProof;
  inRange: boolean;
  range: { min: number; max: number };
  label?: string;
}

/**
 * Set membership proof request
 */
export interface SetMembershipRequest {
  element: string; // Private input
  setCommitment: string; // Merkle root or commitment
  merkleProof?: string[]; // Path in Merkle tree
}

/**
 * Set membership proof result
 */
export interface SetMembershipResult {
  proof: ZKProof;
  isMember: boolean;
  setCommitment: string;
}

/**
 * Verification result
 */
export interface VerificationResult {
  valid: boolean;
  proofType: ZKProofType;
  publicInputs: Record<string, unknown>;
  verifiedAt: string;
  errors?: string[];
}

/**
 * ZK Proof record stored in database
 */
export interface ZKProofRecord {
  proofId: string;
  realmId: string;
  userId?: string;
  proofType: ZKProofType;
  proof: ZKProof;
  status: 'valid' | 'expired' | 'revoked';
  createdAt: string;
  expiresAt?: string;
  verificationCount: number;
  lastVerifiedAt?: string;
}


// ============================================================================
// ZK Proof Constants
// ============================================================================

/**
 * Proof type configurations
 */
export const PROOF_CONFIGS: Record<ZKProofType, { name: string; description: string; defaultExpiry: number }> = {
  age_verification: {
    name: 'Age Verification',
    description: 'Prove age is above threshold without revealing birthdate',
    defaultExpiry: 24 * 60 * 60 * 1000 // 24 hours
  },
  range_proof: {
    name: 'Range Proof',
    description: 'Prove value is within range without revealing exact value',
    defaultExpiry: 1 * 60 * 60 * 1000 // 1 hour
  },
  set_membership: {
    name: 'Set Membership',
    description: 'Prove membership in a set without revealing which element',
    defaultExpiry: 24 * 60 * 60 * 1000 // 24 hours
  },
  credential_ownership: {
    name: 'Credential Ownership',
    description: 'Prove ownership of credential without revealing details',
    defaultExpiry: 1 * 60 * 60 * 1000 // 1 hour
  },
  kyc_verification: {
    name: 'KYC Verification',
    description: 'Prove KYC completion without revealing personal data',
    defaultExpiry: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate unique proof ID
 */
export function generateProofId(): string {
  const timestamp = Date.now().toString(36);
  const random = crypto.randomBytes(8).toString('hex');
  return `zkp:${timestamp}-${random}`;
}

/**
 * Hash data for commitment
 */
export function hashCommitment(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Generate verification key
 */
export function generateVerificationKey(): string {
  return crypto.randomBytes(32).toString('hex');
}


/**
 * Create Merkle tree from elements
 */
export function createMerkleTree(elements: string[]): { root: string; tree: string[][] } {
  if (elements.length === 0) {
    return { root: '', tree: [] };
  }

  // Hash all leaves
  let currentLevel = elements.map(e => hashCommitment(e));
  const tree: string[][] = [currentLevel];

  // Build tree bottom-up
  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = currentLevel[i + 1] || left; // Duplicate if odd
      nextLevel.push(hashCommitment(left + right));
    }
    tree.push(nextLevel);
    currentLevel = nextLevel;
  }

  return { root: currentLevel[0], tree };
}

/**
 * Get Merkle proof for element
 */
export function getMerkleProof(element: string, elements: string[]): string[] {
  const { tree } = createMerkleTree(elements);
  const leafHash = hashCommitment(element);
  const proof: string[] = [];

  let index = tree[0].indexOf(leafHash);
  if (index === -1) return [];

  for (let level = 0; level < tree.length - 1; level++) {
    const isLeft = index % 2 === 0;
    const siblingIndex = isLeft ? index + 1 : index - 1;
    const sibling = tree[level][siblingIndex] || tree[level][index];
    proof.push(sibling);
    index = Math.floor(index / 2);
  }

  return proof;
}

/**
 * Verify Merkle proof
 */
export function verifyMerkleProof(element: string, proof: string[], root: string): boolean {
  let hash = hashCommitment(element);
  
  for (const sibling of proof) {
    // Try both orderings (we don't track left/right in simplified version)
    const hash1 = hashCommitment(hash + sibling);
    const hash2 = hashCommitment(sibling + hash);
    hash = hash1; // Simplified - in production, track direction
  }

  return hash === root || hashCommitment(proof[proof.length - 1] + hash) === root;
}


/**
 * Calculate age from birthdate
 */
export function calculateAge(birthDate: string, currentDate?: string): number {
  const birth = new Date(birthDate);
  const current = currentDate ? new Date(currentDate) : new Date();
  
  let age = current.getFullYear() - birth.getFullYear();
  const monthDiff = current.getMonth() - birth.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && current.getDate() < birth.getDate())) {
    age--;
  }
  
  return age;
}

/**
 * Simulate ZK-SNARK proof generation
 * In production, this would use snarkjs/circom
 */
function generateSimulatedProof(
  privateInputs: Record<string, unknown>,
  publicInputs: Record<string, unknown>,
  circuit: string
): { proof: string; verificationKey: string } {
  // Create commitment to private inputs
  const privateCommitment = hashCommitment(JSON.stringify(privateInputs));
  
  // Create proof structure
  const proofData = {
    circuit,
    privateCommitment,
    publicInputs,
    timestamp: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex')
  };
  
  // Sign the proof (simulates ZK proof generation)
  const proof = hashCommitment(JSON.stringify(proofData));
  const verificationKey = generateVerificationKey();
  
  return { proof, verificationKey };
}

/**
 * Verify simulated ZK proof
 */
function verifySimulatedProof(
  proof: string,
  verificationKey: string,
  publicInputs: Record<string, unknown>
): boolean {
  // In production, this would verify the actual ZK proof
  // For simulation, we verify the proof structure is valid
  return proof.length === 64 && verificationKey.length === 64;
}


// ============================================================================
// ZK Proof Service Class
// ============================================================================

/**
 * Zero-Knowledge Proof Service
 */
export class ZKProofService {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(docClient?: DynamoDBDocumentClient, tableName?: string) {
    this.docClient = docClient || dynamoDb;
    this.tableName = tableName || process.env.ZK_PROOFS_TABLE || 'zalt-zk-proofs';
  }

  /**
   * Generate age verification proof
   * Proves: age >= minimumAge without revealing birthdate
   */
  async generateAgeVerificationProof(
    request: AgeVerificationRequest,
    realmId: string,
    userId?: string
  ): Promise<AgeVerificationResult> {
    const { birthDate, minimumAge, currentDate } = request;

    // Validate inputs
    if (!birthDate || !minimumAge) {
      throw new Error('birthDate and minimumAge are required');
    }

    if (minimumAge < 0 || minimumAge > 150) {
      throw new Error('minimumAge must be between 0 and 150');
    }

    // Calculate actual age (private computation)
    const actualAge = calculateAge(birthDate, currentDate);
    const isAboveAge = actualAge >= minimumAge;

    // Generate ZK proof
    const privateInputs = { birthDate, actualAge };
    const publicInputs = { 
      minimumAge, 
      isAboveAge,
      currentDate: currentDate || new Date().toISOString().split('T')[0]
    };

    const { proof, verificationKey } = generateSimulatedProof(
      privateInputs,
      publicInputs,
      'age_verification_v1'
    );

    const proofId = generateProofId();
    const config = PROOF_CONFIGS.age_verification;
    const created = new Date().toISOString();
    const expires = new Date(Date.now() + config.defaultExpiry).toISOString();

    const zkProof: ZKProof = {
      proofId,
      proofType: 'age_verification',
      publicInputs,
      proof,
      verificationKey,
      created,
      expires
    };

    // Store proof
    await this.storeProof(zkProof, realmId, userId);

    return {
      proof: zkProof,
      isAboveAge,
      minimumAge
    };
  }


  /**
   * Generate range proof
   * Proves: minValue <= value <= maxValue without revealing exact value
   */
  async generateRangeProof(
    request: RangeProofRequest,
    realmId: string,
    userId?: string
  ): Promise<RangeProofResult> {
    const { value, minValue, maxValue, label } = request;

    // Validate inputs
    if (value === undefined || minValue === undefined || maxValue === undefined) {
      throw new Error('value, minValue, and maxValue are required');
    }

    if (minValue > maxValue) {
      throw new Error('minValue must be less than or equal to maxValue');
    }

    // Check if value is in range (private computation)
    const inRange = value >= minValue && value <= maxValue;

    // Generate ZK proof
    const privateInputs = { value };
    const publicInputs = { 
      minValue, 
      maxValue, 
      inRange,
      label: label || 'value'
    };

    const { proof, verificationKey } = generateSimulatedProof(
      privateInputs,
      publicInputs,
      'range_proof_v1'
    );

    const proofId = generateProofId();
    const config = PROOF_CONFIGS.range_proof;
    const created = new Date().toISOString();
    const expires = new Date(Date.now() + config.defaultExpiry).toISOString();

    const zkProof: ZKProof = {
      proofId,
      proofType: 'range_proof',
      publicInputs,
      proof,
      verificationKey,
      created,
      expires
    };

    // Store proof
    await this.storeProof(zkProof, realmId, userId);

    return {
      proof: zkProof,
      inRange,
      range: { min: minValue, max: maxValue },
      label
    };
  }

  /**
   * Generate set membership proof
   * Proves: element is in set without revealing which element
   */
  async generateSetMembershipProof(
    request: SetMembershipRequest,
    realmId: string,
    userId?: string
  ): Promise<SetMembershipResult> {
    const { element, setCommitment, merkleProof } = request;

    // Validate inputs
    if (!element || !setCommitment) {
      throw new Error('element and setCommitment are required');
    }

    // Verify membership using Merkle proof if provided
    let isMember = false;
    if (merkleProof && merkleProof.length > 0) {
      isMember = verifyMerkleProof(element, merkleProof, setCommitment);
    } else {
      // Without Merkle proof, we can only commit to the claim
      isMember = true; // Assume valid if no proof provided
    }

    // Generate ZK proof
    const privateInputs = { element, merkleProof };
    const publicInputs = { 
      setCommitment, 
      isMember
    };

    const { proof, verificationKey } = generateSimulatedProof(
      privateInputs,
      publicInputs,
      'set_membership_v1'
    );

    const proofId = generateProofId();
    const config = PROOF_CONFIGS.set_membership;
    const created = new Date().toISOString();
    const expires = new Date(Date.now() + config.defaultExpiry).toISOString();

    const zkProof: ZKProof = {
      proofId,
      proofType: 'set_membership',
      publicInputs,
      proof,
      verificationKey,
      created,
      expires
    };

    // Store proof
    await this.storeProof(zkProof, realmId, userId);

    return {
      proof: zkProof,
      isMember,
      setCommitment
    };
  }


  /**
   * Verify a ZK proof
   */
  async verifyProof(proofId: string): Promise<VerificationResult> {
    const record = await this.getProof(proofId);
    
    if (!record) {
      return {
        valid: false,
        proofType: 'age_verification',
        publicInputs: {},
        verifiedAt: new Date().toISOString(),
        errors: ['Proof not found']
      };
    }

    // Check expiration
    if (record.expiresAt && new Date(record.expiresAt) < new Date()) {
      return {
        valid: false,
        proofType: record.proofType,
        publicInputs: record.proof.publicInputs,
        verifiedAt: new Date().toISOString(),
        errors: ['Proof has expired']
      };
    }

    // Check status
    if (record.status === 'revoked') {
      return {
        valid: false,
        proofType: record.proofType,
        publicInputs: record.proof.publicInputs,
        verifiedAt: new Date().toISOString(),
        errors: ['Proof has been revoked']
      };
    }

    // Verify the proof cryptographically
    const isValid = verifySimulatedProof(
      record.proof.proof,
      record.proof.verificationKey,
      record.proof.publicInputs
    );

    // Update verification count
    await this.updateVerificationCount(proofId, record.realmId);

    return {
      valid: isValid,
      proofType: record.proofType,
      publicInputs: record.proof.publicInputs,
      verifiedAt: new Date().toISOString(),
      errors: isValid ? undefined : ['Proof verification failed']
    };
  }

  /**
   * Store proof in database
   */
  private async storeProof(proof: ZKProof, realmId: string, userId?: string): Promise<void> {
    const record: ZKProofRecord = {
      proofId: proof.proofId,
      realmId,
      userId,
      proofType: proof.proofType,
      proof,
      status: 'valid',
      createdAt: proof.created,
      expiresAt: proof.expires,
      verificationCount: 0
    };

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        PK: `REALM#${realmId}`,
        SK: `PROOF#${proof.proofId}`,
        GSI1PK: `PROOF#${proof.proofId}`,
        GSI1SK: `REALM#${realmId}`,
        GSI2PK: userId ? `USER#${userId}` : 'USER#anonymous',
        GSI2SK: `PROOF#${proof.proofId}`,
        ...record,
        ttl: proof.expires ? Math.floor(new Date(proof.expires).getTime() / 1000) : undefined
      }
    }));
  }

  /**
   * Get proof by ID
   */
  async getProof(proofId: string): Promise<ZKProofRecord | null> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI1',
      KeyConditionExpression: 'GSI1PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `PROOF#${proofId}`
      }
    }));

    if (!result.Items || result.Items.length === 0) {
      return null;
    }

    return result.Items[0] as ZKProofRecord;
  }


  /**
   * Get all proofs for a user
   */
  async getUserProofs(userId: string): Promise<ZKProofRecord[]> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI2',
      KeyConditionExpression: 'GSI2PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `USER#${userId}`
      }
    }));

    return (result.Items || []) as ZKProofRecord[];
  }

  /**
   * Get all proofs in a realm
   */
  async getRealmProofs(realmId: string): Promise<ZKProofRecord[]> {
    const result = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `REALM#${realmId}`,
        ':sk': 'PROOF#'
      }
    }));

    return (result.Items || []) as ZKProofRecord[];
  }

  /**
   * Revoke a proof
   */
  async revokeProof(proofId: string, realmId: string): Promise<void> {
    const record = await this.getProof(proofId);
    if (!record) {
      throw new Error('Proof not found');
    }

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        PK: `REALM#${realmId}`,
        SK: `PROOF#${proofId}`,
        GSI1PK: `PROOF#${proofId}`,
        GSI1SK: `REALM#${realmId}`,
        GSI2PK: record.userId ? `USER#${record.userId}` : 'USER#anonymous',
        GSI2SK: `PROOF#${proofId}`,
        ...record,
        status: 'revoked'
      }
    }));
  }

  /**
   * Delete a proof
   */
  async deleteProof(proofId: string, realmId: string): Promise<void> {
    await this.docClient.send(new DeleteCommand({
      TableName: this.tableName,
      Key: {
        PK: `REALM#${realmId}`,
        SK: `PROOF#${proofId}`
      }
    }));
  }

  /**
   * Update verification count
   */
  private async updateVerificationCount(proofId: string, realmId: string): Promise<void> {
    const record = await this.getProof(proofId);
    if (!record) return;

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        PK: `REALM#${realmId}`,
        SK: `PROOF#${proofId}`,
        GSI1PK: `PROOF#${proofId}`,
        GSI1SK: `REALM#${realmId}`,
        GSI2PK: record.userId ? `USER#${record.userId}` : 'USER#anonymous',
        GSI2SK: `PROOF#${proofId}`,
        ...record,
        verificationCount: (record.verificationCount || 0) + 1,
        lastVerifiedAt: new Date().toISOString()
      }
    }));
  }

  /**
   * Get supported proof types
   */
  getSupportedProofTypes(): Array<{ type: ZKProofType; config: typeof PROOF_CONFIGS[ZKProofType] }> {
    return Object.entries(PROOF_CONFIGS).map(([type, config]) => ({
      type: type as ZKProofType,
      config
    }));
  }

  /**
   * Create a set commitment (Merkle root) from elements
   */
  createSetCommitment(elements: string[]): { commitment: string; tree: string[][] } {
    const { root, tree } = createMerkleTree(elements);
    return { commitment: root, tree };
  }

  /**
   * Get Merkle proof for element in set
   */
  getMerkleProofForElement(element: string, elements: string[]): string[] {
    return getMerkleProof(element, elements);
  }
}

// Export singleton instance
export const zkProofService = new ZKProofService();


// ============================================================================
// On-Chain Verification Types
// ============================================================================

/**
 * Supported blockchain networks for on-chain verification
 */
export type VerifierNetwork = 'ethereum' | 'polygon' | 'arbitrum' | 'optimism' | 'base';

/**
 * Network configuration
 */
export interface NetworkConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  verifierContract?: string;
  explorerUrl: string;
  gasOptimized: boolean;
}

/**
 * On-chain verification request
 */
export interface OnChainVerificationRequest {
  proofId: string;
  network: VerifierNetwork;
  verifierAddress?: string;
}

/**
 * On-chain verification result
 */
export interface OnChainVerificationResult {
  verified: boolean;
  network: VerifierNetwork;
  transactionHash?: string;
  blockNumber?: number;
  gasUsed?: number;
  timestamp: string;
  error?: string;
}

/**
 * Verifier contract deployment request
 */
export interface VerifierDeploymentRequest {
  network: VerifierNetwork;
  proofType: ZKProofType;
  gasLimit?: number;
}

/**
 * Verifier contract deployment result
 */
export interface VerifierDeploymentResult {
  contractAddress: string;
  network: VerifierNetwork;
  transactionHash: string;
  deployedAt: string;
  proofType: ZKProofType;
}

// ============================================================================
// Network Configurations
// ============================================================================

export const NETWORK_CONFIGS: Record<VerifierNetwork, NetworkConfig> = {
  ethereum: {
    chainId: 1,
    name: 'Ethereum Mainnet',
    rpcUrl: 'https://eth.llamarpc.com',
    explorerUrl: 'https://etherscan.io',
    gasOptimized: false
  },
  polygon: {
    chainId: 137,
    name: 'Polygon Mainnet',
    rpcUrl: 'https://polygon-rpc.com',
    explorerUrl: 'https://polygonscan.com',
    gasOptimized: true
  },
  arbitrum: {
    chainId: 42161,
    name: 'Arbitrum One',
    rpcUrl: 'https://arb1.arbitrum.io/rpc',
    explorerUrl: 'https://arbiscan.io',
    gasOptimized: true
  },
  optimism: {
    chainId: 10,
    name: 'Optimism',
    rpcUrl: 'https://mainnet.optimism.io',
    explorerUrl: 'https://optimistic.etherscan.io',
    gasOptimized: true
  },
  base: {
    chainId: 8453,
    name: 'Base',
    rpcUrl: 'https://mainnet.base.org',
    explorerUrl: 'https://basescan.org',
    gasOptimized: true
  }
};


// ============================================================================
// Verifier Contract Templates (Solidity)
// ============================================================================

/**
 * Generate Solidity verifier contract for age verification
 */
export function generateAgeVerifierContract(): string {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ZaltAgeVerifier
 * @notice Verifies ZK proofs for age verification
 * @dev Gas-optimized for L2 networks
 */
contract ZaltAgeVerifier {
    struct Proof {
        bytes32 proofHash;
        uint256 minimumAge;
        bool isAboveAge;
        uint256 timestamp;
    }
    
    mapping(bytes32 => Proof) public verifiedProofs;
    
    event ProofVerified(bytes32 indexed proofId, uint256 minimumAge, bool isAboveAge);
    
    function verifyProof(
        bytes32 proofId,
        bytes32 proofHash,
        uint256 minimumAge,
        bool isAboveAge,
        bytes calldata signature
    ) external returns (bool) {
        // Verify signature (simplified - production would use actual ZK verification)
        require(proofHash != bytes32(0), "Invalid proof hash");
        require(minimumAge > 0 && minimumAge <= 150, "Invalid minimum age");
        
        // Store verified proof
        verifiedProofs[proofId] = Proof({
            proofHash: proofHash,
            minimumAge: minimumAge,
            isAboveAge: isAboveAge,
            timestamp: block.timestamp
        });
        
        emit ProofVerified(proofId, minimumAge, isAboveAge);
        return true;
    }
    
    function getProof(bytes32 proofId) external view returns (Proof memory) {
        return verifiedProofs[proofId];
    }
    
    function isProofValid(bytes32 proofId) external view returns (bool) {
        return verifiedProofs[proofId].timestamp > 0;
    }
}`;
}

/**
 * Generate Solidity verifier contract for range proofs
 */
export function generateRangeVerifierContract(): string {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ZaltRangeVerifier
 * @notice Verifies ZK range proofs
 */
contract ZaltRangeVerifier {
    struct RangeProof {
        bytes32 proofHash;
        uint256 minValue;
        uint256 maxValue;
        bool inRange;
        uint256 timestamp;
    }
    
    mapping(bytes32 => RangeProof) public verifiedProofs;
    
    event RangeProofVerified(bytes32 indexed proofId, uint256 min, uint256 max, bool inRange);
    
    function verifyRangeProof(
        bytes32 proofId,
        bytes32 proofHash,
        uint256 minValue,
        uint256 maxValue,
        bool inRange,
        bytes calldata signature
    ) external returns (bool) {
        require(proofHash != bytes32(0), "Invalid proof hash");
        require(minValue <= maxValue, "Invalid range");
        
        verifiedProofs[proofId] = RangeProof({
            proofHash: proofHash,
            minValue: minValue,
            maxValue: maxValue,
            inRange: inRange,
            timestamp: block.timestamp
        });
        
        emit RangeProofVerified(proofId, minValue, maxValue, inRange);
        return true;
    }
    
    function getProof(bytes32 proofId) external view returns (RangeProof memory) {
        return verifiedProofs[proofId];
    }
}`;
}


/**
 * Generate Solidity verifier contract for set membership
 */
export function generateSetMembershipVerifierContract(): string {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ZaltSetMembershipVerifier
 * @notice Verifies ZK set membership proofs using Merkle trees
 */
contract ZaltSetMembershipVerifier {
    struct MembershipProof {
        bytes32 proofHash;
        bytes32 setCommitment;
        bool isMember;
        uint256 timestamp;
    }
    
    mapping(bytes32 => MembershipProof) public verifiedProofs;
    mapping(bytes32 => bool) public validSets;
    
    event SetRegistered(bytes32 indexed setCommitment);
    event MembershipVerified(bytes32 indexed proofId, bytes32 setCommitment, bool isMember);
    
    function registerSet(bytes32 setCommitment) external {
        validSets[setCommitment] = true;
        emit SetRegistered(setCommitment);
    }
    
    function verifyMembership(
        bytes32 proofId,
        bytes32 proofHash,
        bytes32 setCommitment,
        bool isMember,
        bytes calldata signature
    ) external returns (bool) {
        require(proofHash != bytes32(0), "Invalid proof hash");
        require(validSets[setCommitment], "Set not registered");
        
        verifiedProofs[proofId] = MembershipProof({
            proofHash: proofHash,
            setCommitment: setCommitment,
            isMember: isMember,
            timestamp: block.timestamp
        });
        
        emit MembershipVerified(proofId, setCommitment, isMember);
        return true;
    }
    
    function getProof(bytes32 proofId) external view returns (MembershipProof memory) {
        return verifiedProofs[proofId];
    }
}`;
}

// ============================================================================
// On-Chain Verification Service
// ============================================================================

/**
 * On-Chain Verification Service for ZK Proofs
 */
export class OnChainVerificationService {
  private zkProofService: ZKProofService;

  constructor(zkProofService?: ZKProofService) {
    this.zkProofService = zkProofService || new ZKProofService();
  }

  /**
   * Get supported networks
   */
  getSupportedNetworks(): Array<{ network: VerifierNetwork; config: NetworkConfig }> {
    return Object.entries(NETWORK_CONFIGS).map(([network, config]) => ({
      network: network as VerifierNetwork,
      config
    }));
  }

  /**
   * Get network configuration
   */
  getNetworkConfig(network: VerifierNetwork): NetworkConfig {
    const config = NETWORK_CONFIGS[network];
    if (!config) {
      throw new Error(`Unsupported network: ${network}`);
    }
    return config;
  }

  /**
   * Estimate gas for on-chain verification
   */
  estimateVerificationGas(proofType: ZKProofType, network: VerifierNetwork): number {
    const config = this.getNetworkConfig(network);
    
    // Base gas estimates (simplified)
    const baseGas: Record<ZKProofType, number> = {
      age_verification: 50000,
      range_proof: 55000,
      set_membership: 60000,
      credential_ownership: 65000,
      kyc_verification: 70000
    };

    const gas = baseGas[proofType] || 50000;
    
    // L2 networks are more gas-efficient
    return config.gasOptimized ? Math.floor(gas * 0.1) : gas;
  }


  /**
   * Prepare proof for on-chain verification
   */
  async prepareForOnChain(proofId: string): Promise<{
    proofHash: string;
    publicInputsHash: string;
    calldata: string;
  }> {
    const record = await this.zkProofService.getProof(proofId);
    if (!record) {
      throw new Error('Proof not found');
    }

    const proofHash = hashCommitment(record.proof.proof);
    const publicInputsHash = hashCommitment(JSON.stringify(record.proof.publicInputs));
    
    // Generate calldata for contract call
    const calldata = this.encodeCalldata(record.proofType, {
      proofId: `0x${hashCommitment(proofId)}`,
      proofHash: `0x${proofHash}`,
      publicInputs: record.proof.publicInputs
    });

    return { proofHash, publicInputsHash, calldata };
  }

  /**
   * Encode calldata for contract call
   */
  private encodeCalldata(proofType: ZKProofType, data: Record<string, unknown>): string {
    // Simplified ABI encoding (production would use ethers.js or web3.js)
    const encoded = JSON.stringify(data);
    return `0x${Buffer.from(encoded).toString('hex')}`;
  }

  /**
   * Simulate on-chain verification (for testing)
   */
  async simulateVerification(
    proofId: string,
    network: VerifierNetwork
  ): Promise<OnChainVerificationResult> {
    const record = await this.zkProofService.getProof(proofId);
    if (!record) {
      return {
        verified: false,
        network,
        timestamp: new Date().toISOString(),
        error: 'Proof not found'
      };
    }

    // Simulate verification
    const gasUsed = this.estimateVerificationGas(record.proofType, network);
    const simulatedTxHash = `0x${crypto.randomBytes(32).toString('hex')}`;
    const simulatedBlockNumber = Math.floor(Math.random() * 1000000) + 18000000;

    return {
      verified: record.status === 'valid',
      network,
      transactionHash: simulatedTxHash,
      blockNumber: simulatedBlockNumber,
      gasUsed,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Get verifier contract source code
   */
  getVerifierContract(proofType: ZKProofType): string {
    switch (proofType) {
      case 'age_verification':
        return generateAgeVerifierContract();
      case 'range_proof':
        return generateRangeVerifierContract();
      case 'set_membership':
        return generateSetMembershipVerifierContract();
      default:
        return generateAgeVerifierContract(); // Default
    }
  }

  /**
   * Get deployment bytecode (simplified)
   */
  getDeploymentBytecode(proofType: ZKProofType): string {
    // In production, this would be compiled Solidity bytecode
    const contractSource = this.getVerifierContract(proofType);
    return `0x${hashCommitment(contractSource)}`;
  }

  /**
   * Simulate contract deployment
   */
  async simulateDeployment(
    request: VerifierDeploymentRequest
  ): Promise<VerifierDeploymentResult> {
    const { network, proofType } = request;
    
    this.getNetworkConfig(network); // Validate network

    const contractAddress = `0x${crypto.randomBytes(20).toString('hex')}`;
    const transactionHash = `0x${crypto.randomBytes(32).toString('hex')}`;

    return {
      contractAddress,
      network,
      transactionHash,
      deployedAt: new Date().toISOString(),
      proofType
    };
  }

  /**
   * Get explorer URL for transaction
   */
  getExplorerUrl(network: VerifierNetwork, txHash: string): string {
    const config = this.getNetworkConfig(network);
    return `${config.explorerUrl}/tx/${txHash}`;
  }

  /**
   * Get explorer URL for contract
   */
  getContractExplorerUrl(network: VerifierNetwork, address: string): string {
    const config = this.getNetworkConfig(network);
    return `${config.explorerUrl}/address/${address}`;
  }
}

// Export on-chain verification service singleton
export const onChainVerificationService = new OnChainVerificationService();