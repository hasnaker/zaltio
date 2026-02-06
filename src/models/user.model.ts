/**
 * User Model - Core user data structure for Zalt.io Auth Platform
 * Validates: Requirements 8.1 (data storage)
 */

export type UserStatus = 'active' | 'suspended' | 'pending_verification' | 'pending_document_review' | 'rejected';

export interface UserProfile {
  first_name?: string;
  last_name?: string;
  avatar_url?: string;
  metadata: Record<string, unknown>;
}

export interface WebAuthnCredentialData {
  id: string;
  credentialId: Buffer | string;
  publicKey: Buffer | string;
  counter: number;
  transports?: string[];
  createdAt: string;
  lastUsedAt?: string;
  deviceName?: string;
  aaguid?: string;
}

export interface User {
  id: string;
  realm_id: string;
  email: string;
  email_verified: boolean;
  password_hash: string;
  profile: UserProfile;
  created_at: string;
  updated_at: string;
  last_login: string;
  status: UserStatus;
  password_changed_at?: string;
  
  // Login security fields
  failed_login_attempts?: number;
  locked_until?: string;
  
  // MFA fields - TOTP
  mfa_enabled?: boolean;
  mfa_secret?: string;  // Encrypted TOTP secret
  backup_codes?: string[];  // Hashed backup codes
  
  // MFA fields - SMS (with risk acceptance)
  sms_mfa_enabled?: boolean;
  sms_phone_number?: string;  // E.164 format
  sms_risk_accepted?: boolean;  // User acknowledged SMS vulnerabilities
  
  // MFA fields - WhatsApp (recommended over SMS)
  whatsapp_mfa_enabled?: boolean;
  whatsapp_phone_number?: string;  // E.164 format without +
  
  // WebAuthn credentials
  webauthn_credentials?: WebAuthnCredentialData[];
  
  // Document verification (for student accounts)
  documents?: UserDocument[];
  verified_at?: string;
  verified_by?: string;
  verification_notes?: string;
}

export interface UserDocument {
  id: string;
  type: 'student_certificate' | 'id_card' | 'other';
  file_key: string;  // S3 key
  uploaded_at: string;
  status: 'pending' | 'approved' | 'rejected';
  reviewed_at?: string;
  reviewed_by?: string;
  notes?: string;
}

export interface CreateUserInput {
  realm_id: string;
  email: string;
  password: string;
  profile?: Partial<UserProfile>;
  documents?: Omit<UserDocument, 'id' | 'uploaded_at' | 'status'>[];
}

export interface UserResponse {
  id: string;
  realm_id: string;
  email: string;
  email_verified: boolean;
  profile: UserProfile;
  created_at: string;
  updated_at: string;
  last_login: string;
  status: UserStatus;
  mfa_enabled?: boolean;
}
