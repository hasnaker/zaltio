/**
 * Realm types for HSD Auth Dashboard
 * Validates: Requirements 1.1, 1.3, 3.2
 */

export interface PasswordPolicy {
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_numbers: boolean;
  require_special_chars: boolean;
}

export interface RealmSettings {
  password_policy: PasswordPolicy;
  session_timeout: number;
  mfa_required: boolean;
  allowed_origins: string[];
}

export type AuthProviderType = 'email_password' | 'oauth' | 'sso';

export interface AuthProvider {
  type: AuthProviderType;
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface Realm {
  id: string;
  name: string;
  domain: string;
  settings: RealmSettings;
  auth_providers: AuthProvider[];
  created_at: string;
  updated_at: string;
}

export interface CreateRealmInput {
  name: string;
  domain: string;
  settings?: Partial<RealmSettings>;
  auth_providers?: AuthProvider[];
}

export interface UpdateRealmInput {
  name?: string;
  domain?: string;
  settings?: Partial<RealmSettings>;
  auth_providers?: AuthProvider[];
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  min_length: 8,
  require_uppercase: true,
  require_lowercase: true,
  require_numbers: true,
  require_special_chars: false
};

export const DEFAULT_REALM_SETTINGS: RealmSettings = {
  password_policy: DEFAULT_PASSWORD_POLICY,
  session_timeout: 3600,
  mfa_required: false,
  allowed_origins: []
};
