/**
 * Realm Model - Multi-tenant realm configuration
 * Validates: Requirements 1.1, 1.3 (multi-tenant architecture)
 */

export interface PasswordPolicy {
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_numbers: boolean;
  require_special_chars: boolean;
}

/**
 * MFA Policy Types
 * - disabled: MFA not available
 * - optional: User can choose to enable MFA
 * - required: MFA mandatory (healthcare realms!)
 */
export type MfaPolicy = 'disabled' | 'optional' | 'required';

/**
 * MFA Configuration for realm
 */
export interface MfaConfig {
  policy: MfaPolicy;
  allowed_methods: ('totp' | 'webauthn')[];
  remember_device_days: number;  // 0 = disabled, max 30 days
  grace_period_hours: number;    // Hours to setup MFA after first login (required policy)
  require_webauthn_for_sensitive: boolean;  // Require WebAuthn for sensitive actions
}

/**
 * Branding Configuration for realm
 * Allows each customer to show their own brand in OAuth screens and emails
 */
export interface BrandingConfig {
  // Display name shown in OAuth consent screens and emails
  display_name: string;
  
  // Logo URL for OAuth screens and email headers
  logo_url?: string;
  
  // Primary brand color (hex)
  primary_color?: string;
  
  // Support email shown in emails
  support_email?: string;
  
  // Custom email sender (requires SES domain verification)
  // e.g., "noreply@clinisyn.com" instead of "noreply@zalt.io"
  email_from_address?: string;
  email_from_name?: string;
  
  // Privacy policy and terms URLs for OAuth consent
  privacy_policy_url?: string;
  terms_of_service_url?: string;
  
  // Custom domain for password reset links etc.
  // e.g., "https://app.clinisyn.com" instead of "https://zalt.io"
  app_url?: string;
}

/**
 * Custom Risk Rules Configuration
 * Allows per-realm customization of AI risk assessment behavior
 * 
 * Validates: Requirement 10.8
 */
export interface CustomRiskRules {
  /**
   * IP addresses that bypass risk assessment entirely
   * Useful for corporate VPNs, office IPs, etc.
   * Supports both IPv4 and IPv6, and CIDR notation
   * Example: ['192.168.1.0/24', '10.0.0.1', '2001:db8::/32']
   */
  ip_whitelist: string[];
  
  /**
   * Device fingerprint hashes that are pre-trusted
   * These devices get a reduced risk score
   * Useful for known corporate devices
   */
  trusted_devices: TrustedDevice[];
  
  /**
   * Custom risk thresholds (override defaults)
   * Default: mfa_threshold=70, block_threshold=90
   */
  thresholds: RiskThresholds;
  
  /**
   * Risk score reduction for whitelisted IPs (0-100)
   * Default: 100 (complete bypass)
   */
  ip_whitelist_score_reduction: number;
  
  /**
   * Risk score reduction for trusted devices (0-100)
   * Default: 30
   */
  trusted_device_score_reduction: number;
  
  /**
   * Whether to enable custom risk rules
   * Default: false
   */
  enabled: boolean;
  
  /**
   * Audit all risk rule applications
   * Default: true
   */
  audit_enabled: boolean;
}

/**
 * Trusted device entry
 */
export interface TrustedDevice {
  /**
   * Device fingerprint hash (SHA-256)
   */
  fingerprint_hash: string;
  
  /**
   * Human-readable device name
   */
  name: string;
  
  /**
   * When this device was added to trusted list
   */
  added_at: string;
  
  /**
   * Who added this device (admin user ID)
   */
  added_by: string;
  
  /**
   * Optional expiration date
   */
  expires_at?: string;
  
  /**
   * Whether this device is currently active
   */
  active: boolean;
}

/**
 * Custom risk thresholds
 */
export interface RiskThresholds {
  /**
   * Score above which MFA is required (default: 70)
   */
  mfa_threshold: number;
  
  /**
   * Score above which login is blocked (default: 90)
   */
  block_threshold: number;
  
  /**
   * Score above which admin is alerted (default: 75)
   */
  alert_threshold: number;
}

/**
 * Session Limits Configuration
 * Validates: Requirement 13.6 - Configure maximum concurrent sessions per realm
 */
export interface SessionLimitsConfig {
  /**
   * Maximum concurrent sessions per user (0 = unlimited)
   * Default: 5
   */
  max_concurrent_sessions: number;
  
  /**
   * Action to take when limit is exceeded
   * - 'revoke_oldest': Revoke the oldest session (default)
   * - 'block_new': Block new session creation
   */
  limit_exceeded_action: 'revoke_oldest' | 'block_new';
  
  /**
   * Whether to notify user when session is revoked due to limit
   * Default: true
   */
  notify_on_revoke: boolean;
  
  /**
   * Whether session limits are enabled
   * Default: true
   */
  enabled: boolean;
}

export interface RealmSettings {
  password_policy: PasswordPolicy;
  session_timeout: number;
  mfa_required: boolean;  // DEPRECATED: Use mfa_config.policy instead
  mfa_config: MfaConfig;
  allowed_origins: string[];
  branding?: BrandingConfig;
  custom_risk_rules?: CustomRiskRules;
  session_limits?: SessionLimitsConfig;
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

export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
  min_length: 8,
  require_uppercase: true,
  require_lowercase: true,
  require_numbers: true,
  require_special_chars: false
};

export const DEFAULT_MFA_CONFIG: MfaConfig = {
  policy: 'optional',
  allowed_methods: ['totp', 'webauthn'],
  remember_device_days: 30,
  grace_period_hours: 24,
  require_webauthn_for_sensitive: false
};

/**
 * Healthcare realm MFA config (Clinisyn)
 * WebAuthn mandatory for Evilginx2 protection
 */
export const HEALTHCARE_MFA_CONFIG: MfaConfig = {
  policy: 'required',
  allowed_methods: ['totp', 'webauthn'],
  remember_device_days: 7,  // Shorter for healthcare
  grace_period_hours: 72,   // 3 days to setup MFA
  require_webauthn_for_sensitive: true
};

/**
 * Default custom risk rules (disabled by default)
 */
export const DEFAULT_CUSTOM_RISK_RULES: CustomRiskRules = {
  ip_whitelist: [],
  trusted_devices: [],
  thresholds: {
    mfa_threshold: 70,
    block_threshold: 90,
    alert_threshold: 75
  },
  ip_whitelist_score_reduction: 100,
  trusted_device_score_reduction: 30,
  enabled: false,
  audit_enabled: true
};

/**
 * Healthcare realm custom risk rules (stricter thresholds)
 */
export const HEALTHCARE_CUSTOM_RISK_RULES: CustomRiskRules = {
  ip_whitelist: [],
  trusted_devices: [],
  thresholds: {
    mfa_threshold: 50,    // Lower threshold for healthcare
    block_threshold: 80,  // Lower block threshold
    alert_threshold: 60   // Lower alert threshold
  },
  ip_whitelist_score_reduction: 100,
  trusted_device_score_reduction: 20,  // Less reduction for healthcare
  enabled: true,
  audit_enabled: true
};

/**
 * Default session limits configuration
 * Validates: Requirement 13.6 - Concurrent session limits per realm policy
 */
export const DEFAULT_SESSION_LIMITS: SessionLimitsConfig = {
  max_concurrent_sessions: 5,
  limit_exceeded_action: 'revoke_oldest',
  notify_on_revoke: true,
  enabled: true
};

/**
 * Healthcare realm session limits (stricter)
 */
export const HEALTHCARE_SESSION_LIMITS: SessionLimitsConfig = {
  max_concurrent_sessions: 3,  // Stricter for healthcare
  limit_exceeded_action: 'revoke_oldest',
  notify_on_revoke: true,
  enabled: true
};

export const DEFAULT_REALM_SETTINGS: RealmSettings = {
  password_policy: DEFAULT_PASSWORD_POLICY,
  session_timeout: 3600,
  mfa_required: false,  // DEPRECATED
  mfa_config: DEFAULT_MFA_CONFIG,
  allowed_origins: [],
  session_limits: DEFAULT_SESSION_LIMITS
};
