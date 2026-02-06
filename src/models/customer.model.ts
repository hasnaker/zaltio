/**
 * Customer Model - Platform customer (B2B) data structure for Zalt.io
 * These are the companies/developers who use Zalt.io to add auth to their apps
 * NOT end-users - those are in user.model.ts
 * 
 * Validates: Requirements 1.2, 1.5 (Customer account system)
 */

export type CustomerPlan = 'free' | 'pro' | 'enterprise';
export type CustomerStatus = 'active' | 'suspended' | 'pending_verification' | 'churned';

export interface CustomerBillingInfo {
  stripe_customer_id?: string;
  stripe_subscription_id?: string;
  plan: CustomerPlan;
  plan_started_at?: string;
  plan_expires_at?: string;
  payment_method_last4?: string;
  payment_method_brand?: string;
}

export interface CustomerUsageLimits {
  max_mau: number;           // Monthly Active Users limit
  max_realms: number;        // Number of realms/apps
  max_api_calls: number;     // API calls per month
  mfa_enabled: boolean;      // MFA feature available
  sso_enabled: boolean;      // SSO/SAML feature available
  webhooks_enabled: boolean; // Webhooks feature available
  audit_logs_days: number;   // Audit log retention days
}

export interface CustomerProfile {
  company_name: string;
  company_website?: string;
  company_size?: 'startup' | 'small' | 'medium' | 'enterprise';
  industry?: string;
  contact_name?: string;
  contact_phone?: string;
  timezone?: string;
  metadata?: Record<string, unknown>;
}

export interface Customer {
  id: string;                    // customer_xxx format
  email: string;                 // Primary contact email
  email_verified: boolean;
  password_hash: string;         // Argon2id hashed
  profile: CustomerProfile;
  billing: CustomerBillingInfo;
  usage_limits: CustomerUsageLimits;
  status: CustomerStatus;
  
  // Timestamps
  created_at: string;
  updated_at: string;
  last_login_at?: string;
  
  // Security
  failed_login_attempts?: number;
  locked_until?: string;
  mfa_enabled?: boolean;
  mfa_secret?: string;
  
  // Default realm created on signup
  default_realm_id?: string;
}

export interface CreateCustomerInput {
  email: string;
  password: string;
  company_name: string;
  company_website?: string;
  plan?: CustomerPlan;
}

export interface CustomerResponse {
  id: string;
  email: string;
  email_verified: boolean;
  profile: CustomerProfile;
  billing: Omit<CustomerBillingInfo, 'stripe_customer_id' | 'stripe_subscription_id'>;
  usage_limits: CustomerUsageLimits;
  status: CustomerStatus;
  created_at: string;
  default_realm_id?: string;
}

// Plan limits configuration
export const PLAN_LIMITS: Record<CustomerPlan, CustomerUsageLimits> = {
  free: {
    max_mau: 1000,
    max_realms: 1,
    max_api_calls: 10000,
    mfa_enabled: true,
    sso_enabled: false,
    webhooks_enabled: false,
    audit_logs_days: 7
  },
  pro: {
    max_mau: 10000,
    max_realms: 5,
    max_api_calls: 100000,
    mfa_enabled: true,
    sso_enabled: true,
    webhooks_enabled: true,
    audit_logs_days: 30
  },
  enterprise: {
    max_mau: -1,  // Unlimited
    max_realms: -1,
    max_api_calls: -1,
    mfa_enabled: true,
    sso_enabled: true,
    webhooks_enabled: true,
    audit_logs_days: 365  // 1 year (HIPAA requires 6 years, handled separately)
  }
};

export const DEFAULT_CUSTOMER_BILLING: CustomerBillingInfo = {
  plan: 'free',
  plan_started_at: new Date().toISOString()
};
