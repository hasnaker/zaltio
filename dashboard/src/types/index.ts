export * from './auth';
export * from './realm';

/**
 * User types for HSD Auth Dashboard
 * Validates: Requirements 3.2
 */
export interface User {
  id: string;
  realm_id: string;
  email: string;
  email_verified: boolean;
  status: 'active' | 'suspended' | 'pending_verification';
  profile?: {
    first_name?: string;
    last_name?: string;
    avatar_url?: string;
    metadata?: Record<string, unknown>;
  };
  created_at: string;
  updated_at?: string;
  last_login: string;
}
