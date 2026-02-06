/**
 * Session Task Integration Service - Login Flow Integration for Zalt.io
 * 
 * This service evaluates conditions after successful login and creates
 * appropriate session tasks based on:
 * - User's organization memberships (choose_organization if multiple)
 * - Realm MFA policy vs user's MFA status (setup_mfa if required but not enabled)
 * - User's password status (reset_password if compromised)
 * 
 * Validates: Requirements 4.3, 4.4, 4.5 (Session Tasks)
 * 
 * Security:
 * - Compromised passwords force immediate reset
 * - MFA setup enforced by realm policy
 * - Organization selection required for multi-org users
 */

import { User } from '../models/user.model';
import { SessionTask, SessionTaskType } from '../models/session-task.model';
import { sessionTasksService } from './session-tasks.service';
import { getUserMemberships } from '../repositories/membership.repository';
import { getOrganization } from '../repositories/organization.repository';
import { getEffectiveMfaConfig, checkMfaSetupRequired } from './realm.service';

/**
 * Session task evaluation result
 */
export interface SessionTaskEvaluationResult {
  tasks: SessionTask[];
  hasBlockingTasks: boolean;
  requiresAction: boolean;
}

/**
 * Login context for session task evaluation
 */
export interface LoginContext {
  user: User;
  sessionId: string;
  realmId: string;
  passwordCompromised?: boolean;
  passwordExpired?: boolean;
  termsVersion?: string;
  currentTermsVersion?: string;
}

/**
 * Organization info for choose_organization task
 */
export interface OrganizationInfo {
  id: string;
  name: string;
  role?: string;
}

/**
 * Session Task Integration Service
 */
export class SessionTaskIntegrationService {
  
  /**
   * Evaluate and create session tasks after successful login
   * 
   * This is the main entry point called by the login handler after
   * successful authentication. It evaluates all conditions and creates
   * appropriate session tasks.
   * 
   * @param context - Login context with user and session info
   * @returns Evaluation result with created tasks
   */
  async evaluateAndCreateTasks(context: LoginContext): Promise<SessionTaskEvaluationResult> {
    const tasks: SessionTask[] = [];
    
    // Priority order:
    // 1. reset_password (highest priority - security critical)
    // 2. setup_mfa (high priority - security requirement)
    // 3. accept_terms (medium priority - legal requirement)
    // 4. choose_organization (lower priority - user preference)
    
    // 1. Check for compromised/expired password
    const passwordTask = await this.evaluatePasswordReset(context);
    if (passwordTask) {
      tasks.push(passwordTask);
    }
    
    // 2. Check for MFA setup requirement
    const mfaTask = await this.evaluateMfaSetup(context);
    if (mfaTask) {
      tasks.push(mfaTask);
    }
    
    // 3. Check for terms acceptance (if terms version provided)
    const termsTask = await this.evaluateTermsAcceptance(context);
    if (termsTask) {
      tasks.push(termsTask);
    }
    
    // 4. Check for organization selection
    const orgTask = await this.evaluateOrganizationSelection(context);
    if (orgTask) {
      tasks.push(orgTask);
    }
    
    const hasBlockingTasks = tasks.some(t => t.blocking);
    
    return {
      tasks,
      hasBlockingTasks,
      requiresAction: tasks.length > 0
    };
  }
  
  /**
   * Evaluate if password reset task is needed
   * 
   * Creates reset_password task if:
   * - Password is marked as compromised
   * - Password has expired (based on realm policy)
   * 
   * @param context - Login context
   * @returns Created task or null
   */
  async evaluatePasswordReset(context: LoginContext): Promise<SessionTask | null> {
    const { user, sessionId, realmId, passwordCompromised, passwordExpired } = context;
    
    // Check if password is compromised
    if (passwordCompromised) {
      try {
        const task = await sessionTasksService.createTask(
          sessionId,
          user.id,
          realmId,
          'reset_password',
          {
            reason: 'compromised',
            compromised_at: new Date().toISOString(),
            message: 'Your password has been found in a data breach. Please reset it immediately.'
          }
        );
        
        this.logTaskCreation('reset_password', user.id, 'password_compromised');
        return task;
      } catch (error) {
        // Task might already exist for this session
        if ((error as Error).message?.includes('TASK_ALREADY_EXISTS')) {
          return null;
        }
        throw error;
      }
    }
    
    // Check if password has expired
    if (passwordExpired) {
      try {
        const task = await sessionTasksService.createTask(
          sessionId,
          user.id,
          realmId,
          'reset_password',
          {
            reason: 'expired',
            message: 'Your password has expired. Please set a new password.'
          }
        );
        
        this.logTaskCreation('reset_password', user.id, 'password_expired');
        return task;
      } catch (error) {
        if ((error as Error).message?.includes('TASK_ALREADY_EXISTS')) {
          return null;
        }
        throw error;
      }
    }
    
    return null;
  }
  
  /**
   * Evaluate if MFA setup task is needed
   * 
   * Creates setup_mfa task if:
   * - Realm MFA policy is 'required'
   * - User does not have MFA enabled (TOTP or WebAuthn)
   * - Grace period has not expired (if applicable)
   * 
   * @param context - Login context
   * @returns Created task or null
   */
  async evaluateMfaSetup(context: LoginContext): Promise<SessionTask | null> {
    const { user, sessionId, realmId } = context;
    
    // Check if user already has MFA enabled
    const userHasMfa = user.mfa_enabled || 
      (user.webauthn_credentials && user.webauthn_credentials.length > 0);
    
    if (userHasMfa) {
      return null;
    }
    
    // Get realm MFA configuration
    const mfaConfig = await getEffectiveMfaConfig(realmId);
    
    // Only create task if MFA is required by policy
    if (mfaConfig.policy !== 'required') {
      return null;
    }
    
    // Check if MFA setup is required (considering grace period)
    const setupStatus = await checkMfaSetupRequired(realmId, user);
    
    if (!setupStatus.required) {
      return null;
    }
    
    try {
      const task = await sessionTasksService.createTask(
        sessionId,
        user.id,
        realmId,
        'setup_mfa',
        {
          required_mfa_methods: mfaConfig.allowed_methods,
          message: setupStatus.message || 'MFA setup is required by your organization policy'
        }
      );
      
      this.logTaskCreation('setup_mfa', user.id, 'mfa_policy_required');
      return task;
    } catch (error) {
      if ((error as Error).message?.includes('TASK_ALREADY_EXISTS')) {
        return null;
      }
      throw error;
    }
  }
  
  /**
   * Evaluate if terms acceptance task is needed
   * 
   * Creates accept_terms task if:
   * - Current terms version is provided
   * - User has not accepted the current version
   * 
   * @param context - Login context
   * @returns Created task or null
   */
  async evaluateTermsAcceptance(context: LoginContext): Promise<SessionTask | null> {
    const { user, sessionId, realmId, termsVersion, currentTermsVersion } = context;
    
    // Skip if no terms version tracking
    if (!currentTermsVersion) {
      return null;
    }
    
    // Check if user has accepted current terms
    if (termsVersion === currentTermsVersion) {
      return null;
    }
    
    try {
      const task = await sessionTasksService.createTask(
        sessionId,
        user.id,
        realmId,
        'accept_terms',
        {
          terms_version: currentTermsVersion,
          message: 'Please accept the updated terms of service'
        }
      );
      
      this.logTaskCreation('accept_terms', user.id, 'terms_updated');
      return task;
    } catch (error) {
      if ((error as Error).message?.includes('TASK_ALREADY_EXISTS')) {
        return null;
      }
      throw error;
    }
  }
  
  /**
   * Evaluate if organization selection task is needed
   * 
   * Creates choose_organization task if:
   * - User belongs to multiple organizations
   * - No default organization is selected
   * 
   * @param context - Login context
   * @returns Created task or null
   */
  async evaluateOrganizationSelection(context: LoginContext): Promise<SessionTask | null> {
    const { user, sessionId, realmId } = context;
    
    // Get user's organization memberships
    const memberships = await getUserMemberships({
      user_id: user.id,
      realm_id: realmId,
      status: 'active'
    });
    
    // No task needed if user has 0 or 1 organization
    if (memberships.length <= 1) {
      return null;
    }
    
    // Check if user has a default organization selected
    const hasDefault = memberships.some(m => m.is_default);
    if (hasDefault) {
      return null;
    }
    
    // Build organization list for the task
    const organizations: OrganizationInfo[] = [];
    
    for (const membership of memberships) {
      const org = await getOrganization(membership.org_id);
      if (org && org.status === 'active') {
        organizations.push({
          id: org.id,
          name: org.name,
          role: membership.role_ids?.[0] // Primary role
        });
      }
    }
    
    // Only create task if there are multiple active organizations
    if (organizations.length <= 1) {
      return null;
    }
    
    try {
      const task = await sessionTasksService.createTask(
        sessionId,
        user.id,
        realmId,
        'choose_organization',
        {
          available_organizations: organizations,
          message: 'Please select an organization to continue'
        }
      );
      
      this.logTaskCreation('choose_organization', user.id, 'multiple_orgs');
      return task;
    } catch (error) {
      if ((error as Error).message?.includes('TASK_ALREADY_EXISTS')) {
        return null;
      }
      throw error;
    }
  }
  
  /**
   * Check if a user has a compromised password flag
   * This would typically be set by:
   * - Admin marking password as compromised
   * - Background job detecting breach
   * - HaveIBeenPwned check during login
   * 
   * @param userId - User ID to check
   * @param realmId - Realm ID
   * @returns True if password is compromised
   */
  async isPasswordCompromised(userId: string, realmId: string): Promise<boolean> {
    // This would check a flag in the user record or a separate table
    // For now, return false - actual implementation would query DynamoDB
    // The login handler will pass this flag based on its own checks
    return false;
  }
  
  /**
   * Check if a user's password has expired based on realm policy
   * 
   * @param user - User to check
   * @param realmId - Realm ID
   * @returns True if password has expired
   */
  async isPasswordExpired(user: User, realmId: string): Promise<boolean> {
    // Check if realm has password expiry policy
    // For now, return false - actual implementation would check realm settings
    // and compare with user.password_changed_at
    if (!user.password_changed_at) {
      return false;
    }
    
    // TODO: Get realm password expiry policy and compare
    // const realmSettings = await getRealmSettings(realmId);
    // if (realmSettings.password_expiry_days) {
    //   const expiryDate = new Date(user.password_changed_at);
    //   expiryDate.setDate(expiryDate.getDate() + realmSettings.password_expiry_days);
    //   return new Date() > expiryDate;
    // }
    
    return false;
  }
  
  /**
   * Log task creation for audit purposes
   */
  private logTaskCreation(taskType: SessionTaskType, userId: string, reason: string): void {
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[SESSION_TASK] Created ${taskType} task for user ${userId}: ${reason}`);
    }
  }
}

// Export singleton instance
export const sessionTaskIntegrationService = new SessionTaskIntegrationService();
