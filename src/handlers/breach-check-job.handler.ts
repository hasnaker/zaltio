/**
 * Background Breach Check Job Handler
 * Task 17.4: Implement background breach check job
 * 
 * This Lambda is triggered by CloudWatch Events (daily schedule) to:
 * 1. Iterate through users in batches
 * 2. Check each user's password SHA-1 hash against HIBP
 * 3. If compromised, create reset_password session task
 * 4. Send notification email to affected users
 * 5. Log results and metrics
 * 
 * SECURITY NOTES:
 * - Uses k-Anonymity API (only first 5 chars of SHA-1 sent to HIBP)
 * - Rate limits HIBP API calls to avoid being blocked
 * - Processes users in batches to avoid Lambda timeouts
 * - Tracks progress for resumption if interrupted
 * 
 * _Requirements: 8.7, 8.8_
 */

import { ScheduledEvent, Context } from 'aws-lambda';
import { HIBPService, createHIBPService } from '../services/hibp.service';
import { SessionTasksService, sessionTasksService } from '../services/session-tasks.service';
import { sendBreachNotificationEmail } from '../services/email.service';
import { listRealmUsers } from '../repositories/user.repository';
import { findUserById, updateUserBreachStatus } from '../repositories/user.repository';
import { getUserSessions } from '../repositories/session.repository';
import { listRealms } from '../repositories/realm.repository';
import { logSecurityEvent } from '../services/security-logger.service';

/**
 * Configuration for the breach check job
 */
export interface BreachCheckJobConfig {
  /** Batch size for processing users (default: 100) */
  batchSize: number;
  /** Delay between HIBP API calls in ms (default: 100ms for rate limiting) */
  apiDelayMs: number;
  /** Maximum users to process per invocation (default: 1000) */
  maxUsersPerInvocation: number;
  /** Whether to send notification emails (default: true) */
  sendNotifications: boolean;
  /** Whether to create session tasks (default: true) */
  createSessionTasks: boolean;
  /** Minimum days since last check before re-checking (default: 7) */
  minDaysSinceLastCheck: number;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: BreachCheckJobConfig = {
  batchSize: 100,
  apiDelayMs: 100, // 10 requests per second to respect HIBP rate limits
  maxUsersPerInvocation: 1000,
  sendNotifications: true,
  createSessionTasks: true,
  minDaysSinceLastCheck: 7,
};

/**
 * Result of the breach check job
 */
export interface BreachCheckJobResult {
  /** Total users checked */
  usersChecked: number;
  /** Users found with compromised passwords */
  breachesFound: number;
  /** Notification emails sent */
  emailsSent: number;
  /** Session tasks created */
  tasksCreated: number;
  /** Errors encountered */
  errors: Array<{ userId: string; realmId: string; error: string }>;
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Whether the job completed all users or was interrupted */
  completed: boolean;
  /** Last processed user ID for resumption */
  lastProcessedUserId?: string;
  /** Realms processed */
  realmsProcessed: number;
}

/**
 * User with password SHA-1 hash for breach checking
 */
interface UserWithPasswordHash {
  id: string;
  realm_id: string;
  email: string;
  password_sha1_hash?: string;
  password_breach_checked_at?: string;
  password_compromised?: boolean;
}

/**
 * Sleep utility for rate limiting
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Check if user needs breach check based on last check time
 */
function needsBreachCheck(
  user: UserWithPasswordHash,
  minDaysSinceLastCheck: number
): boolean {
  // Always check if never checked before
  if (!user.password_breach_checked_at) {
    return true;
  }

  // Skip if already marked as compromised (user needs to reset password first)
  if (user.password_compromised) {
    return false;
  }

  // Check if enough time has passed since last check
  const lastCheck = new Date(user.password_breach_checked_at);
  const daysSinceLastCheck = (Date.now() - lastCheck.getTime()) / (1000 * 60 * 60 * 24);
  
  return daysSinceLastCheck >= minDaysSinceLastCheck;
}

/**
 * Process a single user for breach check
 */
async function processUser(
  user: UserWithPasswordHash,
  hibpService: HIBPService,
  config: BreachCheckJobConfig
): Promise<{
  breachFound: boolean;
  emailSent: boolean;
  taskCreated: boolean;
  error?: string;
}> {
  const result = {
    breachFound: false,
    emailSent: false,
    taskCreated: false,
    error: undefined as string | undefined,
  };

  try {
    // Skip if no SHA-1 hash stored (legacy users before this feature)
    if (!user.password_sha1_hash) {
      return result;
    }

    // Check password hash against HIBP using the stored SHA-1 hash
    const hibpResult = await hibpService.checkPasswordHash(user.password_sha1_hash);

    // Update last checked timestamp
    await updateUserBreachStatus(user.realm_id, user.id, {
      password_breach_checked_at: new Date().toISOString(),
      password_compromised: hibpResult.isCompromised,
      password_breach_count: hibpResult.count,
    });

    if (!hibpResult.isCompromised) {
      return result;
    }

    result.breachFound = true;

    // Log security event
    await logSecurityEvent({
      event_type: 'password_breach_detected',
      ip_address: 'background-job', // No client IP for scheduled jobs
      realm_id: user.realm_id,
      user_id: user.id,
      details: {
        breach_count: hibpResult.count,
        detection_method: 'background_job',
      },
    });

    // Create session task for password reset (Requirement 8.7)
    if (config.createSessionTasks) {
      try {
        // Get user's active sessions
        const sessions = await getUserSessions(user.realm_id, user.id);
        
        if (sessions.length > 0) {
          // Create reset_password task for the first session
          await sessionTasksService.forcePasswordReset(user.id, user.realm_id, {
            reason: 'compromised',
            message: 'Your password was found in a data breach. Please reset it immediately.',
            revokeAllSessions: false, // Don't revoke sessions, just require password reset
          });
          result.taskCreated = true;
        }
      } catch (taskError) {
        console.warn(`Failed to create session task for user ${user.id}:`, taskError);
      }
    }

    // Send notification email (Requirement 8.8)
    if (config.sendNotifications) {
      try {
        const emailResult = await sendBreachNotificationEmail(
          user.email,
          user.realm_id,
          {
            breachCount: hibpResult.count,
            detectedAt: new Date().toISOString(),
          }
        );
        result.emailSent = emailResult.success;
      } catch (emailError) {
        console.warn(`Failed to send breach notification to ${user.email}:`, emailError);
      }
    }

    return result;
  } catch (error) {
    result.error = error instanceof Error ? error.message : 'Unknown error';
    return result;
  }
}

/**
 * Process users in a realm
 */
async function processRealm(
  realmId: string,
  hibpService: HIBPService,
  config: BreachCheckJobConfig,
  result: BreachCheckJobResult,
  remainingUsers: number
): Promise<number> {
  let processedInRealm = 0;
  let lastEvaluatedKey: Record<string, unknown> | undefined;

  do {
    // Check if we've hit the max users limit
    if (result.usersChecked >= config.maxUsersPerInvocation) {
      result.completed = false;
      break;
    }

    // Fetch batch of users
    const usersResult = await listRealmUsers(realmId, {
      limit: Math.min(config.batchSize, remainingUsers - processedInRealm),
      lastEvaluatedKey,
    });

    // Process each user in the batch
    for (const userResponse of usersResult.users) {
      // Check if we've hit the max users limit
      if (result.usersChecked >= config.maxUsersPerInvocation) {
        result.completed = false;
        result.lastProcessedUserId = userResponse.id;
        break;
      }

      // Get full user data with password hash
      const user = await findUserById(realmId, userResponse.id) as UserWithPasswordHash | null;
      
      if (!user) {
        continue;
      }

      // Skip if doesn't need check
      if (!needsBreachCheck(user, config.minDaysSinceLastCheck)) {
        continue;
      }

      // Rate limit HIBP API calls
      await sleep(config.apiDelayMs);

      // Process the user
      const userResult = await processUser(user, hibpService, config);

      result.usersChecked++;
      processedInRealm++;

      if (userResult.breachFound) {
        result.breachesFound++;
      }
      if (userResult.emailSent) {
        result.emailsSent++;
      }
      if (userResult.taskCreated) {
        result.tasksCreated++;
      }
      if (userResult.error) {
        result.errors.push({
          userId: user.id,
          realmId: user.realm_id,
          error: userResult.error,
        });
      }

      result.lastProcessedUserId = user.id;
    }

    lastEvaluatedKey = usersResult.lastEvaluatedKey as Record<string, unknown> | undefined;
  } while (lastEvaluatedKey && result.usersChecked < config.maxUsersPerInvocation);

  return processedInRealm;
}

/**
 * Main handler for the breach check job
 * Triggered by CloudWatch Events on a daily schedule
 */
export async function handler(
  event: ScheduledEvent,
  context: Context
): Promise<BreachCheckJobResult> {
  const startTime = Date.now();
  
  // Parse configuration from event or use defaults
  const config: BreachCheckJobConfig = {
    ...DEFAULT_CONFIG,
    ...(event.detail as Partial<BreachCheckJobConfig> || {}),
  };

  // Initialize result
  const result: BreachCheckJobResult = {
    usersChecked: 0,
    breachesFound: 0,
    emailsSent: 0,
    tasksCreated: 0,
    errors: [],
    processingTimeMs: 0,
    completed: true,
    realmsProcessed: 0,
  };

  // Create HIBP service with appropriate configuration
  const hibpService = createHIBPService({
    cacheTtlMs: 5 * 60 * 1000, // 5 minutes cache
    maxCacheSize: 10000,
    timeoutMs: 10000, // 10 second timeout for background job
    failOpen: true, // Don't fail the entire job on API errors
  });

  try {
    // Log job start
    await logSecurityEvent({
      event_type: 'breach_check_job_started',
      ip_address: 'background-job', // No client IP for scheduled jobs
      details: {
        config: {
          batchSize: config.batchSize,
          maxUsersPerInvocation: config.maxUsersPerInvocation,
          minDaysSinceLastCheck: config.minDaysSinceLastCheck,
        },
        requestId: context.awsRequestId,
      },
    });

    // Get all realms
    const realms = await listRealms();

    // Process each realm
    for (const realm of realms) {
      // Check if we've hit the max users limit
      if (result.usersChecked >= config.maxUsersPerInvocation) {
        result.completed = false;
        break;
      }

      const remainingUsers = config.maxUsersPerInvocation - result.usersChecked;
      await processRealm(realm.id, hibpService, config, result, remainingUsers);
      result.realmsProcessed++;
    }

    // Calculate processing time
    result.processingTimeMs = Date.now() - startTime;

    // Log job completion
    await logSecurityEvent({
      event_type: 'breach_check_job_completed',
      ip_address: 'background-job', // No client IP for scheduled jobs
      details: {
        usersChecked: result.usersChecked,
        breachesFound: result.breachesFound,
        emailsSent: result.emailsSent,
        tasksCreated: result.tasksCreated,
        errorCount: result.errors.length,
        processingTimeMs: result.processingTimeMs,
        completed: result.completed,
        realmsProcessed: result.realmsProcessed,
        requestId: context.awsRequestId,
      },
    });

    // Log cache statistics
    const cacheStats = hibpService.getCacheStats();
    console.log('HIBP Cache Stats:', JSON.stringify(cacheStats));

    return result;
  } catch (error) {
    // Log job failure
    await logSecurityEvent({
      event_type: 'breach_check_job_failed',
      ip_address: 'background-job', // No client IP for scheduled jobs
      details: {
        error: error instanceof Error ? error.message : 'Unknown error',
        usersChecked: result.usersChecked,
        processingTimeMs: Date.now() - startTime,
        requestId: context.awsRequestId,
      },
    });

    throw error;
  }
}

/**
 * Export for testing
 */
export const _testing = {
  needsBreachCheck,
  processUser,
  processRealm,
  sleep,
  DEFAULT_CONFIG,
};
