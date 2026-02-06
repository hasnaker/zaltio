/**
 * Backup and Disaster Recovery Configuration for HSD Auth Platform
 * Validates: Requirements 7.5, 8.3
 * 
 * Configures automated DynamoDB backups with point-in-time recovery
 * and cross-region backup replication
 */

import { AWS_CONFIG } from './aws.config';

/**
 * Point-in-time recovery configuration for DynamoDB
 */
export const PITR_CONFIG = {
  // Enable point-in-time recovery for all tables
  enabled: true,
  
  // Tables with PITR enabled
  tables: Object.values(AWS_CONFIG.dynamodb.tables),
  
  // Recovery window (DynamoDB supports up to 35 days)
  recoveryWindowDays: 35
} as const;

/**
 * On-demand backup configuration
 */
export const BACKUP_CONFIG = {
  // Backup schedule (cron expression for daily backups at 2 AM UTC)
  schedule: 'cron(0 2 * * ? *)',
  
  // Backup retention period in days
  retentionDays: 30,
  
  // Backup naming convention
  namePrefix: 'zalt-backup',
  
  // Tables to backup
  tables: Object.values(AWS_CONFIG.dynamodb.tables),
  
  // Backup tags for organization
  tags: {
    Environment: process.env.ENVIRONMENT || 'production',
    Application: 'zalt-platform',
    ManagedBy: 'automated-backup'
  }
} as const;

/**
 * Cross-region replication configuration
 */
export const REPLICATION_CONFIG = {
  // Enable cross-region replication
  enabled: false, // Set to true when ready for multi-region
  
  // Primary region
  primaryRegion: AWS_CONFIG.region,
  
  // Replica regions for disaster recovery
  replicaRegions: ['eu-west-1'] as const,
  
  // Replication settings
  settings: {
    // Enable global tables for automatic replication
    globalTables: false,
    
    // Manual backup replication to S3
    s3Replication: {
      enabled: true,
      bucket: 'zalt-backups',
      prefix: 'dynamodb-backups/',
      replicaBucket: 'zalt-backups-replica'
    }
  }
} as const;

/**
 * Disaster recovery configuration
 */
export const DISASTER_RECOVERY_CONFIG = {
  // Recovery Time Objective (RTO) in minutes
  rtoMinutes: 60,
  
  // Recovery Point Objective (RPO) in minutes
  rpoMinutes: 15,
  
  // Failover configuration
  failover: {
    // Automatic failover enabled
    automatic: false,
    
    // Health check threshold before failover
    healthCheckThreshold: 3,
    
    // Failover regions in priority order
    regions: [AWS_CONFIG.region, 'eu-west-1'] as const
  },
  
  // Recovery procedures
  procedures: {
    // Database recovery
    database: {
      method: 'pitr', // 'pitr' | 'backup' | 'global-table'
      maxRecoveryTime: 30 // minutes
    },
    
    // Application recovery
    application: {
      method: 'redeploy',
      maxRecoveryTime: 15 // minutes
    },
    
    // DNS failover
    dns: {
      method: 'route53-health-check',
      ttl: 60 // seconds
    }
  },
  
  // Notification settings
  notifications: {
    snsTopicArn: process.env.DR_SNS_TOPIC_ARN || '',
    emailRecipients: [] as string[]
  }
} as const;

/**
 * Backup verification configuration
 */
export const BACKUP_VERIFICATION_CONFIG = {
  // Enable backup verification
  enabled: true,
  
  // Verification schedule (weekly on Sundays at 4 AM UTC)
  schedule: 'cron(0 4 ? * SUN *)',
  
  // Verification method
  method: 'restore-test' as const,
  
  // Test restore settings
  testRestore: {
    // Restore to a test table
    tablePrefix: 'zalt-backup-test-',
    
    // Delete test table after verification
    cleanupAfterTest: true,
    
    // Verification timeout in minutes
    timeoutMinutes: 30
  }
} as const;

export type PITRConfig = typeof PITR_CONFIG;
export type BackupConfig = typeof BACKUP_CONFIG;
export type ReplicationConfig = typeof REPLICATION_CONFIG;
export type DisasterRecoveryConfig = typeof DISASTER_RECOVERY_CONFIG;
export type BackupVerificationConfig = typeof BACKUP_VERIFICATION_CONFIG;
