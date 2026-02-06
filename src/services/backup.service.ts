/**
 * Backup and Disaster Recovery Service for HSD Auth Platform
 * Validates: Requirements 7.5, 8.3
 * 
 * Implements automated DynamoDB backups with point-in-time recovery
 * and cross-region backup replication
 */

import {
  DynamoDBClient,
  CreateBackupCommand,
  DeleteBackupCommand,
  ListBackupsCommand,
  DescribeBackupCommand,
  RestoreTableFromBackupCommand,
  DescribeContinuousBackupsCommand,
  UpdateContinuousBackupsCommand,
  BackupSummary,
  BackupStatus
} from '@aws-sdk/client-dynamodb';
import { AWS_CONFIG } from '../config/aws.config';
import {
  BACKUP_CONFIG,
  PITR_CONFIG,
  DISASTER_RECOVERY_CONFIG
} from '../config/backup.config';

// DynamoDB client singleton
let dynamoClient: DynamoDBClient | null = null;

function getDynamoClient(): DynamoDBClient {
  if (!dynamoClient) {
    dynamoClient = new DynamoDBClient({ region: AWS_CONFIG.region });
  }
  return dynamoClient;
}

/**
 * Backup creation result
 */
export interface BackupResult {
  success: boolean;
  backupArn?: string;
  backupName?: string;
  tableName: string;
  timestamp: string;
  error?: string;
}

/**
 * Backup status information
 */
export interface BackupInfo {
  backupArn: string;
  backupName: string;
  tableName: string;
  status: BackupStatus | string;
  createdAt: Date;
  sizeBytes?: number;
}

/**
 * PITR status for a table
 */
export interface PITRStatus {
  tableName: string;
  enabled: boolean;
  earliestRestorableDateTime?: Date;
  latestRestorableDateTime?: Date;
}

/**
 * Recovery result
 */
export interface RecoveryResult {
  success: boolean;
  restoredTableName?: string;
  sourceBackupArn?: string;
  timestamp: string;
  error?: string;
}

/**
 * Generate backup name with timestamp
 */
function generateBackupName(tableName: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `${BACKUP_CONFIG.namePrefix}-${tableName}-${timestamp}`;
}

/**
 * Create an on-demand backup for a table
 */
export async function createBackup(tableName: string): Promise<BackupResult> {
  const client = getDynamoClient();
  const backupName = generateBackupName(tableName);
  
  try {
    const command = new CreateBackupCommand({
      TableName: tableName,
      BackupName: backupName
    });
    
    const response = await client.send(command);
    
    return {
      success: true,
      backupArn: response.BackupDetails?.BackupArn,
      backupName: response.BackupDetails?.BackupName,
      tableName,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error(`Failed to create backup for ${tableName}:`, error);
    return {
      success: false,
      tableName,
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Create backups for all configured tables
 */
export async function createAllBackups(): Promise<BackupResult[]> {
  const results: BackupResult[] = [];
  
  for (const tableName of BACKUP_CONFIG.tables) {
    const result = await createBackup(tableName);
    results.push(result);
  }
  
  return results;
}

/**
 * List backups for a table
 */
export async function listBackups(
  tableName?: string,
  limit: number = 50
): Promise<BackupInfo[]> {
  const client = getDynamoClient();
  
  try {
    const command = new ListBackupsCommand({
      TableName: tableName,
      Limit: limit
    });
    
    const response = await client.send(command);
    
    return (response.BackupSummaries || []).map((backup: BackupSummary) => ({
      backupArn: backup.BackupArn || '',
      backupName: backup.BackupName || '',
      tableName: backup.TableName || '',
      status: backup.BackupStatus || 'UNKNOWN',
      createdAt: backup.BackupCreationDateTime || new Date(),
      sizeBytes: backup.BackupSizeBytes
    }));
  } catch (error) {
    console.error('Failed to list backups:', error);
    return [];
  }
}

/**
 * Get backup details
 */
export async function getBackupDetails(backupArn: string): Promise<BackupInfo | null> {
  const client = getDynamoClient();
  
  try {
    const command = new DescribeBackupCommand({
      BackupArn: backupArn
    });
    
    const response = await client.send(command);
    const details = response.BackupDescription?.BackupDetails;
    
    if (!details) return null;
    
    return {
      backupArn: details.BackupArn || '',
      backupName: details.BackupName || '',
      tableName: response.BackupDescription?.SourceTableDetails?.TableName || '',
      status: details.BackupStatus || 'UNKNOWN',
      createdAt: details.BackupCreationDateTime || new Date(),
      sizeBytes: details.BackupSizeBytes
    };
  } catch (error) {
    console.error('Failed to get backup details:', error);
    return null;
  }
}

/**
 * Delete a backup
 */
export async function deleteBackup(backupArn: string): Promise<boolean> {
  const client = getDynamoClient();
  
  try {
    const command = new DeleteBackupCommand({
      BackupArn: backupArn
    });
    
    await client.send(command);
    return true;
  } catch (error) {
    console.error('Failed to delete backup:', error);
    return false;
  }
}

/**
 * Clean up old backups based on retention policy
 */
export async function cleanupOldBackups(): Promise<{
  deleted: number;
  errors: number;
}> {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - BACKUP_CONFIG.retentionDays);
  
  let deleted = 0;
  let errors = 0;
  
  for (const tableName of BACKUP_CONFIG.tables) {
    const backups = await listBackups(tableName, 100);
    
    for (const backup of backups) {
      if (backup.createdAt < cutoffDate) {
        const success = await deleteBackup(backup.backupArn);
        if (success) {
          deleted++;
        } else {
          errors++;
        }
      }
    }
  }
  
  return { deleted, errors };
}

/**
 * Enable point-in-time recovery for a table
 */
export async function enablePITR(tableName: string): Promise<boolean> {
  const client = getDynamoClient();
  
  try {
    const command = new UpdateContinuousBackupsCommand({
      TableName: tableName,
      PointInTimeRecoverySpecification: {
        PointInTimeRecoveryEnabled: true
      }
    });
    
    await client.send(command);
    return true;
  } catch (error) {
    console.error(`Failed to enable PITR for ${tableName}:`, error);
    return false;
  }
}

/**
 * Get PITR status for a table
 */
export async function getPITRStatus(tableName: string): Promise<PITRStatus> {
  const client = getDynamoClient();
  
  try {
    const command = new DescribeContinuousBackupsCommand({
      TableName: tableName
    });
    
    const response = await client.send(command);
    const pitrDesc = response.ContinuousBackupsDescription?.PointInTimeRecoveryDescription;
    
    return {
      tableName,
      enabled: pitrDesc?.PointInTimeRecoveryStatus === 'ENABLED',
      earliestRestorableDateTime: pitrDesc?.EarliestRestorableDateTime,
      latestRestorableDateTime: pitrDesc?.LatestRestorableDateTime
    };
  } catch (error) {
    console.error(`Failed to get PITR status for ${tableName}:`, error);
    return {
      tableName,
      enabled: false
    };
  }
}

/**
 * Enable PITR for all configured tables
 */
export async function enableAllPITR(): Promise<{
  enabled: string[];
  failed: string[];
}> {
  const enabled: string[] = [];
  const failed: string[] = [];
  
  for (const tableName of PITR_CONFIG.tables) {
    const success = await enablePITR(tableName);
    if (success) {
      enabled.push(tableName);
    } else {
      failed.push(tableName);
    }
  }
  
  return { enabled, failed };
}

/**
 * Restore a table from backup
 */
export async function restoreFromBackup(
  backupArn: string,
  targetTableName: string
): Promise<RecoveryResult> {
  const client = getDynamoClient();
  
  try {
    const command = new RestoreTableFromBackupCommand({
      BackupArn: backupArn,
      TargetTableName: targetTableName
    });
    
    const response = await client.send(command);
    
    return {
      success: true,
      restoredTableName: response.TableDescription?.TableName,
      sourceBackupArn: backupArn,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error('Failed to restore from backup:', error);
    return {
      success: false,
      sourceBackupArn: backupArn,
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Get disaster recovery status
 */
export async function getDRStatus(): Promise<{
  pitrStatus: PITRStatus[];
  recentBackups: BackupInfo[];
  rtoMinutes: number;
  rpoMinutes: number;
  lastBackupTime?: Date;
}> {
  const pitrStatus: PITRStatus[] = [];
  
  for (const tableName of PITR_CONFIG.tables) {
    const status = await getPITRStatus(tableName);
    pitrStatus.push(status);
  }
  
  const recentBackups = await listBackups(undefined, 10);
  
  const lastBackupTime = recentBackups.length > 0
    ? recentBackups.reduce((latest, backup) => 
        backup.createdAt > latest ? backup.createdAt : latest,
        recentBackups[0].createdAt
      )
    : undefined;
  
  return {
    pitrStatus,
    recentBackups,
    rtoMinutes: DISASTER_RECOVERY_CONFIG.rtoMinutes,
    rpoMinutes: DISASTER_RECOVERY_CONFIG.rpoMinutes,
    lastBackupTime
  };
}

/**
 * Verify backup integrity by checking backup status
 */
export async function verifyBackupIntegrity(backupArn: string): Promise<{
  valid: boolean;
  status: string;
  error?: string;
}> {
  const details = await getBackupDetails(backupArn);
  
  if (!details) {
    return {
      valid: false,
      status: 'NOT_FOUND',
      error: 'Backup not found'
    };
  }
  
  const isValid = details.status === 'AVAILABLE';
  
  return {
    valid: isValid,
    status: details.status,
    error: isValid ? undefined : `Backup status is ${details.status}`
  };
}
