/**
 * Health Check Service for HSD Auth Platform
 * Validates: Requirements 7.4, 7.6
 * 
 * Implements health checks and monitoring endpoints
 */

import { DynamoDBClient, DescribeTableCommand } from '@aws-sdk/client-dynamodb';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { AWS_CONFIG } from '../config/aws.config';
import { HEALTH_CHECK_CONFIG } from '../config/scaling.config';

/**
 * Health status for individual components
 */
export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  latencyMs?: number;
  message?: string;
  lastChecked: string;
}

/**
 * Overall system health response
 */
export interface HealthCheckResponse {
  status: 'healthy' | 'unhealthy' | 'degraded';
  version: string;
  timestamp: string;
  region: string;
  components: ComponentHealth[];
  uptime: number;
}

// Track service start time for uptime calculation
const serviceStartTime = Date.now();

/**
 * Check DynamoDB health by describing core tables only
 * Only checks tables that are critical for auth operations
 */
async function checkDynamoDBHealth(): Promise<ComponentHealth> {
  const startTime = Date.now();
  const client = new DynamoDBClient({ region: AWS_CONFIG.region });
  
  // Only check core tables (users, realms, sessions)
  const coreTables = Object.values(AWS_CONFIG.dynamodb.tables);
  const checkedTables: string[] = [];
  
  try {
    for (const tableName of coreTables) {
      const command = new DescribeTableCommand({ TableName: tableName });
      const response = await client.send(command);
      
      if (response.Table?.TableStatus !== 'ACTIVE') {
        return {
          name: 'dynamodb',
          status: 'degraded',
          latencyMs: Date.now() - startTime,
          message: `Table ${tableName} is not active: ${response.Table?.TableStatus}`,
          lastChecked: new Date().toISOString()
        };
      }
      checkedTables.push(tableName);
    }
    
    return {
      name: 'dynamodb',
      status: 'healthy',
      latencyMs: Date.now() - startTime,
      message: `${checkedTables.length} core tables active`,
      lastChecked: new Date().toISOString()
    };
  } catch (error) {
    return {
      name: 'dynamodb',
      status: 'unhealthy',
      latencyMs: Date.now() - startTime,
      message: error instanceof Error ? error.message : 'Unknown error',
      lastChecked: new Date().toISOString()
    };
  }
}

/**
 * Check Secrets Manager health
 */
async function checkSecretsManagerHealth(): Promise<ComponentHealth> {
  const startTime = Date.now();
  const client = new SecretsManagerClient({ region: AWS_CONFIG.region });
  
  try {
    const command = new GetSecretValueCommand({
      SecretId: AWS_CONFIG.secretsManager.jwtSecrets
    });
    
    await client.send(command);
    
    return {
      name: 'secretsManager',
      status: 'healthy',
      latencyMs: Date.now() - startTime,
      message: 'JWT secrets accessible',
      lastChecked: new Date().toISOString()
    };
  } catch (error) {
    return {
      name: 'secretsManager',
      status: 'unhealthy',
      latencyMs: Date.now() - startTime,
      message: error instanceof Error ? error.message : 'Unknown error',
      lastChecked: new Date().toISOString()
    };
  }
}

/**
 * Check Lambda function health (self-check)
 */
function checkLambdaHealth(): ComponentHealth {
  const memoryUsed = process.memoryUsage();
  const heapUsedPercent = (memoryUsed.heapUsed / memoryUsed.heapTotal) * 100;
  
  let status: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';
  let message = 'Lambda function running normally';
  
  // Adjusted thresholds for Lambda cold starts and esbuild bundles
  if (heapUsedPercent > 98) {
    status = 'unhealthy';
    message = `Critical memory usage: ${heapUsedPercent.toFixed(1)}%`;
  } else if (heapUsedPercent > 92) {
    status = 'degraded';
    message = `Elevated memory usage: ${heapUsedPercent.toFixed(1)}%`;
  }
  
  return {
    name: 'lambda',
    status,
    message,
    lastChecked: new Date().toISOString()
  };
}

/**
 * Perform comprehensive health check
 */
export async function performHealthCheck(): Promise<HealthCheckResponse> {
  const components: ComponentHealth[] = [];
  
  // Check each configured component
  if (HEALTH_CHECK_CONFIG.components.dynamodb) {
    components.push(await checkDynamoDBHealth());
  }
  
  if (HEALTH_CHECK_CONFIG.components.secretsManager) {
    components.push(await checkSecretsManagerHealth());
  }
  
  if (HEALTH_CHECK_CONFIG.components.lambda) {
    components.push(checkLambdaHealth());
  }
  
  // Determine overall status
  const hasUnhealthy = components.some(c => c.status === 'unhealthy');
  const hasDegraded = components.some(c => c.status === 'degraded');
  
  let overallStatus: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';
  if (hasUnhealthy) {
    overallStatus = 'unhealthy';
  } else if (hasDegraded) {
    overallStatus = 'degraded';
  }
  
  return {
    status: overallStatus,
    version: process.env.VERSION || '1.0.0',
    timestamp: new Date().toISOString(),
    region: AWS_CONFIG.region,
    components,
    uptime: Math.floor((Date.now() - serviceStartTime) / 1000)
  };
}

/**
 * Perform lightweight health check (no external calls)
 */
export function performLivenessCheck(): { status: 'ok'; timestamp: string } {
  return {
    status: 'ok',
    timestamp: new Date().toISOString()
  };
}

/**
 * Check if system is ready to accept traffic
 */
export async function performReadinessCheck(): Promise<{
  ready: boolean;
  timestamp: string;
  checks: { name: string; ready: boolean }[];
}> {
  const checks: { name: string; ready: boolean }[] = [];
  
  // Check DynamoDB readiness
  try {
    const dynamoHealth = await checkDynamoDBHealth();
    checks.push({ name: 'dynamodb', ready: dynamoHealth.status !== 'unhealthy' });
  } catch {
    checks.push({ name: 'dynamodb', ready: false });
  }
  
  // Check Secrets Manager readiness
  try {
    const secretsHealth = await checkSecretsManagerHealth();
    checks.push({ name: 'secretsManager', ready: secretsHealth.status !== 'unhealthy' });
  } catch {
    checks.push({ name: 'secretsManager', ready: false });
  }
  
  const allReady = checks.every(c => c.ready);
  
  return {
    ready: allReady,
    timestamp: new Date().toISOString(),
    checks
  };
}
