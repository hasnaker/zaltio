/**
 * Scaling Configuration for HSD Auth Platform
 * Validates: Requirements 7.4, 7.6
 * 
 * Configures Lambda auto-scaling, DynamoDB on-demand scaling,
 * health checks, and CloudWatch metrics/alerting
 */

import { AWS_CONFIG } from './aws.config';

/**
 * Lambda scaling configuration
 * Lambda auto-scales automatically, but we configure concurrency limits
 */
export const LAMBDA_SCALING_CONFIG = {
  // Reserved concurrency per function (0 = unreserved, uses account limit)
  reservedConcurrency: {
    register: 100,
    login: 200,
    refresh: 150,
    logout: 50,
    admin: 25
  },
  
  // Provisioned concurrency for consistent performance (optional, costs more)
  provisionedConcurrency: {
    enabled: false,
    login: 10, // Keep 10 instances warm for login
    register: 5
  },
  
  // Memory configuration (affects CPU allocation)
  memoryMB: {
    register: 256,
    login: 256,
    refresh: 128,
    logout: 128,
    admin: 256
  },
  
  // Timeout configuration in seconds
  timeoutSeconds: {
    register: 30,
    login: 10,
    refresh: 10,
    logout: 10,
    admin: 30
  }
} as const;

/**
 * DynamoDB scaling configuration
 * Using on-demand mode for automatic scaling
 */
export const DYNAMODB_SCALING_CONFIG = {
  // Billing mode: PAY_PER_REQUEST (on-demand) or PROVISIONED
  billingMode: 'PAY_PER_REQUEST' as const,
  
  // On-demand capacity limits (requests per second)
  onDemandLimits: {
    maxReadRequestUnits: 40000,
    maxWriteRequestUnits: 40000
  },
  
  // Provisioned capacity (if using PROVISIONED mode)
  provisionedCapacity: {
    users: { read: 25, write: 25 },
    realms: { read: 10, write: 5 },
    sessions: { read: 50, write: 50 }
  },
  
  // Auto-scaling configuration (for PROVISIONED mode)
  autoScaling: {
    enabled: false,
    minCapacity: 5,
    maxCapacity: 1000,
    targetUtilization: 70 // percentage
  },
  
  // Global tables for multi-region (disaster recovery)
  globalTables: {
    enabled: false,
    replicaRegions: ['eu-west-1'] // Secondary region for DR
  }
} as const;

/**
 * Health check configuration
 */
export const HEALTH_CHECK_CONFIG = {
  // Health check endpoint path
  endpoint: '/health',
  
  // Health check interval in seconds
  intervalSeconds: 30,
  
  // Timeout for health check in seconds
  timeoutSeconds: 5,
  
  // Number of consecutive failures before unhealthy
  unhealthyThreshold: 3,
  
  // Number of consecutive successes before healthy
  healthyThreshold: 2,
  
  // Components to check
  components: {
    dynamodb: true,
    secretsManager: true,
    lambda: true
  },
  
  // Response codes considered healthy
  healthyStatusCodes: [200]
} as const;

/**
 * CloudWatch metrics configuration
 */
export const CLOUDWATCH_METRICS_CONFIG = {
  namespace: 'HSD/AuthPlatform',
  region: AWS_CONFIG.region,
  
  // Custom metrics to publish
  customMetrics: {
    // Authentication metrics
    loginAttempts: 'LoginAttempts',
    loginSuccesses: 'LoginSuccesses',
    loginFailures: 'LoginFailures',
    registrations: 'Registrations',
    tokenRefreshes: 'TokenRefreshes',
    
    // Performance metrics
    authLatency: 'AuthenticationLatency',
    dbLatency: 'DatabaseLatency',
    
    // Error metrics
    errorRate: 'ErrorRate',
    rateLimitHits: 'RateLimitHits',
    
    // Capacity metrics
    activeUsers: 'ActiveUsers',
    activeSessions: 'ActiveSessions',
    realmCount: 'RealmCount'
  },
  
  // Metric dimensions
  dimensions: {
    realm: 'RealmId',
    function: 'FunctionName',
    operation: 'Operation'
  },
  
  // Metric resolution (1 = high resolution, 60 = standard)
  resolutionSeconds: 60,
  
  // Retention period in days
  retentionDays: 30
} as const;

/**
 * CloudWatch alarms configuration
 */
export const CLOUDWATCH_ALARMS_CONFIG = {
  // Error rate alarm
  errorRate: {
    name: 'HSD-Auth-HighErrorRate',
    threshold: 5, // percentage
    evaluationPeriods: 3,
    period: 300, // 5 minutes
    comparisonOperator: 'GreaterThanThreshold' as const,
    statistic: 'Average' as const
  },
  
  // Latency alarm
  latency: {
    name: 'HSD-Auth-HighLatency',
    threshold: 200, // milliseconds
    evaluationPeriods: 3,
    period: 300,
    comparisonOperator: 'GreaterThanThreshold' as const,
    statistic: 'p95' as const
  },
  
  // Throttling alarm
  throttling: {
    name: 'HSD-Auth-Throttling',
    threshold: 10, // count
    evaluationPeriods: 2,
    period: 60,
    comparisonOperator: 'GreaterThanThreshold' as const,
    statistic: 'Sum' as const
  },
  
  // DynamoDB capacity alarm
  dynamoCapacity: {
    name: 'HSD-Auth-DynamoDBCapacity',
    threshold: 80, // percentage of consumed capacity
    evaluationPeriods: 3,
    period: 300,
    comparisonOperator: 'GreaterThanThreshold' as const,
    statistic: 'Average' as const
  },
  
  // SNS topic for alarm notifications
  snsTopicArn: process.env.ALARM_SNS_TOPIC_ARN || ''
} as const;

export type LambdaScalingConfig = typeof LAMBDA_SCALING_CONFIG;
export type DynamoDBScalingConfig = typeof DYNAMODB_SCALING_CONFIG;
export type HealthCheckConfig = typeof HEALTH_CHECK_CONFIG;
export type CloudWatchMetricsConfig = typeof CLOUDWATCH_METRICS_CONFIG;
export type CloudWatchAlarmsConfig = typeof CLOUDWATCH_ALARMS_CONFIG;
