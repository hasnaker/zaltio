/**
 * Production Monitoring and Alerting Configuration for HSD Auth Platform
 * Validates: Requirements 7.6, 7.3
 * 
 * Configures comprehensive monitoring through existing HSD infrastructure,
 * cost monitoring to maintain $50-100/month budget,
 * and performance monitoring with alerting
 */

import { AWS_CONFIG } from './aws.config';

/**
 * CloudWatch Dashboard configuration
 */
export const DASHBOARD_CONFIG = {
  name: 'HSD-Auth-Platform-Dashboard',
  region: AWS_CONFIG.region,
  
  // Dashboard widgets
  widgets: {
    // Authentication metrics
    authentication: {
      title: 'Authentication Metrics',
      metrics: [
        { name: 'LoginAttempts', label: 'Login Attempts' },
        { name: 'LoginSuccesses', label: 'Successful Logins' },
        { name: 'LoginFailures', label: 'Failed Logins' },
        { name: 'Registrations', label: 'New Registrations' },
        { name: 'TokenRefreshes', label: 'Token Refreshes' }
      ],
      period: 300, // 5 minutes
      stat: 'Sum'
    },
    
    // Performance metrics
    performance: {
      title: 'Performance Metrics',
      metrics: [
        { name: 'AuthenticationLatency', label: 'Auth Latency (ms)' },
        { name: 'DatabaseLatency', label: 'DB Latency (ms)' }
      ],
      period: 60,
      stat: 'Average'
    },
    
    // Error metrics
    errors: {
      title: 'Error Metrics',
      metrics: [
        { name: 'ErrorRate', label: 'Error Count' },
        { name: 'RateLimitHits', label: 'Rate Limit Hits' }
      ],
      period: 60,
      stat: 'Sum'
    },
    
    // Capacity metrics
    capacity: {
      title: 'Capacity Metrics',
      metrics: [
        { name: 'ActiveUsers', label: 'Active Users' },
        { name: 'ActiveSessions', label: 'Active Sessions' },
        { name: 'RealmCount', label: 'Total Realms' }
      ],
      period: 300,
      stat: 'Average'
    }
  }
} as const;

/**
 * Cost monitoring configuration
 * Validates: Requirements 7.3 ($50-100/month budget)
 */
export const COST_MONITORING_CONFIG = {
  // Monthly budget limits
  budget: {
    name: 'HSD-Auth-Platform-Budget',
    amount: 100, // USD
    currency: 'USD',
    timeUnit: 'MONTHLY' as const,
    
    // Alert thresholds (percentage of budget)
    thresholds: [
      { percentage: 50, notificationType: 'ACTUAL' as const },
      { percentage: 75, notificationType: 'ACTUAL' as const },
      { percentage: 90, notificationType: 'ACTUAL' as const },
      { percentage: 100, notificationType: 'ACTUAL' as const },
      { percentage: 80, notificationType: 'FORECASTED' as const }
    ]
  },
  
  // Cost allocation tags
  costAllocationTags: {
    Application: 'zalt-platform',
    Environment: 'production',
    CostCenter: 'hsd-infrastructure'
  },
  
  // Service-specific cost tracking
  services: {
    lambda: {
      estimatedMonthlyCost: 15, // USD
      freeRequests: 1000000, // per month
      pricePerRequest: 0.0000002 // USD
    },
    dynamodb: {
      estimatedMonthlyCost: 25, // USD
      onDemandReadPrice: 0.25, // per million RRU
      onDemandWritePrice: 1.25 // per million WRU
    },
    apiGateway: {
      estimatedMonthlyCost: 10, // USD
      pricePerMillion: 3.50 // USD
    },
    cloudwatch: {
      estimatedMonthlyCost: 5, // USD
      customMetricsPrice: 0.30 // per metric per month
    },
    secretsManager: {
      estimatedMonthlyCost: 1, // USD
      pricePerSecret: 0.40 // per month
    },
    route53: {
      estimatedMonthlyCost: 2, // USD
      hostedZonePrice: 0.50, // per month
      queryPrice: 0.40 // per million queries
    }
  },
  
  // Total estimated monthly cost
  totalEstimatedCost: 58 // USD
} as const;

/**
 * Performance monitoring configuration
 */
export const PERFORMANCE_MONITORING_CONFIG = {
  // SLA targets
  sla: {
    availability: 99.9, // percentage
    latencyP50: 50, // ms
    latencyP95: 200, // ms
    latencyP99: 500, // ms
    errorRate: 0.1 // percentage
  },
  
  // Performance thresholds for alerting
  thresholds: {
    latency: {
      warning: 150, // ms
      critical: 300 // ms
    },
    errorRate: {
      warning: 1, // percentage
      critical: 5 // percentage
    },
    throttling: {
      warning: 5, // count per minute
      critical: 20 // count per minute
    }
  },
  
  // Monitoring intervals
  intervals: {
    metrics: 60, // seconds
    healthCheck: 30, // seconds
    costCheck: 3600 // seconds (hourly)
  }
} as const;

/**
 * Alerting configuration
 */
export const ALERTING_CONFIG = {
  // SNS topics for alerts
  snsTopics: {
    critical: process.env.SNS_CRITICAL_TOPIC_ARN || '',
    warning: process.env.SNS_WARNING_TOPIC_ARN || '',
    info: process.env.SNS_INFO_TOPIC_ARN || '',
    cost: process.env.SNS_COST_TOPIC_ARN || ''
  },
  
  // Alert definitions
  alerts: {
    // Critical alerts
    highErrorRate: {
      name: 'HSD-Auth-HighErrorRate',
      severity: 'critical' as const,
      metric: 'ErrorRate',
      threshold: 5, // percentage
      evaluationPeriods: 3,
      period: 300, // 5 minutes
      comparisonOperator: 'GreaterThanThreshold' as const,
      statistic: 'Average' as const,
      description: 'Error rate exceeds 5% for 15 minutes'
    },
    
    highLatency: {
      name: 'HSD-Auth-HighLatency',
      severity: 'critical' as const,
      metric: 'AuthenticationLatency',
      threshold: 300, // ms
      evaluationPeriods: 3,
      period: 300,
      comparisonOperator: 'GreaterThanThreshold' as const,
      statistic: 'p95' as const,
      description: 'P95 latency exceeds 300ms for 15 minutes'
    },
    
    serviceDown: {
      name: 'HSD-Auth-ServiceDown',
      severity: 'critical' as const,
      metric: 'HealthCheckStatus',
      threshold: 0,
      evaluationPeriods: 2,
      period: 60,
      comparisonOperator: 'LessThanOrEqualToThreshold' as const,
      statistic: 'Minimum' as const,
      description: 'Health check failing for 2 minutes'
    },
    
    // Warning alerts
    elevatedErrorRate: {
      name: 'HSD-Auth-ElevatedErrorRate',
      severity: 'warning' as const,
      metric: 'ErrorRate',
      threshold: 1, // percentage
      evaluationPeriods: 5,
      period: 300,
      comparisonOperator: 'GreaterThanThreshold' as const,
      statistic: 'Average' as const,
      description: 'Error rate exceeds 1% for 25 minutes'
    },
    
    elevatedLatency: {
      name: 'HSD-Auth-ElevatedLatency',
      severity: 'warning' as const,
      metric: 'AuthenticationLatency',
      threshold: 150, // ms
      evaluationPeriods: 5,
      period: 300,
      comparisonOperator: 'GreaterThanThreshold' as const,
      statistic: 'p95' as const,
      description: 'P95 latency exceeds 150ms for 25 minutes'
    },
    
    rateLimitingActive: {
      name: 'HSD-Auth-RateLimiting',
      severity: 'warning' as const,
      metric: 'RateLimitHits',
      threshold: 10,
      evaluationPeriods: 3,
      period: 60,
      comparisonOperator: 'GreaterThanThreshold' as const,
      statistic: 'Sum' as const,
      description: 'Rate limiting triggered more than 10 times in 3 minutes'
    },
    
    // Cost alerts
    budgetWarning: {
      name: 'HSD-Auth-BudgetWarning',
      severity: 'warning' as const,
      threshold: 75, // percentage of budget
      description: 'Monthly cost exceeds 75% of budget'
    },
    
    budgetCritical: {
      name: 'HSD-Auth-BudgetCritical',
      severity: 'critical' as const,
      threshold: 90, // percentage of budget
      description: 'Monthly cost exceeds 90% of budget'
    }
  },
  
  // Alert notification settings
  notifications: {
    // Email recipients
    emailRecipients: [] as string[],
    
    // Slack webhook (optional)
    slackWebhook: process.env.SLACK_WEBHOOK_URL || '',
    
    // PagerDuty integration (optional)
    pagerDutyKey: process.env.PAGERDUTY_KEY || '',
    
    // Notification cooldown (prevent alert fatigue)
    cooldownMinutes: 15
  }
} as const;

/**
 * Log monitoring configuration
 */
export const LOG_MONITORING_CONFIG = {
  // CloudWatch Logs configuration
  logGroups: {
    lambda: '/aws/lambda/zalt-*',
    apiGateway: '/aws/api-gateway/zalt-api',
    application: '/zalt-platform/application'
  },
  
  // Log retention
  retentionDays: 30,
  
  // Log insights queries
  queries: {
    errorSummary: `
      fields @timestamp, @message
      | filter @message like /ERROR/
      | stats count(*) as errorCount by bin(1h)
      | sort @timestamp desc
      | limit 24
    `,
    
    latencyAnalysis: `
      fields @timestamp, @message
      | filter @message like /latency/
      | parse @message /latency[=:]\\s*(?<latency>\\d+)/
      | stats avg(latency) as avgLatency, max(latency) as maxLatency, pct(latency, 95) as p95Latency by bin(5m)
      | sort @timestamp desc
      | limit 100
    `,
    
    authenticationFailures: `
      fields @timestamp, @message
      | filter @message like /authentication failed/ or @message like /login failed/
      | stats count(*) as failureCount by bin(1h)
      | sort @timestamp desc
      | limit 24
    `,
    
    topErrors: `
      fields @timestamp, @message
      | filter @message like /ERROR/
      | parse @message /ERROR[:]?\\s*(?<errorType>[^:]+)/
      | stats count(*) as count by errorType
      | sort count desc
      | limit 10
    `
  },
  
  // Metric filters for log-based metrics
  metricFilters: {
    errorCount: {
      name: 'ErrorCount',
      pattern: 'ERROR',
      metricName: 'LogErrors',
      metricValue: '1'
    },
    authFailures: {
      name: 'AuthFailures',
      pattern: '"authentication failed" OR "login failed"',
      metricName: 'AuthenticationFailures',
      metricValue: '1'
    },
    rateLimitHits: {
      name: 'RateLimitHits',
      pattern: '"rate limit" OR "too many requests"',
      metricName: 'RateLimitHitsFromLogs',
      metricValue: '1'
    }
  }
} as const;

/**
 * X-Ray tracing configuration
 */
export const XRAY_CONFIG = {
  enabled: true,
  samplingRate: 0.05, // 5% of requests
  
  // Sampling rules
  samplingRules: {
    default: {
      fixedRate: 0.05,
      reservoirSize: 5,
      serviceName: 'zalt-platform',
      serviceType: '*',
      host: '*',
      httpMethod: '*',
      urlPath: '*'
    },
    errors: {
      fixedRate: 1.0, // Sample all errors
      reservoirSize: 10,
      serviceName: 'zalt-platform',
      serviceType: '*',
      host: '*',
      httpMethod: '*',
      urlPath: '*'
    }
  },
  
  // Annotations for filtering
  annotations: {
    realm: 'RealmId',
    operation: 'Operation',
    userId: 'UserId'
  }
} as const;

export type DashboardConfig = typeof DASHBOARD_CONFIG;
export type CostMonitoringConfig = typeof COST_MONITORING_CONFIG;
export type PerformanceMonitoringConfig = typeof PERFORMANCE_MONITORING_CONFIG;
export type AlertingConfig = typeof ALERTING_CONFIG;
export type LogMonitoringConfig = typeof LOG_MONITORING_CONFIG;
export type XRayConfig = typeof XRAY_CONFIG;
