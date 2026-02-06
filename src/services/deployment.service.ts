/**
 * Deployment Service for HSD Auth Platform
 * Validates: Requirements 7.1, 5.1, 5.2, 5.5
 * 
 * Provides programmatic deployment utilities for Lambda functions,
 * domain configuration, and SSL certificate management
 */

import {
  LAMBDA_DEPLOYMENT_CONFIG,
  DOMAIN_CONFIG,
  SSL_CONFIG,
  DNS_CONFIG,
  API_GATEWAY_DEPLOYMENT_CONFIG,
  CLOUDFRONT_CONFIG
} from '../config/deployment.config';
import { AWS_CONFIG } from '../config/aws.config';

/**
 * Deployment status interface
 */
export interface DeploymentStatus {
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  environment: string;
  region: string;
  timestamp: string;
  components: {
    lambda: ComponentStatus;
    apiGateway: ComponentStatus;
    dynamodb: ComponentStatus;
    dns: ComponentStatus;
    ssl: ComponentStatus;
  };
  errors: string[];
}

/**
 * Component deployment status
 */
export interface ComponentStatus {
  status: 'pending' | 'deployed' | 'failed';
  message: string;
  lastUpdated: string;
}

/**
 * Deployment configuration validation result
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Validates deployment configuration
 */
export function validateDeploymentConfig(): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate region
  if (LAMBDA_DEPLOYMENT_CONFIG.region !== 'eu-central-1') {
    errors.push(`Invalid region: ${LAMBDA_DEPLOYMENT_CONFIG.region}. Must be eu-central-1 for GDPR compliance.`);
  }

  // Validate Lambda functions
  const requiredFunctions = ['register', 'login', 'refresh', 'logout', 'admin', 'sso', 'health'];
  for (const func of requiredFunctions) {
    if (!(func in LAMBDA_DEPLOYMENT_CONFIG.functions)) {
      errors.push(`Missing Lambda function configuration: ${func}`);
    }
  }

  // Validate domain configuration
  if (!DOMAIN_CONFIG.baseDomain) {
    errors.push('Base domain is not configured');
  }

  // Validate SSL configuration
  if (!SSL_CONFIG.certificate.domainNames.length) {
    errors.push('SSL certificate domain names are not configured');
  }

  // Validate API Gateway configuration
  if (!API_GATEWAY_DEPLOYMENT_CONFIG.apiId) {
    warnings.push('API Gateway ID is not configured - will create new API');
  }

  // Validate environment variables
  const requiredEnvVars = ['DYNAMODB_USERS_TABLE', 'DYNAMODB_REALMS_TABLE', 'DYNAMODB_SESSIONS_TABLE'];
  for (const envVar of requiredEnvVars) {
    if (!(envVar in LAMBDA_DEPLOYMENT_CONFIG.environment)) {
      errors.push(`Missing environment variable: ${envVar}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Environment-specific domain configuration
 */
interface EnvironmentDomainConfig {
  baseDomain: string;
  subdomains: {
    main: { name: string; description: string; target: string };
    api: { name: string; description: string; target: string };
    dashboard: { name: string; description: string; target: string };
  };
  hostedZone: { name: string; id: string };
  apiGateway: { domainName: string; basePath: string; stage: string; endpointType: string };
}

/**
 * Gets the deployment configuration for a specific environment
 */
export function getDeploymentConfig(environment: 'production' | 'staging' | 'development') {
  // Environment-specific domain configurations
  const domainConfigs: Record<string, EnvironmentDomainConfig> = {
    production: {
      baseDomain: 'hsdcore.com',
      subdomains: {
        main: { name: 'auth.hsdcore.com', description: 'Main authentication service', target: 'api-gateway' },
        api: { name: 'api.auth.hsdcore.com', description: 'REST API endpoint', target: 'api-gateway' },
        dashboard: { name: 'dashboard.auth.hsdcore.com', description: 'Administrative dashboard', target: 'cloudfront' }
      },
      hostedZone: { name: 'hsdcore.com', id: process.env.ROUTE53_HOSTED_ZONE_ID || '' },
      apiGateway: { domainName: 'api.auth.hsdcore.com', basePath: '/', stage: 'prod', endpointType: 'REGIONAL' }
    },
    staging: {
      baseDomain: 'hsdcore.com',
      subdomains: {
        main: { name: 'auth-staging.hsdcore.com', description: 'Staging authentication service', target: 'api-gateway' },
        api: { name: 'api.auth-staging.hsdcore.com', description: 'Staging REST API endpoint', target: 'api-gateway' },
        dashboard: { name: 'dashboard.auth-staging.hsdcore.com', description: 'Staging dashboard', target: 'cloudfront' }
      },
      hostedZone: { name: 'hsdcore.com', id: process.env.ROUTE53_HOSTED_ZONE_ID || '' },
      apiGateway: { domainName: 'api.auth-staging.hsdcore.com', basePath: '/', stage: 'staging', endpointType: 'REGIONAL' }
    },
    development: {
      baseDomain: 'hsdcore.com',
      subdomains: {
        main: { name: 'auth-dev.hsdcore.com', description: 'Development authentication service', target: 'api-gateway' },
        api: { name: 'api.auth-dev.hsdcore.com', description: 'Development REST API endpoint', target: 'api-gateway' },
        dashboard: { name: 'dashboard.auth-dev.hsdcore.com', description: 'Development dashboard', target: 'cloudfront' }
      },
      hostedZone: { name: 'hsdcore.com', id: process.env.ROUTE53_HOSTED_ZONE_ID || '' },
      apiGateway: { domainName: 'api.auth-dev.hsdcore.com', basePath: '/', stage: 'dev', endpointType: 'REGIONAL' }
    }
  };

  return {
    region: AWS_CONFIG.region,
    lambda: LAMBDA_DEPLOYMENT_CONFIG,
    domain: domainConfigs[environment],
    ssl: SSL_CONFIG,
    dns: DNS_CONFIG,
    apiGateway: API_GATEWAY_DEPLOYMENT_CONFIG,
    cloudfront: CLOUDFRONT_CONFIG,
    environment
  };
}

/**
 * Creates initial deployment status
 */
export function createDeploymentStatus(environment: string): DeploymentStatus {
  const now = new Date().toISOString();
  
  return {
    status: 'pending',
    environment,
    region: AWS_CONFIG.region,
    timestamp: now,
    components: {
      lambda: { status: 'pending', message: 'Waiting to deploy', lastUpdated: now },
      apiGateway: { status: 'pending', message: 'Waiting to deploy', lastUpdated: now },
      dynamodb: { status: 'pending', message: 'Waiting to deploy', lastUpdated: now },
      dns: { status: 'pending', message: 'Waiting to deploy', lastUpdated: now },
      ssl: { status: 'pending', message: 'Waiting to deploy', lastUpdated: now }
    },
    errors: []
  };
}

/**
 * Gets Lambda function ARN
 */
export function getLambdaArn(functionName: string): string {
  return `arn:aws:lambda:${AWS_CONFIG.region}:*:function:${functionName}`;
}

/**
 * Gets API Gateway URL
 */
export function getApiGatewayUrl(environment: 'production' | 'staging' | 'development'): string {
  const config = getDeploymentConfig(environment);
  return `https://${config.domain.subdomains.api.name}`;
}

/**
 * Gets dashboard URL
 */
export function getDashboardUrl(environment: 'production' | 'staging' | 'development'): string {
  const config = getDeploymentConfig(environment);
  return `https://${config.domain.subdomains.dashboard.name}`;
}

/**
 * Generates CloudFormation parameter overrides
 */
export function generateParameterOverrides(
  environment: 'production' | 'staging' | 'development',
  certificateArn: string,
  hostedZoneId: string
): Record<string, string> {
  const config = getDeploymentConfig(environment);
  
  return {
    Environment: environment,
    DomainName: config.domain.subdomains.api.name,
    CertificateArn: certificateArn,
    HostedZoneId: hostedZoneId
  };
}

/**
 * Validates SSL certificate configuration
 */
export function validateSSLConfig(): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check TLS version
  if (SSL_CONFIG.tls.minimumVersion !== 'TLSv1.2') {
    warnings.push('TLS version should be at least TLSv1.2 for security compliance');
  }

  // Check HTTPS enforcement
  if (!SSL_CONFIG.httpsEnforcement.enabled) {
    errors.push('HTTPS enforcement must be enabled for production');
  }

  // Check HSTS
  if (!SSL_CONFIG.httpsEnforcement.hstsEnabled) {
    warnings.push('HSTS should be enabled for enhanced security');
  }

  // Check certificate domains
  const requiredDomains = ['auth.hsdcore.com', '*.auth.hsdcore.com'];
  const configuredDomains = SSL_CONFIG.certificate.domainNames as readonly string[];
  for (const domain of requiredDomains) {
    if (!configuredDomains.includes(domain)) {
      errors.push(`Missing domain in SSL certificate: ${domain}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Validates DNS configuration
 */
export function validateDNSConfig(): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check required DNS records
  const requiredRecords = ['main', 'api', 'dashboard'];
  for (const record of requiredRecords) {
    if (!(record in DNS_CONFIG.records)) {
      errors.push(`Missing DNS record configuration: ${record}`);
    }
  }

  // Check health check configuration
  if (!DNS_CONFIG.healthChecks.api) {
    warnings.push('API health check is not configured');
  }

  // Check TTL values
  if (DNS_CONFIG.ttl.default > 3600) {
    warnings.push('DNS TTL is high (>1 hour), may slow down failover');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

/**
 * Gets deployment summary
 */
export function getDeploymentSummary(environment: 'production' | 'staging' | 'development'): string {
  const config = getDeploymentConfig(environment);
  const validation = validateDeploymentConfig();
  
  return `
HSD Auth Platform Deployment Summary
=====================================
Environment: ${environment}
Region: ${config.region}

Domains:
  - Main: ${config.domain.subdomains.main.name}
  - API: ${config.domain.subdomains.api.name}
  - Dashboard: ${config.domain.subdomains.dashboard.name}

Lambda Functions:
${Object.entries(config.lambda.functions)
  .map(([name, func]) => `  - ${func.name} (${func.memorySize}MB, ${func.timeout}s timeout)`)
  .join('\n')}

Validation:
  - Valid: ${validation.valid}
  - Errors: ${validation.errors.length}
  - Warnings: ${validation.warnings.length}

${validation.errors.length > 0 ? `Errors:\n${validation.errors.map(e => `  - ${e}`).join('\n')}` : ''}
${validation.warnings.length > 0 ? `Warnings:\n${validation.warnings.map(w => `  - ${w}`).join('\n')}` : ''}
`.trim();
}
