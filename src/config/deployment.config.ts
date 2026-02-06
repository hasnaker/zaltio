/**
 * Deployment Configuration for HSD Auth Platform
 * Validates: Requirements 7.1, 5.1, 5.2, 5.5
 * 
 * Configures Lambda deployment to eu-central-1 region,
 * domain routing for auth.hsdcore.com subdomains,
 * and SSL certificates with DNS configuration
 */

import { AWS_CONFIG } from './aws.config';

/**
 * Lambda deployment configuration
 * Validates: Requirements 7.1 (eu-central-1 deployment)
 */
export const LAMBDA_DEPLOYMENT_CONFIG = {
  region: AWS_CONFIG.region,
  
  // Lambda function configurations
  functions: {
    register: {
      name: 'zalt-register',
      handler: 'dist/handlers/register.handler',
      runtime: 'nodejs20.x',
      memorySize: 256,
      timeout: 30,
      description: 'User registration handler for HSD Auth Platform'
    },
    login: {
      name: 'zalt-login',
      handler: 'dist/handlers/login.handler',
      runtime: 'nodejs20.x',
      memorySize: 256,
      timeout: 10,
      description: 'User authentication handler for HSD Auth Platform'
    },
    refresh: {
      name: 'zalt-refresh',
      handler: 'dist/handlers/refresh.handler',
      runtime: 'nodejs20.x',
      memorySize: 128,
      timeout: 10,
      description: 'Token refresh handler for HSD Auth Platform'
    },
    logout: {
      name: 'zalt-logout',
      handler: 'dist/handlers/logout.handler',
      runtime: 'nodejs20.x',
      memorySize: 128,
      timeout: 10,
      description: 'Session termination handler for HSD Auth Platform'
    },
    admin: {
      name: 'zalt-admin',
      handler: 'dist/handlers/admin.handler',
      runtime: 'nodejs20.x',
      memorySize: 256,
      timeout: 30,
      description: 'Administrative operations handler for HSD Auth Platform'
    },
    sso: {
      name: 'zalt-sso',
      handler: 'dist/handlers/sso.handler',
      runtime: 'nodejs20.x',
      memorySize: 256,
      timeout: 30,
      description: 'SSO and OAuth handler for HSD Auth Platform'
    },
    health: {
      name: 'zalt-health',
      handler: 'dist/handlers/health.handler',
      runtime: 'nodejs20.x',
      memorySize: 128,
      timeout: 10,
      description: 'Health check handler for HSD Auth Platform'
    }
  },
  
  // Environment variables for all functions
  environment: {
    NODE_ENV: 'production',
    AWS_REGION: AWS_CONFIG.region,
    DYNAMODB_USERS_TABLE: AWS_CONFIG.dynamodb.tables.users,
    DYNAMODB_REALMS_TABLE: AWS_CONFIG.dynamodb.tables.realms,
    DYNAMODB_SESSIONS_TABLE: AWS_CONFIG.dynamodb.tables.sessions,
    JWT_SECRETS_ARN: `arn:aws:secretsmanager:${AWS_CONFIG.region}:*:secret:${AWS_CONFIG.secretsManager.jwtSecrets}*`
  },
  
  // IAM role configuration
  iamRole: {
    name: 'zalt-lambda-role',
    policies: [
      'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
      'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
      'arn:aws:iam::aws:policy/SecretsManagerReadWrite',
      'arn:aws:iam::aws:policy/CloudWatchFullAccess'
    ]
  },
  
  // VPC configuration (optional, for enhanced security)
  vpc: {
    enabled: false,
    subnetIds: [] as string[],
    securityGroupIds: [] as string[]
  }
} as const;

/**
 * Domain routing configuration
 * Validates: Requirements 5.1, 5.2 (domain architecture)
 */
export const DOMAIN_CONFIG = {
  // Base domain
  baseDomain: 'hsdcore.com',
  
  // Subdomains for auth platform
  subdomains: {
    main: {
      name: 'auth.hsdcore.com',
      description: 'Main authentication service',
      target: 'api-gateway'
    },
    api: {
      name: 'api.auth.hsdcore.com',
      description: 'REST API endpoint',
      target: 'api-gateway'
    },
    dashboard: {
      name: 'dashboard.auth.hsdcore.com',
      description: 'Administrative dashboard',
      target: 'cloudfront'
    }
  },
  
  // Route 53 hosted zone
  hostedZone: {
    name: 'hsdcore.com',
    id: process.env.ROUTE53_HOSTED_ZONE_ID || ''
  },
  
  // API Gateway custom domain
  apiGateway: {
    domainName: 'api.auth.hsdcore.com',
    basePath: '/',
    stage: 'prod',
    endpointType: 'REGIONAL' as const
  }
} as const;

/**
 * SSL/TLS certificate configuration
 * Validates: Requirements 5.2, 5.4 (SSL termination, HTTPS)
 */
export const SSL_CONFIG = {
  // ACM certificate configuration
  certificate: {
    // Certificate must be in us-east-1 for CloudFront, eu-central-1 for API Gateway
    regions: {
      cloudfront: 'us-east-1',
      apiGateway: AWS_CONFIG.region
    },
    
    // Domain names covered by certificate
    domainNames: [
      'auth.hsdcore.com',
      '*.auth.hsdcore.com'
    ],
    
    // Validation method
    validationMethod: 'DNS' as const,
    
    // Certificate tags
    tags: {
      Application: 'zalt-platform',
      Environment: 'production'
    }
  },
  
  // TLS configuration
  tls: {
    minimumVersion: 'TLSv1.2' as const,
    securityPolicy: 'TLS_1_2_2021_06' as const
  },
  
  // HTTPS enforcement
  httpsEnforcement: {
    enabled: true,
    redirectHttp: true,
    hstsEnabled: true,
    hstsMaxAge: 31536000 // 1 year
  }
} as const;

/**
 * DNS configuration
 * Validates: Requirements 5.5 (DNS configuration with health checks)
 */
export const DNS_CONFIG = {
  // Route 53 record configurations
  records: {
    // Main auth domain - points to API Gateway
    main: {
      name: 'auth.hsdcore.com',
      type: 'A' as const,
      aliasTarget: {
        hostedZoneId: '', // API Gateway hosted zone ID
        dnsName: '', // API Gateway domain name
        evaluateTargetHealth: true
      }
    },
    
    // API subdomain - points to API Gateway
    api: {
      name: 'api.auth.hsdcore.com',
      type: 'A' as const,
      aliasTarget: {
        hostedZoneId: '',
        dnsName: '',
        evaluateTargetHealth: true
      }
    },
    
    // Dashboard subdomain - points to CloudFront
    dashboard: {
      name: 'dashboard.auth.hsdcore.com',
      type: 'A' as const,
      aliasTarget: {
        hostedZoneId: 'Z2FDTNDATAQYW2', // CloudFront hosted zone ID (global)
        dnsName: '', // CloudFront distribution domain
        evaluateTargetHealth: false
      }
    }
  },
  
  // Health check configuration
  healthChecks: {
    api: {
      name: 'zalt-api-health',
      type: 'HTTPS' as const,
      resourcePath: '/health',
      port: 443,
      requestInterval: 30,
      failureThreshold: 3,
      measureLatency: true,
      regions: ['eu-central-1', 'eu-west-1', 'us-east-1']
    }
  },
  
  // TTL configuration
  ttl: {
    default: 300, // 5 minutes
    healthCheck: 60 // 1 minute for health-checked records
  }
} as const;

/**
 * API Gateway deployment configuration
 */
export const API_GATEWAY_DEPLOYMENT_CONFIG = {
  // Existing API Gateway
  apiId: '65tnchimfk',
  region: AWS_CONFIG.region,
  
  // Stage configuration
  stage: {
    name: 'prod',
    description: 'Production stage for HSD Auth Platform',
    throttling: {
      burstLimit: 1000,
      rateLimit: 500
    },
    logging: {
      level: 'INFO' as const,
      dataTraceEnabled: false,
      metricsEnabled: true
    },
    caching: {
      enabled: false,
      ttlInSeconds: 300
    }
  },
  
  // Custom domain configuration
  customDomain: {
    domainName: 'api.auth.hsdcore.com',
    certificateArn: process.env.ACM_CERTIFICATE_ARN || '',
    endpointType: 'REGIONAL' as const,
    securityPolicy: 'TLS_1_2' as const
  },
  
  // API routes
  routes: {
    // Authentication routes
    'POST /register': 'zalt-register',
    'POST /login': 'zalt-login',
    'POST /refresh': 'zalt-refresh',
    'POST /logout': 'zalt-logout',
    
    // Admin routes
    'POST /admin/realms': 'zalt-admin',
    'GET /admin/realms': 'zalt-admin',
    'DELETE /admin/realms/{realmId}': 'zalt-admin',
    
    // SSO routes
    'GET /.well-known/openid-configuration': 'zalt-sso',
    'GET /oauth/authorize': 'zalt-sso',
    'POST /oauth/token': 'zalt-sso',
    'GET /oauth/userinfo': 'zalt-sso',
    
    // Health routes
    'GET /health': 'zalt-health',
    'GET /health/live': 'zalt-health',
    'GET /health/ready': 'zalt-health'
  }
} as const;

/**
 * CloudFront distribution configuration for dashboard
 */
export const CLOUDFRONT_CONFIG = {
  // Distribution settings
  distribution: {
    enabled: true,
    comment: 'HSD Auth Platform Dashboard',
    defaultRootObject: 'index.html',
    priceClass: 'PriceClass_100', // Europe and North America only
    httpVersion: 'http2and3' as const
  },
  
  // Origin configuration (EKS/ALB)
  origins: {
    dashboard: {
      domainName: '', // ALB domain name
      originPath: '',
      protocol: 'https-only' as const,
      sslProtocols: ['TLSv1.2'] as const
    }
  },
  
  // Cache behavior
  cacheBehavior: {
    viewerProtocolPolicy: 'redirect-to-https' as const,
    allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'POST', 'PATCH', 'DELETE'],
    cachedMethods: ['GET', 'HEAD'],
    compress: true,
    ttl: {
      default: 86400, // 1 day
      max: 31536000, // 1 year
      min: 0
    }
  },
  
  // Custom error responses
  customErrorResponses: [
    {
      errorCode: 403,
      responseCode: 200,
      responsePagePath: '/index.html',
      errorCachingMinTTL: 300
    },
    {
      errorCode: 404,
      responseCode: 200,
      responsePagePath: '/index.html',
      errorCachingMinTTL: 300
    }
  ],
  
  // Aliases (custom domain names)
  aliases: ['dashboard.auth.hsdcore.com'],
  
  // SSL certificate
  viewerCertificate: {
    acmCertificateArn: process.env.CLOUDFRONT_ACM_CERTIFICATE_ARN || '',
    sslSupportMethod: 'sni-only' as const,
    minimumProtocolVersion: 'TLSv1.2_2021' as const
  }
} as const;

export type LambdaDeploymentConfig = typeof LAMBDA_DEPLOYMENT_CONFIG;
export type DomainConfig = typeof DOMAIN_CONFIG;
export type SSLConfig = typeof SSL_CONFIG;
export type DNSConfig = typeof DNS_CONFIG;
export type APIGatewayDeploymentConfig = typeof API_GATEWAY_DEPLOYMENT_CONFIG;
export type CloudFrontConfig = typeof CLOUDFRONT_CONFIG;
