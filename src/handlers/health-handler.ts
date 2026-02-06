/**
 * Health Check Handler for HSD Auth Platform
 * Validates: Requirements 7.4, 7.6
 * 
 * Provides health check endpoints for monitoring and load balancing
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  performHealthCheck,
  performLivenessCheck,
  performReadinessCheck
} from '../services/health.service';
import { createSuccessResponse, createErrorResponse } from '../utils/response';

/**
 * Main health check endpoint - comprehensive system health
 * GET /health
 */
export async function healthHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const path = event.path;
  
  // Route based on path
  if (path === '/health/live') {
    return livenessHandler(event);
  }
  
  if (path === '/health/ready') {
    return readinessHandler(event);
  }
  
  // Default: /health
  try {
    const healthStatus = await performHealthCheck();
    
    // Return 503 if unhealthy, 200 otherwise
    const statusCode = healthStatus.status === 'unhealthy' ? 503 : 200;
    
    return {
      statusCode,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      },
      body: JSON.stringify(healthStatus)
    };
  } catch (error) {
    console.error('Health check failed:', error);
    return createErrorResponse(
      event,
      503,
      'HEALTH_CHECK_FAILED',
      'Unable to perform health check'
    );
  }
}

/**
 * Liveness probe - simple check that the service is running
 * GET /health/live
 */
export async function livenessHandler(
  _event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const status = performLivenessCheck();
  
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    },
    body: JSON.stringify(status)
  };
}

/**
 * Readiness probe - check if service is ready to accept traffic
 * GET /health/ready
 */
export async function readinessHandler(
  _event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const readiness = await performReadinessCheck();
    
    const statusCode = readiness.ready ? 200 : 503;
    
    return {
      statusCode,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      },
      body: JSON.stringify(readiness)
    };
  } catch (error) {
    console.error('Readiness check failed:', error);
    return {
      statusCode: 503,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      },
      body: JSON.stringify({
        ready: false,
        timestamp: new Date().toISOString(),
        error: 'Readiness check failed'
      })
    };
  }
}

/**
 * Metrics endpoint - returns current metrics summary
 * GET /health/metrics
 */
export async function metricsHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const memoryUsage = process.memoryUsage();
    
    const metrics = {
      timestamp: new Date().toISOString(),
      memory: {
        heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
        heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
        external: Math.round(memoryUsage.external / 1024 / 1024),
        rss: Math.round(memoryUsage.rss / 1024 / 1024)
      },
      uptime: process.uptime()
    };
    
    return createSuccessResponse(event, 200, metrics);
  } catch (error) {
    console.error('Metrics retrieval failed:', error);
    return createErrorResponse(
      event,
      500,
      'METRICS_FAILED',
      'Unable to retrieve metrics'
    );
  }
}
