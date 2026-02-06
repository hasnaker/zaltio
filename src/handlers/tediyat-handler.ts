/**
 * Tediyat Combined Handler
 * Routes all Tediyat API requests to appropriate handlers
 * 
 * Endpoints:
 * - POST /v1/tediyat/auth/register
 * - POST /v1/tediyat/auth/login
 * - POST /v1/tediyat/tenants/{tenantId}/switch
 * - POST /v1/tediyat/tenants
 * - GET /v1/tediyat/tenants
 * - GET /v1/tediyat/tenants/{tenantId}/members
 * - PATCH /v1/tediyat/tenants/{tenantId}/members/{userId}
 * - DELETE /v1/tediyat/tenants/{tenantId}/members/{userId}
 * - POST /v1/tediyat/tenants/{tenantId}/invitations
 * - POST /v1/tediyat/invitations/{token}/accept
 * - GET /v1/tediyat/tenants/{tenantId}/roles
 * - POST /v1/tediyat/tenants/{tenantId}/roles
 * - GET /v1/tediyat/auth/sessions
 * - DELETE /v1/tediyat/auth/sessions/{sessionId}
 * - GET /v1/tediyat/auth/permissions
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { applySecurityHeaders } from '../middleware/security.middleware';

// Import all Tediyat handlers
import { handler as registerHandler } from './tediyat/register.handler';
import { handler as loginHandler } from './tediyat/login.handler';
import { handler as switchHandler } from './tediyat/switch.handler';
import { handler as tenantCreateHandler } from './tediyat/tenant-create.handler';
import { handler as tenantListHandler } from './tediyat/tenant-list.handler';
import { handler as memberListHandler } from './tediyat/member-list.handler';
import { handler as memberUpdateHandler } from './tediyat/member-update.handler';
import { handler as memberRemoveHandler } from './tediyat/member-remove.handler';
import { handler as invitationCreateHandler } from './tediyat/invitation-create.handler';
import { handler as invitationAcceptHandler } from './tediyat/invitation-accept.handler';
import { handler as roleListHandler } from './tediyat/role-list.handler';
import { handler as roleCreateHandler } from './tediyat/role-create.handler';
import { handler as sessionListHandler } from './tediyat/session-list.handler';
import { handler as sessionTerminateHandler } from './tediyat/session-terminate.handler';
import { handler as permissionsHandler } from './tediyat/permissions.handler';

/**
 * Main router for Tediyat API
 */
export const handler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  const path = event.path;
  const method = event.httpMethod;

  console.log(`[Tediyat Router] ${method} ${path}`);

  try {
    // Route to appropriate handler based on path and method
    let response: APIGatewayProxyResult;

    // Auth routes
    if (path === '/v1/tediyat/auth/register' && method === 'POST') {
      response = await registerHandler(event);
    } else if (path === '/v1/tediyat/auth/login' && method === 'POST') {
      response = await loginHandler(event);
    } else if (path === '/v1/tediyat/auth/sessions' && method === 'GET') {
      response = await sessionListHandler(event);
    } else if (path.match(/^\/v1\/tediyat\/auth\/sessions\/[^/]+$/) && method === 'DELETE') {
      response = await sessionTerminateHandler(event);
    } else if (path === '/v1/tediyat/auth/permissions' && method === 'GET') {
      response = await permissionsHandler(event);
    }
    // Tenant routes
    else if (path === '/v1/tediyat/tenants' && method === 'POST') {
      response = await tenantCreateHandler(event);
    } else if (path === '/v1/tediyat/tenants' && method === 'GET') {
      response = await tenantListHandler(event);
    } else if (path.match(/^\/v1\/tediyat\/tenants\/[^/]+\/switch$/) && method === 'POST') {
      response = await switchHandler(event);
    }
    // Member routes
    else if (path.match(/^\/v1\/tediyat\/tenants\/[^/]+\/members$/) && method === 'GET') {
      response = await memberListHandler(event);
    } else if (path.match(/^\/v1\/tediyat\/tenants\/[^/]+\/members\/[^/]+$/) && method === 'PATCH') {
      response = await memberUpdateHandler(event);
    } else if (path.match(/^\/v1\/tediyat\/tenants\/[^/]+\/members\/[^/]+$/) && method === 'DELETE') {
      response = await memberRemoveHandler(event);
    }
    // Invitation routes
    else if (path.match(/^\/v1\/tediyat\/tenants\/[^/]+\/invitations$/) && method === 'POST') {
      response = await invitationCreateHandler(event);
    } else if (path.match(/^\/v1\/tediyat\/invitations\/[^/]+\/accept$/) && method === 'POST') {
      response = await invitationAcceptHandler(event);
    }
    // Role routes
    else if (path.match(/^\/v1\/tediyat\/tenants\/[^/]+\/roles$/) && method === 'GET') {
      response = await roleListHandler(event);
    } else if (path.match(/^\/v1\/tediyat\/tenants\/[^/]+\/roles$/) && method === 'POST') {
      response = await roleCreateHandler(event);
    }
    // Not found
    else {
      response = {
        statusCode: 404,
        body: JSON.stringify({
          success: false,
          error: {
            code: 'NOT_FOUND',
            message: 'Endpoint bulunamadı',
          },
        }),
      };
    }

    // Add security headers
    return applySecurityHeaders(response);
  } catch (error) {
    console.error('[Tediyat Router] Error:', error);
    return applySecurityHeaders({
      statusCode: 500,
      body: JSON.stringify({
        success: false,
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Sunucu hatası',
        },
      }),
    });
  }
};
