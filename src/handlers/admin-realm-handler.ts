/**
 * Admin Realm Handler - Create/List/Manage Realms
 * For Zalt.io Dashboard - Clerk-like self-service
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { createRealm, findRealmById, listRealms } from '../repositories/realm.repository';
import { logSecurityEvent } from '../services/security-logger.service';

const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Zalt-Admin-Key',
  'X-Content-Type-Options': 'nosniff'
};

// Simple admin key validation (use proper auth in production)
const ADMIN_KEY = process.env.ZALT_ADMIN_KEY || 'zalt-admin-secret-key';

function validateAdminKey(event: APIGatewayProxyEvent): boolean {
  const key = event.headers['X-Zalt-Admin-Key'] || event.headers['x-zalt-admin-key'];
  return key === ADMIN_KEY;
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const method = event.httpMethod;
  const path = event.path;

  // Validate admin key
  if (!validateAdminKey(event)) {
    return {
      statusCode: 401,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: 'Unauthorized' })
    };
  }

  try {
    // POST /admin/realms - Create realm
    if (method === 'POST' && path === '/admin/realms') {
      const body = JSON.parse(event.body || '{}');
      
      if (!body.name) {
        return {
          statusCode: 400,
          headers: CORS_HEADERS,
          body: JSON.stringify({ error: 'Realm name is required' })
        };
      }

      const realm = await createRealm({
        name: body.name,
        domain: body.domain,
        settings: body.settings,
        auth_providers: body.auth_providers
      });

      const clientIp = event.requestContext?.identity?.sourceIp || 'unknown';
      
      await logSecurityEvent({
        event_type: 'realm_created',
        realm_id: realm.id,
        ip_address: clientIp,
        details: { name: realm.name }
      });

      return {
        statusCode: 201,
        headers: CORS_HEADERS,
        body: JSON.stringify({ realm })
      };
    }

    // GET /admin/realms - List realms
    if (method === 'GET' && path === '/admin/realms') {
      const realms = await listRealms();
      return {
        statusCode: 200,
        headers: CORS_HEADERS,
        body: JSON.stringify({ realms })
      };
    }

    // GET /admin/realms/{id} - Get realm
    if (method === 'GET' && path.startsWith('/admin/realms/')) {
      const realmId = path.split('/').pop();
      if (!realmId) {
        return {
          statusCode: 400,
          headers: CORS_HEADERS,
          body: JSON.stringify({ error: 'Realm ID required' })
        };
      }

      const realm = await findRealmById(realmId);
      if (!realm) {
        return {
          statusCode: 404,
          headers: CORS_HEADERS,
          body: JSON.stringify({ error: 'Realm not found' })
        };
      }

      return {
        statusCode: 200,
        headers: CORS_HEADERS,
        body: JSON.stringify({ realm })
      };
    }

    return {
      statusCode: 404,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: 'Not found' })
    };

  } catch (error) {
    console.error('Admin realm error:', error);
    
    // Handle duplicate realm
    if ((error as Error).name === 'ConditionalCheckFailedException') {
      return {
        statusCode: 409,
        headers: CORS_HEADERS,
        body: JSON.stringify({ error: 'Realm already exists' })
      };
    }

    return {
      statusCode: 500,
      headers: CORS_HEADERS,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
}
