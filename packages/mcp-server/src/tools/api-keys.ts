/**
 * API Key Management Tools for Zalt MCP Server
 * @zalt/mcp-server
 */

import { makeApiRequest } from '../config.js';

// Types
interface ZaltAPIKey {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  status: 'active' | 'revoked';
  created_at: string;
  last_used_at?: string;
  expires_at?: string;
}

interface CreateAPIKeyResponse {
  id: string;
  name: string;
  key: string; // Full key, only shown once
  key_prefix: string;
  scopes: string[];
  created_at: string;
}

// Tool Definitions
export const apiKeyTools = [
  {
    name: 'zalt_list_api_keys',
    description: 'List API keys for a user (keys are masked for security)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to list API keys for',
        },
      },
      required: ['realm_id', 'user_id'],
    },
  },
  {
    name: 'zalt_create_api_key',
    description: 'Create a new API key for a user (full key shown only once)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to create API key for',
        },
        name: {
          type: 'string',
          description: 'Name/description for the API key',
        },
        scopes: {
          type: 'array',
          items: { type: 'string' },
          description: 'Permission scopes for the key (e.g., ["read:users", "write:users"])',
        },
        expires_in_days: {
          type: 'number',
          description: 'Number of days until key expires (optional, default: no expiry)',
        },
      },
      required: ['realm_id', 'user_id', 'name'],
    },
  },
  {
    name: 'zalt_revoke_api_key',
    description: 'Revoke an API key (immediate invalidation)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        key_id: {
          type: 'string',
          description: 'API key ID to revoke',
        },
      },
      required: ['realm_id', 'key_id'],
    },
  },
];

// Tool Handlers
export async function handleListAPIKeys(args: {
  realm_id: string;
  user_id: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}/api-keys`,
    { method: 'GET' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to list API keys: ${response.error}` }],
      isError: true,
    };
  }

  const data = response.data as { api_keys: ZaltAPIKey[] };
  const keys = data.api_keys || [];

  if (keys.length === 0) {
    return {
      content: [{ type: 'text' as const, text: 'No API keys found for this user.' }],
    };
  }

  const keyList = keys.map((k: ZaltAPIKey) => {
    const status = k.status === 'revoked' ? '❌ REVOKED' : '✅ Active';
    const expiry = k.expires_at ? `\n   Expires: ${k.expires_at}` : '';
    const lastUsed = k.last_used_at ? `\n   Last used: ${k.last_used_at}` : '\n   Never used';
    
    return `🔑 ${k.name} (${status})\n   ID: ${k.id}\n   Prefix: ${k.key_prefix}...\n   Scopes: ${k.scopes.join(', ') || 'all'}${expiry}${lastUsed}`;
  }).join('\n\n');

  return {
    content: [{
      type: 'text' as const,
      text: `Found ${keys.length} API key(s):\n\n${keyList}`,
    }],
  };
}

export async function handleCreateAPIKey(args: {
  realm_id: string;
  user_id: string;
  name: string;
  scopes?: string[];
  expires_in_days?: number;
}) {
  const body: Record<string, unknown> = {
    name: args.name,
  };

  if (args.scopes && args.scopes.length > 0) {
    body.scopes = args.scopes;
  }

  if (args.expires_in_days) {
    body.expires_in_days = args.expires_in_days;
  }

  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}/api-keys`,
    { method: 'POST', body }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to create API key: ${response.error}` }],
      isError: true,
    };
  }

  const data = response.data as CreateAPIKeyResponse;

  return {
    content: [{
      type: 'text' as const,
      text: `✅ API Key Created Successfully!\n\n🔑 Name: ${data.name}\n📋 Key ID: ${data.id}\n\n⚠️ IMPORTANT: Save this key now - it will NOT be shown again!\n\n\`\`\`\n${data.key}\n\`\`\`\n\nScopes: ${data.scopes?.join(', ') || 'all'}\nCreated: ${data.created_at}`,
    }],
  };
}

export async function handleRevokeAPIKey(args: {
  realm_id: string;
  key_id: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/api-keys/${args.key_id}`,
    { method: 'DELETE' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to revoke API key: ${response.error}` }],
      isError: true,
    };
  }

  return {
    content: [{
      type: 'text' as const,
      text: `✅ API key ${args.key_id} has been revoked.\nThe key is now invalid and cannot be used.`,
    }],
  };
}
