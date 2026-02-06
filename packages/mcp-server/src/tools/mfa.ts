/**
 * MFA Management Tools for Zalt MCP Server
 * @zalt/mcp-server
 */

import { makeApiRequest } from '../config.js';

// Types
interface MFAStatus {
  enabled: boolean;
  methods: {
    totp: boolean;
    webauthn: boolean;
    backup_codes: boolean;
  };
  webauthn_credentials?: Array<{
    id: string;
    name: string;
    created_at: string;
    last_used_at?: string;
  }>;
  backup_codes_remaining?: number;
}

interface MFAPolicy {
  policy: 'disabled' | 'optional' | 'required';
  allowed_methods: string[];
  webauthn_required_for_sensitive?: boolean;
}

// Tool Definitions
export const mfaTools = [
  {
    name: 'zalt_get_mfa_status',
    description: 'Get MFA status and enabled methods for a user',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to check MFA status',
        },
      },
      required: ['realm_id', 'user_id'],
    },
  },
  {
    name: 'zalt_reset_mfa',
    description: 'Reset MFA for a user (admin action, requires reason for audit)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to reset MFA for',
        },
        reason: {
          type: 'string',
          description: 'Reason for MFA reset (required for audit, min 10 chars)',
        },
        notify_user: {
          type: 'boolean',
          description: 'Send email notification to user (default: true)',
          default: true,
        },
      },
      required: ['realm_id', 'user_id', 'reason'],
    },
  },
  {
    name: 'zalt_configure_mfa_policy',
    description: 'Configure MFA policy for a realm',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        policy: {
          type: 'string',
          enum: ['disabled', 'optional', 'required'],
          description: 'MFA policy: disabled (no MFA), optional (user choice), required (mandatory)',
        },
        allowed_methods: {
          type: 'array',
          items: { type: 'string', enum: ['totp', 'webauthn'] },
          description: 'Allowed MFA methods (Note: SMS is NOT recommended due to SS7 vulnerabilities)',
        },
        webauthn_required_for_sensitive: {
          type: 'boolean',
          description: 'Require WebAuthn for sensitive operations (recommended for healthcare)',
        },
      },
      required: ['realm_id', 'policy'],
    },
  },
  {
    name: 'zalt_get_mfa_policy',
    description: 'Get current MFA policy for a realm',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
      },
      required: ['realm_id'],
    },
  },
];

// Tool Handlers
export async function handleGetMFAStatus(args: {
  realm_id: string;
  user_id: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}/mfa`,
    { method: 'GET' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to get MFA status: ${response.error}` }],
      isError: true,
    };
  }

  const status = response.data as MFAStatus;

  const methods: string[] = [];
  if (status.methods.totp) methods.push('✅ TOTP (Authenticator App)');
  if (status.methods.webauthn) methods.push('✅ WebAuthn/Passkeys');
  if (status.methods.backup_codes) methods.push(`✅ Backup Codes (${status.backup_codes_remaining || 0} remaining)`);

  if (methods.length === 0) {
    methods.push('❌ No MFA methods enabled');
  }

  let webauthnInfo = '';
  if (status.webauthn_credentials && status.webauthn_credentials.length > 0) {
    webauthnInfo = '\n\n🔑 WebAuthn Credentials:\n' + status.webauthn_credentials.map(c => 
      `  - ${c.name} (created: ${c.created_at})`
    ).join('\n');
  }

  return {
    content: [{
      type: 'text' as const,
      text: `🔐 MFA Status for User ${args.user_id}\n\nEnabled: ${status.enabled ? 'Yes' : 'No'}\n\nMethods:\n${methods.join('\n')}${webauthnInfo}`,
    }],
  };
}

export async function handleResetMFA(args: {
  realm_id: string;
  user_id: string;
  reason: string;
  notify_user?: boolean;
}) {
  if (args.reason.length < 10) {
    return {
      content: [{ type: 'text' as const, text: 'Reason must be at least 10 characters for audit purposes.' }],
      isError: true,
    };
  }

  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}/mfa/reset`,
    { 
      method: 'POST',
      body: {
        reason: args.reason,
        notify_user: args.notify_user !== false,
      },
    }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to reset MFA: ${response.error}` }],
      isError: true,
    };
  }

  const notified = args.notify_user !== false ? '\nUser has been notified via email.' : '';

  return {
    content: [{
      type: 'text' as const,
      text: `⚠️ MFA has been reset for user ${args.user_id}.\nReason: ${args.reason}${notified}\n\nThe user will need to set up MFA again on next login.`,
    }],
  };
}

export async function handleConfigureMFAPolicy(args: {
  realm_id: string;
  policy: 'disabled' | 'optional' | 'required';
  allowed_methods?: string[];
  webauthn_required_for_sensitive?: boolean;
}) {
  const body: Record<string, unknown> = {
    mfa_policy: args.policy,
  };

  if (args.allowed_methods) {
    // Filter out SMS - it's not recommended
    const safeMethods = args.allowed_methods.filter(m => m !== 'sms');
    if (safeMethods.length !== args.allowed_methods.length) {
      // User tried to enable SMS
      return {
        content: [{
          type: 'text' as const,
          text: '⚠️ SMS MFA is NOT supported due to SS7 protocol vulnerabilities.\nPlease use TOTP or WebAuthn instead.',
        }],
        isError: true,
      };
    }
    body.allowed_mfa_methods = safeMethods;
  }

  if (args.webauthn_required_for_sensitive !== undefined) {
    body.webauthn_required_for_sensitive = args.webauthn_required_for_sensitive;
  }

  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}`,
    { method: 'PATCH', body }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to configure MFA policy: ${response.error}` }],
      isError: true,
    };
  }

  const policyDesc = {
    disabled: 'MFA is disabled for all users',
    optional: 'Users can optionally enable MFA',
    required: 'MFA is required for all users',
  };

  return {
    content: [{
      type: 'text' as const,
      text: `✅ MFA policy updated for realm ${args.realm_id}.\n\nPolicy: ${args.policy.toUpperCase()}\n${policyDesc[args.policy]}${args.allowed_methods ? `\nAllowed methods: ${args.allowed_methods.join(', ')}` : ''}${args.webauthn_required_for_sensitive ? '\n🔐 WebAuthn required for sensitive operations' : ''}`,
    }],
  };
}

export async function handleGetMFAPolicy(args: {
  realm_id: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}`,
    { method: 'GET' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to get MFA policy: ${response.error}` }],
      isError: true,
    };
  }

  const realm = response.data as { 
    mfa_policy?: string;
    allowed_mfa_methods?: string[];
    webauthn_required_for_sensitive?: boolean;
  };

  const policy = realm.mfa_policy || 'optional';
  const methods = realm.allowed_mfa_methods || ['totp', 'webauthn'];
  const webauthnSensitive = realm.webauthn_required_for_sensitive || false;

  const policyDesc = {
    disabled: 'MFA is disabled for all users',
    optional: 'Users can optionally enable MFA',
    required: 'MFA is required for all users',
  };

  return {
    content: [{
      type: 'text' as const,
      text: `🔐 MFA Policy for Realm ${args.realm_id}\n\nPolicy: ${policy.toUpperCase()}\n${policyDesc[policy as keyof typeof policyDesc] || 'Unknown policy'}\n\nAllowed Methods: ${methods.join(', ')}\nWebAuthn for Sensitive Ops: ${webauthnSensitive ? 'Yes ✅' : 'No'}`,
    }],
  };
}
