#!/usr/bin/env node
/**
 * Zalt MCP Server
 * @zalt/mcp-server
 * 
 * Model Context Protocol server for AI assistants
 * Provides tools for managing Zalt authentication
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  CallToolRequest,
  ReadResourceRequest,
} from '@modelcontextprotocol/sdk/types.js';

import { ZALT_API_URL, ZALT_ADMIN_KEY, makeApiRequest } from './config.js';
import {
  // User tools
  userTools,
  handleListUsers,
  handleGetUser,
  handleUpdateUser,
  handleSuspendUser,
  handleActivateUser,
  handleDeleteUser,
  // Session tools
  sessionTools,
  handleListSessions,
  handleRevokeSession,
  handleRevokeAllSessions,
  // MFA tools
  mfaTools,
  handleGetMFAStatus,
  handleResetMFA,
  handleConfigureMFAPolicy,
  handleGetMFAPolicy,
  // API Key tools
  apiKeyTools,
  handleListAPIKeys,
  handleCreateAPIKey,
  handleRevokeAPIKey,
  // Analytics tools
  analyticsTools,
  handleGetAuthStats,
  handleGetSecurityEvents,
  handleGetFailedLogins,
} from './tools/index.js';

// API Response types
interface ZaltRealm {
  id: string;
  name: string;
  domain?: string;
}

interface ZaltUser {
  id: string;
  email: string;
}

interface ZaltAPIResponse {
  realm?: ZaltRealm;
  realms?: ZaltRealm[];
  user?: ZaltUser;
  error?: { message: string };
  issuer?: string;
  jwks_uri?: string;
  token_endpoint?: string;
}

// Create server
const server = new Server(
  {
    name: 'zalt-mcp-server',
    version: '1.1.0',
  },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  }
);

// ============================================================================
// Core Tools (Realm Management)
// ============================================================================

const coreTools = [
  {
    name: 'zalt_create_realm',
    description: 'Create a new Zalt realm for multi-tenant isolation',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Display name for the realm',
        },
        domain: {
          type: 'string',
          description: 'Domain associated with the realm (e.g., company.com)',
        },
      },
      required: ['name'],
    },
  },
  {
    name: 'zalt_list_realms',
    description: 'List all Zalt realms',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'zalt_create_user',
    description: 'Create a new user in a Zalt realm',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID to create user in',
        },
        email: {
          type: 'string',
          description: 'User email address',
        },
        password: {
          type: 'string',
          description: 'User password (min 8 chars, uppercase, lowercase, number)',
        },
        first_name: {
          type: 'string',
          description: 'User first name',
        },
        last_name: {
          type: 'string',
          description: 'User last name',
        },
      },
      required: ['realm_id', 'email', 'password'],
    },
  },
  {
    name: 'zalt_check_auth_status',
    description: 'Check Zalt API health and authentication status',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'zalt_get_sdk_snippet',
    description: 'Get code snippet for Zalt SDK integration',
    inputSchema: {
      type: 'object',
      properties: {
        framework: {
          type: 'string',
          enum: ['react', 'nextjs', 'node', 'vanilla', 'python'],
          description: 'Target framework',
        },
        feature: {
          type: 'string',
          enum: ['login', 'register', 'mfa', 'webauthn', 'provider', 'middleware'],
          description: 'Feature to implement',
        },
      },
      required: ['framework', 'feature'],
    },
  },
  {
    name: 'zalt_security_check',
    description: 'Check security best practices for auth implementation',
    inputSchema: {
      type: 'object',
      properties: {
        code: {
          type: 'string',
          description: 'Code to analyze for security issues',
        },
      },
      required: ['code'],
    },
  },
];

// ============================================================================
// Tools Registration
// ============================================================================

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      ...coreTools,
      ...userTools,
      ...sessionTools,
      ...mfaTools,
      ...apiKeyTools,
      ...analyticsTools,
    ],
  };
});

// ============================================================================
// Tool Call Handler
// ============================================================================

server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
  const { name, arguments: args } = request.params;

  // Core tools
  switch (name) {
    case 'zalt_create_realm':
      return await createRealm(args as { name: string; domain?: string });
    case 'zalt_list_realms':
      return await listRealms();
    case 'zalt_create_user':
      return await createUser(args as {
        realm_id: string;
        email: string;
        password: string;
        first_name?: string;
        last_name?: string;
      });
    case 'zalt_check_auth_status':
      return await checkAuthStatus();
    case 'zalt_get_sdk_snippet':
      return getSdkSnippet(args as { framework: string; feature: string });
    case 'zalt_security_check':
      return securityCheck(args as { code: string });
  }

  // User management tools
  switch (name) {
    case 'zalt_list_users':
      return await handleListUsers(args as Parameters<typeof handleListUsers>[0]);
    case 'zalt_get_user':
      return await handleGetUser(args as Parameters<typeof handleGetUser>[0]);
    case 'zalt_update_user':
      return await handleUpdateUser(args as Parameters<typeof handleUpdateUser>[0]);
    case 'zalt_suspend_user':
      return await handleSuspendUser(args as Parameters<typeof handleSuspendUser>[0]);
    case 'zalt_activate_user':
      return await handleActivateUser(args as Parameters<typeof handleActivateUser>[0]);
    case 'zalt_delete_user':
      return await handleDeleteUser(args as Parameters<typeof handleDeleteUser>[0]);
  }

  // Session management tools
  switch (name) {
    case 'zalt_list_sessions':
      return await handleListSessions(args as Parameters<typeof handleListSessions>[0]);
    case 'zalt_revoke_session':
      return await handleRevokeSession(args as Parameters<typeof handleRevokeSession>[0]);
    case 'zalt_revoke_all_sessions':
      return await handleRevokeAllSessions(args as Parameters<typeof handleRevokeAllSessions>[0]);
  }

  // MFA management tools
  switch (name) {
    case 'zalt_get_mfa_status':
      return await handleGetMFAStatus(args as Parameters<typeof handleGetMFAStatus>[0]);
    case 'zalt_reset_mfa':
      return await handleResetMFA(args as Parameters<typeof handleResetMFA>[0]);
    case 'zalt_configure_mfa_policy':
      return await handleConfigureMFAPolicy(args as Parameters<typeof handleConfigureMFAPolicy>[0]);
    case 'zalt_get_mfa_policy':
      return await handleGetMFAPolicy(args as Parameters<typeof handleGetMFAPolicy>[0]);
  }

  // API Key management tools
  switch (name) {
    case 'zalt_list_api_keys':
      return await handleListAPIKeys(args as Parameters<typeof handleListAPIKeys>[0]);
    case 'zalt_create_api_key':
      return await handleCreateAPIKey(args as Parameters<typeof handleCreateAPIKey>[0]);
    case 'zalt_revoke_api_key':
      return await handleRevokeAPIKey(args as Parameters<typeof handleRevokeAPIKey>[0]);
  }

  // Analytics tools
  switch (name) {
    case 'zalt_get_auth_stats':
      return await handleGetAuthStats(args as Parameters<typeof handleGetAuthStats>[0]);
    case 'zalt_get_security_events':
      return await handleGetSecurityEvents(args as Parameters<typeof handleGetSecurityEvents>[0]);
    case 'zalt_get_failed_logins':
      return await handleGetFailedLogins(args as Parameters<typeof handleGetFailedLogins>[0]);
  }

  throw new Error(`Unknown tool: ${name}`);
});

// ============================================================================
// Resources
// ============================================================================

server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
      {
        uri: 'zalt://docs/quickstart',
        name: 'Zalt Quick Start Guide',
        description: 'Get started with Zalt authentication in minutes',
        mimeType: 'text/markdown',
      },
      {
        uri: 'zalt://docs/security',
        name: 'Zalt Security Best Practices',
        description: 'Security guidelines for Zalt implementation',
        mimeType: 'text/markdown',
      },
      {
        uri: 'zalt://docs/mfa',
        name: 'Zalt MFA Guide',
        description: 'Multi-factor authentication setup and best practices',
        mimeType: 'text/markdown',
      },
    ],
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request: ReadResourceRequest) => {
  const { uri } = request.params;

  switch (uri) {
    case 'zalt://docs/quickstart':
      return {
        contents: [{ uri, mimeType: 'text/markdown', text: QUICKSTART_DOC }],
      };
    case 'zalt://docs/security':
      return {
        contents: [{ uri, mimeType: 'text/markdown', text: SECURITY_DOC }],
      };
    case 'zalt://docs/mfa':
      return {
        contents: [{ uri, mimeType: 'text/markdown', text: MFA_DOC }],
      };
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
});

// ============================================================================
// Core Tool Implementations
// ============================================================================

async function createRealm(args: { name: string; domain?: string }) {
  const response = await makeApiRequest<ZaltAPIResponse>('/admin/realms', {
    method: 'POST',
    body: { name: args.name, domain: args.domain },
  });

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to create realm: ${response.error}` }],
      isError: true,
    };
  }

  const data = response.data!;
  return {
    content: [{
      type: 'text' as const,
      text: `✅ Realm created successfully!\n\nRealm ID: ${data.realm?.id}\nName: ${data.realm?.name}\n\nUse this realm_id in your SDK configuration.`,
    }],
  };
}

async function listRealms() {
  const response = await makeApiRequest<ZaltAPIResponse>('/admin/realms', { method: 'GET' });

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to list realms: ${response.error}` }],
      isError: true,
    };
  }

  const realms = response.data?.realms || [];
  const realmList = realms.map((r: ZaltRealm) => `- ${r.name} (${r.id})`).join('\n');

  return {
    content: [{
      type: 'text' as const,
      text: `Found ${realms.length} realm(s):\n\n${realmList || 'No realms found'}`,
    }],
  };
}

async function createUser(args: {
  realm_id: string;
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
}) {
  const response = await makeApiRequest<ZaltAPIResponse>('/register', {
    method: 'POST',
    body: {
      realm_id: args.realm_id,
      email: args.email,
      password: args.password,
      profile: {
        first_name: args.first_name,
        last_name: args.last_name,
      },
    },
  });

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to create user: ${response.error}` }],
      isError: true,
    };
  }

  return {
    content: [{
      type: 'text' as const,
      text: `✅ User created successfully!\n\nUser ID: ${response.data?.user?.id}\nEmail: ${args.email}\nRealm: ${args.realm_id}`,
    }],
  };
}

async function checkAuthStatus() {
  try {
    const response = await fetch(`${ZALT_API_URL}/.well-known/openid-configuration`);
    const data = await response.json() as ZaltAPIResponse;

    return {
      content: [{
        type: 'text' as const,
        text: `✅ Zalt API is healthy!\n\nIssuer: ${data.issuer}\nJWKS URI: ${data.jwks_uri}\nToken Endpoint: ${data.token_endpoint}`,
      }],
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: `❌ Zalt API is not reachable: ${error instanceof Error ? error.message : 'Unknown error'}`,
      }],
      isError: true,
    };
  }
}

function getSdkSnippet(args: { framework: string; feature: string }) {
  const snippets: Record<string, Record<string, string>> = {
    react: {
      provider: `import { ZaltProvider } from '@zalt/react';

function App() {
  return (
    <ZaltProvider realmId="your-realm-id">
      <YourApp />
    </ZaltProvider>
  );
}`,
      login: `import { useAuth } from '@zalt/react';

function LoginForm() {
  const { signIn, isLoading } = useAuth();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    await signIn(email, password);
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input type="email" value={email} onChange={...} />
      <input type="password" value={password} onChange={...} />
      <button disabled={isLoading}>Sign In</button>
    </form>
  );
}`,
      mfa: `import { useMFA } from '@zalt/react';

function MFASetup() {
  const { setup, verify, isLoading } = useMFA();
  
  const handleSetup = async () => {
    const { qrCode, secret } = await setup('totp');
    // Show QR code to user
  };
  
  return <button onClick={handleSetup}>Enable 2FA</button>;
}`,
    },
    nextjs: {
      provider: `// app/layout.tsx
import { ZaltProvider } from '@zalt/react';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <ZaltProvider realmId="your-realm-id">
          {children}
        </ZaltProvider>
      </body>
    </html>
  );
}`,
      middleware: `// middleware.ts
import { zaltMiddleware } from '@zalt/next';

export default zaltMiddleware({
  publicRoutes: ['/', '/sign-in', '/sign-up'],
  signInUrl: '/sign-in',
});

export const config = {
  matcher: ['/((?!_next|.*\\..*).*)'],
};`,
      login: `// app/sign-in/page.tsx
import { SignIn } from '@zalt/ui';

export default function SignInPage() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <SignIn afterSignInUrl="/dashboard" />
    </div>
  );
}`,
    },
    python: {
      login: `from zalt_auth import ZaltClient

client = ZaltClient(realm_id="your-realm-id")

# Login
result = client.login(email="user@example.com", password="password")
print(f"Logged in as: {result.user.email}")

# Get current user
user = client.get_current_user()
print(f"User ID: {user.id}")`,
      middleware: `# FastAPI middleware
from fastapi import FastAPI, Depends
from zalt_auth.integrations.fastapi import ZaltFastAPI, get_current_user

app = FastAPI()
zalt = ZaltFastAPI(app, realm_id="your-realm-id")

@app.get("/protected")
async def protected_route(user = Depends(get_current_user)):
    return {"message": f"Hello {user.email}"}`,
    },
  };

  const snippet = snippets[args.framework]?.[args.feature];

  if (!snippet) {
    return {
      content: [{
        type: 'text' as const,
        text: `No snippet available for ${args.framework}/${args.feature}. Check docs at https://zalt.io/docs`,
      }],
    };
  }

  return {
    content: [{ type: 'text' as const, text: `\`\`\`typescript\n${snippet}\n\`\`\`` }],
  };
}

function securityCheck(args: { code: string }) {
  const issues: string[] = [];
  const code = args.code.toLowerCase();

  // Check for common security issues
  if (code.includes('localstorage') && code.includes('token')) {
    issues.push('⚠️ Storing tokens in localStorage is vulnerable to XSS. Use httpOnly cookies instead.');
  }

  if (code.includes('console.log') && (code.includes('token') || code.includes('password'))) {
    issues.push('🚨 Never log sensitive data like tokens or passwords!');
  }

  if (code.includes('sms') && code.includes('mfa')) {
    issues.push('⚠️ SMS MFA is vulnerable to SS7 attacks. Consider TOTP or WebAuthn instead.');
  }

  if (!code.includes('httponly') && code.includes('cookie')) {
    issues.push('⚠️ Cookies should use httpOnly flag to prevent XSS access.');
  }

  if (code.includes('eval(') || code.includes('innerhtml')) {
    issues.push('🚨 Avoid eval() and innerHTML - they can lead to XSS vulnerabilities.');
  }

  if (code.includes('md5') || code.includes('sha1')) {
    issues.push('🚨 MD5 and SHA1 are not secure for password hashing. Use Argon2id.');
  }

  if (issues.length === 0) {
    return {
      content: [{
        type: 'text' as const,
        text: '✅ No obvious security issues found. Remember to:\n- Use httpOnly cookies for tokens\n- Never log sensitive data\n- Prefer TOTP/WebAuthn over SMS MFA\n- Validate all user input\n- Use Argon2id for password hashing',
      }],
    };
  }

  return {
    content: [{
      type: 'text' as const,
      text: `Found ${issues.length} potential security issue(s):\n\n${issues.join('\n\n')}`,
    }],
  };
}

// ============================================================================
// Documentation
// ============================================================================

const QUICKSTART_DOC = `# Zalt Quick Start Guide

## Installation

\`\`\`bash
npm install @zalt/core @zalt/react
\`\`\`

## Setup Provider

\`\`\`tsx
import { ZaltProvider } from '@zalt/react';

function App() {
  return (
    <ZaltProvider realmId="your-realm-id">
      <YourApp />
    </ZaltProvider>
  );
}
\`\`\`

## Use Authentication

\`\`\`tsx
import { useAuth, SignedIn, SignedOut } from '@zalt/react';

function Header() {
  const { user, signOut } = useAuth();
  
  return (
    <header>
      <SignedIn>
        <span>Hello, {user.email}</span>
        <button onClick={signOut}>Sign Out</button>
      </SignedIn>
      <SignedOut>
        <a href="/sign-in">Sign In</a>
      </SignedOut>
    </header>
  );
}
\`\`\`

## Pre-built UI Components

\`\`\`tsx
import { SignIn, SignUp, UserButton } from '@zalt/ui';

// Drop-in sign in page
<SignIn afterSignInUrl="/dashboard" />

// User menu with avatar
<UserButton />
\`\`\`
`;

const SECURITY_DOC = `# Zalt Security Best Practices

## Token Storage
- ✅ Use httpOnly cookies (default in @zalt/next)
- ❌ Never store tokens in localStorage
- ❌ Never expose tokens in URLs

## MFA
- ✅ Use TOTP (Google Authenticator, etc.)
- ✅ Use WebAuthn/Passkeys (phishing-proof)
- ⚠️ SMS MFA is vulnerable to SS7 attacks - NOT RECOMMENDED

## Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- Checked against HaveIBeenPwned breach database
- Hashed with Argon2id (32MB memory, timeCost 5)

## Rate Limiting
- Login: 5 attempts / 15 min / IP
- Register: 3 attempts / hour / IP
- Password Reset: 3 attempts / hour / email

## Session Security
- Access tokens: 15 minutes
- Refresh tokens: 7 days (rotated on use)
- Device fingerprinting with 70% fuzzy matching
- Automatic session invalidation on password change
`;

const MFA_DOC = `# Zalt MFA Guide

## Supported Methods

### 1. TOTP (Time-based One-Time Password)
- Works with Google Authenticator, Authy, 1Password
- 6-digit codes, 30-second window
- Backup codes provided (10 single-use codes)

### 2. WebAuthn/Passkeys (Recommended)
- Phishing-proof authentication
- Works with Face ID, Touch ID, Windows Hello
- Hardware security keys (YubiKey, etc.)
- **Mandatory for healthcare realms (HIPAA)**

## Setup Flow

\`\`\`tsx
import { useMFA } from '@zalt/react';

function MFASetup() {
  const { setup, verify } = useMFA();
  
  // 1. Get QR code
  const { qrCode, secret, backupCodes } = await setup('totp');
  
  // 2. User scans QR code
  // 3. User enters code from authenticator
  await verify(code);
  
  // 4. Save backup codes securely!
}
\`\`\`

## WebAuthn Setup

\`\`\`tsx
import { useWebAuthn } from '@zalt/react';

function PasskeySetup() {
  const { register, authenticate } = useWebAuthn();
  
  // Register new passkey
  await register({ name: 'My MacBook' });
  
  // Authenticate with passkey
  await authenticate();
}
\`\`\`

## Security Notes

⚠️ **SMS MFA is NOT supported** due to SS7 protocol vulnerabilities.
Use TOTP or WebAuthn instead for secure authentication.
`;

// ============================================================================
// Start Server
// ============================================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Zalt MCP Server v1.1.0 running on stdio');
  console.error(`API URL: ${ZALT_API_URL}`);
  console.error(`Admin Key: ${ZALT_ADMIN_KEY ? 'Configured' : 'Not configured'}`);
}

main().catch(console.error);
