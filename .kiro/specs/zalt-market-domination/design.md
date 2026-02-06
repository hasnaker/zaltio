# Zalt.io Market Domination - Technical Design

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZALT.IO ECOSYSTEM                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  @zalt/ui   │  │ @zalt/react │  │ @zalt/next  │              │
│  │  Components │  │   Hooks     │  │  Middleware │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         └────────────────┼────────────────┘                      │
│                          │                                       │
│                   ┌──────▼──────┐                                │
│                   │ @zalt/core  │                                │
│                   │   Client    │                                │
│                   └──────┬──────┘                                │
│                          │                                       │
│         ┌────────────────┼────────────────┐                      │
│         │                │                │                      │
│  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐              │
│  │ @zalt/mcp   │  │  docs.zalt  │  │  dashboard  │              │
│  │   Server    │  │     .io     │  │  .zalt.io   │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Package Structure

```
packages/
├── ui/                    # @zalt/ui - Pre-built components
│   ├── src/
│   │   ├── components/
│   │   │   ├── SignIn/
│   │   │   │   ├── SignIn.tsx
│   │   │   │   ├── SignIn.styles.ts
│   │   │   │   ├── SignIn.test.tsx
│   │   │   │   └── index.ts
│   │   │   ├── SignUp/
│   │   │   ├── UserButton/
│   │   │   ├── UserProfile/
│   │   │   ├── OrganizationSwitcher/
│   │   │   ├── MFASetup/
│   │   │   └── ProtectedRoute/
│   │   ├── themes/
│   │   │   ├── default.ts
│   │   │   ├── dark.ts
│   │   │   └── types.ts
│   │   └── index.ts
│   ├── package.json
│   └── tsconfig.json
│
├── mcp-server/            # @zalt/mcp-server - AI integration
│   ├── src/
│   │   ├── tools/
│   │   │   ├── users.ts
│   │   │   ├── sessions.ts
│   │   │   ├── mfa.ts
│   │   │   ├── oauth.ts
│   │   │   └── api-keys.ts
│   │   ├── server.ts
│   │   └── index.ts
│   ├── package.json
│   └── README.md
│
└── docs/                  # Documentation site
    ├── pages/
    │   ├── index.mdx
    │   ├── quickstart.mdx
    │   ├── guides/
    │   │   ├── nextjs.mdx
    │   │   ├── react.mdx
    │   │   ├── remix.mdx
    │   │   └── ...
    │   ├── components/
    │   ├── api/
    │   └── self-hosting/
    ├── next.config.js
    └── package.json
```

## UI Components Design

### SignIn Component

```tsx
// Usage
<SignIn 
  appearance={{
    theme: 'dark',
    variables: {
      colorPrimary: '#6366f1',
      borderRadius: '8px'
    }
  }}
  routing="path"
  path="/sign-in"
  signUpUrl="/sign-up"
  afterSignInUrl="/dashboard"
/>

// Headless alternative
const { signIn, isLoading, error } = useSignIn();
```

### Component API Design

```tsx
// All components follow this pattern
interface ComponentProps {
  // Appearance
  appearance?: {
    theme?: 'light' | 'dark' | 'system';
    variables?: ThemeVariables;
    elements?: ElementOverrides;
  };
  
  // Routing
  routing?: 'path' | 'hash' | 'virtual';
  path?: string;
  
  // Callbacks
  onSuccess?: (result: AuthResult) => void;
  onError?: (error: ZaltError) => void;
  
  // Customization
  children?: React.ReactNode;
  asChild?: boolean;
}
```

### Theme System

```typescript
// themes/types.ts
interface ThemeVariables {
  // Colors
  colorPrimary: string;
  colorPrimaryHover: string;
  colorBackground: string;
  colorText: string;
  colorTextSecondary: string;
  colorBorder: string;
  colorError: string;
  colorSuccess: string;
  
  // Typography
  fontFamily: string;
  fontSize: string;
  fontWeight: string;
  
  // Spacing
  spacing: string;
  borderRadius: string;
  
  // Shadows
  shadow: string;
  shadowHover: string;
}

// Default theme
const defaultTheme: ThemeVariables = {
  colorPrimary: '#6366f1',
  colorPrimaryHover: '#4f46e5',
  colorBackground: '#ffffff',
  colorText: '#1f2937',
  colorTextSecondary: '#6b7280',
  colorBorder: '#e5e7eb',
  colorError: '#ef4444',
  colorSuccess: '#22c55e',
  fontFamily: 'Inter, system-ui, sans-serif',
  fontSize: '14px',
  fontWeight: '500',
  spacing: '16px',
  borderRadius: '8px',
  shadow: '0 1px 3px rgba(0,0,0,0.1)',
  shadowHover: '0 4px 6px rgba(0,0,0,0.1)',
};
```

## MCP Server Design

### Tool Definitions

```typescript
// tools/users.ts
export const userTools = [
  {
    name: 'zalt_list_users',
    description: 'List all users in the application',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', default: 10 },
        offset: { type: 'number', default: 0 },
        search: { type: 'string' },
        status: { enum: ['active', 'suspended', 'all'] }
      }
    }
  },
  {
    name: 'zalt_create_user',
    description: 'Create a new user',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', required: true },
        password: { type: 'string' },
        firstName: { type: 'string' },
        lastName: { type: 'string' },
        sendInvite: { type: 'boolean', default: true }
      }
    }
  },
  {
    name: 'zalt_get_user',
    description: 'Get user details by ID or email',
    inputSchema: {
      type: 'object',
      properties: {
        userId: { type: 'string' },
        email: { type: 'string' }
      }
    }
  },
  {
    name: 'zalt_update_user',
    description: 'Update user properties',
    inputSchema: {
      type: 'object',
      properties: {
        userId: { type: 'string', required: true },
        firstName: { type: 'string' },
        lastName: { type: 'string' },
        metadata: { type: 'object' }
      }
    }
  },
  {
    name: 'zalt_delete_user',
    description: 'Delete a user',
    inputSchema: {
      type: 'object',
      properties: {
        userId: { type: 'string', required: true },
        hardDelete: { type: 'boolean', default: false }
      }
    }
  }
];

// tools/sessions.ts
export const sessionTools = [
  {
    name: 'zalt_list_sessions',
    description: 'List active sessions for a user',
    inputSchema: {
      type: 'object',
      properties: {
        userId: { type: 'string' }
      }
    }
  },
  {
    name: 'zalt_revoke_session',
    description: 'Revoke a specific session',
    inputSchema: {
      type: 'object',
      properties: {
        sessionId: { type: 'string', required: true }
      }
    }
  },
  {
    name: 'zalt_revoke_all_sessions',
    description: 'Revoke all sessions for a user',
    inputSchema: {
      type: 'object',
      properties: {
        userId: { type: 'string', required: true }
      }
    }
  }
];

// tools/mfa.ts
export const mfaTools = [
  {
    name: 'zalt_enable_mfa_policy',
    description: 'Enable MFA requirement for all users',
    inputSchema: {
      type: 'object',
      properties: {
        policy: { enum: ['optional', 'required', 'disabled'] },
        methods: { 
          type: 'array', 
          items: { enum: ['totp', 'webauthn', 'sms'] }
        }
      }
    }
  },
  {
    name: 'zalt_reset_user_mfa',
    description: 'Reset MFA for a specific user',
    inputSchema: {
      type: 'object',
      properties: {
        userId: { type: 'string', required: true },
        reason: { type: 'string', required: true }
      }
    }
  }
];
```

### MCP Server Implementation

```typescript
// server.ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { userTools, sessionTools, mfaTools, oauthTools, apiKeyTools } from './tools';

const server = new Server({
  name: 'zalt-auth-server',
  version: '1.0.0',
}, {
  capabilities: {
    tools: {}
  }
});

// Register all tools
const allTools = [
  ...userTools,
  ...sessionTools,
  ...mfaTools,
  ...oauthTools,
  ...apiKeyTools
];

server.setRequestHandler('tools/list', async () => ({
  tools: allTools
}));

server.setRequestHandler('tools/call', async (request) => {
  const { name, arguments: args } = request.params;
  
  // Route to appropriate handler
  switch (name) {
    case 'zalt_list_users':
      return handleListUsers(args);
    case 'zalt_create_user':
      return handleCreateUser(args);
    // ... etc
  }
});

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
```

## Documentation Site Design

### Tech Stack
- **Framework:** Next.js 14 + Nextra
- **Styling:** Tailwind CSS
- **Search:** Algolia DocSearch
- **Analytics:** Plausible (privacy-friendly)
- **Hosting:** Vercel

### Site Structure

```
docs.zalt.io/
├── /                      # Landing + quickstart
├── /quickstart            # 5-minute setup
├── /guides/
│   ├── /nextjs           # Next.js integration
│   ├── /react            # React integration
│   ├── /remix            # Remix integration
│   ├── /astro            # Astro integration
│   ├── /express          # Express.js backend
│   └── /fastapi          # FastAPI backend
├── /components/
│   ├── /sign-in          # SignIn component
│   ├── /sign-up          # SignUp component
│   ├── /user-button      # UserButton component
│   └── /...              # Other components
├── /hooks/
│   ├── /use-auth         # useAuth hook
│   ├── /use-user         # useUser hook
│   └── /...              # Other hooks
├── /api/
│   ├── /authentication   # Auth endpoints
│   ├── /users            # User management
│   ├── /sessions         # Session management
│   └── /webhooks         # Webhook events
├── /security/
│   ├── /mfa              # MFA setup
│   ├── /webauthn         # Passkeys
│   └── /best-practices   # Security guide
├── /self-hosting/
│   ├── /docker           # Docker setup
│   ├── /kubernetes       # K8s deployment
│   └── /configuration    # Config options
└── /changelog            # Version history
```

## Community Strategy

### Launch Sequence

```
Week 1: Soft Launch
├── GitHub repo public
├── NPM packages published
├── Basic docs live
└── Discord server created

Week 2: Content Push
├── Dev.to article: "Why I built a Clerk alternative"
├── Twitter thread: Feature comparison
├── Reddit posts: r/nextjs, r/webdev
└── YouTube: 5-min quickstart video

Week 3: Community Engagement
├── Respond to all GitHub issues
├── Discord active support
├── Twitter engagement
└── Blog post: "Migrating from Clerk"

Week 4: Product Hunt Launch
├── PH launch preparation
├── Hacker News post
├── Influencer outreach
└── Press release
```

### Content Calendar

| Day | Platform | Content |
|-----|----------|---------|
| Mon | Twitter | Feature highlight |
| Tue | Dev.to | Tutorial article |
| Wed | Discord | Community Q&A |
| Thu | YouTube | Short tutorial |
| Fri | Reddit | Discussion post |

## Self-Hosting Design

### Docker Image

```dockerfile
# Dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 3000
CMD ["node", "dist/server.js"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  zalt:
    image: zaltio/zalt-auth:latest
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgres://user:pass@db:5432/zalt
      - JWT_SECRET=${JWT_SECRET}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:15-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=zalt
  
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### Helm Chart

```yaml
# Chart.yaml
apiVersion: v2
name: zalt-auth
description: Self-hosted authentication platform
version: 1.0.0
appVersion: "1.0.0"

# values.yaml
replicaCount: 2
image:
  repository: zaltio/zalt-auth
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 3000

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: auth.example.com
      paths:
        - path: /
          pathType: Prefix

postgresql:
  enabled: true
  auth:
    postgresPassword: changeme
    database: zalt

redis:
  enabled: true
  auth:
    enabled: false
```

## Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Login latency | < 200ms p95 | API response time |
| Token refresh | < 100ms p95 | API response time |
| SDK bundle | < 20KB gzip | Bundlephobia |
| Component render | < 50ms | React profiler |
| Docs page load | < 1s | Lighthouse |
| Cold start | < 500ms | Lambda metrics |
