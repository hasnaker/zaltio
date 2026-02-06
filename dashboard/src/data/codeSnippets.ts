/**
 * Code Snippets for SDK Integration Examples
 * 
 * Contains installation commands and integration code for each supported framework
 */

export interface CodeSnippet {
  framework: string;
  language: string;
  install: string;
  code: string;
  filename: string;
}

export const codeSnippets: Record<string, CodeSnippet> = {
  nextjs: {
    framework: 'Next.js',
    language: 'typescript',
    install: 'npm install @zalt/next',
    filename: 'middleware.ts',
    code: `import { authMiddleware } from '@zalt/next';

export default authMiddleware({
  publicRoutes: ['/', '/pricing', '/docs(.*)'],
  afterAuth(auth, req) {
    // Redirect unauthenticated users to sign-in
    if (!auth.userId && !auth.isPublicRoute) {
      return auth.redirectToSignIn();
    }
  },
});

export const config = {
  matcher: ['/((?!.*\\\\..*|_next).*)', '/', '/(api|trpc)(.*)'],
};`,
  },
  react: {
    framework: 'React',
    language: 'typescript',
    install: 'npm install @zalt/react',
    filename: 'App.tsx',
    code: `import { ZaltProvider, SignIn, useAuth } from '@zalt/react';

function App() {
  return (
    <ZaltProvider realmId="your-realm-id">
      <AuthenticatedApp />
    </ZaltProvider>
  );
}

function AuthenticatedApp() {
  const { isSignedIn, user } = useAuth();

  if (!isSignedIn) {
    return <SignIn />;
  }

  return (
    <div>
      <h1>Welcome, {user.email}!</h1>
    </div>
  );
}`,
  },
  vue: {
    framework: 'Vue.js',
    language: 'typescript',
    install: 'npm install @zalt/vue',
    filename: 'main.ts',
    code: `import { createApp } from 'vue';
import { ZaltPlugin } from '@zalt/vue';
import App from './App.vue';

const app = createApp(App);

app.use(ZaltPlugin, {
  realmId: 'your-realm-id',
  redirectUrl: window.location.origin,
});

app.mount('#app');

// In your component:
// <script setup>
// import { useAuth } from '@zalt/vue';
// const { isSignedIn, user, signOut } = useAuth();
// </script>`,
  },
  node: {
    framework: 'Node.js',
    language: 'typescript',
    install: 'npm install @zalt/node',
    filename: 'server.ts',
    code: `import express from 'express';
import { ZaltClient, requireAuth } from '@zalt/node';

const app = express();
const zalt = new ZaltClient({
  realmId: process.env.ZALT_REALM_ID!,
  secretKey: process.env.ZALT_SECRET_KEY!,
});

// Protect routes with authentication
app.use('/api', requireAuth(zalt));

app.get('/api/profile', async (req, res) => {
  // req.auth contains the authenticated user
  const user = await zalt.users.get(req.auth.userId);
  res.json(user);
});

app.listen(3000);`,
  },
  python: {
    framework: 'Python',
    language: 'python',
    install: 'pip install zalt-auth',
    filename: 'app.py',
    code: `from fastapi import FastAPI, Depends
from zalt_auth import ZaltClient, require_auth
from zalt_auth.integrations.fastapi import ZaltMiddleware

app = FastAPI()
zalt = ZaltClient(
    realm_id="your-realm-id",
    secret_key="your-secret-key"
)

app.add_middleware(ZaltMiddleware, client=zalt)

@app.get("/api/profile")
async def get_profile(auth = Depends(require_auth)):
    user = await zalt.users.get(auth.user_id)
    return {"user": user}

@app.get("/api/protected")
async def protected_route(auth = Depends(require_auth)):
    return {"message": f"Hello, {auth.email}!"}`,
  },
  express: {
    framework: 'Express',
    language: 'typescript',
    install: 'npm install @zalt/node',
    filename: 'app.ts',
    code: `import express from 'express';
import { ZaltClient, zaltMiddleware } from '@zalt/node';

const app = express();
const zalt = new ZaltClient({
  realmId: process.env.ZALT_REALM_ID!,
  secretKey: process.env.ZALT_SECRET_KEY!,
});

// Apply Zalt middleware
app.use(zaltMiddleware(zalt));

// Public route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the API' });
});

// Protected route
app.get('/api/me', (req, res) => {
  if (!req.auth) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({ user: req.auth });
});

app.listen(3000);`,
  },
};

/**
 * Get code snippet for a framework
 */
export function getCodeSnippet(frameworkId: string): CodeSnippet | undefined {
  return codeSnippets[frameworkId];
}

/**
 * Get all available framework IDs
 */
export function getAvailableFrameworks(): string[] {
  return Object.keys(codeSnippets);
}

export default codeSnippets;
