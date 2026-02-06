'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { 
  ArrowRight, Check, Copy, Terminal, Code, 
  Zap, Shield, Key, CheckCircle
} from 'lucide-react';

type Framework = 'nextjs' | 'react' | 'node' | 'python';

const frameworks: { id: Framework; name: string; icon: string }[] = [
  { id: 'nextjs', name: 'Next.js', icon: '▲' },
  { id: 'react', name: 'React', icon: '⚛️' },
  { id: 'node', name: 'Node.js', icon: '🟢' },
  { id: 'python', name: 'Python', icon: '🐍' },
];

const codeExamples: Record<Framework, { install: string; setup: string; usage: string }> = {
  nextjs: {
    install: 'npm install @zalt/next @zalt/react',
    setup: `// middleware.ts
import { zaltMiddleware } from '@zalt/next';

export default zaltMiddleware({
  publicRoutes: ['/', '/login', '/signup'],
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};`,
    usage: `// app/layout.tsx
import { ZaltProvider } from '@zalt/react';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <ZaltProvider
          realmId={process.env.NEXT_PUBLIC_ZALT_REALM_ID!}
          clientId={process.env.NEXT_PUBLIC_ZALT_CLIENT_ID!}
        >
          {children}
        </ZaltProvider>
      </body>
    </html>
  );
}

// app/dashboard/page.tsx
'use client';
import { useAuth, UserButton } from '@zalt/react';

export default function Dashboard() {
  const { user, isLoaded } = useAuth();
  
  if (!isLoaded) return <div>Loading...</div>;
  if (!user) return <div>Please sign in</div>;
  
  return (
    <div>
      <UserButton />
      <h1>Welcome, {user.email}</h1>
    </div>
  );
}`,
  },
  react: {
    install: 'npm install @zalt/react',
    setup: `// main.tsx
import { ZaltProvider } from '@zalt/react';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <ZaltProvider
    realmId={import.meta.env.VITE_ZALT_REALM_ID}
    clientId={import.meta.env.VITE_ZALT_CLIENT_ID}
  >
    <App />
  </ZaltProvider>
);`,
    usage: `// App.tsx
import { useAuth, SignIn, UserButton } from '@zalt/react';

function App() {
  const { user, isLoaded, signOut } = useAuth();

  if (!isLoaded) return <div>Loading...</div>;

  if (!user) {
    return <SignIn redirectUrl="/dashboard" />;
  }

  return (
    <div>
      <UserButton />
      <h1>Welcome, {user.email}</h1>
      <button onClick={signOut}>Sign Out</button>
    </div>
  );
}`,
  },
  node: {
    install: 'npm install @zalt/core',
    setup: `// server.js
import express from 'express';
import { ZaltClient, verifyToken } from '@zalt/core';

const app = express();
const zalt = new ZaltClient({
  realmId: process.env.ZALT_REALM_ID,
  secretKey: process.env.ZALT_SECRET_KEY,
});`,
    usage: `// Middleware to protect routes
const requireAuth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    const payload = await zalt.verifyToken(token);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Protected route
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await zalt.login({ email, password });
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});`,
  },
  python: {
    install: 'pip install zalt-auth',
    setup: `# FastAPI example
from fastapi import FastAPI, Depends
from zalt_auth import ZaltClient
from zalt_auth.integrations.fastapi import (
    ZaltFastAPI, 
    get_current_user,
    require_permissions
)

app = FastAPI()
zalt = ZaltFastAPI(
    app,
    realm_id=os.environ["ZALT_REALM_ID"],
    secret_key=os.environ["ZALT_SECRET_KEY"],
)`,
    usage: `# Protected route
@app.get("/api/profile")
async def get_profile(user = Depends(get_current_user)):
    return {"user": user}

# Route with permission check
@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: str,
    user = Depends(require_permissions(["admin:users"]))
):
    # Only users with admin:users permission can access
    return {"deleted": user_id}

# Login endpoint
@app.post("/api/login")
async def login(email: str, password: str):
    result = await zalt.client.login(email=email, password=password)
    return result`,
  },
};

export default function QuickstartPage() {
  const [selectedFramework, setSelectedFramework] = useState<Framework>('nextjs');
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const copyCode = (code: string, section: string) => {
    navigator.clipboard.writeText(code);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const code = codeExamples[selectedFramework];

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Zap size={14} />
          QUICKSTART
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">
          Get Started in 5 Minutes
        </h1>
        <p className="text-neutral-400 max-w-2xl">
          Add enterprise-grade authentication to your app with just a few lines of code.
          Choose your framework below to get started.
        </p>
      </motion.div>

      {/* Framework Selector */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="flex flex-wrap gap-3"
      >
        {frameworks.map((fw) => (
          <button
            key={fw.id}
            onClick={() => setSelectedFramework(fw.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors ${
              selectedFramework === fw.id
                ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400'
                : 'bg-neutral-900 border-neutral-800 text-neutral-400 hover:border-neutral-700'
            }`}
          >
            <span>{fw.icon}</span>
            <span>{fw.name}</span>
          </button>
        ))}
      </motion.div>

      {/* Steps */}
      <div className="space-y-6">
        {/* Step 1: Create Account */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden"
        >
          <div className="flex items-center gap-3 px-4 py-3 border-b border-emerald-500/10">
            <div className="w-6 h-6 rounded-full bg-emerald-500 text-neutral-950 flex items-center justify-center text-sm font-bold">
              1
            </div>
            <h3 className="text-white font-medium">Create a Zalt Account</h3>
          </div>
          <div className="p-4">
            <p className="text-neutral-400 text-sm mb-4">
              Sign up for a free account and create your first realm.
            </p>
            <Link
              href="/signup"
              className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium text-sm"
            >
              Create Free Account
              <ArrowRight size={14} />
            </Link>
          </div>
        </motion.div>

        {/* Step 2: Install SDK */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden"
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-emerald-500/10">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 rounded-full bg-emerald-500 text-neutral-950 flex items-center justify-center text-sm font-bold">
                2
              </div>
              <h3 className="text-white font-medium">Install the SDK</h3>
            </div>
            <button
              onClick={() => copyCode(code.install, 'install')}
              className="flex items-center gap-1 text-neutral-500 hover:text-white text-sm"
            >
              {copiedSection === 'install' ? <CheckCircle size={14} className="text-emerald-400" /> : <Copy size={14} />}
              {copiedSection === 'install' ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="p-4 bg-neutral-950">
            <code className="text-emerald-400 font-mono text-sm">{code.install}</code>
          </div>
        </motion.div>

        {/* Step 3: Setup */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden"
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-emerald-500/10">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 rounded-full bg-emerald-500 text-neutral-950 flex items-center justify-center text-sm font-bold">
                3
              </div>
              <h3 className="text-white font-medium">Configure Your App</h3>
            </div>
            <button
              onClick={() => copyCode(code.setup, 'setup')}
              className="flex items-center gap-1 text-neutral-500 hover:text-white text-sm"
            >
              {copiedSection === 'setup' ? <CheckCircle size={14} className="text-emerald-400" /> : <Copy size={14} />}
              {copiedSection === 'setup' ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="p-4 bg-neutral-950 overflow-x-auto">
            <pre className="text-neutral-300 font-mono text-sm whitespace-pre">{code.setup}</pre>
          </div>
        </motion.div>

        {/* Step 4: Usage */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden"
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-emerald-500/10">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 rounded-full bg-emerald-500 text-neutral-950 flex items-center justify-center text-sm font-bold">
                4
              </div>
              <h3 className="text-white font-medium">Add Authentication</h3>
            </div>
            <button
              onClick={() => copyCode(code.usage, 'usage')}
              className="flex items-center gap-1 text-neutral-500 hover:text-white text-sm"
            >
              {copiedSection === 'usage' ? <CheckCircle size={14} className="text-emerald-400" /> : <Copy size={14} />}
              {copiedSection === 'usage' ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="p-4 bg-neutral-950 overflow-x-auto">
            <pre className="text-neutral-300 font-mono text-sm whitespace-pre">{code.usage}</pre>
          </div>
        </motion.div>
      </div>

      {/* Environment Variables */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4"
      >
        <div className="flex items-start gap-3">
          <Key size={20} className="text-amber-500 mt-0.5" />
          <div>
            <h4 className="text-amber-400 font-medium">Environment Variables</h4>
            <p className="text-amber-400/70 text-sm mt-1">
              Add these to your <code className="bg-amber-500/20 px-1 rounded">.env.local</code> file:
            </p>
            <pre className="mt-3 text-sm font-mono text-amber-300 bg-amber-500/10 p-3 rounded">
{`ZALT_REALM_ID=your-realm-id
ZALT_CLIENT_ID=your-client-id
ZALT_SECRET_KEY=your-secret-key  # Server-side only!`}
            </pre>
          </div>
        </div>
      </motion.div>

      {/* Next Steps */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
      >
        <h2 className="text-lg font-semibold text-white mb-4">Next Steps</h2>
        <div className="grid md:grid-cols-3 gap-4">
          {[
            { title: 'Add MFA', href: '/docs/guides/mfa', icon: Shield, desc: 'Enable TOTP or WebAuthn' },
            { title: 'Social Login', href: '/docs/guides/social', icon: Key, desc: 'Add Google, Apple login' },
            { title: 'Organizations', href: '/docs/guides/organizations', icon: Code, desc: 'Multi-tenant setup' },
          ].map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="group bg-neutral-900 border border-emerald-500/10 rounded-lg p-4 hover:border-emerald-500/30 transition-colors"
            >
              <item.icon size={20} className="text-emerald-500 mb-2" />
              <h3 className="text-white font-medium group-hover:text-emerald-400 transition-colors">
                {item.title}
              </h3>
              <p className="text-sm text-neutral-500 mt-1">{item.desc}</p>
            </Link>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
