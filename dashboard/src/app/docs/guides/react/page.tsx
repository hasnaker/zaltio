'use client';

import { motion } from 'framer-motion';
import { Code, Copy, Check } from 'lucide-react';
import { useState } from 'react';

function CodeBlock({ code, language = 'typescript', title }: { code: string; language?: string; title?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative bg-neutral-950 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-emerald-500/10">
        <span className="text-xs text-neutral-500 font-mono">{title || language}</span>
        <button onClick={handleCopy} className="text-neutral-500 hover:text-white">
          {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
        </button>
      </div>
      <pre className="p-4 text-sm font-mono text-neutral-300 overflow-x-auto">{code}</pre>
    </div>
  );
}

export default function ReactGuidePage() {
  return (
    <div className="space-y-12">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Code size={14} />
          INTEGRATION GUIDE
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">React / Next.js Integration</h1>
        <p className="text-neutral-400">Complete guide to integrating Zalt authentication in your React application.</p>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="space-y-6">
        <h2 className="font-outfit text-xl font-semibold text-white">Installation</h2>
        <CodeBlock code="npm install @zalt/auth-sdk @zalt/react" language="bash" />
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="space-y-6">
        <h2 className="font-outfit text-xl font-semibold text-white">Setup Provider</h2>
        <CodeBlock title="app/providers.tsx" code={`import { ZaltProvider } from '@zalt/react';

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ZaltProvider
      realmId={process.env.NEXT_PUBLIC_ZALT_REALM_ID!}
      clientId={process.env.NEXT_PUBLIC_ZALT_CLIENT_ID!}
    >
      {children}
    </ZaltProvider>
  );
}`} />
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="space-y-6">
        <h2 className="font-outfit text-xl font-semibold text-white">Login Component</h2>
        <CodeBlock title="components/LoginForm.tsx" code={`'use client';

import { useState } from 'react';
import { useZalt } from '@zalt/react';

export function LoginForm() {
  const { login, isLoading, error } = useZalt();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const result = await login({ email, password });
    
    if (result.requiresMfa) {
      // Redirect to MFA verification
      router.push('/mfa-verify');
    } else if (result.success) {
      // Redirect to dashboard
      router.push('/dashboard');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
        required
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
        required
      />
      {error && <p className="error">{error.message}</p>}
      <button type="submit" disabled={isLoading}>
        {isLoading ? 'Signing in...' : 'Sign in'}
      </button>
    </form>
  );
}`} />
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="space-y-6">
        <h2 className="font-outfit text-xl font-semibold text-white">Protected Routes</h2>
        <CodeBlock title="middleware.ts (Next.js)" code={`import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verifyToken } from '@zalt/auth-sdk/server';

export async function middleware(request: NextRequest) {
  const token = request.cookies.get('zalt_access_token')?.value;

  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  try {
    await verifyToken(token, {
      realmId: process.env.ZALT_REALM_ID!,
    });
    return NextResponse.next();
  } catch {
    return NextResponse.redirect(new URL('/login', request.url));
  }
}

export const config = {
  matcher: ['/dashboard/:path*', '/settings/:path*'],
};`} />
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }} className="space-y-6">
        <h2 className="font-outfit text-xl font-semibold text-white">useZalt Hook</h2>
        <CodeBlock title="Available methods" code={`const {
  // State
  user,           // Current user object
  isAuthenticated,// Boolean auth status
  isLoading,      // Loading state
  error,          // Last error

  // Methods
  login,          // Login with email/password
  logout,         // Logout and clear tokens
  register,       // Create new account
  refreshToken,   // Manually refresh tokens
  verifyMfa,      // Verify MFA code
  
  // WebAuthn
  registerPasskey,// Register new passkey
  loginWithPasskey,// Login with passkey
} = useZalt();`} />
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.6 }} className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-6">
        <h2 className="font-outfit text-lg font-semibold text-white mb-4">Environment Variables</h2>
        <CodeBlock title=".env.local" code={`NEXT_PUBLIC_ZALT_REALM_ID=your-realm-id
NEXT_PUBLIC_ZALT_CLIENT_ID=your-client-id
ZALT_REALM_ID=your-realm-id  # Server-side only`} language="env" />
      </motion.div>
    </div>
  );
}
