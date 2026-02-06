'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { 
  Package, Copy, CheckCircle, Terminal, Code, 
  Smartphone, Server, Cpu, ArrowRight
} from 'lucide-react';

type SDK = 'core' | 'react' | 'next' | 'python';

const sdks: { id: SDK; name: string; pkg: string; icon: React.ElementType; desc: string }[] = [
  { id: 'core', name: 'Core SDK', pkg: '@zalt/core', icon: Package, desc: 'Universal TypeScript SDK for any environment' },
  { id: 'react', name: 'React SDK', pkg: '@zalt/react', icon: Code, desc: 'React hooks and components' },
  { id: 'next', name: 'Next.js SDK', pkg: '@zalt/next', icon: Server, desc: 'Server components and middleware' },
  { id: 'python', name: 'Python SDK', pkg: 'zalt-auth', icon: Terminal, desc: 'FastAPI and Flask integrations' },
];

const coreExamples = {
  client: `import { ZaltClient } from '@zalt/core';

const zalt = new ZaltClient({
  realmId: process.env.ZALT_REALM_ID!,
  secretKey: process.env.ZALT_SECRET_KEY!, // Server-side only
});

// Login
const { accessToken, refreshToken, user } = await zalt.login({
  email: 'user@example.com',
  password: 'securePassword123',
});

// Verify token
const payload = await zalt.verifyToken(accessToken);
console.log(payload.sub); // User ID`,

  webhooks: `import { verifyWebhookSignature } from '@zalt/core';

// Express webhook handler
app.post('/webhooks/zalt', (req, res) => {
  const signature = req.headers['x-zalt-signature'];
  const payload = req.body;
  
  const isValid = verifyWebhookSignature(
    payload,
    signature,
    process.env.ZALT_WEBHOOK_SECRET!
  );
  
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  // Handle event
  switch (payload.type) {
    case 'user.created':
      console.log('New user:', payload.data.email);
      break;
    case 'session.created':
      console.log('New session:', payload.data.sessionId);
      break;
  }
  
  res.json({ received: true });
});`,

  mfa: `// Setup TOTP MFA
const { secret, qrCode, backupCodes } = await zalt.mfa.setupTOTP(userId);

// Verify TOTP code
const verified = await zalt.mfa.verifyTOTP(userId, '123456');

// Setup WebAuthn (passkeys)
const options = await zalt.mfa.startWebAuthnRegistration(userId);
// ... browser handles credential creation
const credential = await zalt.mfa.completeWebAuthnRegistration(userId, response);`,
};

const reactExamples = {
  provider: `// app/layout.tsx or main.tsx
import { ZaltProvider } from '@zalt/react';

export default function App({ children }) {
  return (
    <ZaltProvider
      realmId={process.env.NEXT_PUBLIC_ZALT_REALM_ID!}
      clientId={process.env.NEXT_PUBLIC_ZALT_CLIENT_ID!}
    >
      {children}
    </ZaltProvider>
  );
}`,

  hooks: `import { useAuth, useUser, useOrganization } from '@zalt/react';

function Dashboard() {
  const { isLoaded, isSignedIn, signOut } = useAuth();
  const { user } = useUser();
  const { organization, switchOrganization } = useOrganization();
  
  if (!isLoaded) return <Loading />;
  if (!isSignedIn) return <Redirect to="/login" />;
  
  return (
    <div>
      <h1>Welcome, {user.email}</h1>
      <p>Organization: {organization?.name}</p>
      <button onClick={signOut}>Sign Out</button>
    </div>
  );
}`,

  components: `import { 
  SignIn, 
  SignUp, 
  UserButton, 
  OrganizationSwitcher 
} from '@zalt/react';

// Pre-built sign in form
<SignIn 
  redirectUrl="/dashboard"
  appearance={{
    variables: { colorPrimary: '#10b981' }
  }}
/>

// User avatar with dropdown
<UserButton afterSignOutUrl="/" />

// Organization switcher
<OrganizationSwitcher 
  hidePersonal={false}
  afterSelectOrganization={(org) => router.push(\`/\${org.slug}\`)}
/>`,
};

export default function SDKPage() {
  const [selectedSDK, setSelectedSDK] = useState<SDK>('core');
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const copyCode = (code: string, section: string) => {
    navigator.clipboard.writeText(code);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const CodeBlock = ({ code, section }: { code: string; section: string }) => (
    <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-emerald-500/10 bg-neutral-800/50">
        <span className="text-xs text-neutral-500 font-mono">{section}</span>
        <button
          onClick={() => copyCode(code, section)}
          className="flex items-center gap-1 text-neutral-500 hover:text-white text-xs"
        >
          {copiedSection === section ? <CheckCircle size={12} className="text-emerald-400" /> : <Copy size={12} />}
          {copiedSection === section ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-sm text-neutral-300 font-mono">{code}</pre>
    </div>
  );

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Package size={14} />
          SDK REFERENCE
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">
          SDK Documentation
        </h1>
        <p className="text-neutral-400 max-w-2xl">
          Official SDKs for integrating Zalt authentication into your applications.
          All SDKs are open-source and available on npm/PyPI.
        </p>
      </motion.div>

      {/* SDK Selector */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4"
      >
        {sdks.map((sdk) => (
          <button
            key={sdk.id}
            onClick={() => setSelectedSDK(sdk.id)}
            className={`text-left p-4 rounded-lg border transition-all ${
              selectedSDK === sdk.id
                ? 'bg-emerald-500/10 border-emerald-500/50'
                : 'bg-neutral-900 border-emerald-500/10 hover:border-emerald-500/30'
            }`}
          >
            <sdk.icon size={24} className={selectedSDK === sdk.id ? 'text-emerald-400' : 'text-neutral-500'} />
            <h3 className="text-white font-medium mt-2">{sdk.name}</h3>
            <code className="text-xs text-emerald-400 font-mono">{sdk.pkg}</code>
            <p className="text-xs text-neutral-500 mt-1">{sdk.desc}</p>
          </button>
        ))}
      </motion.div>

      {/* Installation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <h2 className="text-lg font-semibold text-white mb-4">Installation</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
          <code className="text-emerald-400 font-mono">
            {selectedSDK === 'python' 
              ? 'pip install zalt-auth'
              : `npm install ${sdks.find(s => s.id === selectedSDK)?.pkg}`
            }
          </code>
        </div>
      </motion.div>

      {/* Examples based on selected SDK */}
      {selectedSDK === 'core' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="space-y-6"
        >
          <h2 className="text-lg font-semibold text-white">Core SDK Examples</h2>
          <CodeBlock code={coreExamples.client} section="Client Setup & Authentication" />
          <CodeBlock code={coreExamples.webhooks} section="Webhook Verification" />
          <CodeBlock code={coreExamples.mfa} section="MFA Setup" />
        </motion.div>
      )}

      {(selectedSDK === 'react' || selectedSDK === 'next') && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="space-y-6"
        >
          <h2 className="text-lg font-semibold text-white">React/Next.js Examples</h2>
          <CodeBlock code={reactExamples.provider} section="Provider Setup" />
          <CodeBlock code={reactExamples.hooks} section="Authentication Hooks" />
          <CodeBlock code={reactExamples.components} section="Pre-built Components" />
        </motion.div>
      )}

      {selectedSDK === 'python' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="space-y-6"
        >
          <h2 className="text-lg font-semibold text-white">Python SDK Examples</h2>
          <CodeBlock 
            code={`from zalt_auth import ZaltClient
from zalt_auth.integrations.fastapi import ZaltFastAPI, get_current_user

# Initialize client
zalt = ZaltClient(
    realm_id=os.environ["ZALT_REALM_ID"],
    secret_key=os.environ["ZALT_SECRET_KEY"],
)

# FastAPI integration
app = FastAPI()
ZaltFastAPI(app, zalt)

@app.get("/api/profile")
async def get_profile(user = Depends(get_current_user)):
    return {"user": user}`} 
            section="FastAPI Integration" 
          />
        </motion.div>
      )}

      {/* API Reference Link */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
      >
        <h3 className="text-white font-medium mb-2">Full API Reference</h3>
        <p className="text-neutral-400 text-sm mb-4">
          See the complete API documentation with all methods, types, and examples.
        </p>
        <Link
          href="/docs/api"
          className="inline-flex items-center gap-2 text-emerald-400 hover:text-emerald-300"
        >
          View API Reference
          <ArrowRight size={16} />
        </Link>
      </motion.div>
    </div>
  );
}
