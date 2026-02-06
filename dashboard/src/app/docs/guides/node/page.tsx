'use client';

import { motion } from 'framer-motion';
import { ArrowLeft, Copy, Check } from 'lucide-react';
import Link from 'next/link';
import { useState } from 'react';

function CodeBlock({ code, language = 'typescript' }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false);
  
  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative bg-neutral-950 rounded-lg border border-emerald-500/10 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-neutral-900 border-b border-emerald-500/10">
        <span className="text-xs text-neutral-500 font-mono">{language}</span>
        <button onClick={copy} className="text-neutral-500 hover:text-white">
          {copied ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-sm font-mono text-neutral-300">{code}</pre>
    </div>
  );
}

export default function NodeGuidePage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">Node.js / Express Integration</h1>
        <p className="text-neutral-400">Add Zalt authentication to your Node.js backend.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Installation</h2>
        <CodeBlock code="npm install @zalt/core" language="bash" />
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Initialize Client</h2>
        <CodeBlock code={`import { ZaltClient } from '@zalt/core';

const zalt = new ZaltClient({
  realmId: process.env.ZALT_REALM_ID,
  apiUrl: 'https://api.zalt.io',
});`} />
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Express Middleware</h2>
        <CodeBlock code={`import express from 'express';
import { ZaltClient } from '@zalt/core';

const app = express();
const zalt = new ZaltClient({ realmId: process.env.ZALT_REALM_ID });

// Auth middleware
const requireAuth = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const user = await zalt.verifyToken(token);
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Protected route
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);`} />
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Login Endpoint</h2>
        <CodeBlock code={`app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await zalt.login({ email, password });
    
    if (result.mfaRequired) {
      return res.json({
        mfaRequired: true,
        sessionId: result.sessionId,
        methods: result.mfaMethods,
      });
    }

    res.json({
      user: result.user,
      accessToken: result.tokens.accessToken,
      refreshToken: result.tokens.refreshToken,
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});`} />
      </section>
    </div>
  );
}
