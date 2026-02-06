'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { ArrowRight, Shield, Zap, Lock, Code, Users, Key } from 'lucide-react';

const features = [
  {
    icon: Shield,
    title: 'Enterprise Security',
    description: 'RS256 JWT, Argon2id hashing, WebAuthn support, and darkweb-resistant architecture.',
  },
  {
    icon: Zap,
    title: 'Quick Integration',
    description: 'Get started in minutes with our SDK. Works with React, Next.js, Node.js, and more.',
  },
  {
    icon: Lock,
    title: 'Multi-Factor Auth',
    description: 'TOTP and WebAuthn/Passkeys. No SMS - we take security seriously.',
  },
  {
    icon: Users,
    title: 'Multi-Tenant',
    description: 'Isolated realms for each customer with custom branding and policies.',
  },
];

const quickLinks = [
  { title: 'Quick Start Guide', href: '/docs/quickstart', description: 'Get up and running in 5 minutes' },
  { title: 'React Integration', href: '/docs/guides/react', description: 'Add Zalt to your React app' },
  { title: 'API Reference', href: '/docs/api/auth', description: 'Complete API documentation' },
  { title: 'Security Best Practices', href: '/docs/security/best-practices', description: 'Secure your implementation' },
];

export default function DocsPage() {
  return (
    <div className="space-y-12">
      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
          DOCUMENTATION
        </div>
        <h1 className="font-outfit text-4xl font-bold text-white mb-4">
          Zalt.io Documentation
        </h1>
        <p className="text-lg text-neutral-400 max-w-2xl">
          Enterprise-grade authentication for modern applications. 
          Secure, scalable, and developer-friendly.
        </p>
      </motion.div>

      {/* Quick Start */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-neutral-900 border border-emerald-500/20 rounded-lg p-6"
      >
        <h2 className="font-outfit text-xl font-semibold text-white mb-4">Quick Start</h2>
        <div className="bg-neutral-950 rounded-lg p-4 font-mono text-sm">
          <div className="text-neutral-500 mb-2"># Install the SDK</div>
          <div className="text-emerald-400 mb-4">npm install @zalt/auth-sdk</div>
          
          <div className="text-neutral-500 mb-2"># Initialize in your app</div>
          <pre className="text-neutral-300">
{`import { ZaltAuth } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  realmId: 'your-realm-id',
  clientId: 'your-client-id',
});

// Login
const { user, tokens } = await auth.login({
  email: 'user@example.com',
  password: 'secure-password',
});`}
          </pre>
        </div>
        <Link 
          href="/docs/quickstart"
          className="inline-flex items-center gap-2 mt-4 text-emerald-400 hover:underline text-sm"
        >
          View full guide <ArrowRight size={14} />
        </Link>
      </motion.div>

      {/* Features */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <h2 className="font-outfit text-xl font-semibold text-white mb-6">Why Zalt?</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {features.map((feature, index) => (
            <div 
              key={feature.title}
              className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-5"
            >
              <div className="w-10 h-10 rounded border border-emerald-500/20 bg-emerald-500/5 flex items-center justify-center mb-4">
                <feature.icon size={18} className="text-emerald-500" />
              </div>
              <h3 className="font-semibold text-white mb-2">{feature.title}</h3>
              <p className="text-sm text-neutral-400">{feature.description}</p>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Quick Links */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <h2 className="font-outfit text-xl font-semibold text-white mb-6">Popular Guides</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {quickLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className="group bg-neutral-900 border border-emerald-500/10 rounded-lg p-5 hover:border-emerald-500/30 transition-colors"
            >
              <h3 className="font-semibold text-white group-hover:text-emerald-400 transition-colors flex items-center gap-2">
                {link.title}
                <ArrowRight size={14} className="opacity-0 group-hover:opacity-100 transition-opacity" />
              </h3>
              <p className="text-sm text-neutral-400 mt-1">{link.description}</p>
            </Link>
          ))}
        </div>
      </motion.div>

      {/* Support */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-6"
      >
        <h2 className="font-outfit text-lg font-semibold text-white mb-2">Need Help?</h2>
        <p className="text-neutral-400 text-sm mb-4">
          Can't find what you're looking for? Our team is here to help.
        </p>
        <div className="flex flex-wrap gap-3">
          <a 
            href="mailto:support@zalt.io"
            className="px-4 py-2 bg-emerald-500 text-neutral-950 text-sm font-medium rounded hover:bg-emerald-400 transition-colors"
          >
            Contact Support
          </a>
          <a 
            href="https://github.com/zalt-io"
            target="_blank"
            rel="noopener noreferrer"
            className="px-4 py-2 bg-neutral-800 text-white text-sm font-medium rounded hover:bg-neutral-700 transition-colors"
          >
            GitHub
          </a>
        </div>
      </motion.div>
    </div>
  );
}
