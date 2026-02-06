'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { Check, X, Minus, ArrowRight, Shield, Zap, DollarSign } from 'lucide-react';

interface Feature {
  name: string;
  zalt: boolean | string;
  clerk: boolean | string;
  auth0: boolean | string;
  category: string;
}

const features: Feature[] = [
  // Pricing
  { name: 'Free tier MAU', zalt: '1,000', clerk: '10,000', auth0: '7,000', category: 'Pricing' },
  { name: 'Pro tier price', zalt: '$25/mo', clerk: '$25/mo', auth0: '$23/mo', category: 'Pricing' },
  { name: 'Enterprise pricing', zalt: 'Transparent', clerk: 'Contact', auth0: 'Contact', category: 'Pricing' },
  { name: 'No hidden fees', zalt: true, clerk: false, auth0: false, category: 'Pricing' },
  
  // Security
  { name: 'WebAuthn/Passkeys', zalt: true, clerk: true, auth0: true, category: 'Security' },
  { name: 'TOTP MFA', zalt: true, clerk: true, auth0: true, category: 'Security' },
  { name: 'SMS MFA (disabled by default)', zalt: 'Opt-in only', clerk: true, auth0: true, category: 'Security' },
  { name: 'Breach detection (HIBP)', zalt: true, clerk: false, auth0: 'Add-on', category: 'Security' },
  { name: 'AI-powered risk scoring', zalt: true, clerk: false, auth0: 'Add-on', category: 'Security' },
  { name: 'Device fingerprinting', zalt: true, clerk: true, auth0: true, category: 'Security' },
  { name: 'Geo-velocity checks', zalt: true, clerk: false, auth0: 'Add-on', category: 'Security' },
  
  // Enterprise
  { name: 'SAML SSO', zalt: true, clerk: true, auth0: true, category: 'Enterprise' },
  { name: 'OIDC SSO', zalt: true, clerk: true, auth0: true, category: 'Enterprise' },
  { name: 'SCIM provisioning', zalt: true, clerk: true, auth0: true, category: 'Enterprise' },
  { name: 'Custom domains', zalt: true, clerk: true, auth0: true, category: 'Enterprise' },
  { name: 'Data residency (EU/US/Asia)', zalt: true, clerk: 'EU only', auth0: true, category: 'Enterprise' },
  { name: 'HIPAA compliance', zalt: true, clerk: false, auth0: 'Add-on', category: 'Enterprise' },
  { name: 'SOC 2 Type II', zalt: true, clerk: true, auth0: true, category: 'Enterprise' },
  
  // Developer Experience
  { name: 'React SDK', zalt: true, clerk: true, auth0: true, category: 'DX' },
  { name: 'Next.js SDK', zalt: true, clerk: true, auth0: true, category: 'DX' },
  { name: 'Python SDK', zalt: true, clerk: false, auth0: true, category: 'DX' },
  { name: 'MCP Server (AI agents)', zalt: true, clerk: false, auth0: false, category: 'DX' },
  { name: 'Pre-built UI components', zalt: true, clerk: true, auth0: true, category: 'DX' },
  { name: 'Webhooks', zalt: true, clerk: true, auth0: true, category: 'DX' },
  { name: 'Real-time events', zalt: true, clerk: true, auth0: false, category: 'DX' },
  
  // Features
  { name: 'Multi-tenant (Organizations)', zalt: true, clerk: true, auth0: true, category: 'Features' },
  { name: 'User impersonation', zalt: true, clerk: true, auth0: true, category: 'Features' },
  { name: 'Session tasks (step-up auth)', zalt: true, clerk: false, auth0: false, category: 'Features' },
  { name: 'Waitlist mode', zalt: true, clerk: false, auth0: false, category: 'Features' },
  { name: 'User API keys', zalt: true, clerk: false, auth0: false, category: 'Features' },
  { name: 'Machine-to-machine auth', zalt: true, clerk: false, auth0: true, category: 'Features' },
];

const categories = ['Pricing', 'Security', 'Enterprise', 'DX', 'Features'];

export default function ComparePage() {
  const renderValue = (value: boolean | string) => {
    if (value === true) return <Check size={18} className="text-emerald-400" />;
    if (value === false) return <X size={18} className="text-red-400" />;
    return <span className="text-sm text-neutral-300">{value}</span>;
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Shield size={14} />
          COMPARISON
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">
          Zalt vs Clerk vs Auth0
        </h1>
        <p className="text-neutral-400 max-w-2xl">
          See how Zalt compares to other authentication providers. We focus on security-first 
          design, transparent pricing, and developer experience.
        </p>
      </motion.div>

      {/* Key Differentiators */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid md:grid-cols-3 gap-4"
      >
        {[
          { icon: Shield, title: 'Security First', desc: 'AI risk scoring, breach detection, no SMS MFA by default' },
          { icon: DollarSign, title: 'Transparent Pricing', desc: 'No hidden fees, no surprise bills, predictable costs' },
          { icon: Zap, title: 'AI-Native', desc: 'MCP server for AI agents, built for the vibe coding era' },
        ].map((item, i) => (
          <div key={i} className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4">
            <item.icon size={24} className="text-emerald-400 mb-2" />
            <h3 className="text-white font-medium">{item.title}</h3>
            <p className="text-sm text-neutral-400 mt-1">{item.desc}</p>
          </div>
        ))}
      </motion.div>

      {/* Comparison Table */}
      {categories.map((category, catIndex) => (
        <motion.div
          key={category}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 + catIndex * 0.1 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden"
        >
          <div className="px-4 py-3 border-b border-emerald-500/10 bg-neutral-800/50">
            <h2 className="text-white font-medium">{category}</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-emerald-500/10">
                  <th className="text-left px-4 py-3 text-sm text-neutral-400 font-normal">Feature</th>
                  <th className="text-center px-4 py-3 text-sm font-medium text-emerald-400 w-32">Zalt</th>
                  <th className="text-center px-4 py-3 text-sm text-neutral-400 font-normal w-32">Clerk</th>
                  <th className="text-center px-4 py-3 text-sm text-neutral-400 font-normal w-32">Auth0</th>
                </tr>
              </thead>
              <tbody>
                {features
                  .filter(f => f.category === category)
                  .map((feature, i) => (
                    <tr key={i} className="border-b border-emerald-500/5 hover:bg-neutral-800/30">
                      <td className="px-4 py-3 text-sm text-neutral-300">{feature.name}</td>
                      <td className="px-4 py-3 text-center">{renderValue(feature.zalt)}</td>
                      <td className="px-4 py-3 text-center">{renderValue(feature.clerk)}</td>
                      <td className="px-4 py-3 text-center">{renderValue(feature.auth0)}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      ))}

      {/* CTA */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="bg-gradient-to-r from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-lg p-6 text-center"
      >
        <h2 className="text-xl font-bold text-white mb-2">Ready to switch?</h2>
        <p className="text-neutral-400 mb-4">
          Migrate from Clerk or Auth0 in minutes with our migration tools.
        </p>
        <div className="flex items-center justify-center gap-4">
          <Link
            href="/docs/quickstart"
            className="inline-flex items-center gap-2 px-6 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium"
          >
            Get Started Free
            <ArrowRight size={16} />
          </Link>
          <Link
            href="/docs/guides/migration"
            className="inline-flex items-center gap-2 px-6 py-2 border border-neutral-700 text-neutral-300 rounded-lg hover:bg-neutral-800"
          >
            Migration Guide
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
