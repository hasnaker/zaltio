'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { Check, X, ArrowRight, Shield, Zap, DollarSign, Users, Code, Lock } from 'lucide-react';

interface ComparisonItem {
  feature: string;
  zalt: boolean | string;
  clerk: boolean | string;
  advantage: 'zalt' | 'clerk' | 'equal';
}

const comparisons: ComparisonItem[] = [
  // Security
  { feature: 'WebAuthn/Passkeys', zalt: true, clerk: true, advantage: 'equal' },
  { feature: 'TOTP MFA', zalt: true, clerk: true, advantage: 'equal' },
  { feature: 'SMS MFA disabled by default', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'Breach detection (HIBP)', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'AI-powered risk scoring', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'Geo-velocity checks', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'Device fingerprinting', zalt: true, clerk: true, advantage: 'equal' },
  
  // Enterprise
  { feature: 'SAML SSO', zalt: true, clerk: true, advantage: 'equal' },
  { feature: 'SCIM provisioning', zalt: true, clerk: true, advantage: 'equal' },
  { feature: 'HIPAA compliance', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'Data residency (EU/US/Asia)', zalt: true, clerk: 'EU only', advantage: 'zalt' },
  
  // Features
  { feature: 'Session tasks (step-up auth)', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'User API keys', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'Machine-to-machine auth', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'Waitlist mode', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'MCP Server (AI agents)', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'Python SDK', zalt: true, clerk: false, advantage: 'zalt' },
  
  // Pricing
  { feature: 'Free tier', zalt: '1,000 MAU', clerk: '10,000 MAU', advantage: 'clerk' },
  { feature: 'Transparent enterprise pricing', zalt: true, clerk: false, advantage: 'zalt' },
  { feature: 'No hidden fees', zalt: true, clerk: false, advantage: 'zalt' },
];

const migrationSteps = [
  { step: 1, title: 'Export Users', desc: 'Use Clerk dashboard to export your user data as CSV' },
  { step: 2, title: 'Create Zalt Realm', desc: 'Set up your realm with matching settings' },
  { step: 3, title: 'Import Users', desc: 'Use our migration script to import users' },
  { step: 4, title: 'Update SDK', desc: 'Replace @clerk/nextjs with @zalt/next' },
  { step: 5, title: 'Test & Deploy', desc: 'Verify authentication flows work correctly' },
];

export default function ClerkComparisonPage() {
  const renderValue = (value: boolean | string) => {
    if (value === true) return <Check size={18} className="text-emerald-400" />;
    if (value === false) return <X size={18} className="text-red-400" />;
    return <span className="text-sm text-neutral-300">{value}</span>;
  };

  const zaltAdvantages = comparisons.filter(c => c.advantage === 'zalt').length;
  const clerkAdvantages = comparisons.filter(c => c.advantage === 'clerk').length;

  return (
    <div className="min-h-screen bg-neutral-950">
      <div className="max-w-5xl mx-auto px-4 py-16">
        {/* Header */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="text-center mb-12">
          <div className="flex items-center justify-center gap-2 text-emerald-400 text-sm font-mono mb-4">
            <Shield size={14} />
            COMPARISON
          </div>
          <h1 className="font-outfit text-4xl md:text-5xl font-bold text-white mb-4">
            Zalt vs Clerk
          </h1>
          <p className="text-neutral-400 max-w-2xl mx-auto text-lg">
            Both are modern auth solutions, but Zalt is built security-first with enterprise 
            features included, not as add-ons.
          </p>
        </motion.div>

        {/* Score Summary */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid md:grid-cols-2 gap-4 mb-12"
        >
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-6 text-center">
            <div className="text-4xl font-bold text-emerald-400 mb-2">{zaltAdvantages}</div>
            <div className="text-white font-medium">Zalt Advantages</div>
          </div>
          <div className="bg-neutral-800/50 border border-neutral-700 rounded-lg p-6 text-center">
            <div className="text-4xl font-bold text-neutral-400 mb-2">{clerkAdvantages}</div>
            <div className="text-neutral-400 font-medium">Clerk Advantages</div>
          </div>
        </motion.div>

        {/* Key Differentiators */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="grid md:grid-cols-3 gap-4 mb-12"
        >
          {[
            { icon: Shield, title: 'Security First', desc: 'AI risk scoring, breach detection, no SMS MFA by default - security is not an afterthought' },
            { icon: Lock, title: 'HIPAA Ready', desc: 'Built for healthcare from day one. Clinisyn trusts us with 4000+ psychologists.' },
            { icon: Code, title: 'AI-Native', desc: 'MCP server for AI agents, Python SDK, built for the vibe coding era' },
          ].map((item, i) => (
            <div key={i} className="bg-neutral-900 border border-emerald-500/20 rounded-lg p-5">
              <item.icon size={24} className="text-emerald-400 mb-3" />
              <h3 className="text-white font-medium mb-1">{item.title}</h3>
              <p className="text-sm text-neutral-400">{item.desc}</p>
            </div>
          ))}
        </motion.div>

        {/* Comparison Table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden mb-12"
        >
          <div className="px-4 py-3 border-b border-emerald-500/10 bg-neutral-800/50">
            <h2 className="text-white font-medium">Feature Comparison</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-emerald-500/10">
                  <th className="text-left px-4 py-3 text-sm text-neutral-400 font-normal">Feature</th>
                  <th className="text-center px-4 py-3 text-sm font-medium text-emerald-400 w-28">Zalt</th>
                  <th className="text-center px-4 py-3 text-sm text-neutral-400 font-normal w-28">Clerk</th>
                </tr>
              </thead>
              <tbody>
                {comparisons.map((item, i) => (
                  <tr 
                    key={i} 
                    className={`border-b border-emerald-500/5 ${
                      item.advantage === 'zalt' ? 'bg-emerald-500/5' : ''
                    }`}
                  >
                    <td className="px-4 py-3 text-sm text-neutral-300">{item.feature}</td>
                    <td className="px-4 py-3 text-center">{renderValue(item.zalt)}</td>
                    <td className="px-4 py-3 text-center">{renderValue(item.clerk)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* Migration Guide */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="mb-12"
        >
          <h2 className="text-2xl font-bold text-white mb-6">Migrate from Clerk in 5 Steps</h2>
          <div className="space-y-4">
            {migrationSteps.map((step, i) => (
              <div key={i} className="flex items-start gap-4 bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
                <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-bold shrink-0">
                  {step.step}
                </div>
                <div>
                  <h3 className="text-white font-medium">{step.title}</h3>
                  <p className="text-sm text-neutral-400">{step.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Code Example */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="mb-12"
        >
          <h2 className="text-2xl font-bold text-white mb-6">SDK Comparison</h2>
          <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-neutral-900 border border-neutral-700 rounded-lg overflow-hidden">
              <div className="px-4 py-2 border-b border-neutral-700 bg-neutral-800/50">
                <span className="text-sm text-neutral-400">Clerk</span>
              </div>
              <pre className="p-4 text-sm text-neutral-400 overflow-x-auto">
{`import { ClerkProvider } from '@clerk/nextjs';

export default function App({ children }) {
  return (
    <ClerkProvider>
      {children}
    </ClerkProvider>
  );
}`}
              </pre>
            </div>
            <div className="bg-neutral-900 border border-emerald-500/20 rounded-lg overflow-hidden">
              <div className="px-4 py-2 border-b border-emerald-500/20 bg-emerald-500/5">
                <span className="text-sm text-emerald-400">Zalt</span>
              </div>
              <pre className="p-4 text-sm text-emerald-400 overflow-x-auto">
{`import { ZaltProvider } from '@zalt/next';

export default function App({ children }) {
  return (
    <ZaltProvider realmId="your-realm">
      {children}
    </ZaltProvider>
  );
}`}
              </pre>
            </div>
          </div>
        </motion.div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="bg-gradient-to-r from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-lg p-8 text-center"
        >
          <h2 className="text-2xl font-bold text-white mb-2">Ready to switch from Clerk?</h2>
          <p className="text-neutral-400 mb-6">
            Get started free with 1,000 MAU. Migration takes less than an hour.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Link
              href="/signup"
              className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-500 text-neutral-950 rounded-lg font-medium"
            >
              Start Free Migration
              <ArrowRight size={16} />
            </Link>
            <Link
              href="/docs/guides/clerk-migration"
              className="inline-flex items-center gap-2 px-6 py-3 border border-neutral-700 text-neutral-300 rounded-lg hover:bg-neutral-800"
            >
              Full Migration Guide
            </Link>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
