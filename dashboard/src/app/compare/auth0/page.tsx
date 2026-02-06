'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { Check, X, ArrowRight, Shield, Zap, DollarSign, Building, Code, Lock } from 'lucide-react';

interface ComparisonItem {
  feature: string;
  zalt: boolean | string;
  auth0: boolean | string;
  advantage: 'zalt' | 'auth0' | 'equal';
}

const comparisons: ComparisonItem[] = [
  // Security
  { feature: 'WebAuthn/Passkeys', zalt: true, auth0: true, advantage: 'equal' },
  { feature: 'TOTP MFA', zalt: true, auth0: true, advantage: 'equal' },
  { feature: 'SMS MFA disabled by default', zalt: true, auth0: false, advantage: 'zalt' },
  { feature: 'Breach detection (HIBP)', zalt: 'Included', auth0: 'Add-on ($)', advantage: 'zalt' },
  { feature: 'AI-powered risk scoring', zalt: 'Included', auth0: 'Add-on ($)', advantage: 'zalt' },
  { feature: 'Geo-velocity checks', zalt: 'Included', auth0: 'Add-on ($)', advantage: 'zalt' },
  { feature: 'Adaptive MFA', zalt: true, auth0: true, advantage: 'equal' },
  
  // Enterprise
  { feature: 'SAML SSO', zalt: true, auth0: true, advantage: 'equal' },
  { feature: 'SCIM provisioning', zalt: true, auth0: true, advantage: 'equal' },
  { feature: 'HIPAA compliance', zalt: 'Included', auth0: 'Enterprise only', advantage: 'zalt' },
  { feature: 'Data residency', zalt: 'EU/US/Asia', auth0: 'EU/US/AU', advantage: 'equal' },
  { feature: 'Custom domains', zalt: true, auth0: true, advantage: 'equal' },
  
  // Features
  { feature: 'Session tasks (step-up auth)', zalt: true, auth0: false, advantage: 'zalt' },
  { feature: 'User API keys', zalt: true, auth0: false, advantage: 'zalt' },
  { feature: 'Machine-to-machine auth', zalt: true, auth0: true, advantage: 'equal' },
  { feature: 'Waitlist mode', zalt: true, auth0: false, advantage: 'zalt' },
  { feature: 'MCP Server (AI agents)', zalt: true, auth0: false, advantage: 'zalt' },
  { feature: 'Real-time events', zalt: true, auth0: false, advantage: 'zalt' },
  
  // Developer Experience
  { feature: 'React SDK', zalt: true, auth0: true, advantage: 'equal' },
  { feature: 'Next.js SDK', zalt: true, auth0: true, advantage: 'equal' },
  { feature: 'Python SDK', zalt: true, auth0: true, advantage: 'equal' },
  { feature: 'Pre-built UI components', zalt: true, auth0: true, advantage: 'equal' },
  
  // Pricing
  { feature: 'Free tier', zalt: '1,000 MAU', auth0: '7,000 MAU', advantage: 'auth0' },
  { feature: 'Transparent pricing', zalt: true, auth0: false, advantage: 'zalt' },
  { feature: 'No add-on fees for security', zalt: true, auth0: false, advantage: 'zalt' },
  { feature: 'Predictable enterprise costs', zalt: true, auth0: false, advantage: 'zalt' },
];

const migrationSteps = [
  { step: 1, title: 'Export Users', desc: 'Use Auth0 Management API to export user data' },
  { step: 2, title: 'Map Connections', desc: 'Map Auth0 connections to Zalt social providers' },
  { step: 3, title: 'Create Zalt Realm', desc: 'Configure realm with matching settings' },
  { step: 4, title: 'Import Users', desc: 'Run migration script with password hash migration' },
  { step: 5, title: 'Update Application', desc: 'Replace Auth0 SDK with @zalt/react or @zalt/next' },
  { step: 6, title: 'Test & Cutover', desc: 'Verify flows and switch DNS' },
];

export default function Auth0ComparisonPage() {
  const renderValue = (value: boolean | string) => {
    if (value === true) return <Check size={18} className="text-emerald-400" />;
    if (value === false) return <X size={18} className="text-red-400" />;
    return <span className="text-sm text-neutral-300">{value}</span>;
  };

  const zaltAdvantages = comparisons.filter(c => c.advantage === 'zalt').length;
  const auth0Advantages = comparisons.filter(c => c.advantage === 'auth0').length;

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
            Zalt vs Auth0
          </h1>
          <p className="text-neutral-400 max-w-2xl mx-auto text-lg">
            Auth0 is powerful but complex and expensive. Zalt gives you enterprise security 
            without the enterprise price tag or add-on fees.
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
            <div className="text-4xl font-bold text-neutral-400 mb-2">{auth0Advantages}</div>
            <div className="text-neutral-400 font-medium">Auth0 Advantages</div>
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
            { icon: DollarSign, title: 'No Add-on Fees', desc: 'Breach detection, AI risk scoring, geo-velocity - all included, not $500/mo extras' },
            { icon: Building, title: 'Simpler Architecture', desc: 'No Actions, Rules, Hooks confusion. Just clean APIs and webhooks.' },
            { icon: Zap, title: 'Modern Stack', desc: 'Built for 2026: AI agents, real-time events, TypeScript-first' },
          ].map((item, i) => (
            <div key={i} className="bg-neutral-900 border border-emerald-500/20 rounded-lg p-5">
              <item.icon size={24} className="text-emerald-400 mb-3" />
              <h3 className="text-white font-medium mb-1">{item.title}</h3>
              <p className="text-sm text-neutral-400">{item.desc}</p>
            </div>
          ))}
        </motion.div>

        {/* Pricing Comparison */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 mb-12"
        >
          <h2 className="text-xl font-bold text-white mb-4">Real Cost Comparison (10,000 MAU)</h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="border border-neutral-700 rounded-lg p-4">
              <h3 className="text-neutral-400 font-medium mb-3">Auth0</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between"><span className="text-neutral-400">Base plan</span><span className="text-white">$240/mo</span></div>
                <div className="flex justify-between"><span className="text-neutral-400">Breach detection</span><span className="text-white">+$100/mo</span></div>
                <div className="flex justify-between"><span className="text-neutral-400">Adaptive MFA</span><span className="text-white">+$150/mo</span></div>
                <div className="flex justify-between"><span className="text-neutral-400">Attack protection</span><span className="text-white">+$100/mo</span></div>
                <div className="border-t border-neutral-700 pt-2 mt-2 flex justify-between font-medium">
                  <span className="text-neutral-300">Total</span><span className="text-red-400">$590/mo</span>
                </div>
              </div>
            </div>
            <div className="border border-emerald-500/30 rounded-lg p-4 bg-emerald-500/5">
              <h3 className="text-emerald-400 font-medium mb-3">Zalt</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between"><span className="text-neutral-400">Pro plan</span><span className="text-white">$99/mo</span></div>
                <div className="flex justify-between"><span className="text-neutral-400">Breach detection</span><span className="text-emerald-400">Included</span></div>
                <div className="flex justify-between"><span className="text-neutral-400">AI risk scoring</span><span className="text-emerald-400">Included</span></div>
                <div className="flex justify-between"><span className="text-neutral-400">Attack protection</span><span className="text-emerald-400">Included</span></div>
                <div className="border-t border-emerald-500/30 pt-2 mt-2 flex justify-between font-medium">
                  <span className="text-neutral-300">Total</span><span className="text-emerald-400">$99/mo</span>
                </div>
              </div>
            </div>
          </div>
          <p className="text-center text-emerald-400 mt-4 font-medium">Save $491/month with Zalt</p>
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
                  <th className="text-center px-4 py-3 text-sm font-medium text-emerald-400 w-32">Zalt</th>
                  <th className="text-center px-4 py-3 text-sm text-neutral-400 font-normal w-32">Auth0</th>
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
                    <td className="px-4 py-3 text-center">{renderValue(item.auth0)}</td>
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
          <h2 className="text-2xl font-bold text-white mb-6">Migrate from Auth0</h2>
          <div className="grid md:grid-cols-2 gap-4">
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

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-gradient-to-r from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-lg p-8 text-center"
        >
          <h2 className="text-2xl font-bold text-white mb-2">Stop paying for add-ons</h2>
          <p className="text-neutral-400 mb-6">
            Get enterprise security features included, not as expensive extras.
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
              href="/docs/guides/auth0-migration"
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
