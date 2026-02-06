'use client';

import { motion } from 'framer-motion';
import { Shield, Key, Lock, Server, Database, Globe, ArrowRight, Check } from 'lucide-react';

const architecture = [
  {
    icon: Globe,
    title: 'Client Application',
    description: 'Your web or mobile app integrates with Zalt SDK',
    details: ['React, Next.js, Vue, Angular', 'iOS, Android, React Native', 'Any HTTP client'],
  },
  {
    icon: Server,
    title: 'Zalt API',
    description: 'Serverless authentication endpoints',
    details: ['AWS Lambda (Node.js 20.x)', 'API Gateway with WAF', 'Global edge deployment'],
  },
  {
    icon: Database,
    title: 'Data Layer',
    description: 'Secure, isolated data storage',
    details: ['DynamoDB (multi-region)', 'KMS encryption at rest', 'Per-realm isolation'],
  },
];

const securityFeatures = [
  {
    title: 'RS256 JWT Tokens',
    description: 'Asymmetric signing with rotating keys. FIPS-compliant for healthcare.',
  },
  {
    title: 'Argon2id Password Hashing',
    description: '32MB memory, timeCost 5, parallelism 2. Resistant to GPU attacks.',
  },
  {
    title: 'WebAuthn / Passkeys',
    description: 'Phishing-proof authentication. Mandatory for healthcare realms.',
  },
  {
    title: 'Device Fingerprinting',
    description: '70% fuzzy matching threshold. Detects suspicious device changes.',
  },
  {
    title: 'Rate Limiting',
    description: 'Per-IP and per-user limits. Progressive delays on failures.',
  },
  {
    title: 'Audit Logging',
    description: 'Complete audit trail. HIPAA/GDPR compliant retention.',
  },
];

const authFlow = [
  { step: 1, title: 'User submits credentials', description: 'Email/password or WebAuthn assertion' },
  { step: 2, title: 'Rate limit check', description: 'IP and user-based throttling' },
  { step: 3, title: 'Credential verification', description: 'Argon2id hash comparison' },
  { step: 4, title: 'MFA challenge (if enabled)', description: 'TOTP or WebAuthn verification' },
  { step: 5, title: 'Device trust evaluation', description: 'Fingerprint matching and risk scoring' },
  { step: 6, title: 'Token generation', description: 'RS256 signed JWT with claims' },
  { step: 7, title: 'Session creation', description: 'Refresh token stored securely' },
];

export default function HowItWorksPage() {
  return (
    <div className="space-y-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Shield size={14} />
          ARCHITECTURE
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">
          How Zalt Works
        </h1>
        <p className="text-neutral-400">
          A deep dive into Zalt's architecture, security model, and authentication flow.
        </p>
      </motion.div>

      {/* Architecture Overview */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <h2 className="font-outfit text-xl font-semibold text-white mb-6">Architecture</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {architecture.map((item, index) => (
            <div 
              key={item.title}
              className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-5"
            >
              <div className="w-10 h-10 rounded border border-emerald-500/20 bg-emerald-500/5 flex items-center justify-center mb-4">
                <item.icon size={18} className="text-emerald-500" />
              </div>
              <h3 className="font-semibold text-white mb-2">{item.title}</h3>
              <p className="text-sm text-neutral-400 mb-4">{item.description}</p>
              <ul className="space-y-1">
                {item.details.map((detail) => (
                  <li key={detail} className="text-xs text-neutral-500 flex items-center gap-2">
                    <span className="w-1 h-1 bg-emerald-500 rounded-full" />
                    {detail}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Auth Flow */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <h2 className="font-outfit text-xl font-semibold text-white mb-6">Authentication Flow</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <div className="space-y-4">
            {authFlow.map((item, index) => (
              <div key={item.step} className="flex items-start gap-4">
                <div className="w-8 h-8 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-mono text-sm flex-shrink-0">
                  {item.step}
                </div>
                <div className="flex-1 pb-4 border-b border-emerald-500/5 last:border-0">
                  <h4 className="font-medium text-white">{item.title}</h4>
                  <p className="text-sm text-neutral-500">{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Security Features */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <h2 className="font-outfit text-xl font-semibold text-white mb-6">Security Features</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {securityFeatures.map((feature) => (
            <div 
              key={feature.title}
              className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-5"
            >
              <div className="flex items-start gap-3">
                <Check size={16} className="text-emerald-500 mt-0.5 flex-shrink-0" />
                <div>
                  <h3 className="font-medium text-white mb-1">{feature.title}</h3>
                  <p className="text-sm text-neutral-400">{feature.description}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Token Configuration */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
      >
        <h2 className="font-outfit text-lg font-semibold text-white mb-4">Token Configuration</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <h4 className="text-xs font-mono text-emerald-500/70 uppercase mb-2">Access Token</h4>
            <p className="text-2xl font-mono text-white">15 min</p>
            <p className="text-xs text-neutral-500 mt-1">RS256 signed, kid header</p>
          </div>
          <div>
            <h4 className="text-xs font-mono text-emerald-500/70 uppercase mb-2">Refresh Token</h4>
            <p className="text-2xl font-mono text-white">7 days</p>
            <p className="text-xs text-neutral-500 mt-1">Rotated on each use</p>
          </div>
          <div>
            <h4 className="text-xs font-mono text-emerald-500/70 uppercase mb-2">Grace Period</h4>
            <p className="text-2xl font-mono text-white">30 sec</p>
            <p className="text-xs text-neutral-500 mt-1">Idempotent response</p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
