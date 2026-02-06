'use client';

import { motion } from 'framer-motion';
import { 
  Sparkles, Shield, Zap, Bug, AlertTriangle, 
  ArrowUp, Package, Clock
} from 'lucide-react';

interface ChangelogEntry {
  version: string;
  date: string;
  changes: {
    type: 'feature' | 'improvement' | 'fix' | 'security' | 'breaking' | 'deprecated';
    title: string;
    description?: string;
  }[];
}

const changelog: ChangelogEntry[] = [
  {
    version: '1.5.0',
    date: 'February 3, 2026',
    changes: [
      { type: 'feature', title: 'AI-powered risk scoring', description: 'Real-time login risk assessment using AWS Bedrock' },
      { type: 'feature', title: 'Session tasks (step-up auth)', description: 'Require additional verification for sensitive operations' },
      { type: 'improvement', title: 'Improved device fingerprinting accuracy', description: 'Better detection of browser and device changes' },
      { type: 'fix', title: 'Fixed refresh token race condition', description: 'Resolved edge case with concurrent token refresh requests' },
    ],
  },
  {
    version: '1.4.0',
    date: 'January 25, 2026',
    changes: [
      { type: 'feature', title: 'MCP Server for AI agents', description: 'Model Context Protocol server for programmatic auth management' },
      { type: 'feature', title: 'User API keys', description: 'Allow users to create personal API keys for automation' },
      { type: 'feature', title: 'Waitlist mode', description: 'Control user registration with approval workflows' },
      { type: 'security', title: 'HIBP breach detection', description: 'Check passwords against HaveIBeenPwned database' },
      { type: 'improvement', title: 'Python SDK release', description: 'Official Python SDK with FastAPI and Flask integrations' },
    ],
  },
  {
    version: '1.3.0',
    date: 'January 15, 2026',
    changes: [
      { type: 'feature', title: 'SAML SSO support', description: 'Enterprise SAML 2.0 single sign-on integration' },
      { type: 'feature', title: 'SCIM provisioning', description: 'Automatic user provisioning from identity providers' },
      { type: 'feature', title: 'Domain verification', description: 'Verify domain ownership for SSO enforcement' },
      { type: 'improvement', title: 'Improved webhook reliability', description: 'Automatic retries with exponential backoff' },
      { type: 'fix', title: 'Fixed OIDC state parameter validation' },
    ],
  },
  {
    version: '1.2.0',
    date: 'January 5, 2026',
    changes: [
      { type: 'feature', title: 'User impersonation', description: 'Admin ability to impersonate users for support' },
      { type: 'feature', title: 'Billing and subscriptions', description: 'Built-in billing management with Stripe integration' },
      { type: 'feature', title: 'Custom risk rules', description: 'Define custom rules for login risk assessment' },
      { type: 'security', title: 'Geo-velocity checks', description: 'Detect impossible travel scenarios' },
      { type: 'improvement', title: 'Dashboard redesign', description: 'New Clerk-inspired dashboard UI' },
    ],
  },
  {
    version: '1.1.0',
    date: 'December 20, 2025',
    changes: [
      { type: 'feature', title: 'WebAuthn/Passkeys support', description: 'Phishing-proof passwordless authentication' },
      { type: 'feature', title: 'Organization invitations', description: 'Invite users to organizations via email' },
      { type: 'feature', title: 'Webhooks', description: 'Real-time event notifications for auth events' },
      { type: 'improvement', title: 'React SDK improvements', description: 'New hooks and components for easier integration' },
      { type: 'fix', title: 'Fixed session timeout calculation' },
      { type: 'fix', title: 'Fixed email template rendering on mobile' },
    ],
  },
  {
    version: '1.0.0',
    date: 'December 1, 2025',
    changes: [
      { type: 'feature', title: 'Initial release', description: 'Zalt.io authentication platform launch' },
      { type: 'feature', title: 'Multi-tenant realms', description: 'Isolated authentication environments per customer' },
      { type: 'feature', title: 'TOTP MFA', description: 'Time-based one-time password support' },
      { type: 'feature', title: 'Organizations & RBAC', description: 'Multi-tenant organizations with role-based access' },
      { type: 'feature', title: 'React & Next.js SDKs', description: 'Official SDKs for React and Next.js' },
      { type: 'security', title: 'Argon2id password hashing', description: '32MB memory cost for brute-force resistance' },
      { type: 'security', title: 'RS256 JWT signing', description: 'FIPS-compliant asymmetric token signing' },
    ],
  },
];

const changeTypeConfig = {
  feature: { icon: Sparkles, color: 'text-emerald-400', bg: 'bg-emerald-500/20', label: 'New' },
  improvement: { icon: ArrowUp, color: 'text-blue-400', bg: 'bg-blue-500/20', label: 'Improved' },
  fix: { icon: Bug, color: 'text-amber-400', bg: 'bg-amber-500/20', label: 'Fixed' },
  security: { icon: Shield, color: 'text-red-400', bg: 'bg-red-500/20', label: 'Security' },
  breaking: { icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-500/20', label: 'Breaking' },
  deprecated: { icon: Clock, color: 'text-neutral-400', bg: 'bg-neutral-500/20', label: 'Deprecated' },
};

export default function ChangelogPage() {
  return (
    <div className="min-h-screen bg-neutral-950">
      <div className="max-w-4xl mx-auto px-4 py-16">
        {/* Header */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }} 
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-12"
        >
          <div className="flex items-center justify-center gap-2 text-emerald-400 text-sm font-mono mb-4">
            <Package size={14} />
            CHANGELOG
          </div>
          <h1 className="font-outfit text-4xl md:text-5xl font-bold text-white mb-4">
            What&apos;s New in Zalt
          </h1>
          <p className="text-neutral-400 max-w-2xl mx-auto">
            Track all updates, improvements, and fixes to the Zalt platform.
          </p>
        </motion.div>

        {/* Changelog Entries */}
        <div className="space-y-8">
          {changelog.map((entry, entryIndex) => (
            <motion.div
              key={entry.version}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: entryIndex * 0.1 }}
              className="relative"
            >
              {/* Version Header */}
              <div className="flex items-center gap-4 mb-4">
                <div className="flex items-center gap-2">
                  <span className="px-3 py-1 bg-emerald-500/20 text-emerald-400 rounded-lg font-mono font-bold">
                    v{entry.version}
                  </span>
                  <span className="text-neutral-500 text-sm">{entry.date}</span>
                </div>
              </div>

              {/* Changes */}
              <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
                {entry.changes.map((change, changeIndex) => {
                  const config = changeTypeConfig[change.type];
                  const Icon = config.icon;
                  
                  return (
                    <div
                      key={changeIndex}
                      className={`flex items-start gap-3 p-4 ${
                        changeIndex !== entry.changes.length - 1 ? 'border-b border-emerald-500/5' : ''
                      }`}
                    >
                      <div className={`p-1.5 rounded ${config.bg}`}>
                        <Icon size={14} className={config.color} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-xs font-medium ${config.color}`}>
                            {config.label}
                          </span>
                        </div>
                        <h3 className="text-white font-medium">{change.title}</h3>
                        {change.description && (
                          <p className="text-sm text-neutral-400 mt-1">{change.description}</p>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Subscribe CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="mt-12 bg-gradient-to-r from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-lg p-6 text-center"
        >
          <h2 className="text-xl font-bold text-white mb-2">Stay Updated</h2>
          <p className="text-neutral-400 mb-4">
            Get notified about new features and updates.
          </p>
          <div className="flex items-center justify-center gap-2 max-w-md mx-auto">
            <input
              type="email"
              placeholder="your@email.com"
              className="flex-1 px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
            />
            <button className="px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium">
              Subscribe
            </button>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
