'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { 
  Cpu, Copy, CheckCircle, Terminal, Zap, 
  Users, Shield, Key, Activity, ArrowRight
} from 'lucide-react';

const tools = [
  {
    category: 'User Management',
    icon: Users,
    items: [
      { name: 'zalt_list_users', desc: 'List users with pagination and filters' },
      { name: 'zalt_get_user', desc: 'Get user by ID or email' },
      { name: 'zalt_update_user', desc: 'Update user profile and metadata' },
      { name: 'zalt_suspend_user', desc: 'Suspend user account' },
      { name: 'zalt_activate_user', desc: 'Reactivate suspended user' },
      { name: 'zalt_delete_user', desc: 'Soft or hard delete user (GDPR)' },
    ]
  },
  {
    category: 'Session Management',
    icon: Key,
    items: [
      { name: 'zalt_list_sessions', desc: 'List active sessions for user' },
      { name: 'zalt_revoke_session', desc: 'Revoke specific session' },
      { name: 'zalt_revoke_all_sessions', desc: 'Revoke all sessions for user' },
    ]
  },
  {
    category: 'MFA Management',
    icon: Shield,
    items: [
      { name: 'zalt_get_mfa_status', desc: 'Get MFA status for user' },
      { name: 'zalt_reset_mfa', desc: 'Reset MFA for user (admin)' },
      { name: 'zalt_configure_mfa_policy', desc: 'Set realm MFA policy' },
      { name: 'zalt_get_mfa_policy', desc: 'Get current MFA policy' },
    ]
  },
  {
    category: 'API Keys',
    icon: Key,
    items: [
      { name: 'zalt_list_api_keys', desc: 'List API keys for user' },
      { name: 'zalt_create_api_key', desc: 'Create new API key' },
      { name: 'zalt_revoke_api_key', desc: 'Revoke API key' },
    ]
  },
  {
    category: 'Analytics',
    icon: Activity,
    items: [
      { name: 'zalt_get_auth_stats', desc: 'Login success/failure rates, DAU/MAU' },
      { name: 'zalt_get_security_events', desc: 'Recent security events' },
      { name: 'zalt_get_failed_logins', desc: 'Failed login attempts' },
    ]
  },
];

const configExample = `{
  "mcpServers": {
    "zalt": {
      "command": "npx",
      "args": ["@zalt/mcp-server"],
      "env": {
        "ZALT_REALM_ID": "your-realm-id",
        "ZALT_SECRET_KEY": "your-secret-key"
      }
    }
  }
}`;

const usageExample = `// Example: List all active users with MFA enabled
> Use zalt_list_users with status="active" and mfaEnabled=true

// Example: Suspend a user after security incident
> Use zalt_suspend_user with userId="user_abc123" 
  and reason="Suspicious activity detected"

// Example: Get authentication statistics
> Use zalt_get_auth_stats for the last 7 days

// Example: Reset MFA for locked out user
> Use zalt_reset_mfa with userId="user_xyz" 
  and reason="User lost authenticator device"`;

export default function MCPPage() {
  const [copied, setCopied] = useState<string | null>(null);

  const copyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Cpu size={14} />
          MCP SERVER
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">
          Model Context Protocol Server
        </h1>
        <p className="text-neutral-400 max-w-2xl">
          The Zalt MCP Server enables AI agents and coding assistants to manage authentication 
          directly. Built for the vibe coding era - let your AI handle user management, 
          security policies, and analytics.
        </p>
      </motion.div>

      {/* Why MCP */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-gradient-to-r from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-lg p-6"
      >
        <div className="flex items-start gap-4">
          <Zap size={24} className="text-emerald-400 mt-1" />
          <div>
            <h2 className="text-lg font-semibold text-white mb-2">Why MCP?</h2>
            <p className="text-neutral-400">
              MCP (Model Context Protocol) allows AI assistants like Claude, Cursor, and Kiro to 
              interact with external services. With Zalt's MCP server, you can manage users, 
              sessions, and security policies using natural language - no dashboard needed.
            </p>
          </div>
        </div>
      </motion.div>

      {/* Installation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <h2 className="text-lg font-semibold text-white mb-4">Installation</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-emerald-500/10 bg-neutral-800/50">
            <span className="text-xs text-neutral-500 font-mono">Terminal</span>
            <button
              onClick={() => copyCode('npm install -g @zalt/mcp-server', 'install')}
              className="flex items-center gap-1 text-neutral-500 hover:text-white text-xs"
            >
              {copied === 'install' ? <CheckCircle size={12} className="text-emerald-400" /> : <Copy size={12} />}
            </button>
          </div>
          <div className="p-4">
            <code className="text-emerald-400 font-mono">npm install -g @zalt/mcp-server</code>
          </div>
        </div>
      </motion.div>

      {/* Configuration */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <h2 className="text-lg font-semibold text-white mb-4">Configuration</h2>
        <p className="text-neutral-400 text-sm mb-4">
          Add to your MCP configuration file (e.g., <code className="text-emerald-400">~/.kiro/settings/mcp.json</code>):
        </p>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-emerald-500/10 bg-neutral-800/50">
            <span className="text-xs text-neutral-500 font-mono">mcp.json</span>
            <button
              onClick={() => copyCode(configExample, 'config')}
              className="flex items-center gap-1 text-neutral-500 hover:text-white text-xs"
            >
              {copied === 'config' ? <CheckCircle size={12} className="text-emerald-400" /> : <Copy size={12} />}
            </button>
          </div>
          <pre className="p-4 text-sm text-neutral-300 font-mono overflow-x-auto">{configExample}</pre>
        </div>
      </motion.div>

      {/* Available Tools */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <h2 className="text-lg font-semibold text-white mb-4">Available Tools (21 total)</h2>
        <div className="space-y-4">
          {tools.map((category) => (
            <div key={category.category} className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-emerald-500/10 bg-neutral-800/50 flex items-center gap-2">
                <category.icon size={16} className="text-emerald-500" />
                <span className="text-white font-medium">{category.category}</span>
                <span className="text-xs text-neutral-500">({category.items.length} tools)</span>
              </div>
              <div className="divide-y divide-emerald-500/5">
                {category.items.map((tool) => (
                  <div key={tool.name} className="px-4 py-3 flex items-center justify-between hover:bg-neutral-800/30">
                    <div>
                      <code className="text-emerald-400 font-mono text-sm">{tool.name}</code>
                      <p className="text-sm text-neutral-500 mt-0.5">{tool.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Usage Examples */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <h2 className="text-lg font-semibold text-white mb-4">Usage Examples</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
          <div className="px-4 py-2 border-b border-emerald-500/10 bg-neutral-800/50">
            <span className="text-xs text-neutral-500 font-mono">Natural Language Commands</span>
          </div>
          <pre className="p-4 text-sm text-neutral-300 font-mono overflow-x-auto whitespace-pre-wrap">{usageExample}</pre>
        </div>
      </motion.div>

      {/* Security Note */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4"
      >
        <div className="flex items-start gap-3">
          <Shield size={20} className="text-amber-500 mt-0.5" />
          <div>
            <h3 className="text-amber-400 font-medium">Security Note</h3>
            <p className="text-amber-400/70 text-sm mt-1">
              The MCP server uses your secret key for authentication. Never share your secret key 
              or commit it to version control. All operations are logged for audit purposes.
            </p>
          </div>
        </div>
      </motion.div>

      {/* CTA */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="flex items-center gap-4"
      >
        <Link
          href="/docs/quickstart"
          className="inline-flex items-center gap-2 px-6 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium"
        >
          Get Started
          <ArrowRight size={16} />
        </Link>
        <a
          href="https://github.com/zalt-io/mcp-server"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-6 py-2 border border-neutral-700 text-neutral-300 rounded-lg hover:bg-neutral-800"
        >
          View on GitHub
        </a>
      </motion.div>
    </div>
  );
}
