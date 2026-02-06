'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import Image from 'next/image';
import { Menu, X, ExternalLink, Search } from 'lucide-react';

const docsSections = [
  {
    title: 'Getting Started',
    items: [
      { name: 'Introduction', href: '/docs' },
      { name: 'Quick Start', href: '/docs/quickstart' },
      { name: 'How It Works', href: '/docs/how-it-works' },
      { name: 'Compare', href: '/docs/compare' },
    ]
  },
  {
    title: 'SDKs & Tools',
    items: [
      { name: 'SDK Reference', href: '/docs/sdk' },
      { name: 'API Playground', href: '/docs/playground' },
      { name: 'MCP Server', href: '/docs/mcp' },
    ]
  },
  {
    title: 'Integration Guides',
    items: [
      { name: 'React / Next.js', href: '/docs/guides/react' },
      { name: 'Node.js / Express', href: '/docs/guides/node' },
      { name: 'Python / FastAPI', href: '/docs/guides/python' },
      { name: 'Mobile Apps', href: '/docs/guides/mobile' },
    ]
  },
  {
    title: 'Security',
    items: [
      { name: 'MFA Setup', href: '/docs/security/mfa' },
      { name: 'WebAuthn / Passkeys', href: '/docs/security/webauthn' },
      { name: 'Best Practices', href: '/docs/security/best-practices' },
    ]
  },
  {
    title: 'API Reference',
    items: [
      { name: 'Authentication', href: '/docs/api/auth' },
      { name: 'Users', href: '/docs/api/users' },
      { name: 'Sessions', href: '/docs/api/sessions' },
      { name: 'Organizations', href: '/docs/api/organizations' },
    ]
  },
  {
    title: 'Configuration',
    items: [
      { name: 'Realm Settings', href: '/docs/config/realms' },
      { name: 'SSO / SAML', href: '/docs/config/sso' },
      { name: 'Webhooks', href: '/docs/config/webhooks' },
      { name: 'Branding', href: '/docs/config/branding' },
    ]
  },
];

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <div className="min-h-screen bg-neutral-950">
      {/* Background */}
      <div className="fixed inset-0 bg-[linear-gradient(rgba(16,185,129,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(16,185,129,0.02)_1px,transparent_1px)] bg-[size:50px_50px]" />

      {/* Header */}
      <header className="fixed top-0 left-0 right-0 h-16 bg-neutral-900/80 backdrop-blur-sm border-b border-emerald-500/10 z-50">
        <div className="h-full max-w-7xl mx-auto px-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button 
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden text-neutral-400 hover:text-white"
            >
              <Menu size={24} />
            </button>
            <Link href="/" className="flex items-center">
              <Image
                src="/zalt-full-logo.svg"
                alt="Zalt"
                width={80}
                height={111}
                className="h-10 w-auto"
                priority
              />
            </Link>
            <span className="text-neutral-600">/</span>
            <span className="text-emerald-400 text-sm font-medium">docs</span>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-neutral-800 rounded-lg border border-emerald-500/10">
              <Search size={14} className="text-neutral-500" />
              <input
                type="text"
                placeholder="Search docs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-transparent text-sm text-white placeholder:text-neutral-500 outline-none w-48"
              />
              <kbd className="text-xs text-neutral-600 bg-neutral-700 px-1.5 py-0.5 rounded">⌘K</kbd>
            </div>
            <Link 
              href="/dashboard" 
              className="text-sm text-neutral-400 hover:text-white transition-colors"
            >
              Dashboard
            </Link>
            <a 
              href="https://github.com/zalt-io" 
              target="_blank"
              rel="noopener noreferrer"
              className="text-neutral-400 hover:text-white"
            >
              <ExternalLink size={18} />
            </a>
          </div>
        </div>
      </header>

      {/* Mobile Sidebar */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSidebarOpen(false)}
              className="lg:hidden fixed inset-0 bg-black/60 z-50"
            />
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              className="lg:hidden fixed left-0 top-0 h-full w-72 bg-neutral-900 border-r border-emerald-500/10 z-50 overflow-y-auto"
            >
              <div className="h-16 flex items-center justify-between px-4 border-b border-emerald-500/10">
                <span className="font-outfit font-semibold text-white">Documentation</span>
                <button onClick={() => setSidebarOpen(false)} className="text-neutral-500 hover:text-white">
                  <X size={20} />
                </button>
              </div>
              <nav className="p-4">
                {docsSections.map((section) => (
                  <div key={section.title} className="mb-6">
                    <h3 className="text-xs font-mono text-emerald-500/70 uppercase tracking-wider mb-2">
                      {section.title}
                    </h3>
                    <ul className="space-y-1">
                      {section.items.map((item) => (
                        <li key={item.href}>
                          <Link
                            href={item.href}
                            onClick={() => setSidebarOpen(false)}
                            className={`block px-3 py-2 rounded text-sm transition-colors ${
                              pathname === item.href
                                ? 'bg-emerald-500/10 text-emerald-400 border-l-2 border-emerald-500'
                                : 'text-neutral-400 hover:text-white hover:bg-neutral-800'
                            }`}
                          >
                            {item.name}
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </nav>
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Desktop Sidebar */}
      <aside className="hidden lg:block fixed left-0 top-16 bottom-0 w-64 bg-neutral-900/50 border-r border-emerald-500/10 overflow-y-auto">
        <nav className="p-4">
          {docsSections.map((section) => (
            <div key={section.title} className="mb-6">
              <h3 className="text-xs font-mono text-emerald-500/70 uppercase tracking-wider mb-2 px-3">
                {section.title}
              </h3>
              <ul className="space-y-1">
                {section.items.map((item) => (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      className={`block px-3 py-2 rounded text-sm transition-colors ${
                        pathname === item.href
                          ? 'bg-emerald-500/10 text-emerald-400 border-l-2 border-emerald-500'
                          : 'text-neutral-400 hover:text-white hover:bg-neutral-800'
                      }`}
                    >
                      {item.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </aside>

      {/* Main Content */}
      <main className="relative z-10 pt-16 lg:pl-64">
        <div className="max-w-4xl mx-auto px-6 py-12">
          {children}
        </div>
      </main>
    </div>
  );
}
