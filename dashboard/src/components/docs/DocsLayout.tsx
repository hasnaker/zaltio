'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { 
  ChevronRight, 
  ChevronDown, 
  Book, 
  Code, 
  Shield, 
  Users, 
  Settings,
  Zap,
  Key,
  Globe
} from 'lucide-react';

export interface DocsLayoutProps {
  children: React.ReactNode;
  /** Current page title for breadcrumb */
  title?: string;
  /** Current section for breadcrumb */
  section?: string;
}

interface NavItem {
  title: string;
  href?: string;
  icon?: React.ReactNode;
  children?: NavItem[];
}

const docsNavigation: NavItem[] = [
  {
    title: 'Getting Started',
    icon: <Zap className="w-4 h-4" />,
    children: [
      { title: 'Introduction', href: '/docs' },
      { title: 'Quickstart', href: '/docs/quickstart' },
      { title: 'Installation', href: '/docs/installation' },
    ],
  },
  {
    title: 'Authentication',
    icon: <Key className="w-4 h-4" />,
    children: [
      { title: 'Email & Password', href: '/docs/auth/email-password' },
      { title: 'Social Login', href: '/docs/auth/social' },
      { title: 'Passwordless', href: '/docs/auth/passwordless' },
      { title: 'WebAuthn/Passkeys', href: '/docs/auth/webauthn' },
    ],
  },
  {
    title: 'Multi-Factor Auth',
    icon: <Shield className="w-4 h-4" />,
    children: [
      { title: 'TOTP Setup', href: '/docs/mfa/totp' },
      { title: 'WebAuthn MFA', href: '/docs/mfa/webauthn' },
      { title: 'Backup Codes', href: '/docs/mfa/backup-codes' },
    ],
  },
  {
    title: 'Organizations',
    icon: <Users className="w-4 h-4" />,
    children: [
      { title: 'Multi-tenancy', href: '/docs/orgs/multi-tenancy' },
      { title: 'Roles & Permissions', href: '/docs/orgs/rbac' },
      { title: 'Invitations', href: '/docs/orgs/invitations' },
      { title: 'SSO/SAML', href: '/docs/orgs/sso' },
    ],
  },
  {
    title: 'SDK Reference',
    icon: <Code className="w-4 h-4" />,
    children: [
      { title: 'React', href: '/docs/sdk/react' },
      { title: 'Next.js', href: '/docs/sdk/nextjs' },
      { title: 'Node.js', href: '/docs/sdk/node' },
      { title: 'Python', href: '/docs/sdk/python' },
    ],
  },
  {
    title: 'API Reference',
    icon: <Globe className="w-4 h-4" />,
    children: [
      { title: 'REST API', href: '/docs/api/rest' },
      { title: 'Webhooks', href: '/docs/api/webhooks' },
      { title: 'Error Codes', href: '/docs/api/errors' },
    ],
  },
  {
    title: 'Configuration',
    icon: <Settings className="w-4 h-4" />,
    children: [
      { title: 'Realm Settings', href: '/docs/config/realm' },
      { title: 'Branding', href: '/docs/config/branding' },
      { title: 'Email Templates', href: '/docs/config/email' },
    ],
  },
];

// Collapsible nav section
function NavSection({ item, level = 0 }: { item: NavItem; level?: number }) {
  const pathname = usePathname();
  const [isOpen, setIsOpen] = useState(() => {
    // Auto-expand if current page is in this section
    if (item.children) {
      return item.children.some(child => 
        child.href === pathname || 
        child.children?.some(grandchild => grandchild.href === pathname)
      );
    }
    return false;
  });

  const hasChildren = item.children && item.children.length > 0;
  const isActive = item.href === pathname;

  if (!hasChildren && item.href) {
    return (
      <Link
        href={item.href}
        className={cn(
          'flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors',
          isActive
            ? 'bg-primary/10 text-primary font-medium'
            : 'text-neutral-600 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-neutral-800'
        )}
      >
        {item.icon}
        {item.title}
      </Link>
    );
  }

  return (
    <div>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          'w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors',
          'text-neutral-700 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-neutral-800',
          level === 0 && 'font-medium'
        )}
      >
        <span className="flex items-center gap-2">
          {item.icon}
          {item.title}
        </span>
        <ChevronDown
          className={cn(
            'w-4 h-4 transition-transform',
            isOpen && 'rotate-180'
          )}
        />
      </button>
      
      <AnimatePresence>
        {isOpen && hasChildren && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className={cn('ml-4 mt-1 space-y-1', level > 0 && 'border-l border-neutral-200 dark:border-neutral-700 pl-3')}>
              {item.children!.map((child) => (
                <NavSection key={child.title} item={child} level={level + 1} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Breadcrumb component
function Breadcrumb({ section, title }: { section?: string; title?: string }) {
  return (
    <nav className="flex items-center gap-2 text-sm text-neutral-500 dark:text-neutral-400 mb-6">
      <Link href="/docs" className="hover:text-primary transition-colors">
        Docs
      </Link>
      {section && (
        <>
          <ChevronRight className="w-4 h-4" />
          <span>{section}</span>
        </>
      )}
      {title && (
        <>
          <ChevronRight className="w-4 h-4" />
          <span className="text-neutral-900 dark:text-white font-medium">{title}</span>
        </>
      )}
    </nav>
  );
}

/**
 * Documentation Layout Component
 * Provides sidebar navigation with collapsible sections and breadcrumb navigation
 */
export function DocsLayout({ children, title, section }: DocsLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-white dark:bg-neutral-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex gap-8 py-8">
          {/* Sidebar */}
          <aside className="hidden lg:block w-64 flex-shrink-0">
            <div className="sticky top-24 space-y-1">
              <div className="flex items-center gap-2 px-3 py-2 mb-4">
                <Book className="w-5 h-5 text-primary" />
                <span className="font-semibold text-neutral-900 dark:text-white">
                  Documentation
                </span>
              </div>
              
              <nav className="space-y-1">
                {docsNavigation.map((item) => (
                  <NavSection key={item.title} item={item} />
                ))}
              </nav>
            </div>
          </aside>

          {/* Main content */}
          <main className="flex-1 min-w-0">
            <Breadcrumb section={section} title={title} />
            <div className="prose prose-neutral dark:prose-invert max-w-none">
              {children}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}

export default DocsLayout;
