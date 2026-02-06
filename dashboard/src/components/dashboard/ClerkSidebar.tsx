'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  Users,
  Key,
  Shield,
  Settings,
  CreditCard,
  Building2,
  Activity,
  Bell,
  ChevronLeft,
  ChevronRight,
  LogOut,
  HelpCircle,
  FileText,
  Webhook,
  Lock,
} from 'lucide-react';
import { AdminUser, AdminPermission, ROLE_PERMISSIONS } from '@/types/auth';

// Navigation items with icons
const navigationItems = [
  { name: 'Overview', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Users', href: '/dashboard/users', icon: Users, permission: 'users:read' as AdminPermission },
  { name: 'Organizations', href: '/dashboard/organizations', icon: Building2, permission: 'organizations:read' as AdminPermission },
  { name: 'API Keys', href: '/dashboard/api-keys', icon: Key, permission: 'api_keys:read' as AdminPermission },
  { name: 'Sessions', href: '/dashboard/sessions', icon: Activity, permission: 'sessions:read' as AdminPermission },
  { name: 'Webhooks', href: '/dashboard/webhooks', icon: Webhook, permission: 'webhooks:read' as AdminPermission },
  { name: 'SSO', href: '/dashboard/sso', icon: Lock, permission: 'sso:read' as AdminPermission },
  { name: 'Security', href: '/dashboard/security', icon: Shield, permission: 'security:read' as AdminPermission },
  { name: 'Billing', href: '/dashboard/billing', icon: CreditCard, permission: 'billing:read' as AdminPermission },
  { name: 'Settings', href: '/dashboard/settings', icon: Settings },
];

const bottomItems = [
  { name: 'Documentation', href: '/docs', icon: FileText, external: true },
  { name: 'Help & Support', href: '/support', icon: HelpCircle, external: true },
];

export interface ClerkSidebarProps {
  user: AdminUser | null;
  onLogout: () => void;
  defaultCollapsed?: boolean;
}

export function ClerkSidebar({ user, onLogout, defaultCollapsed = false }: ClerkSidebarProps) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const pathname = usePathname();

  const hasPermission = (permission?: AdminPermission): boolean => {
    if (!permission || !user) return true;
    return ROLE_PERMISSIONS[user.role]?.includes(permission) ?? false;
  };

  const filteredNavItems = navigationItems.filter(item => hasPermission(item.permission));

  const toggleCollapse = () => setCollapsed(!collapsed);

  return (
    <motion.aside
      initial={false}
      animate={{ width: collapsed ? 72 : 256 }}
      transition={{ duration: 0.2, ease: 'easeInOut' }}
      className="h-screen bg-white border-r border-neutral-200 flex flex-col relative"
    >
      {/* Logo Section */}
      <div className="h-16 px-4 flex items-center justify-between border-b border-neutral-100">
        <Link href="/dashboard" className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-primary to-accent flex items-center justify-center shadow-md">
            <span className="text-white font-bold text-lg">Z</span>
          </div>
          <AnimatePresence>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                transition={{ duration: 0.15 }}
              >
                <span className="font-semibold text-neutral-900">Zalt.io</span>
              </motion.div>
            )}
          </AnimatePresence>
        </Link>
      </div>

      {/* Collapse Toggle */}
      <button
        onClick={toggleCollapse}
        className="absolute -right-3 top-20 w-6 h-6 rounded-full bg-white border border-neutral-200 
                   shadow-sm flex items-center justify-center text-neutral-500 hover:text-primary
                   hover:border-primary/30 transition-colors z-10"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>

      {/* Main Navigation */}
      <nav className="flex-1 py-4 overflow-y-auto">
        <ul className="space-y-1 px-3">
          {filteredNavItems.map((item) => {
            const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
            const Icon = item.icon;

            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className={`
                    flex items-center gap-3 px-3 py-2.5 rounded-lg
                    transition-all duration-150 group relative
                    ${isActive
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-neutral-600 hover:bg-neutral-100 hover:text-neutral-900'
                    }
                  `}
                >
                  <Icon 
                    size={20} 
                    className={isActive ? 'text-primary' : 'text-neutral-500 group-hover:text-neutral-700'} 
                  />
                  <AnimatePresence>
                    {!collapsed && (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        className="text-sm"
                      >
                        {item.name}
                      </motion.span>
                    )}
                  </AnimatePresence>

                  {/* Tooltip for collapsed state */}
                  {collapsed && (
                    <div className="absolute left-full ml-2 px-2 py-1 bg-neutral-900 text-white text-xs 
                                    rounded-md opacity-0 invisible group-hover:opacity-100 group-hover:visible
                                    transition-all duration-150 whitespace-nowrap z-50 shadow-lg">
                      {item.name}
                    </div>
                  )}

                  {/* Active indicator */}
                  {isActive && (
                    <motion.div
                      layoutId="activeIndicator"
                      className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-primary rounded-r-full"
                      transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                    />
                  )}
                </Link>
              </li>
            );
          })}
        </ul>

        {/* Divider */}
        <div className="my-4 mx-3 border-t border-neutral-100" />

        {/* Bottom Navigation */}
        <ul className="space-y-1 px-3">
          {bottomItems.map((item) => {
            const Icon = item.icon;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  target={item.external ? '_blank' : undefined}
                  rel={item.external ? 'noopener noreferrer' : undefined}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-neutral-500 
                             hover:bg-neutral-100 hover:text-neutral-700 transition-all duration-150 group relative"
                >
                  <Icon size={20} />
                  <AnimatePresence>
                    {!collapsed && (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        className="text-sm"
                      >
                        {item.name}
                      </motion.span>
                    )}
                  </AnimatePresence>

                  {collapsed && (
                    <div className="absolute left-full ml-2 px-2 py-1 bg-neutral-900 text-white text-xs 
                                    rounded-md opacity-0 invisible group-hover:opacity-100 group-hover:visible
                                    transition-all duration-150 whitespace-nowrap z-50 shadow-lg">
                      {item.name}
                    </div>
                  )}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* User Section */}
      <div className="p-3 border-t border-neutral-100">
        {user && (
          <div className={`flex items-center gap-3 p-2 rounded-lg hover:bg-neutral-50 transition-colors ${collapsed ? 'justify-center' : ''}`}>
            {/* Avatar */}
            <div className="w-9 h-9 rounded-full bg-gradient-to-br from-primary to-accent flex items-center justify-center flex-shrink-0">
              <span className="text-white font-medium text-sm">
                {user.email.charAt(0).toUpperCase()}
              </span>
            </div>
            
            <AnimatePresence>
              {!collapsed && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  className="flex-1 min-w-0"
                >
                  <p className="text-sm font-medium text-neutral-900 truncate">
                    {user.email}
                  </p>
                  <p className="text-xs text-neutral-500 capitalize">
                    {user.role.replace('_', ' ')}
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

        {/* Logout Button */}
        <button
          onClick={onLogout}
          className={`
            w-full mt-2 px-3 py-2.5 rounded-lg
            text-neutral-500 hover:text-red-600 hover:bg-red-50
            transition-all duration-150 flex items-center gap-3
            ${collapsed ? 'justify-center' : ''}
          `}
          title={collapsed ? 'Sign out' : undefined}
        >
          <LogOut size={20} />
          <AnimatePresence>
            {!collapsed && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.15 }}
                className="text-sm"
              >
                Sign out
              </motion.span>
            )}
          </AnimatePresence>
        </button>
      </div>
    </motion.aside>
  );
}

export default ClerkSidebar;
