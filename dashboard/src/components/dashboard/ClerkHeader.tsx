'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Bell,
  ChevronDown,
  ChevronRight,
  Settings,
  LogOut,
  User,
  HelpCircle,
  Moon,
  Sun,
} from 'lucide-react';
import { AdminUser } from '@/types/auth';

// Breadcrumb mapping
const breadcrumbLabels: Record<string, string> = {
  dashboard: 'Dashboard',
  users: 'Users',
  organizations: 'Organizations',
  'api-keys': 'API Keys',
  sessions: 'Sessions',
  webhooks: 'Webhooks',
  sso: 'SSO',
  security: 'Security',
  billing: 'Billing',
  settings: 'Settings',
  analytics: 'Analytics',
  risk: 'Risk Assessment',
};

export interface ClerkHeaderProps {
  user: AdminUser | null;
  onLogout: () => void;
  notifications?: number;
}

export function ClerkHeader({ user, onLogout, notifications = 0 }: ClerkHeaderProps) {
  const pathname = usePathname();
  const [searchOpen, setSearchOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  // Generate breadcrumbs from pathname
  const generateBreadcrumbs = () => {
    const segments = pathname.split('/').filter(Boolean);
    return segments.map((segment, index) => ({
      label: breadcrumbLabels[segment] || segment.charAt(0).toUpperCase() + segment.slice(1),
      href: '/' + segments.slice(0, index + 1).join('/'),
      isLast: index === segments.length - 1,
    }));
  };

  const breadcrumbs = generateBreadcrumbs();

  return (
    <header className="h-16 bg-white border-b border-neutral-200 px-6 flex items-center justify-between">
      {/* Left: Breadcrumbs */}
      <nav className="flex items-center gap-2" aria-label="Breadcrumb">
        {breadcrumbs.map((crumb, index) => (
          <React.Fragment key={crumb.href}>
            {index > 0 && (
              <ChevronRight size={14} className="text-neutral-400" />
            )}
            {crumb.isLast ? (
              <span className="text-sm font-medium text-neutral-900">
                {crumb.label}
              </span>
            ) : (
              <Link
                href={crumb.href}
                className="text-sm text-neutral-500 hover:text-neutral-700 transition-colors"
              >
                {crumb.label}
              </Link>
            )}
          </React.Fragment>
        ))}
      </nav>

      {/* Right: Actions */}
      <div className="flex items-center gap-3">
        {/* Search */}
        <div className="relative">
          <button
            onClick={() => setSearchOpen(!searchOpen)}
            className="w-9 h-9 rounded-lg flex items-center justify-center text-neutral-500 
                       hover:bg-neutral-100 hover:text-neutral-700 transition-colors"
            aria-label="Search"
          >
            <Search size={18} />
          </button>

          <AnimatePresence>
            {searchOpen && (
              <motion.div
                initial={{ opacity: 0, y: -10, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -10, scale: 0.95 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-full mt-2 w-80 bg-white rounded-xl shadow-lg 
                           border border-neutral-200 p-2 z-50"
              >
                <div className="relative">
                  <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-400" />
                  <input
                    type="text"
                    placeholder="Search users, organizations..."
                    className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-neutral-50 border border-neutral-200
                               text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary"
                    autoFocus
                  />
                </div>
                <div className="mt-2 text-xs text-neutral-500 px-3">
                  Press <kbd className="px-1.5 py-0.5 bg-neutral-100 rounded text-neutral-600">⌘K</kbd> to search anywhere
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Notifications */}
        <div className="relative">
          <button
            onClick={() => setNotificationsOpen(!notificationsOpen)}
            className="w-9 h-9 rounded-lg flex items-center justify-center text-neutral-500 
                       hover:bg-neutral-100 hover:text-neutral-700 transition-colors relative"
            aria-label={`Notifications${notifications > 0 ? ` (${notifications} unread)` : ''}`}
          >
            <Bell size={18} />
            {notifications > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-500 text-white text-[10px] 
                               font-medium rounded-full flex items-center justify-center">
                {notifications > 9 ? '9+' : notifications}
              </span>
            )}
          </button>

          <AnimatePresence>
            {notificationsOpen && (
              <motion.div
                initial={{ opacity: 0, y: -10, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -10, scale: 0.95 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-full mt-2 w-80 bg-white rounded-xl shadow-lg 
                           border border-neutral-200 overflow-hidden z-50"
              >
                <div className="px-4 py-3 border-b border-neutral-100">
                  <h3 className="font-semibold text-neutral-900">Notifications</h3>
                </div>
                <div className="max-h-80 overflow-y-auto">
                  {notifications === 0 ? (
                    <div className="px-4 py-8 text-center text-neutral-500 text-sm">
                      No new notifications
                    </div>
                  ) : (
                    <div className="divide-y divide-neutral-100">
                      <div className="px-4 py-3 hover:bg-neutral-50 transition-colors cursor-pointer">
                        <p className="text-sm text-neutral-900">New user registered</p>
                        <p className="text-xs text-neutral-500 mt-1">2 minutes ago</p>
                      </div>
                      <div className="px-4 py-3 hover:bg-neutral-50 transition-colors cursor-pointer">
                        <p className="text-sm text-neutral-900">Security alert: Unusual login</p>
                        <p className="text-xs text-neutral-500 mt-1">1 hour ago</p>
                      </div>
                    </div>
                  )}
                </div>
                <div className="px-4 py-2 border-t border-neutral-100">
                  <Link
                    href="/dashboard/notifications"
                    className="text-sm text-primary hover:text-primary/80 transition-colors"
                  >
                    View all notifications
                  </Link>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Divider */}
        <div className="w-px h-6 bg-neutral-200" />

        {/* User Profile Dropdown */}
        <div className="relative">
          <button
            onClick={() => setProfileOpen(!profileOpen)}
            className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-neutral-100 transition-colors"
          >
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-accent flex items-center justify-center">
              <span className="text-white font-medium text-sm">
                {user?.email.charAt(0).toUpperCase() || 'U'}
              </span>
            </div>
            <ChevronDown size={14} className={`text-neutral-500 transition-transform ${profileOpen ? 'rotate-180' : ''}`} />
          </button>

          <AnimatePresence>
            {profileOpen && (
              <motion.div
                initial={{ opacity: 0, y: -10, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -10, scale: 0.95 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 top-full mt-2 w-56 bg-white rounded-xl shadow-lg 
                           border border-neutral-200 overflow-hidden z-50"
              >
                {/* User Info */}
                <div className="px-4 py-3 border-b border-neutral-100">
                  <p className="font-medium text-neutral-900 truncate">{user?.email}</p>
                  <p className="text-xs text-neutral-500 capitalize mt-0.5">
                    {user?.role.replace('_', ' ')}
                  </p>
                </div>

                {/* Menu Items */}
                <div className="py-1">
                  <Link
                    href="/dashboard/profile"
                    className="flex items-center gap-3 px-4 py-2 text-sm text-neutral-700 
                               hover:bg-neutral-50 transition-colors"
                  >
                    <User size={16} />
                    Profile
                  </Link>
                  <Link
                    href="/dashboard/settings"
                    className="flex items-center gap-3 px-4 py-2 text-sm text-neutral-700 
                               hover:bg-neutral-50 transition-colors"
                  >
                    <Settings size={16} />
                    Settings
                  </Link>
                  <Link
                    href="/docs"
                    className="flex items-center gap-3 px-4 py-2 text-sm text-neutral-700 
                               hover:bg-neutral-50 transition-colors"
                  >
                    <HelpCircle size={16} />
                    Help & Support
                  </Link>
                </div>

                {/* Logout */}
                <div className="py-1 border-t border-neutral-100">
                  <button
                    onClick={onLogout}
                    className="flex items-center gap-3 px-4 py-2 text-sm text-red-600 
                               hover:bg-red-50 transition-colors w-full"
                  >
                    <LogOut size={16} />
                    Sign out
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Click outside to close dropdowns */}
      {(searchOpen || profileOpen || notificationsOpen) && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => {
            setSearchOpen(false);
            setProfileOpen(false);
            setNotificationsOpen(false);
          }}
        />
      )}
    </header>
  );
}

export default ClerkHeader;
