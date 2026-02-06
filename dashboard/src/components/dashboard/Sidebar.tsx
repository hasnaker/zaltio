'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { AdminUser, AdminPermission, ROLE_PERMISSIONS } from '@/types/auth';

export interface NavItem {
  name: string;
  href: string;
  icon: React.ReactNode;
  permission?: AdminPermission;
}

export interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  user: AdminUser | null;
  onLogout: () => void;
  navItems: NavItem[];
}

/**
 * Sidebar Component
 * 
 * A collapsible sidebar with glassmorphism effect, navigation icons,
 * user info footer, and logout button.
 * 
 * Requirements: 4.1, 4.2
 */
export function Sidebar({
  collapsed,
  onToggle,
  user,
  onLogout,
  navItems,
}: SidebarProps) {
  const pathname = usePathname();

  const hasPermission = (permission?: AdminPermission): boolean => {
    if (!permission || !user) return true;
    return ROLE_PERMISSIONS[user.role]?.includes(permission) ?? false;
  };

  const filteredNavItems = navItems.filter(item => hasPermission(item.permission));

  return (
    <aside
      data-testid="sidebar"
      data-collapsed={collapsed}
      className={`
        ${collapsed ? 'w-20' : 'w-64'}
        bg-nexus-cosmic-void/80
        backdrop-blur-xl
        border-r border-white/10
        text-white
        transition-all duration-300
        flex flex-col
        h-full
      `}
      style={{ transitionProperty: 'width, transform' }}
    >
      {/* Logo Section */}
      <div className="p-4 border-b border-white/10 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-nexus-glow-cyan to-nexus-glow-purple flex items-center justify-center shadow-glow-cyan">
            <span className="text-xl font-bold text-nexus-cosmic-black">N</span>
          </div>
          {!collapsed && (
            <div className="animate-fade-in-up">
              <h1 className="font-heading font-bold text-lg text-white">NEXUS</h1>
              <p className="text-xs text-nexus-text-muted">Auth Platform</p>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 overflow-y-auto">
        <ul className="space-y-2">
          {filteredNavItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className={`
                    flex items-center px-3 py-2.5 rounded-lg
                    transition-all duration-200
                    group relative
                    ${isActive
                      ? 'bg-gradient-to-r from-nexus-glow-cyan/20 to-nexus-glow-purple/20 text-nexus-glow-cyan border border-nexus-glow-cyan/30'
                      : 'text-nexus-text-secondary hover:bg-white/5 hover:text-white'
                    }
                  `}
                  title={collapsed ? item.name : undefined}
                >
                  <span className={`text-xl ${isActive ? 'text-nexus-glow-cyan' : ''}`}>
                    {item.icon}
                  </span>
                  {!collapsed && (
                    <span className="ml-3 font-medium animate-fade-in-up">{item.name}</span>
                  )}
                  {collapsed && (
                    <div
                      className="
                        absolute left-full ml-2 px-2 py-1
                        bg-nexus-cosmic-nebula rounded-md
                        text-sm text-white whitespace-nowrap
                        opacity-0 invisible
                        group-hover:opacity-100 group-hover:visible
                        transition-all duration-200
                        z-50 shadow-lg border border-white/10
                      "
                      role="tooltip"
                    >
                      {item.name}
                    </div>
                  )}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* User Info Footer */}
      <div className="p-4 border-t border-white/10">
        {user && (
          <div className={`mb-4 ${collapsed ? 'text-center' : ''}`}>
            <div className="flex items-center space-x-3">
              {/* Avatar */}
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-nexus-glow-purple to-nexus-glow-pink flex items-center justify-center flex-shrink-0">
                <span className="text-sm font-bold text-white">
                  {user.email.charAt(0).toUpperCase()}
                </span>
              </div>
              {!collapsed && (
                <div className="flex-1 min-w-0 animate-fade-in-up">
                  <p className="text-sm font-medium text-white truncate">
                    {user.email}
                  </p>
                  <p className="text-xs text-nexus-text-muted capitalize">
                    {user.role.replace('_', ' ')}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}
        
        {/* Logout Button */}
        <button
          onClick={onLogout}
          className={`
            w-full px-3 py-2.5 rounded-lg
            text-nexus-text-secondary hover:text-nexus-error
            hover:bg-nexus-error/10
            transition-all duration-200
            flex items-center justify-center
            border border-transparent hover:border-nexus-error/30
          `}
          title={collapsed ? 'Logout' : undefined}
        >
          <svg
            className="w-5 h-5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
            />
          </svg>
          {!collapsed && <span className="ml-2 font-medium">Logout</span>}
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
