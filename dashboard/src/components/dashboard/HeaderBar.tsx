'use client';

import React, { useState, useRef, useEffect } from 'react';
import { AdminUser } from '@/types/auth';

export interface HeaderBarProps {
  onToggleSidebar: () => void;
  sidebarCollapsed: boolean;
  user: AdminUser | null;
  onLogout: () => void;
  onNotificationClick?: () => void;
  unreadNotifications?: number;
  showSearch?: boolean;
}

/**
 * HeaderBar Component
 * 
 * A header bar with sidebar toggle, optional search, notification bell,
 * and user menu dropdown.
 * 
 * Requirements: 4.3
 */
export function HeaderBar({
  onToggleSidebar,
  sidebarCollapsed,
  user,
  onLogout,
  onNotificationClick,
  unreadNotifications = 0,
  showSearch = true,
}: HeaderBarProps) {
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const userMenuRef = useRef<HTMLDivElement>(null);

  // Close user menu when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setUserMenuOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <header
      className="
        bg-nexus-cosmic-deep/80
        backdrop-blur-xl
        border-b border-white/10
        px-6 py-4
        flex items-center justify-between
      "
    >
      {/* Left Section: Toggle + Search */}
      <div className="flex items-center space-x-4">
        {/* Sidebar Toggle Button */}
        <button
          onClick={onToggleSidebar}
          className="
            p-2 rounded-lg
            text-nexus-text-secondary hover:text-white
            hover:bg-white/5
            transition-all duration-200
            focus:outline-none focus:ring-2 focus:ring-nexus-glow-cyan/50
          "
          aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <svg
            className={`w-5 h-5 transition-transform duration-300 ${sidebarCollapsed ? 'rotate-180' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M11 19l-7-7 7-7m8 14l-7-7 7-7"
            />
          </svg>
        </button>

        {/* Search Input (Optional) */}
        {showSearch && (
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <svg
                className="w-4 h-4 text-nexus-text-muted"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                />
              </svg>
            </div>
            <input
              type="text"
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="
                w-64 pl-10 pr-4 py-2
                bg-nexus-cosmic-nebula/50
                border border-white/10
                rounded-lg
                text-white placeholder-nexus-text-muted
                focus:outline-none focus:ring-2 focus:ring-nexus-glow-cyan/50 focus:border-nexus-glow-cyan/50
                transition-all duration-200
              "
            />
          </div>
        )}
      </div>

      {/* Right Section: Notifications + User Menu */}
      <div className="flex items-center space-x-4">
        {/* Date Display */}
        <span className="text-sm text-nexus-text-muted hidden md:block">
          {new Date().toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric',
          })}
        </span>

        {/* Notification Bell */}
        <button
          onClick={onNotificationClick}
          className="
            relative p-2 rounded-lg
            text-nexus-text-secondary hover:text-nexus-glow-cyan
            hover:bg-white/5
            transition-all duration-200
            focus:outline-none focus:ring-2 focus:ring-nexus-glow-cyan/50
          "
          aria-label="Notifications"
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
              d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
            />
          </svg>
          {unreadNotifications > 0 && (
            <span className="
              absolute -top-1 -right-1
              w-5 h-5
              bg-nexus-error
              text-white text-xs font-bold
              rounded-full
              flex items-center justify-center
              animate-pulse
            ">
              {unreadNotifications > 9 ? '9+' : unreadNotifications}
            </span>
          )}
        </button>

        {/* User Menu */}
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => setUserMenuOpen(!userMenuOpen)}
            className="
              flex items-center space-x-2 p-2 rounded-lg
              text-nexus-text-secondary hover:text-white
              hover:bg-white/5
              transition-all duration-200
              focus:outline-none focus:ring-2 focus:ring-nexus-glow-cyan/50
            "
          >
            {/* User Avatar */}
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-nexus-glow-purple to-nexus-glow-pink flex items-center justify-center">
              <span className="text-sm font-bold text-white">
                {user?.email?.charAt(0).toUpperCase() || 'U'}
              </span>
            </div>
            <svg
              className={`w-4 h-4 transition-transform duration-200 ${userMenuOpen ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M19 9l-7 7-7-7"
              />
            </svg>
          </button>

          {/* Dropdown Menu */}
          {userMenuOpen && (
            <div className="
              absolute right-0 mt-2 w-56
              bg-nexus-cosmic-nebula/95
              backdrop-blur-xl
              border border-white/10
              rounded-xl
              shadow-elevated
              py-2
              z-50
              animate-fade-in-up
            ">
              {/* User Info */}
              {user && (
                <div className="px-4 py-3 border-b border-white/10">
                  <p className="text-sm font-medium text-white truncate">
                    {user.email}
                  </p>
                  <p className="text-xs text-nexus-text-muted capitalize">
                    {user.role.replace('_', ' ')}
                  </p>
                </div>
              )}

              {/* Menu Items */}
              <div className="py-1">
                <a
                  href="/dashboard/settings"
                  className="
                    flex items-center px-4 py-2
                    text-sm text-nexus-text-secondary
                    hover:text-white hover:bg-white/5
                    transition-colors duration-150
                  "
                >
                  <svg className="w-4 h-4 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                  Settings
                </a>
              </div>

              {/* Logout */}
              <div className="border-t border-white/10 pt-1">
                <button
                  onClick={() => {
                    setUserMenuOpen(false);
                    onLogout();
                  }}
                  className="
                    flex items-center w-full px-4 py-2
                    text-sm text-nexus-error
                    hover:bg-nexus-error/10
                    transition-colors duration-150
                  "
                >
                  <svg className="w-4 h-4 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                  Logout
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

export default HeaderBar;
