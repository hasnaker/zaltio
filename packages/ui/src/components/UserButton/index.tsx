'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Avatar } from '../../primitives/Avatar';
import { cn } from '../../utils/cn';
import { LogOut, User, Settings, Shield, Users } from 'lucide-react';

export interface UserButtonAppearance {
  elements?: {
    avatarBox?: string;
    userButtonTrigger?: string;
    userButtonPopover?: string;
    userButtonPopoverCard?: string;
  };
}

export interface UserButtonUser {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  imageUrl?: string | null;
  hasOrganizations?: boolean;
}

export interface UserButtonProps {
  /** User data to display */
  user?: UserButtonUser | null;
  /** Custom appearance */
  appearance?: UserButtonAppearance;
  /** URL to redirect after sign out */
  afterSignOutUrl?: string;
  /** User profile mode */
  userProfileMode?: 'modal' | 'navigation';
  /** URL for user profile page */
  userProfileUrl?: string;
  /** Show manage account option */
  showManageAccount?: boolean;
  /** Custom menu items */
  customMenuItems?: Array<{
    label: string;
    icon?: React.ReactNode;
    onClick: () => void;
  }>;
  /** Sign out handler */
  onSignOut?: () => Promise<void>;
  /** Profile click handler */
  onProfileClick?: () => void;
}

export function UserButton({
  user,
  appearance,
  afterSignOutUrl = '/',
  userProfileMode = 'navigation',
  userProfileUrl = '/profile',
  showManageAccount = true,
  customMenuItems = [],
  onSignOut,
  onProfileClick,
}: UserButtonProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Close menu when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        menuRef.current &&
        buttonRef.current &&
        !menuRef.current.contains(event.target as Node) &&
        !buttonRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Close on escape
  useEffect(() => {
    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    }

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, []);

  const handleSignOut = async () => {
    if (!onSignOut) return;
    
    setSigningOut(true);
    try {
      await onSignOut();
      window.location.href = afterSignOutUrl;
    } catch (error) {
      console.error('Sign out failed:', error);
    } finally {
      setSigningOut(false);
    }
  };

  const handleProfileClick = () => {
    setIsOpen(false);
    if (onProfileClick) {
      onProfileClick();
    } else if (userProfileMode === 'navigation' && userProfileUrl) {
      window.location.href = userProfileUrl;
    }
  };

  if (!user) {
    return null;
  }

  const displayName = user.firstName 
    ? `${user.firstName}${user.lastName ? ` ${user.lastName}` : ''}`
    : user.email;

  return (
    <div className="relative">
      <button
        ref={buttonRef}
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          'flex items-center gap-2 rounded-full focus:outline-none focus:ring-2 focus:ring-[var(--zalt-ring)] focus:ring-offset-2',
          appearance?.elements?.userButtonTrigger
        )}
        aria-expanded={isOpen}
        aria-haspopup="true"
      >
        <Avatar
          src={user.imageUrl}
          alt={displayName}
          fallback={user.firstName?.[0] || user.email[0]}
          size="md"
          className={appearance?.elements?.avatarBox}
        />
      </button>

      {isOpen && (
        <div
          ref={menuRef}
          className={cn(
            'absolute right-0 mt-2 w-64 rounded-lg border border-[var(--zalt-border)] bg-[var(--zalt-card)] shadow-[var(--zalt-shadow-lg)] z-50',
            appearance?.elements?.userButtonPopover
          )}
          role="menu"
        >
          {/* User info header */}
          <div className="p-4 border-b border-[var(--zalt-border)]">
            <div className="flex items-center gap-3">
              <Avatar
                src={user.imageUrl}
                alt={displayName}
                fallback={user.firstName?.[0] || user.email[0]}
                size="lg"
              />
              <div className="flex-1 min-w-0">
                <p className="font-medium text-[var(--zalt-foreground)] truncate">
                  {displayName}
                </p>
                <p className="text-sm text-[var(--zalt-muted-foreground)] truncate">
                  {user.email}
                </p>
              </div>
            </div>
          </div>

          {/* Menu items */}
          <div className="py-2">
            {showManageAccount && (
              <button
                onClick={handleProfileClick}
                className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--zalt-foreground)] hover:bg-[var(--zalt-muted)] transition-colors"
                role="menuitem"
              >
                <User className="h-4 w-4 text-[var(--zalt-muted-foreground)]" />
                Manage account
              </button>
            )}

            <button
              onClick={() => {
                setIsOpen(false);
                window.location.href = '/settings/security';
              }}
              className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--zalt-foreground)] hover:bg-[var(--zalt-muted)] transition-colors"
              role="menuitem"
            >
              <Shield className="h-4 w-4 text-[var(--zalt-muted-foreground)]" />
              Security
            </button>

            {user.hasOrganizations && (
              <button
                onClick={() => {
                  setIsOpen(false);
                  window.location.href = '/organizations';
                }}
                className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--zalt-foreground)] hover:bg-[var(--zalt-muted)] transition-colors"
                role="menuitem"
              >
                <Users className="h-4 w-4 text-[var(--zalt-muted-foreground)]" />
                Organizations
              </button>
            )}

            {customMenuItems.map((item, index) => (
              <button
                key={index}
                onClick={() => {
                  setIsOpen(false);
                  item.onClick();
                }}
                className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--zalt-foreground)] hover:bg-[var(--zalt-muted)] transition-colors"
                role="menuitem"
              >
                {item.icon || <Settings className="h-4 w-4 text-[var(--zalt-muted-foreground)]" />}
                {item.label}
              </button>
            ))}
          </div>

          {/* Sign out */}
          <div className="border-t border-[var(--zalt-border)] py-2">
            <button
              onClick={handleSignOut}
              disabled={signingOut}
              className="w-full flex items-center gap-3 px-4 py-2 text-sm text-[var(--zalt-error)] hover:bg-[var(--zalt-muted)] transition-colors disabled:opacity-50"
              role="menuitem"
            >
              <LogOut className="h-4 w-4" />
              {signingOut ? 'Signing out...' : 'Sign out'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
