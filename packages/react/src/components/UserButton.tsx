/**
 * UserButton Component
 * @zalt/react
 */

'use client';

import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../hooks/useAuth';
import { useUser } from '../hooks/useUser';

/**
 * UserButton props
 */
export interface UserButtonProps {
  /** Size of the avatar */
  size?: 'sm' | 'md' | 'lg';
  /** Show user name next to avatar */
  showName?: boolean;
  /** Custom class name */
  className?: string;
  /** After sign out URL */
  afterSignOutUrl?: string;
}

const sizeMap = {
  sm: 32,
  md: 40,
  lg: 48,
};

/**
 * User avatar button with dropdown menu
 * 
 * @example
 * ```tsx
 * import { UserButton } from '@zalt/react';
 * 
 * function Header() {
 *   return (
 *     <header>
 *       <UserButton showName />
 *     </header>
 *   );
 * }
 * ```
 */
export function UserButton({
  size = 'md',
  showName = false,
  className = '',
  afterSignOutUrl,
}: UserButtonProps): JSX.Element | null {
  const user = useUser();
  const { signOut } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (!user) return null;

  const avatarSize = sizeMap[size];
  const initials = getInitials(user.profile?.firstName, user.profile?.lastName, user.email);
  const displayName = user.profile?.firstName 
    ? `${user.profile.firstName} ${user.profile.lastName || ''}`.trim()
    : user.email;

  const handleSignOut = async () => {
    await signOut();
    if (afterSignOutUrl) {
      window.location.href = afterSignOutUrl;
    }
  };

  return (
    <div ref={dropdownRef} className={`zalt-user-button ${className}`} style={{ position: 'relative' }}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '4px',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          borderRadius: 'var(--zalt-radius, 0.5rem)',
        }}
        aria-label="User menu"
        aria-expanded={isOpen}
      >
        {user.profile?.avatarUrl ? (
          <img
            src={user.profile.avatarUrl}
            alt={displayName}
            style={{
              width: avatarSize,
              height: avatarSize,
              borderRadius: '50%',
              objectFit: 'cover',
            }}
          />
        ) : (
          <div
            style={{
              width: avatarSize,
              height: avatarSize,
              borderRadius: '50%',
              background: 'var(--zalt-primary, #10b981)',
              color: '#000',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 600,
              fontSize: avatarSize * 0.4,
            }}
          >
            {initials}
          </div>
        )}
        {showName && (
          <span style={{ color: 'var(--zalt-text, #fff)', fontSize: '14px' }}>
            {displayName}
          </span>
        )}
      </button>

      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            right: 0,
            marginTop: '8px',
            minWidth: '200px',
            background: 'var(--zalt-bg, #1a1a1a)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: 'var(--zalt-radius, 0.5rem)',
            boxShadow: '0 10px 40px rgba(0,0,0,0.3)',
            zIndex: 1000,
            overflow: 'hidden',
          }}
        >
          {/* User info */}
          <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
            <div style={{ fontWeight: 600, color: 'var(--zalt-text, #fff)' }}>{displayName}</div>
            <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)' }}>{user.email}</div>
          </div>

          {/* Menu items */}
          <div style={{ padding: '8px 0' }}>
            <MenuItem onClick={() => setIsOpen(false)}>
              Profile Settings
            </MenuItem>
            <MenuItem onClick={() => setIsOpen(false)}>
              Security
            </MenuItem>
            <div style={{ height: '1px', background: 'rgba(255,255,255,0.1)', margin: '8px 0' }} />
            <MenuItem onClick={handleSignOut} danger>
              Sign Out
            </MenuItem>
          </div>
        </div>
      )}
    </div>
  );
}

function MenuItem({ 
  children, 
  onClick, 
  danger = false 
}: { 
  children: React.ReactNode; 
  onClick: () => void; 
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'block',
        width: '100%',
        padding: '8px 16px',
        background: 'transparent',
        border: 'none',
        textAlign: 'left',
        cursor: 'pointer',
        color: danger ? '#ef4444' : 'var(--zalt-text, #fff)',
        fontSize: '14px',
        transition: 'background 0.15s',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = 'rgba(255,255,255,0.05)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = 'transparent';
      }}
    >
      {children}
    </button>
  );
}

function getInitials(firstName?: string, lastName?: string, email?: string): string {
  if (firstName && lastName) {
    return `${firstName[0]}${lastName[0]}`.toUpperCase();
  }
  if (firstName) {
    return firstName.slice(0, 2).toUpperCase();
  }
  if (email) {
    return email.slice(0, 2).toUpperCase();
  }
  return 'U';
}

export default UserButton;
