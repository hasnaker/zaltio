'use client';

import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '../../primitives/Card';
import { Button } from '../../primitives/Button';
import { Input } from '../../primitives/Input';
import { Avatar } from '../../primitives/Avatar';
import { cn } from '../../utils/cn';
import { User, Shield, Smartphone, Key, Trash2, Monitor } from 'lucide-react';

export interface UserProfileAppearance {
  elements?: {
    card?: string;
    navbar?: string;
    navbarButton?: string;
    page?: string;
  };
}

export interface UserProfileUser {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  imageUrl?: string | null;
  emailVerified?: boolean;
  mfaEnabled?: boolean;
  mfaMethods?: ('totp' | 'webauthn')[];
  createdAt?: string;
}

export interface Session {
  id: string;
  deviceName: string;
  browser: string;
  location?: string;
  lastActive: string;
  isCurrent: boolean;
}

export interface UserProfileProps {
  user?: UserProfileUser | null;
  sessions?: Session[];
  appearance?: UserProfileAppearance;
  routing?: 'path' | 'hash' | 'virtual';
  path?: string;
  /** Handlers */
  onUpdateProfile?: (data: { firstName?: string; lastName?: string }) => Promise<void>;
  onUpdatePassword?: (currentPassword: string, newPassword: string) => Promise<void>;
  onSetupMFA?: () => void;
  onDisableMFA?: () => Promise<void>;
  onRevokeSession?: (sessionId: string) => Promise<void>;
  onRevokeAllSessions?: () => Promise<void>;
  onDeleteAccount?: () => Promise<void>;
}

type Tab = 'profile' | 'security' | 'sessions';

export function UserProfile({
  user,
  sessions = [],
  appearance,
  onUpdateProfile,
  onUpdatePassword,
  onSetupMFA,
  onDisableMFA,
  onRevokeSession,
  onRevokeAllSessions,
  onDeleteAccount,
}: UserProfileProps) {
  const [activeTab, setActiveTab] = useState<Tab>('profile');

  if (!user) {
    return null;
  }

  const tabs = [
    { id: 'profile' as const, label: 'Profile', icon: User },
    { id: 'security' as const, label: 'Security', icon: Shield },
    { id: 'sessions' as const, label: 'Sessions', icon: Monitor },
  ];

  return (
    <div className="w-full max-w-4xl mx-auto">
      {/* Navigation */}
      <div className={cn('flex gap-2 mb-6 border-b border-[var(--zalt-border)] pb-2', appearance?.elements?.navbar)}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              'flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors',
              activeTab === tab.id
                ? 'text-[var(--zalt-primary)] border-b-2 border-[var(--zalt-primary)] -mb-[2px]'
                : 'text-[var(--zalt-muted-foreground)] hover:text-[var(--zalt-foreground)]',
              appearance?.elements?.navbarButton
            )}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className={appearance?.elements?.page}>
        {activeTab === 'profile' && (
          <ProfileSection user={user} onUpdate={onUpdateProfile} appearance={appearance} />
        )}
        {activeTab === 'security' && (
          <SecuritySection
            user={user}
            onUpdatePassword={onUpdatePassword}
            onSetupMFA={onSetupMFA}
            onDisableMFA={onDisableMFA}
            onDeleteAccount={onDeleteAccount}
            appearance={appearance}
          />
        )}
        {activeTab === 'sessions' && (
          <SessionsSection
            sessions={sessions}
            onRevoke={onRevokeSession}
            onRevokeAll={onRevokeAllSessions}
            appearance={appearance}
          />
        )}
      </div>
    </div>
  );
}

// Profile Section
function ProfileSection({
  user,
  onUpdate,
  appearance,
}: {
  user: UserProfileUser;
  onUpdate?: (data: { firstName?: string; lastName?: string }) => Promise<void>;
  appearance?: UserProfileAppearance;
}) {
  const [firstName, setFirstName] = useState(user.firstName || '');
  const [lastName, setLastName] = useState(user.lastName || '');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onUpdate) return;

    setLoading(true);
    setSuccess(false);
    try {
      await onUpdate({ firstName, lastName });
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className={appearance?.elements?.card}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <User className="h-5 w-5" />
          Profile Information
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Avatar */}
          <div className="flex items-center gap-4">
            <Avatar
              src={user.imageUrl}
              alt={user.firstName || user.email}
              fallback={user.firstName?.[0] || user.email[0]}
              size="xl"
            />
            <div>
              <p className="font-medium">{user.firstName} {user.lastName}</p>
              <p className="text-sm text-[var(--zalt-muted-foreground)]">{user.email}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Input
              label="First name"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              disabled={loading}
            />
            <Input
              label="Last name"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              disabled={loading}
            />
          </div>

          <Input
            label="Email"
            value={user.email}
            disabled
            hint={user.emailVerified ? '✓ Verified' : 'Not verified'}
          />

          <div className="flex items-center gap-4">
            <Button type="submit" loading={loading}>
              Save changes
            </Button>
            {success && (
              <span className="text-sm text-[var(--zalt-success)]">
                Profile updated successfully
              </span>
            )}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

// Security Section
function SecuritySection({
  user,
  onUpdatePassword,
  onSetupMFA,
  onDisableMFA,
  onDeleteAccount,
  appearance,
}: {
  user: UserProfileUser;
  onUpdatePassword?: (currentPassword: string, newPassword: string) => Promise<void>;
  onSetupMFA?: () => void;
  onDisableMFA?: () => Promise<void>;
  onDeleteAccount?: () => Promise<void>;
  appearance?: UserProfileAppearance;
}) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [mfaLoading, setMfaLoading] = useState(false);

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onUpdatePassword) return;

    if (newPassword !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return;
    }

    setPasswordLoading(true);
    setPasswordError(null);
    try {
      await onUpdatePassword(currentPassword, newPassword);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setPasswordError(err instanceof Error ? err.message : 'Failed to update password');
    } finally {
      setPasswordLoading(false);
    }
  };

  const handleMFAToggle = async () => {
    if (user.mfaEnabled && onDisableMFA) {
      setMfaLoading(true);
      try {
        await onDisableMFA();
      } finally {
        setMfaLoading(false);
      }
    } else if (onSetupMFA) {
      onSetupMFA();
    }
  };

  return (
    <div className="space-y-6">
      {/* Password */}
      <Card className={appearance?.elements?.card}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Change Password
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handlePasswordChange} className="space-y-4">
            <Input
              type="password"
              label="Current password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
              disabled={passwordLoading}
            />
            <Input
              type="password"
              label="New password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              disabled={passwordLoading}
            />
            <Input
              type="password"
              label="Confirm new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              error={passwordError || undefined}
              disabled={passwordLoading}
            />
            <Button type="submit" loading={passwordLoading}>
              Update password
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* MFA */}
      <Card className={appearance?.elements?.card}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="h-5 w-5" />
            Two-Factor Authentication
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">
                {user.mfaEnabled ? 'Enabled' : 'Disabled'}
              </p>
              <p className="text-sm text-[var(--zalt-muted-foreground)]">
                {user.mfaEnabled
                  ? `Using ${user.mfaMethods?.join(', ') || 'authenticator app'}`
                  : 'Add an extra layer of security to your account'}
              </p>
            </div>
            <Button
              variant={user.mfaEnabled ? 'destructive' : 'default'}
              onClick={handleMFAToggle}
              loading={mfaLoading}
            >
              {user.mfaEnabled ? 'Disable' : 'Enable'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Delete Account */}
      {onDeleteAccount && (
        <Card className={cn('border-[var(--zalt-error)]/50', appearance?.elements?.card)}>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-[var(--zalt-error)]">
              <Trash2 className="h-5 w-5" />
              Delete Account
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-[var(--zalt-muted-foreground)] mb-4">
              Permanently delete your account and all associated data. This action cannot be undone.
            </p>
            <Button variant="destructive" onClick={onDeleteAccount}>
              Delete my account
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// Sessions Section
function SessionsSection({
  sessions,
  onRevoke,
  onRevokeAll,
  appearance,
}: {
  sessions: Session[];
  onRevoke?: (sessionId: string) => Promise<void>;
  onRevokeAll?: () => Promise<void>;
  appearance?: UserProfileAppearance;
}) {
  const [revoking, setRevoking] = useState<string | null>(null);

  const handleRevoke = async (sessionId: string) => {
    if (!onRevoke) return;
    setRevoking(sessionId);
    try {
      await onRevoke(sessionId);
    } finally {
      setRevoking(null);
    }
  };

  return (
    <Card className={appearance?.elements?.card}>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <Monitor className="h-5 w-5" />
          Active Sessions
        </CardTitle>
        {onRevokeAll && sessions.length > 1 && (
          <Button variant="outline" size="sm" onClick={onRevokeAll}>
            Sign out all devices
          </Button>
        )}
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {sessions.map((session) => (
            <div
              key={session.id}
              className="flex items-center justify-between p-4 rounded-lg border border-[var(--zalt-border)]"
            >
              <div className="flex items-center gap-4">
                <Monitor className="h-8 w-8 text-[var(--zalt-muted-foreground)]" />
                <div>
                  <p className="font-medium">
                    {session.deviceName}
                    {session.isCurrent && (
                      <span className="ml-2 text-xs bg-[var(--zalt-primary)]/10 text-[var(--zalt-primary)] px-2 py-0.5 rounded">
                        Current
                      </span>
                    )}
                  </p>
                  <p className="text-sm text-[var(--zalt-muted-foreground)]">
                    {session.browser} • {session.location || 'Unknown location'}
                  </p>
                  <p className="text-xs text-[var(--zalt-muted-foreground)]">
                    Last active: {session.lastActive}
                  </p>
                </div>
              </div>
              {!session.isCurrent && onRevoke && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => handleRevoke(session.id)}
                  loading={revoking === session.id}
                >
                  Revoke
                </Button>
              )}
            </div>
          ))}
          {sessions.length === 0 && (
            <p className="text-center text-[var(--zalt-muted-foreground)] py-8">
              No active sessions
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
