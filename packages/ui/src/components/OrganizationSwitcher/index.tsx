'use client';

import React, { useState, useRef, useEffect } from 'react';
import { Avatar } from '../../primitives/Avatar';
import { Button } from '../../primitives/Button';
import { Input } from '../../primitives/Input';
import { cn } from '../../utils/cn';
import { ChevronDown, Plus, Check, Building2 } from 'lucide-react';

export interface Organization {
  id: string;
  name: string;
  slug: string;
  imageUrl?: string | null;
  role?: string;
}

export interface OrganizationSwitcherProps {
  /** Current organization */
  currentOrganization?: Organization | null;
  /** List of organizations user belongs to */
  organizations?: Organization[];
  /** Whether to show personal account option */
  hidePersonal?: boolean;
  /** Personal account info */
  personalAccount?: {
    id: string;
    name: string;
    imageUrl?: string | null;
  };
  /** URL to redirect after creating organization */
  afterCreateOrganizationUrl?: string;
  /** URL to redirect after selecting organization */
  afterSelectOrganizationUrl?: string;
  /** Custom appearance */
  appearance?: {
    elements?: {
      organizationSwitcherTrigger?: string;
      organizationSwitcherPopover?: string;
    };
  };
  /** Handlers */
  onSelectOrganization?: (org: Organization | null) => void;
  onCreateOrganization?: (name: string) => Promise<Organization>;
}

export function OrganizationSwitcher({
  currentOrganization,
  organizations = [],
  hidePersonal = false,
  personalAccount,
  afterCreateOrganizationUrl,
  afterSelectOrganizationUrl,
  appearance,
  onSelectOrganization,
  onCreateOrganization,
}: OrganizationSwitcherProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
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
        setShowCreateForm(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelect = (org: Organization | null) => {
    setIsOpen(false);
    onSelectOrganization?.(org);
    
    if (afterSelectOrganizationUrl && org) {
      const url = afterSelectOrganizationUrl.replace(':slug', org.slug);
      window.location.href = url;
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!onCreateOrganization || !newOrgName.trim()) return;

    setCreating(true);
    setError(null);

    try {
      const newOrg = await onCreateOrganization(newOrgName.trim());
      setNewOrgName('');
      setShowCreateForm(false);
      setIsOpen(false);
      
      if (afterCreateOrganizationUrl) {
        const url = afterCreateOrganizationUrl.replace(':slug', newOrg.slug);
        window.location.href = url;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create organization');
    } finally {
      setCreating(false);
    }
  };

  const currentDisplay = currentOrganization || (personalAccount && !hidePersonal ? {
    id: personalAccount.id,
    name: personalAccount.name,
    imageUrl: personalAccount.imageUrl,
    isPersonal: true,
  } : null);

  return (
    <div className="relative">
      <button
        ref={buttonRef}
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          'flex items-center gap-2 px-3 py-2 rounded-lg border border-[var(--zalt-border)] hover:bg-[var(--zalt-muted)] transition-colors',
          appearance?.elements?.organizationSwitcherTrigger
        )}
        aria-expanded={isOpen}
        aria-haspopup="true"
      >
        {currentDisplay ? (
          <>
            <Avatar
              src={currentDisplay.imageUrl}
              alt={currentDisplay.name}
              fallback={currentDisplay.name[0]}
              size="sm"
            />
            <span className="font-medium text-sm max-w-[150px] truncate">
              {currentDisplay.name}
            </span>
          </>
        ) : (
          <>
            <Building2 className="h-5 w-5 text-[var(--zalt-muted-foreground)]" />
            <span className="text-sm text-[var(--zalt-muted-foreground)]">
              Select organization
            </span>
          </>
        )}
        <ChevronDown className="h-4 w-4 text-[var(--zalt-muted-foreground)]" />
      </button>

      {isOpen && (
        <div
          ref={menuRef}
          className={cn(
            'absolute left-0 mt-2 w-72 rounded-lg border border-[var(--zalt-border)] bg-[var(--zalt-card)] shadow-[var(--zalt-shadow-lg)] z-50',
            appearance?.elements?.organizationSwitcherPopover
          )}
        >
          {/* Personal account */}
          {!hidePersonal && personalAccount && (
            <div className="p-2 border-b border-[var(--zalt-border)]">
              <button
                onClick={() => handleSelect(null)}
                className={cn(
                  'w-full flex items-center gap-3 p-2 rounded-md hover:bg-[var(--zalt-muted)] transition-colors',
                  !currentOrganization && 'bg-[var(--zalt-muted)]'
                )}
              >
                <Avatar
                  src={personalAccount.imageUrl}
                  alt={personalAccount.name}
                  fallback={personalAccount.name[0]}
                  size="sm"
                />
                <div className="flex-1 text-left">
                  <p className="text-sm font-medium">{personalAccount.name}</p>
                  <p className="text-xs text-[var(--zalt-muted-foreground)]">Personal account</p>
                </div>
                {!currentOrganization && (
                  <Check className="h-4 w-4 text-[var(--zalt-primary)]" />
                )}
              </button>
            </div>
          )}

          {/* Organizations list */}
          {organizations.length > 0 && (
            <div className="p-2">
              <p className="px-2 py-1 text-xs font-medium text-[var(--zalt-muted-foreground)] uppercase">
                Organizations
              </p>
              {organizations.map((org) => (
                <button
                  key={org.id}
                  onClick={() => handleSelect(org)}
                  className={cn(
                    'w-full flex items-center gap-3 p-2 rounded-md hover:bg-[var(--zalt-muted)] transition-colors',
                    currentOrganization?.id === org.id && 'bg-[var(--zalt-muted)]'
                  )}
                >
                  <Avatar
                    src={org.imageUrl}
                    alt={org.name}
                    fallback={org.name[0]}
                    size="sm"
                  />
                  <div className="flex-1 text-left">
                    <p className="text-sm font-medium">{org.name}</p>
                    {org.role && (
                      <p className="text-xs text-[var(--zalt-muted-foreground)]">{org.role}</p>
                    )}
                  </div>
                  {currentOrganization?.id === org.id && (
                    <Check className="h-4 w-4 text-[var(--zalt-primary)]" />
                  )}
                </button>
              ))}
            </div>
          )}

          {/* Create organization */}
          {onCreateOrganization && (
            <div className="p-2 border-t border-[var(--zalt-border)]">
              {showCreateForm ? (
                <form onSubmit={handleCreate} className="space-y-2">
                  <Input
                    placeholder="Organization name"
                    value={newOrgName}
                    onChange={(e) => setNewOrgName(e.target.value)}
                    error={error || undefined}
                    autoFocus
                  />
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setShowCreateForm(false);
                        setNewOrgName('');
                        setError(null);
                      }}
                      className="flex-1"
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      size="sm"
                      loading={creating}
                      disabled={!newOrgName.trim()}
                      className="flex-1"
                    >
                      Create
                    </Button>
                  </div>
                </form>
              ) : (
                <button
                  onClick={() => setShowCreateForm(true)}
                  className="w-full flex items-center gap-3 p-2 rounded-md hover:bg-[var(--zalt-muted)] transition-colors text-[var(--zalt-primary)]"
                >
                  <Plus className="h-5 w-5" />
                  <span className="text-sm font-medium">Create organization</span>
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
