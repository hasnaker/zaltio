'use client';

import React, { useEffect, useRef } from 'react';
import { Notification } from '@/types/notifications';

export interface NotificationPanelProps {
  isOpen: boolean;
  onClose: () => void;
  notifications: Notification[];
  onMarkAsRead: (id: string) => void;
  onMarkAllAsRead: () => void;
}

/**
 * NotificationPanel Component
 * 
 * A slide-in panel from the right with notification list
 * and mark as read functionality.
 * 
 * Requirements: 4.7, 8.6
 */
export function NotificationPanel({
  isOpen,
  onClose,
  notifications,
  onMarkAsRead,
  onMarkAllAsRead,
}: NotificationPanelProps) {
  const panelRef = useRef<HTMLDivElement>(null);

  // Close panel when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(event.target as Node)) {
        onClose();
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen, onClose]);

  // Close panel on Escape key
  useEffect(() => {
    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        onClose();
      }
    }

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
    }

    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  const unreadCount = notifications.filter(n => !n.read).length;

  const getSeverityStyles = (severity: Notification['severity']) => {
    switch (severity) {
      case 'critical':
        return {
          bg: 'bg-nexus-error/20',
          border: 'border-nexus-error/50',
          icon: '🚨',
          iconColor: 'text-nexus-error',
        };
      case 'error':
        return {
          bg: 'bg-nexus-error/10',
          border: 'border-nexus-error/30',
          icon: '❌',
          iconColor: 'text-nexus-error',
        };
      case 'warning':
        return {
          bg: 'bg-nexus-warning/10',
          border: 'border-nexus-warning/30',
          icon: '⚠️',
          iconColor: 'text-nexus-warning',
        };
      default:
        return {
          bg: 'bg-nexus-glow-blue/10',
          border: 'border-nexus-glow-blue/30',
          icon: 'ℹ️',
          iconColor: 'text-nexus-glow-blue',
        };
    }
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className={`
          fixed inset-0 bg-black/50 backdrop-blur-sm z-40
          transition-opacity duration-300
          ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'}
        `}
        aria-hidden="true"
      />

      {/* Panel */}
      <div
        ref={panelRef}
        className={`
          fixed top-0 right-0 h-full w-96 max-w-full
          bg-nexus-cosmic-deep/95
          backdrop-blur-xl
          border-l border-white/10
          shadow-elevated
          z-50
          transform transition-transform duration-300 ease-out
          ${isOpen ? 'translate-x-0' : 'translate-x-full'}
        `}
        role="dialog"
        aria-modal="true"
        aria-label="Notifications"
      >
        {/* Header */}
        <div className="
          flex items-center justify-between
          px-6 py-4
          border-b border-white/10
        ">
          <div className="flex items-center space-x-3">
            <h2 className="text-lg font-heading font-semibold text-white">
              Notifications
            </h2>
            {unreadCount > 0 && (
              <span className="
                px-2 py-0.5
                bg-nexus-glow-cyan/20
                text-nexus-glow-cyan
                text-xs font-medium
                rounded-full
              ">
                {unreadCount} new
              </span>
            )}
          </div>
          <div className="flex items-center space-x-2">
            {unreadCount > 0 && (
              <button
                onClick={onMarkAllAsRead}
                className="
                  text-sm text-nexus-glow-cyan
                  hover:text-nexus-glow-cyan/80
                  transition-colors duration-200
                "
              >
                Mark all read
              </button>
            )}
            <button
              onClick={onClose}
              className="
                p-2 rounded-lg
                text-nexus-text-muted hover:text-white
                hover:bg-white/5
                transition-all duration-200
              "
              aria-label="Close notifications"
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
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>
        </div>

        {/* Notification List */}
        <div className="overflow-y-auto h-[calc(100%-80px)]">
          {notifications.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-center px-6">
              <div className="
                w-16 h-16 rounded-full
                bg-nexus-cosmic-nebula
                flex items-center justify-center
                mb-4
              ">
                <svg
                  className="w-8 h-8 text-nexus-text-muted"
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
              </div>
              <p className="text-nexus-text-secondary font-medium">
                No notifications
              </p>
              <p className="text-nexus-text-muted text-sm mt-1">
                You're all caught up!
              </p>
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {notifications.map((notification, index) => {
                const styles = getSeverityStyles(notification.severity);
                
                return (
                  <div
                    key={notification.id}
                    className={`
                      px-6 py-4
                      cursor-pointer
                      transition-all duration-200
                      hover:bg-white/5
                      ${!notification.read ? 'bg-nexus-glow-cyan/5' : ''}
                      ${isOpen ? 'animate-slide-in-right' : ''}
                    `}
                    style={{ animationDelay: `${index * 50}ms` }}
                    onClick={() => onMarkAsRead(notification.id)}
                  >
                    <div className="flex items-start space-x-3">
                      {/* Severity Icon */}
                      <div className={`
                        w-8 h-8 rounded-lg
                        ${styles.bg}
                        border ${styles.border}
                        flex items-center justify-center
                        flex-shrink-0
                      `}>
                        <span className="text-sm">{styles.icon}</span>
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <p className={`
                            text-sm font-medium truncate
                            ${!notification.read ? 'text-white' : 'text-nexus-text-secondary'}
                          `}>
                            {notification.title}
                          </p>
                          {!notification.read && (
                            <span className="
                              w-2 h-2 rounded-full
                              bg-nexus-glow-cyan
                              flex-shrink-0 ml-2
                            " />
                          )}
                        </div>
                        <p className="text-sm text-nexus-text-muted mt-1 line-clamp-2">
                          {notification.message}
                        </p>
                        <div className="flex items-center justify-between mt-2">
                          <span className={`
                            px-2 py-0.5
                            text-xs font-medium
                            rounded
                            ${styles.bg} ${styles.iconColor}
                          `}>
                            {notification.severity}
                          </span>
                          <span className="text-xs text-nexus-text-muted">
                            {formatTimestamp(notification.timestamp)}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </>
  );
}

/**
 * Format a timestamp into a relative time string
 */
function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) {
    return 'Just now';
  } else if (diffMins < 60) {
    return `${diffMins}m ago`;
  } else if (diffHours < 24) {
    return `${diffHours}h ago`;
  } else if (diffDays < 7) {
    return `${diffDays}d ago`;
  } else {
    return date.toLocaleDateString();
  }
}

export default NotificationPanel;
