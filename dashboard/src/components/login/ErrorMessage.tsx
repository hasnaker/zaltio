'use client';

import React, { useEffect, useState } from 'react';

export interface ErrorMessageProps {
  message: string;
  onDismiss?: () => void;
  autoHide?: number; // ms
  className?: string;
}

/**
 * ErrorMessage Component
 * 
 * An error message component with shake animation for visual feedback.
 * Supports auto-hide and manual dismiss functionality.
 * 
 * Requirements: 3.5, 8.8
 */
export function ErrorMessage({
  message,
  onDismiss,
  autoHide,
  className = '',
}: ErrorMessageProps) {
  const [isShaking, setIsShaking] = useState(true);
  const [isVisible, setIsVisible] = useState(true);

  // Trigger shake animation on mount and when message changes
  useEffect(() => {
    setIsShaking(true);
    const timer = setTimeout(() => setIsShaking(false), 500);
    return () => clearTimeout(timer);
  }, [message]);

  // Auto-hide functionality
  useEffect(() => {
    if (autoHide && autoHide > 0) {
      const timer = setTimeout(() => {
        setIsVisible(false);
        onDismiss?.();
      }, autoHide);
      return () => clearTimeout(timer);
    }
  }, [autoHide, onDismiss]);

  if (!isVisible || !message) {
    return null;
  }

  const containerClasses = [
    'relative flex items-start gap-3 px-4 py-3 rounded-lg',
    'bg-nexus-error/10 border border-nexus-error/30',
    'text-nexus-error text-sm',
    isShaking ? 'animate-shake' : '',
    className,
  ].filter(Boolean).join(' ');

  return (
    <div
      className={containerClasses}
      role="alert"
      aria-live="assertive"
      data-testid="error-message"
      data-shaking={isShaking}
    >
      {/* Error Icon */}
      <svg
        className="w-5 h-5 flex-shrink-0 mt-0.5"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
        />
      </svg>

      {/* Error Message */}
      <span className="flex-1">{message}</span>

      {/* Dismiss Button */}
      {onDismiss && (
        <button
          type="button"
          onClick={() => {
            setIsVisible(false);
            onDismiss();
          }}
          className="flex-shrink-0 p-1 rounded hover:bg-nexus-error/20 transition-colors duration-200"
          aria-label="Dismiss error"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      )}
    </div>
  );
}

export default ErrorMessage;
