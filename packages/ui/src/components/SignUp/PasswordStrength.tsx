'use client';

import { useMemo } from 'react';
import { cn } from '../../utils/cn';

interface PasswordStrengthProps {
  password: string;
  className?: string;
}

interface StrengthResult {
  score: number; // 0-4
  label: string;
  color: string;
  feedback: string[];
}

function calculateStrength(password: string): StrengthResult {
  const feedback: string[] = [];
  let score = 0;

  // Length checks
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length < 8) feedback.push('Use at least 8 characters');

  // Character variety
  if (/[a-z]/.test(password)) score += 0.5;
  else feedback.push('Add lowercase letters');

  if (/[A-Z]/.test(password)) score += 0.5;
  else feedback.push('Add uppercase letters');

  if (/[0-9]/.test(password)) score += 0.5;
  else feedback.push('Add numbers');

  if (/[^a-zA-Z0-9]/.test(password)) score += 0.5;
  else feedback.push('Add special characters');

  // Common patterns (reduce score)
  if (/^[a-zA-Z]+$/.test(password)) score -= 0.5;
  if (/^[0-9]+$/.test(password)) score -= 1;
  if (/(.)\1{2,}/.test(password)) {
    score -= 0.5;
    feedback.push('Avoid repeated characters');
  }
  if (/^(123|abc|qwerty|password)/i.test(password)) {
    score -= 1;
    feedback.push('Avoid common patterns');
  }

  // Normalize score to 0-4
  score = Math.max(0, Math.min(4, Math.round(score)));

  const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
  const colors = [
    'bg-[var(--zalt-error)]',
    'bg-orange-500',
    'bg-yellow-500',
    'bg-[var(--zalt-success)]/70',
    'bg-[var(--zalt-success)]',
  ];

  return {
    score,
    label: labels[score],
    color: colors[score],
    feedback: feedback.slice(0, 2), // Show max 2 suggestions
  };
}

export function PasswordStrength({ password, className }: PasswordStrengthProps) {
  const strength = useMemo(() => calculateStrength(password), [password]);

  return (
    <div className={cn('mt-2 space-y-2', className)}>
      {/* Strength bars */}
      <div className="flex gap-1">
        {[0, 1, 2, 3].map((index) => (
          <div
            key={index}
            className={cn(
              'h-1 flex-1 rounded-full transition-colors',
              index <= strength.score ? strength.color : 'bg-[var(--zalt-muted)]'
            )}
          />
        ))}
      </div>

      {/* Label and feedback */}
      <div className="flex items-center justify-between text-xs">
        <span className={cn(
          'font-medium',
          strength.score <= 1 ? 'text-[var(--zalt-error)]' :
          strength.score === 2 ? 'text-yellow-600' :
          'text-[var(--zalt-success)]'
        )}>
          {strength.label}
        </span>
        {strength.feedback.length > 0 && (
          <span className="text-[var(--zalt-muted-foreground)]">
            {strength.feedback[0]}
          </span>
        )}
      </div>
    </div>
  );
}
