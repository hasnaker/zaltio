'use client';

import React, { useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../../primitives/Card';
import { Button } from '../../primitives/Button';
import { Input } from '../../primitives/Input';
import { cn } from '../../utils/cn';
import type { SignInResult, SignInAppearance } from './index';
import { Shield, Smartphone, Key } from 'lucide-react';

type MFAMethod = 'totp' | 'webauthn' | 'backup_code';

interface MFAChallengeProps {
  sessionId: string;
  methods: MFAMethod[];
  onComplete: (result: SignInResult) => void;
  onCancel: () => void;
  appearance?: SignInAppearance;
  /** Custom MFA verification handler */
  verifyHandler?: (sessionId: string, method: MFAMethod, code: string) => Promise<SignInResult>;
}

const methodConfig: Record<MFAMethod, { name: string; description: string; icon: React.ReactNode }> = {
  totp: {
    name: 'Authenticator App',
    description: 'Enter the 6-digit code from your authenticator app',
    icon: <Smartphone className="h-5 w-5" />,
  },
  webauthn: {
    name: 'Security Key',
    description: 'Use your security key or biometric authentication',
    icon: <Shield className="h-5 w-5" />,
  },
  backup_code: {
    name: 'Backup Code',
    description: 'Enter one of your backup codes',
    icon: <Key className="h-5 w-5" />,
  },
};

export function MFAChallenge({
  sessionId,
  methods,
  onComplete,
  onCancel,
  appearance,
  verifyHandler,
}: MFAChallengeProps) {
  const [selectedMethod, setSelectedMethod] = useState<MFAMethod>(methods[0]);
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (!verifyHandler) {
        throw new Error('verifyHandler is required');
      }

      const result = await verifyHandler(sessionId, selectedMethod, code);

      if (result.success) {
        onComplete(result);
      } else {
        setError(result.error || 'Invalid code');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  }, [sessionId, selectedMethod, code, verifyHandler, onComplete]);

  const handleWebAuthn = useCallback(async () => {
    setError(null);
    setLoading(true);

    try {
      if (!verifyHandler) {
        throw new Error('verifyHandler is required');
      }

      // For WebAuthn, we pass an empty code - the handler should trigger the browser API
      const result = await verifyHandler(sessionId, 'webauthn', '');

      if (result.success) {
        onComplete(result);
      } else {
        setError(result.error || 'WebAuthn verification failed');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'WebAuthn verification failed');
    } finally {
      setLoading(false);
    }
  }, [sessionId, verifyHandler, onComplete]);

  const config = methodConfig[selectedMethod];

  return (
    <Card className={cn('w-full max-w-md mx-auto', appearance?.elements?.card)}>
      <CardHeader className={cn('space-y-1 text-center', appearance?.elements?.header)}>
        <div className="flex justify-center mb-2">
          <div className="p-3 rounded-full bg-[var(--zalt-primary)]/10 text-[var(--zalt-primary)]">
            {config.icon}
          </div>
        </div>
        <CardTitle className={cn('text-2xl', appearance?.elements?.title)}>
          Two-Factor Authentication
        </CardTitle>
        <CardDescription className={appearance?.elements?.description}>
          {config.description}
        </CardDescription>
      </CardHeader>

      <CardContent className={appearance?.elements?.form}>
        {methods.length > 1 && (
          <div className="flex gap-2 mb-4">
            {methods.map((method) => (
              <Button
                key={method}
                type="button"
                variant={selectedMethod === method ? 'default' : 'outline'}
                size="sm"
                onClick={() => {
                  setSelectedMethod(method);
                  setCode('');
                  setError(null);
                }}
                className="flex-1"
              >
                {methodConfig[method].icon}
                <span className="ml-1 hidden sm:inline">{methodConfig[method].name}</span>
              </Button>
            ))}
          </div>
        )}

        {selectedMethod === 'webauthn' ? (
          <div className="space-y-4">
            <p className="text-sm text-[var(--zalt-muted-foreground)] text-center">
              Click the button below to authenticate with your security key or biometric.
            </p>
            <Button
              type="button"
              className="w-full"
              onClick={handleWebAuthn}
              loading={loading}
            >
              <Shield className="mr-2 h-4 w-4" />
              Authenticate
            </Button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              type="text"
              label={selectedMethod === 'totp' ? 'Verification Code' : 'Backup Code'}
              placeholder={selectedMethod === 'totp' ? '000000' : 'XXXX-XXXX'}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
              autoComplete="one-time-code"
              disabled={loading}
              maxLength={selectedMethod === 'totp' ? 6 : 10}
              className={cn('text-center text-2xl tracking-widest', appearance?.elements?.input)}
            />

            {error && (
              <div className="text-sm text-[var(--zalt-error)] text-center">
                {error}
              </div>
            )}

            <Button
              type="submit"
              className={cn('w-full', appearance?.elements?.button)}
              loading={loading}
            >
              Verify
            </Button>
          </form>
        )}
      </CardContent>

      <CardFooter className={cn('flex justify-center', appearance?.elements?.footer)}>
        <Button
          type="button"
          variant="ghost"
          onClick={onCancel}
          disabled={loading}
        >
          Back to sign in
        </Button>
      </CardFooter>
    </Card>
  );
}
