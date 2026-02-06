'use client';

import { useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../../primitives/Card';
import { Button } from '../../primitives/Button';
import { Input } from '../../primitives/Input';
import { cn } from '../../utils/cn';
import { Smartphone, Shield, Key, Check, Copy } from 'lucide-react';

type MFAMethod = 'totp' | 'webauthn';
type SetupStep = 'choose' | 'setup' | 'verify' | 'backup' | 'complete';

export interface MFASetupProps {
  /** Available MFA methods */
  methods?: MFAMethod[];
  /** Callback when setup is complete */
  onComplete?: () => void;
  /** Callback to cancel setup */
  onCancel?: () => void;
  /** Custom appearance */
  appearance?: {
    elements?: {
      card?: string;
    };
  };
  /** TOTP setup handler - returns QR code URL and secret */
  setupTOTPHandler?: () => Promise<{ qrCodeUrl: string; secret: string }>;
  /** TOTP verify handler */
  verifyTOTPHandler?: (code: string) => Promise<{ success: boolean; backupCodes?: string[] }>;
  /** WebAuthn setup handler */
  setupWebAuthnHandler?: () => Promise<{ success: boolean; backupCodes?: string[] }>;
}

export function MFASetup({
  methods = ['totp', 'webauthn'],
  onComplete,
  onCancel,
  appearance,
  setupTOTPHandler,
  verifyTOTPHandler,
  setupWebAuthnHandler,
}: MFASetupProps) {
  const [step, setStep] = useState<SetupStep>('choose');
  const [selectedMethod, setSelectedMethod] = useState<MFAMethod | null>(null);
  const [totpData, setTotpData] = useState<{ qrCodeUrl: string; secret: string } | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedBackup, setCopiedBackup] = useState(false);

  const handleMethodSelect = useCallback(async (method: MFAMethod) => {
    setSelectedMethod(method);
    setError(null);
    setLoading(true);

    try {
      if (method === 'totp' && setupTOTPHandler) {
        const data = await setupTOTPHandler();
        setTotpData(data);
        setStep('setup');
      } else if (method === 'webauthn' && setupWebAuthnHandler) {
        const result = await setupWebAuthnHandler();
        if (result.success) {
          setBackupCodes(result.backupCodes || []);
          setStep('backup');
        } else {
          setError('WebAuthn setup failed');
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed');
    } finally {
      setLoading(false);
    }
  }, [setupTOTPHandler, setupWebAuthnHandler]);

  const handleVerifyTOTP = useCallback(async () => {
    if (!verifyTOTPHandler) return;

    setLoading(true);
    setError(null);

    try {
      const result = await verifyTOTPHandler(verificationCode);
      if (result.success) {
        setBackupCodes(result.backupCodes || []);
        setStep('backup');
      } else {
        setError('Invalid verification code');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  }, [verificationCode, verifyTOTPHandler]);

  const copyToClipboard = async (text: string, type: 'secret' | 'backup') => {
    await navigator.clipboard.writeText(text);
    if (type === 'secret') {
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    } else {
      setCopiedBackup(true);
      setTimeout(() => setCopiedBackup(false), 2000);
    }
  };

  // Step 1: Choose method
  if (step === 'choose') {
    return (
      <Card className={cn('w-full max-w-md mx-auto', appearance?.elements?.card)}>
        <CardHeader className="text-center">
          <CardTitle>Set up two-factor authentication</CardTitle>
          <CardDescription>
            Choose a method to add an extra layer of security
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {methods.includes('totp') && (
            <button
              onClick={() => handleMethodSelect('totp')}
              disabled={loading}
              className="w-full flex items-center gap-4 p-4 rounded-lg border border-[var(--zalt-border)] hover:border-[var(--zalt-primary)] hover:bg-[var(--zalt-muted)] transition-colors text-left"
            >
              <div className="p-2 rounded-full bg-[var(--zalt-primary)]/10 text-[var(--zalt-primary)]">
                <Smartphone className="h-6 w-6" />
              </div>
              <div>
                <p className="font-medium">Authenticator App</p>
                <p className="text-sm text-[var(--zalt-muted-foreground)]">
                  Use Google Authenticator, Authy, or similar
                </p>
              </div>
            </button>
          )}

          {methods.includes('webauthn') && (
            <button
              onClick={() => handleMethodSelect('webauthn')}
              disabled={loading}
              className="w-full flex items-center gap-4 p-4 rounded-lg border border-[var(--zalt-border)] hover:border-[var(--zalt-primary)] hover:bg-[var(--zalt-muted)] transition-colors text-left"
            >
              <div className="p-2 rounded-full bg-[var(--zalt-success)]/10 text-[var(--zalt-success)]">
                <Shield className="h-6 w-6" />
              </div>
              <div>
                <p className="font-medium">Security Key / Passkey</p>
                <p className="text-sm text-[var(--zalt-muted-foreground)]">
                  Use biometrics or a hardware security key
                </p>
                <span className="text-xs text-[var(--zalt-success)]">Recommended</span>
              </div>
            </button>
          )}

          {error && (
            <p className="text-sm text-[var(--zalt-error)] text-center">{error}</p>
          )}
        </CardContent>
        {onCancel && (
          <CardFooter className="justify-center">
            <Button variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          </CardFooter>
        )}
      </Card>
    );
  }

  // Step 2: TOTP Setup
  if (step === 'setup' && selectedMethod === 'totp' && totpData) {
    return (
      <Card className={cn('w-full max-w-md mx-auto', appearance?.elements?.card)}>
        <CardHeader className="text-center">
          <CardTitle>Scan QR Code</CardTitle>
          <CardDescription>
            Scan this QR code with your authenticator app
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* QR Code */}
          <div className="flex justify-center">
            <div className="p-4 bg-white rounded-lg">
              <img
                src={totpData.qrCodeUrl}
                alt="QR Code for authenticator app"
                className="w-48 h-48"
              />
            </div>
          </div>

          {/* Manual entry */}
          <div className="text-center">
            <p className="text-sm text-[var(--zalt-muted-foreground)] mb-2">
              Or enter this code manually:
            </p>
            <div className="flex items-center justify-center gap-2">
              <code className="px-3 py-2 bg-[var(--zalt-muted)] rounded text-sm font-mono">
                {totpData.secret}
              </code>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => copyToClipboard(totpData.secret, 'secret')}
              >
                {copiedSecret ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
          </div>

          {/* Verification */}
          <div className="pt-4">
            <Input
              label="Enter verification code"
              placeholder="000000"
              value={verificationCode}
              onChange={(e) => setVerificationCode(e.target.value)}
              maxLength={6}
              className="text-center text-2xl tracking-widest"
              error={error || undefined}
            />
          </div>

          <Button
            className="w-full"
            onClick={handleVerifyTOTP}
            loading={loading}
            disabled={verificationCode.length !== 6}
          >
            Verify and continue
          </Button>
        </CardContent>
        <CardFooter className="justify-center">
          <Button variant="ghost" onClick={() => setStep('choose')}>
            Back
          </Button>
        </CardFooter>
      </Card>
    );
  }

  // Step 3: Backup codes
  if (step === 'backup') {
    return (
      <Card className={cn('w-full max-w-md mx-auto', appearance?.elements?.card)}>
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <div className="p-3 rounded-full bg-[var(--zalt-warning)]/10 text-[var(--zalt-warning)]">
              <Key className="h-6 w-6" />
            </div>
          </div>
          <CardTitle>Save your backup codes</CardTitle>
          <CardDescription>
            Store these codes in a safe place. You can use them to access your account if you lose your device.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-2 p-4 bg-[var(--zalt-muted)] rounded-lg">
            {backupCodes.map((code, index) => (
              <code key={index} className="text-sm font-mono text-center py-1">
                {code}
              </code>
            ))}
          </div>

          <Button
            variant="outline"
            className="w-full"
            onClick={() => copyToClipboard(backupCodes.join('\n'), 'backup')}
          >
            {copiedBackup ? (
              <>
                <Check className="mr-2 h-4 w-4" />
                Copied!
              </>
            ) : (
              <>
                <Copy className="mr-2 h-4 w-4" />
                Copy all codes
              </>
            )}
          </Button>

          <p className="text-xs text-[var(--zalt-muted-foreground)] text-center">
            Each code can only be used once. Generate new codes if you run out.
          </p>

          <Button className="w-full" onClick={() => setStep('complete')}>
            I've saved my codes
          </Button>
        </CardContent>
      </Card>
    );
  }

  // Step 4: Complete
  if (step === 'complete') {
    return (
      <Card className={cn('w-full max-w-md mx-auto', appearance?.elements?.card)}>
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <div className="p-3 rounded-full bg-[var(--zalt-success)]/10 text-[var(--zalt-success)]">
              <Check className="h-8 w-8" />
            </div>
          </div>
          <CardTitle>Two-factor authentication enabled</CardTitle>
          <CardDescription>
            Your account is now more secure. You'll need to enter a code from your{' '}
            {selectedMethod === 'totp' ? 'authenticator app' : 'security key'} when signing in.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button className="w-full" onClick={onComplete}>
            Done
          </Button>
        </CardContent>
      </Card>
    );
  }

  return null;
}
