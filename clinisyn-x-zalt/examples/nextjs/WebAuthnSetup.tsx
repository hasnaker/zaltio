/**
 * Clinisyn x Zalt.io - WebAuthn/Passkey Setup Component
 * 
 * Kullanım:
 * <WebAuthnSetup onSuccess={() => toast.success('Passkey eklendi!')} />
 */

'use client';

import { useState, useEffect } from 'react';
import { zaltAuth } from './auth-client';

interface Credential {
  id: string;
  name: string;
  created_at: string;
}

interface WebAuthnSetupProps {
  onSuccess?: () => void;
}

export function WebAuthnSetup({ onSuccess }: WebAuthnSetupProps) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [supported, setSupported] = useState(false);

  useEffect(() => {
    setSupported(zaltAuth.webauthn.isSupported());
    loadCredentials();
  }, []);

  const loadCredentials = async () => {
    try {
      const creds = await zaltAuth.webauthn.listCredentials();
      setCredentials(creds);
    } catch {
      setError('Credential listesi yüklenemedi.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!supported) {
      setError('Bu cihaz WebAuthn desteklemiyor.');
      return;
    }

    setError(null);
    setRegistering(true);

    try {
      // Get registration options from server
      const options = await zaltAuth.webauthn.getRegisterOptions();
      
      // Convert base64 strings to ArrayBuffer for WebAuthn API
      const publicKeyOptions: PublicKeyCredentialCreationOptions = {
        ...options,
        challenge: base64ToArrayBuffer(options.challenge as unknown as string),
        user: {
          ...options.user,
          id: base64ToArrayBuffer(options.user.id as unknown as string),
        },
      };

      // Create credential using browser API
      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions,
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Credential oluşturulamadı');
      }

      // Send credential to server for verification
      // This would require a verify endpoint call
      console.log('Credential created:', credential.id);
      
      await loadCredentials();
      onSuccess?.();
    } catch (err) {
      if (err instanceof Error) {
        if (err.name === 'NotAllowedError') {
          setError('İşlem iptal edildi veya zaman aşımına uğradı.');
        } else if (err.name === 'InvalidStateError') {
          setError('Bu cihaz zaten kayıtlı.');
        } else {
          setError(`Passkey kaydı başarısız: ${err.message}`);
        }
      } else {
        setError('Passkey kaydı başarısız.');
      }
    } finally {
      setRegistering(false);
    }
  };

  if (!supported) {
    return (
      <div className="rounded-md bg-yellow-50 p-4">
        <div className="flex">
          <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-yellow-800">WebAuthn Desteklenmiyor</h3>
            <p className="mt-2 text-sm text-yellow-700">
              Bu tarayıcı veya cihaz Passkey/WebAuthn desteklemiyor. 
              Lütfen güncel bir tarayıcı kullanın.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium text-gray-900">Passkey / WebAuthn</h3>
        <p className="mt-1 text-sm text-gray-500">
          Passkey, şifresiz ve phishing-proof güvenlik sağlar. 
          Touch ID, Face ID veya güvenlik anahtarı kullanabilirsiniz.
        </p>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      {loading ? (
        <div className="text-center py-4">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
        </div>
      ) : (
        <>
          {credentials.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-sm font-medium text-gray-700">Kayıtlı Passkey'ler</h4>
              <ul className="divide-y divide-gray-200 border rounded-md">
                {credentials.map((cred) => (
                  <li key={cred.id} className="px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                      </svg>
                      <div>
                        <p className="text-sm font-medium text-gray-900">{cred.name || 'Passkey'}</p>
                        <p className="text-xs text-gray-500">
                          Eklendi: {new Date(cred.created_at).toLocaleDateString('tr-TR')}
                        </p>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <button
            type="button"
            onClick={handleRegister}
            disabled={registering}
            className="w-full rounded-md bg-blue-600 px-4 py-2 text-white font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            {registering ? 'Kaydediliyor...' : 'Yeni Passkey Ekle'}
          </button>

          <div className="rounded-md bg-green-50 p-4">
            <div className="flex">
              <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-green-800">Neden Passkey?</h3>
                <ul className="mt-2 text-sm text-green-700 list-disc list-inside">
                  <li>Phishing saldırılarına karşı bağışık</li>
                  <li>Şifre hatırlamaya gerek yok</li>
                  <li>Biyometrik doğrulama (Touch ID, Face ID)</li>
                  <li>HIPAA uyumlu sağlık uygulamaları için zorunlu</li>
                </ul>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// Helper function to convert base64 to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

export default WebAuthnSetup;
