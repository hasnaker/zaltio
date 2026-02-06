'use client';

import { useState, useEffect } from 'react';
import { useZaltClient } from '@zalt/react';
import Link from 'next/link';

interface Passkey {
  id: string;
  name: string;
  createdAt: string;
  lastUsed?: string;
}

export default function PasskeysPage() {
  const client = useZaltClient();
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [isSupported, setIsSupported] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [newPasskeyName, setNewPasskeyName] = useState('');

  useEffect(() => {
    checkSupport();
    loadPasskeys();
  }, []);

  const checkSupport = async () => {
    const supported = await client.webauthn.isSupported();
    setIsSupported(supported);
  };

  const loadPasskeys = async () => {
    try {
      const credentials = await client.webauthn.listCredentials();
      setPasskeys(credentials);
    } catch (err) {
      console.error('Failed to load passkeys');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async () => {
    if (!newPasskeyName.trim()) {
      setError('Please enter a name for your passkey');
      return;
    }

    setError('');
    setIsLoading(true);

    try {
      await client.webauthn.register({ name: newPasskeyName });
      setNewPasskeyName('');
      await loadPasskeys();
    } catch (err: any) {
      setError(err.message || 'Failed to register passkey');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRemove = async (id: string) => {
    if (!confirm('Are you sure you want to remove this passkey?')) return;

    try {
      await client.webauthn.removeCredential(id);
      await loadPasskeys();
    } catch (err) {
      setError('Failed to remove passkey');
    }
  };

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-2xl mx-auto">
        <Link href="/dashboard" className="text-indigo-600 hover:underline mb-4 inline-block">
          ← Back to Dashboard
        </Link>
        
        <h1 className="text-3xl font-bold mb-2">Passkeys (WebAuthn)</h1>
        <p className="text-gray-600 mb-8">
          Sign in with your fingerprint, face, or security key. Passkeys are phishing-proof and more secure than passwords.
        </p>

        {error && (
          <div className="p-3 bg-red-100 text-red-700 rounded-lg mb-4">
            {error}
          </div>
        )}

        {!isSupported ? (
          <div className="p-6 bg-yellow-50 border border-yellow-200 rounded-xl">
            <h2 className="font-semibold text-yellow-800 mb-2">Browser Not Supported</h2>
            <p className="text-yellow-700">
              Your browser doesn't support WebAuthn. Please use a modern browser like Chrome, Firefox, Safari, or Edge.
            </p>
          </div>
        ) : (
          <>
            {/* Register New Passkey */}
            <div className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow mb-6">
              <h2 className="text-xl font-semibold mb-4">Add New Passkey</h2>
              <div className="flex gap-3">
                <input
                  type="text"
                  value={newPasskeyName}
                  onChange={(e) => setNewPasskeyName(e.target.value)}
                  placeholder="e.g., MacBook Pro, iPhone"
                  className="flex-1 px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500"
                />
                <button
                  onClick={handleRegister}
                  disabled={isLoading}
                  className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50"
                >
                  {isLoading ? 'Adding...' : 'Add Passkey'}
                </button>
              </div>
            </div>

            {/* Passkey List */}
            <div className="p-6 bg-white dark:bg-gray-800 rounded-xl shadow">
              <h2 className="text-xl font-semibold mb-4">Your Passkeys</h2>
              
              {isLoading ? (
                <p className="text-gray-500">Loading...</p>
              ) : passkeys.length === 0 ? (
                <p className="text-gray-500">No passkeys registered yet.</p>
              ) : (
                <div className="space-y-3">
                  {passkeys.map((passkey) => (
                    <div 
                      key={passkey.id}
                      className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg"
                    >
                      <div>
                        <p className="font-medium">{passkey.name}</p>
                        <p className="text-sm text-gray-500">
                          Added {new Date(passkey.createdAt).toLocaleDateString()}
                          {passkey.lastUsed && ` • Last used ${new Date(passkey.lastUsed).toLocaleDateString()}`}
                        </p>
                      </div>
                      <button
                        onClick={() => handleRemove(passkey.id)}
                        className="text-red-600 hover:text-red-700"
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </main>
  );
}
