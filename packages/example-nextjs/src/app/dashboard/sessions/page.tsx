'use client';

import { useState, useEffect } from 'react';
import { useZaltClient } from '@zalt/react';
import Link from 'next/link';

interface Session {
  id: string;
  deviceName: string;
  browser: string;
  os: string;
  ip: string;
  lastActive: string;
  current: boolean;
}

export default function SessionsPage() {
  const client = useZaltClient();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadSessions();
  }, []);

  const loadSessions = async () => {
    try {
      // Mock data - in real app this would call client.sessions.list()
      setSessions([
        {
          id: '1',
          deviceName: 'MacBook Pro',
          browser: 'Chrome 120',
          os: 'macOS Sonoma',
          ip: '192.168.1.***',
          lastActive: new Date().toISOString(),
          current: true,
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRevokeAll = async () => {
    if (!confirm('This will sign you out from all other devices. Continue?')) return;
    
    // In real app: await client.sessions.revokeAll();
    alert('All other sessions have been revoked');
    await loadSessions();
  };

  const handleRevoke = async (sessionId: string) => {
    if (!confirm('Revoke this session?')) return;
    
    // In real app: await client.sessions.revoke(sessionId);
    setSessions(sessions.filter(s => s.id !== sessionId));
  };

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-2xl mx-auto">
        <Link href="/dashboard" className="text-indigo-600 hover:underline mb-4 inline-block">
          ← Back to Dashboard
        </Link>
        
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">Active Sessions</h1>
          <button
            onClick={handleRevokeAll}
            className="px-4 py-2 text-red-600 border border-red-600 rounded-lg hover:bg-red-50"
          >
            Sign out all other devices
          </button>
        </div>

        {isLoading ? (
          <p className="text-gray-500">Loading sessions...</p>
        ) : (
          <div className="space-y-4">
            {sessions.map((session) => (
              <div 
                key={session.id}
                className="p-4 bg-white dark:bg-gray-800 rounded-xl shadow"
              >
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{session.deviceName}</span>
                      {session.current && (
                        <span className="px-2 py-0.5 text-xs bg-green-100 text-green-700 rounded-full">
                          Current
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-gray-500">
                      {session.browser} on {session.os}
                    </p>
                    <p className="text-sm text-gray-500">
                      IP: {session.ip} • Last active: {new Date(session.lastActive).toLocaleString()}
                    </p>
                  </div>
                  {!session.current && (
                    <button
                      onClick={() => handleRevoke(session.id)}
                      className="text-red-600 hover:text-red-700"
                    >
                      Revoke
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
