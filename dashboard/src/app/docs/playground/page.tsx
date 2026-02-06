'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Play, Copy, CheckCircle, ChevronDown, Lock, 
  User, Key, Shield, RefreshCw, AlertTriangle
} from 'lucide-react';

type Endpoint = {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  name: string;
  description: string;
  body?: Record<string, unknown>;
  headers?: Record<string, string>;
  requiresAuth: boolean;
};

const endpoints: Endpoint[] = [
  {
    method: 'POST',
    path: '/auth/register',
    name: 'Register',
    description: 'Create a new user account',
    body: { email: 'user@example.com', password: 'SecurePass123!' },
    requiresAuth: false,
  },
  {
    method: 'POST',
    path: '/auth/login',
    name: 'Login',
    description: 'Authenticate and get tokens',
    body: { email: 'user@example.com', password: 'SecurePass123!' },
    requiresAuth: false,
  },
  {
    method: 'POST',
    path: '/auth/refresh',
    name: 'Refresh Token',
    description: 'Get new access token using refresh token',
    body: { refreshToken: 'your-refresh-token' },
    requiresAuth: false,
  },
  {
    method: 'GET',
    path: '/auth/me',
    name: 'Get Current User',
    description: 'Get authenticated user profile',
    requiresAuth: true,
  },
  {
    method: 'POST',
    path: '/auth/logout',
    name: 'Logout',
    description: 'Invalidate current session',
    requiresAuth: true,
  },
  {
    method: 'POST',
    path: '/mfa/totp/setup',
    name: 'Setup TOTP',
    description: 'Initialize TOTP MFA setup',
    requiresAuth: true,
  },
  {
    method: 'POST',
    path: '/mfa/totp/verify',
    name: 'Verify TOTP',
    description: 'Verify TOTP code',
    body: { code: '123456' },
    requiresAuth: true,
  },
  {
    method: 'GET',
    path: '/sessions',
    name: 'List Sessions',
    description: 'Get all active sessions',
    requiresAuth: true,
  },
  {
    method: 'DELETE',
    path: '/sessions/:sessionId',
    name: 'Revoke Session',
    description: 'Terminate a specific session',
    requiresAuth: true,
  },
];

const methodColors = {
  GET: 'bg-emerald-500/20 text-emerald-400',
  POST: 'bg-blue-500/20 text-blue-400',
  PUT: 'bg-amber-500/20 text-amber-400',
  DELETE: 'bg-red-500/20 text-red-400',
};

export default function PlaygroundPage() {
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint>(endpoints[1]);
  const [accessToken, setAccessToken] = useState('');
  const [requestBody, setRequestBody] = useState(
    selectedEndpoint.body ? JSON.stringify(selectedEndpoint.body, null, 2) : ''
  );
  const [response, setResponse] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleEndpointChange = (endpoint: Endpoint) => {
    setSelectedEndpoint(endpoint);
    setRequestBody(endpoint.body ? JSON.stringify(endpoint.body, null, 2) : '');
    setResponse(null);
  };

  const executeRequest = async () => {
    setLoading(true);
    setResponse(null);

    // Simulate API call (in production, this would call the real API)
    await new Promise(resolve => setTimeout(resolve, 800));

    // Mock responses
    const mockResponses: Record<string, unknown> = {
      '/auth/register': {
        success: true,
        user: {
          id: 'user_abc123',
          email: 'user@example.com',
          createdAt: new Date().toISOString(),
        },
        message: 'Verification email sent',
      },
      '/auth/login': {
        accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
        refreshToken: 'rt_abc123xyz...',
        expiresIn: 900,
        user: {
          id: 'user_abc123',
          email: 'user@example.com',
          mfaEnabled: false,
        },
      },
      '/auth/me': {
        id: 'user_abc123',
        email: 'user@example.com',
        emailVerified: true,
        mfaEnabled: true,
        mfaMethods: ['totp'],
        createdAt: '2026-01-15T10:00:00Z',
        lastLoginAt: new Date().toISOString(),
      },
      '/mfa/totp/setup': {
        secret: 'JBSWY3DPEHPK3PXP',
        qrCode: 'data:image/png;base64,iVBORw0KGgo...',
        backupCodes: ['abc123', 'def456', 'ghi789', 'jkl012'],
      },
      '/sessions': {
        sessions: [
          {
            id: 'sess_abc123',
            device: 'Chrome on macOS',
            ip: '192.168.1.xxx',
            location: 'Istanbul, Turkey',
            createdAt: '2026-02-03T10:00:00Z',
            current: true,
          },
        ],
      },
    };

    const mockResponse = mockResponses[selectedEndpoint.path] || { success: true };
    setResponse(JSON.stringify(mockResponse, null, 2));
    setLoading(false);
  };

  const copyResponse = () => {
    if (response) {
      navigator.clipboard.writeText(response);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const curlCommand = `curl -X ${selectedEndpoint.method} \\
  'https://api.zalt.io${selectedEndpoint.path}' \\
  -H 'Content-Type: application/json' \\${selectedEndpoint.requiresAuth ? `
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \\` : ''}${selectedEndpoint.body ? `
  -d '${JSON.stringify(selectedEndpoint.body)}'` : ''}`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-mono mb-4">
          <Play size={14} />
          API PLAYGROUND
        </div>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">
          Interactive API Explorer
        </h1>
        <p className="text-neutral-400 max-w-2xl">
          Test Zalt API endpoints directly from your browser. This playground uses mock 
          responses for demonstration purposes.
        </p>
      </motion.div>

      {/* Warning */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4 flex items-start gap-3"
      >
        <AlertTriangle size={20} className="text-amber-500 mt-0.5" />
        <div>
          <p className="text-amber-400 font-medium">Sandbox Environment</p>
          <p className="text-amber-400/70 text-sm mt-1">
            This playground uses mock data. For real API testing, use your dashboard API keys.
          </p>
        </div>
      </motion.div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Request Panel */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-4"
        >
          {/* Endpoint Selector */}
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
            <label className="block text-sm text-neutral-400 mb-2">Endpoint</label>
            <div className="relative">
              <select
                value={selectedEndpoint.path}
                onChange={(e) => {
                  const ep = endpoints.find(ep => ep.path === e.target.value);
                  if (ep) handleEndpointChange(ep);
                }}
                className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white appearance-none cursor-pointer focus:border-emerald-500 focus:outline-none"
              >
                {endpoints.map((ep) => (
                  <option key={ep.path} value={ep.path}>
                    {ep.method} {ep.path} - {ep.name}
                  </option>
                ))}
              </select>
              <ChevronDown size={16} className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-500 pointer-events-none" />
            </div>
            <p className="text-sm text-neutral-500 mt-2">{selectedEndpoint.description}</p>
          </div>

          {/* Auth Token */}
          {selectedEndpoint.requiresAuth && (
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
              <label className="block text-sm text-neutral-400 mb-2 flex items-center gap-2">
                <Lock size={14} />
                Access Token (Required)
              </label>
              <input
                type="text"
                value={accessToken}
                onChange={(e) => setAccessToken(e.target.value)}
                placeholder="eyJhbGciOiJSUzI1NiIs..."
                className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white font-mono text-sm focus:border-emerald-500 focus:outline-none"
              />
            </div>
          )}

          {/* Request Body */}
          {selectedEndpoint.body && (
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
              <label className="block text-sm text-neutral-400 mb-2">Request Body</label>
              <textarea
                value={requestBody}
                onChange={(e) => setRequestBody(e.target.value)}
                rows={6}
                className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white font-mono text-sm focus:border-emerald-500 focus:outline-none resize-none"
              />
            </div>
          )}

          {/* Execute Button */}
          <button
            onClick={executeRequest}
            disabled={loading || (selectedEndpoint.requiresAuth && !accessToken)}
            className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-emerald-500 text-neutral-950 rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <RefreshCw size={18} className="animate-spin" />
            ) : (
              <Play size={18} />
            )}
            {loading ? 'Executing...' : 'Send Request'}
          </button>

          {/* cURL */}
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
            <div className="px-4 py-2 border-b border-emerald-500/10 bg-neutral-800/50 flex items-center justify-between">
              <span className="text-xs text-neutral-500 font-mono">cURL</span>
              <button
                onClick={() => navigator.clipboard.writeText(curlCommand)}
                className="text-neutral-500 hover:text-white"
              >
                <Copy size={12} />
              </button>
            </div>
            <pre className="p-4 text-xs text-neutral-400 font-mono overflow-x-auto">{curlCommand}</pre>
          </div>
        </motion.div>

        {/* Response Panel */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden h-full">
            <div className="px-4 py-3 border-b border-emerald-500/10 bg-neutral-800/50 flex items-center justify-between">
              <span className="text-sm text-white font-medium">Response</span>
              {response && (
                <button
                  onClick={copyResponse}
                  className="flex items-center gap-1 text-neutral-500 hover:text-white text-xs"
                >
                  {copied ? <CheckCircle size={12} className="text-emerald-400" /> : <Copy size={12} />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              )}
            </div>
            <div className="p-4 min-h-[400px]">
              {response ? (
                <pre className="text-sm text-emerald-400 font-mono whitespace-pre-wrap">{response}</pre>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-neutral-500">
                  <Play size={48} className="mb-4 opacity-20" />
                  <p>Click "Send Request" to see the response</p>
                </div>
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
