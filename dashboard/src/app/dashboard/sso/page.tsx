'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Plus, Trash2, Edit2, CheckCircle, XCircle, 
  Clock, Copy, Eye, EyeOff, AlertTriangle, ExternalLink,
  Upload, Globe, Key, Users, Settings, Play, RefreshCw,
  ChevronRight, ChevronLeft, FileText, Link2, Check,
  Building2, Mail, User, Lock, Loader2
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

type SSOType = 'saml' | 'oidc';
type SSOConfigStatus = 'active' | 'inactive' | 'pending_verification' | 'deleted';
type DomainVerificationStatus = 'pending' | 'verified' | 'failed';
type OIDCProviderPreset = 'google_workspace' | 'microsoft_entra' | 'okta' | 'auth0' | 'onelogin' | 'custom';

interface VerifiedDomain {
  domain: string;
  verificationStatus: DomainVerificationStatus;
  verificationToken?: string;
  verifiedAt?: string;
}

interface AttributeMapping {
  email?: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  groups?: string;
  department?: string;
  employeeId?: string;
}

interface SAMLConfig {
  idpMetadataXml?: string;
  idpEntityId: string;
  idpSsoUrl: string;
  idpSloUrl?: string;
  idpCertificate: string;
}


interface OIDCConfig {
  providerPreset?: OIDCProviderPreset;
  issuer: string;
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
}

interface JITProvisioningConfig {
  enabled: boolean;
  defaultRole?: string;
  autoVerifyEmail?: boolean;
  syncGroups?: boolean;
  groupRoleMapping?: Record<string, string>;
}

interface OrgSSOConfig {
  id: string;
  tenantId: string;
  realmId: string;
  ssoType: SSOType;
  enabled: boolean;
  status: SSOConfigStatus;
  providerName: string;
  samlConfig?: SAMLConfig;
  oidcConfig?: OIDCConfig;
  spEntityId: string;
  acsUrl: string;
  sloUrl?: string;
  attributeMapping?: AttributeMapping;
  domains: VerifiedDomain[];
  enforced: boolean;
  jitProvisioning: JITProvisioningConfig;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
  totalLogins?: number;
}

interface TestConnectionResult {
  success: boolean;
  message: string;
  details?: {
    idpReachable?: boolean;
    metadataValid?: boolean;
    certificateValid?: boolean;
    attributesFound?: string[];
  };
}

// ============================================================================
// Constants
// ============================================================================

const WIZARD_STEPS = [
  { id: 'type', title: 'SSO Type', description: 'Choose SAML or OIDC' },
  { id: 'provider', title: 'Provider', description: 'Configure identity provider' },
  { id: 'attributes', title: 'Attributes', description: 'Map user attributes' },
  { id: 'domains', title: 'Domains', description: 'Verify email domains' },
  { id: 'review', title: 'Review', description: 'Test and activate' }
];


const OIDC_PROVIDERS: { value: OIDCProviderPreset; label: string; icon: string; description: string }[] = [
  { value: 'google_workspace', label: 'Google Workspace', icon: '🔵', description: 'Google Workspace / G Suite' },
  { value: 'microsoft_entra', label: 'Microsoft Entra', icon: '🔷', description: 'Azure AD / Microsoft 365' },
  { value: 'okta', label: 'Okta', icon: '🟣', description: 'Okta Identity Cloud' },
  { value: 'auth0', label: 'Auth0', icon: '🔴', description: 'Auth0 by Okta' },
  { value: 'onelogin', label: 'OneLogin', icon: '🟢', description: 'OneLogin by One Identity' },
  { value: 'custom', label: 'Custom OIDC', icon: '⚙️', description: 'Any OIDC-compliant provider' }
];

const DEFAULT_ATTRIBUTE_MAPPINGS: Record<string, AttributeMapping> = {
  saml: {
    email: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    firstName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    lastName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    displayName: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    groups: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'
  },
  oidc: {
    email: 'email',
    firstName: 'given_name',
    lastName: 'family_name',
    displayName: 'name',
    groups: 'groups'
  }
};

// ============================================================================
// Mock Data (Replace with API calls)
// ============================================================================

const mockSSOConfig: OrgSSOConfig | null = null;


// ============================================================================
// Step Components
// ============================================================================

function StepIndicator({ 
  steps, 
  currentStep, 
  onStepClick 
}: { 
  steps: typeof WIZARD_STEPS;
  currentStep: number;
  onStepClick: (step: number) => void;
}) {
  return (
    <div className="flex items-center justify-between mb-8">
      {steps.map((step, index) => (
        <div key={step.id} className="flex items-center">
          <button
            onClick={() => index < currentStep && onStepClick(index)}
            disabled={index > currentStep}
            className={`flex items-center gap-2 ${index <= currentStep ? 'cursor-pointer' : 'cursor-not-allowed'}`}
          >
            <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-medium transition-colors ${
              index < currentStep 
                ? 'bg-emerald-500 text-white' 
                : index === currentStep 
                  ? 'bg-emerald-500/20 text-emerald-400 border-2 border-emerald-500' 
                  : 'bg-neutral-800 text-neutral-500'
            }`}>
              {index < currentStep ? <Check size={16} /> : index + 1}
            </div>
            <div className="hidden md:block">
              <p className={`text-sm font-medium ${index <= currentStep ? 'text-white' : 'text-neutral-500'}`}>
                {step.title}
              </p>
              <p className="text-xs text-neutral-500">{step.description}</p>
            </div>
          </button>
          {index < steps.length - 1 && (
            <div className={`w-12 lg:w-24 h-0.5 mx-2 ${index < currentStep ? 'bg-emerald-500' : 'bg-neutral-700'}`} />
          )}
        </div>
      ))}
    </div>
  );
}


function SSOTypeStep({ 
  ssoType, 
  onSelect 
}: { 
  ssoType: SSOType | null;
  onSelect: (type: SSOType) => void;
}) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white mb-2">Choose SSO Protocol</h2>
        <p className="text-neutral-400">Select the authentication protocol your identity provider supports.</p>
      </div>
      
      <div className="grid md:grid-cols-2 gap-4">
        <button
          onClick={() => onSelect('saml')}
          className={`p-6 rounded-xl border-2 text-left transition-all ${
            ssoType === 'saml'
              ? 'border-emerald-500 bg-emerald-500/10'
              : 'border-neutral-700 bg-neutral-800/50 hover:border-neutral-600'
          }`}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-blue-500/10 rounded-lg">
              <Shield className="text-blue-400" size={24} />
            </div>
            <div>
              <h3 className="text-lg font-medium text-white">SAML 2.0</h3>
              <p className="text-sm text-neutral-500">Enterprise standard</p>
            </div>
          </div>
          <p className="text-sm text-neutral-400">
            Security Assertion Markup Language. Best for enterprise IdPs like Okta, Azure AD, ADFS, PingIdentity.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {['Okta', 'Azure AD', 'ADFS', 'OneLogin'].map(provider => (
              <span key={provider} className="px-2 py-1 text-xs bg-neutral-700 text-neutral-300 rounded">
                {provider}
              </span>
            ))}
          </div>
        </button>
        
        <button
          onClick={() => onSelect('oidc')}
          className={`p-6 rounded-xl border-2 text-left transition-all ${
            ssoType === 'oidc'
              ? 'border-emerald-500 bg-emerald-500/10'
              : 'border-neutral-700 bg-neutral-800/50 hover:border-neutral-600'
          }`}
        >
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-purple-500/10 rounded-lg">
              <Key className="text-purple-400" size={24} />
            </div>
            <div>
              <h3 className="text-lg font-medium text-white">OpenID Connect</h3>
              <p className="text-sm text-neutral-500">Modern OAuth 2.0</p>
            </div>
          </div>
          <p className="text-sm text-neutral-400">
            OAuth 2.0 based authentication. Best for Google Workspace, Microsoft Entra, and modern IdPs.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {['Google', 'Microsoft', 'Okta', 'Auth0'].map(provider => (
              <span key={provider} className="px-2 py-1 text-xs bg-neutral-700 text-neutral-300 rounded">
                {provider}
              </span>
            ))}
          </div>
        </button>
      </div>
    </div>
  );
}


function SAMLProviderStep({
  config,
  onChange,
  spEntityId,
  acsUrl
}: {
  config: Partial<SAMLConfig>;
  onChange: (config: Partial<SAMLConfig>) => void;
  spEntityId: string;
  acsUrl: string;
}) {
  const [uploadMethod, setUploadMethod] = useState<'file' | 'url' | 'manual'>('file');
  const [metadataUrl, setMetadataUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [parseSuccess, setParseSuccess] = useState(false);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setParseSuccess(false);

    try {
      const text = await file.text();
      await parseMetadata(text);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to parse metadata');
    } finally {
      setLoading(false);
    }
  };

  const handleUrlFetch = async () => {
    if (!metadataUrl) return;

    setLoading(true);
    setError(null);
    setParseSuccess(false);

    try {
      // In production, this would call the backend API
      const response = await fetch(`/api/sso/fetch-metadata?url=${encodeURIComponent(metadataUrl)}`);
      if (!response.ok) throw new Error('Failed to fetch metadata');
      const data = await response.json();
      await parseMetadata(data.metadata);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch metadata');
    } finally {
      setLoading(false);
    }
  };

  const parseMetadata = async (xml: string) => {
    // Simple XML parsing - in production use proper XML parser
    const entityIdMatch = xml.match(/entityID="([^"]+)"/);
    const ssoUrlMatch = xml.match(/SingleSignOnService[^>]*Location="([^"]+)"/);
    const certMatch = xml.match(/<(?:ds:)?X509Certificate>([^<]+)<\/(?:ds:)?X509Certificate>/);

    if (!entityIdMatch || !ssoUrlMatch || !certMatch) {
      throw new Error('Invalid IdP metadata: missing required fields');
    }

    onChange({
      idpMetadataXml: xml,
      idpEntityId: entityIdMatch[1],
      idpSsoUrl: ssoUrlMatch[1],
      idpCertificate: `-----BEGIN CERTIFICATE-----\n${certMatch[1].trim()}\n-----END CERTIFICATE-----`
    });
    setParseSuccess(true);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white mb-2">Configure SAML Provider</h2>
        <p className="text-neutral-400">Upload your IdP metadata or enter configuration manually.</p>
      </div>

      {/* SP Configuration Info */}
      <div className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700">
        <h3 className="text-sm font-medium text-white mb-3 flex items-center gap-2">
          <FileText size={16} className="text-emerald-400" />
          Service Provider Configuration (for your IdP)
        </h3>
        <div className="grid md:grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-neutral-500 mb-1">Entity ID / Issuer</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 px-3 py-1.5 bg-neutral-900 rounded text-neutral-300 font-mono text-xs truncate">
                {spEntityId}
              </code>
              <button 
                onClick={() => navigator.clipboard.writeText(spEntityId)}
                className="p-1.5 text-neutral-500 hover:text-white"
              >
                <Copy size={14} />
              </button>
            </div>
          </div>
          <div>
            <p className="text-neutral-500 mb-1">ACS URL</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 px-3 py-1.5 bg-neutral-900 rounded text-neutral-300 font-mono text-xs truncate">
                {acsUrl}
              </code>
              <button 
                onClick={() => navigator.clipboard.writeText(acsUrl)}
                className="p-1.5 text-neutral-500 hover:text-white"
              >
                <Copy size={14} />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Upload Method Selection */}
      <div className="flex gap-2">
        {[
          { id: 'file', label: 'Upload XML', icon: Upload },
          { id: 'url', label: 'Metadata URL', icon: Link2 },
          { id: 'manual', label: 'Manual Entry', icon: Settings }
        ].map(method => (
          <button
            key={method.id}
            onClick={() => setUploadMethod(method.id as 'file' | 'url' | 'manual')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
              uploadMethod === method.id
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'bg-neutral-800 text-neutral-400 hover:text-white'
            }`}
          >
            <method.icon size={16} />
            {method.label}
          </button>
        ))}
      </div>

      {/* File Upload */}
      {uploadMethod === 'file' && (
        <div className="border-2 border-dashed border-neutral-700 rounded-xl p-8 text-center">
          <input
            type="file"
            accept=".xml,application/xml,text/xml"
            onChange={handleFileUpload}
            className="hidden"
            id="metadata-upload"
          />
          <label htmlFor="metadata-upload" className="cursor-pointer">
            <Upload className="mx-auto text-neutral-500 mb-3" size={32} />
            <p className="text-white font-medium mb-1">Upload IdP Metadata XML</p>
            <p className="text-sm text-neutral-500">Drag and drop or click to browse</p>
          </label>
        </div>
      )}

      {/* URL Fetch */}
      {uploadMethod === 'url' && (
        <div className="space-y-3">
          <label className="block text-sm text-neutral-400">IdP Metadata URL</label>
          <div className="flex gap-2">
            <input
              type="url"
              value={metadataUrl}
              onChange={e => setMetadataUrl(e.target.value)}
              placeholder="https://idp.example.com/metadata.xml"
              className="flex-1 px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
            />
            <button
              onClick={handleUrlFetch}
              disabled={!metadataUrl || loading}
              className="px-4 py-2.5 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {loading ? <Loader2 className="animate-spin" size={16} /> : <RefreshCw size={16} />}
              Fetch
            </button>
          </div>
        </div>
      )}

      {/* Manual Entry */}
      {uploadMethod === 'manual' && (
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-neutral-400 mb-1.5">IdP Entity ID</label>
            <input
              type="text"
              value={config.idpEntityId || ''}
              onChange={e => onChange({ ...config, idpEntityId: e.target.value })}
              placeholder="http://www.okta.com/exk123..."
              className="w-full px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-sm text-neutral-400 mb-1.5">IdP SSO URL</label>
            <input
              type="url"
              value={config.idpSsoUrl || ''}
              onChange={e => onChange({ ...config, idpSsoUrl: e.target.value })}
              placeholder="https://yourcompany.okta.com/app/.../sso/saml"
              className="w-full px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-sm text-neutral-400 mb-1.5">IdP Certificate (X.509 PEM)</label>
            <textarea
              value={config.idpCertificate || ''}
              onChange={e => onChange({ ...config, idpCertificate: e.target.value })}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              rows={6}
              className="w-full px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none font-mono text-sm"
            />
          </div>
        </div>
      )}

      {/* Status Messages */}
      {loading && (
        <div className="flex items-center gap-2 text-neutral-400">
          <Loader2 className="animate-spin" size={16} />
          Parsing metadata...
        </div>
      )}
      
      {error && (
        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-2 text-red-400">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}
      
      {parseSuccess && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex items-center gap-2 text-emerald-400">
          <CheckCircle size={16} />
          Metadata parsed successfully! IdP Entity ID: {config.idpEntityId}
        </div>
      )}

      {/* Parsed Configuration Preview */}
      {config.idpEntityId && (
        <div className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700">
          <h3 className="text-sm font-medium text-white mb-3">Parsed Configuration</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-neutral-500">Entity ID:</span>
              <span className="text-neutral-300 font-mono text-xs">{config.idpEntityId}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-neutral-500">SSO URL:</span>
              <span className="text-neutral-300 font-mono text-xs truncate max-w-xs">{config.idpSsoUrl}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-neutral-500">Certificate:</span>
              <span className="text-emerald-400">✓ Valid</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


function OIDCProviderStep({
  config,
  onChange
}: {
  config: Partial<OIDCConfig>;
  onChange: (config: Partial<OIDCConfig>) => void;
}) {
  const [showSecret, setShowSecret] = useState(false);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white mb-2">Configure OIDC Provider</h2>
        <p className="text-neutral-400">Select your identity provider and enter OAuth credentials.</p>
      </div>

      {/* Provider Selection */}
      <div>
        <label className="block text-sm text-neutral-400 mb-3">Identity Provider</label>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {OIDC_PROVIDERS.map(provider => (
            <button
              key={provider.value}
              onClick={() => onChange({ ...config, providerPreset: provider.value })}
              className={`p-4 rounded-xl border text-left transition-all ${
                config.providerPreset === provider.value
                  ? 'border-emerald-500 bg-emerald-500/10'
                  : 'border-neutral-700 bg-neutral-800/50 hover:border-neutral-600'
              }`}
            >
              <span className="text-2xl mb-2 block">{provider.icon}</span>
              <p className="text-sm font-medium text-white">{provider.label}</p>
              <p className="text-xs text-neutral-500">{provider.description}</p>
            </button>
          ))}
        </div>
      </div>

      {/* OAuth Credentials */}
      <div className="space-y-4">
        <div>
          <label className="block text-sm text-neutral-400 mb-1.5">
            {config.providerPreset === 'custom' ? 'Issuer URL' : 'Tenant/Domain (optional)'}
          </label>
          <input
            type="text"
            value={config.issuer || ''}
            onChange={e => onChange({ ...config, issuer: e.target.value })}
            placeholder={
              config.providerPreset === 'microsoft_entra' 
                ? 'your-tenant-id or your-domain.onmicrosoft.com'
                : config.providerPreset === 'okta'
                  ? 'your-org.okta.com'
                  : 'https://issuer.example.com'
            }
            className="w-full px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-sm text-neutral-400 mb-1.5">Client ID</label>
          <input
            type="text"
            value={config.clientId || ''}
            onChange={e => onChange({ ...config, clientId: e.target.value })}
            placeholder="your-client-id"
            className="w-full px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-sm text-neutral-400 mb-1.5">Client Secret</label>
          <div className="relative">
            <input
              type={showSecret ? 'text' : 'password'}
              value={config.clientSecret || ''}
              onChange={e => onChange({ ...config, clientSecret: e.target.value })}
              placeholder="your-client-secret"
              className="w-full px-4 py-2.5 pr-10 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowSecret(!showSecret)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-white"
            >
              {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>
      </div>

      {/* Provider-specific instructions */}
      {config.providerPreset && config.providerPreset !== 'custom' && (
        <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl">
          <h4 className="text-sm font-medium text-blue-400 mb-2">Setup Instructions</h4>
          <ProviderInstructions provider={config.providerPreset} />
        </div>
      )}
    </div>
  );
}


function ProviderInstructions({ provider }: { provider: OIDCProviderPreset }) {
  const instructions: Record<OIDCProviderPreset, React.ReactNode> = {
    google_workspace: (
      <ol className="text-sm text-neutral-300 space-y-1 list-decimal list-inside">
        <li>Go to <a href="https://console.cloud.google.com/" target="_blank" rel="noopener" className="text-blue-400 hover:underline">Google Cloud Console</a></li>
        <li>Create or select a project</li>
        <li>Go to APIs & Services → Credentials</li>
        <li>Create OAuth 2.0 Client ID (Web application)</li>
        <li>Add authorized redirect URI: <code className="text-xs bg-neutral-800 px-1 rounded">https://api.zalt.io/v1/sso/oidc/callback</code></li>
      </ol>
    ),
    microsoft_entra: (
      <ol className="text-sm text-neutral-300 space-y-1 list-decimal list-inside">
        <li>Go to <a href="https://portal.azure.com/" target="_blank" rel="noopener" className="text-blue-400 hover:underline">Azure Portal</a></li>
        <li>Navigate to Microsoft Entra ID → App registrations</li>
        <li>Create new registration</li>
        <li>Add redirect URI: <code className="text-xs bg-neutral-800 px-1 rounded">https://api.zalt.io/v1/sso/oidc/callback</code></li>
        <li>Create a client secret under Certificates & secrets</li>
      </ol>
    ),
    okta: (
      <ol className="text-sm text-neutral-300 space-y-1 list-decimal list-inside">
        <li>Go to Okta Admin Console</li>
        <li>Applications → Create App Integration</li>
        <li>Select OIDC - OpenID Connect</li>
        <li>Select Web Application</li>
        <li>Add sign-in redirect URI: <code className="text-xs bg-neutral-800 px-1 rounded">https://api.zalt.io/v1/sso/oidc/callback</code></li>
      </ol>
    ),
    auth0: (
      <ol className="text-sm text-neutral-300 space-y-1 list-decimal list-inside">
        <li>Go to <a href="https://manage.auth0.com/" target="_blank" rel="noopener" className="text-blue-400 hover:underline">Auth0 Dashboard</a></li>
        <li>Applications → Create Application</li>
        <li>Select Regular Web Application</li>
        <li>Add callback URL: <code className="text-xs bg-neutral-800 px-1 rounded">https://api.zalt.io/v1/sso/oidc/callback</code></li>
      </ol>
    ),
    onelogin: (
      <ol className="text-sm text-neutral-300 space-y-1 list-decimal list-inside">
        <li>Go to OneLogin Admin Portal</li>
        <li>Applications → Add App</li>
        <li>Search for "OpenID Connect"</li>
        <li>Configure redirect URI: <code className="text-xs bg-neutral-800 px-1 rounded">https://api.zalt.io/v1/sso/oidc/callback</code></li>
      </ol>
    ),
    custom: (
      <p className="text-sm text-neutral-300">
        Enter your OIDC provider's issuer URL. The discovery document will be fetched automatically from <code className="text-xs bg-neutral-800 px-1 rounded">.well-known/openid-configuration</code>
      </p>
    )
  };

  return instructions[provider] || null;
}


function AttributeMappingStep({
  ssoType,
  mapping,
  onChange,
  jitConfig,
  onJITChange
}: {
  ssoType: SSOType;
  mapping: AttributeMapping;
  onChange: (mapping: AttributeMapping) => void;
  jitConfig: JITProvisioningConfig;
  onJITChange: (config: JITProvisioningConfig) => void;
}) {
  const defaultMapping = DEFAULT_ATTRIBUTE_MAPPINGS[ssoType];

  const handleReset = () => {
    onChange(defaultMapping);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white mb-2">Attribute Mapping</h2>
        <p className="text-neutral-400">Map IdP attributes to Zalt user profile fields.</p>
      </div>

      {/* Attribute Mapping */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-white">User Attributes</h3>
          <button
            onClick={handleReset}
            className="text-sm text-emerald-400 hover:text-emerald-300"
          >
            Reset to defaults
          </button>
        </div>

        <div className="grid md:grid-cols-2 gap-4">
          {[
            { key: 'email', label: 'Email', required: true, icon: Mail },
            { key: 'firstName', label: 'First Name', required: false, icon: User },
            { key: 'lastName', label: 'Last Name', required: false, icon: User },
            { key: 'displayName', label: 'Display Name', required: false, icon: User },
            { key: 'groups', label: 'Groups', required: false, icon: Users },
            { key: 'department', label: 'Department', required: false, icon: Building2 }
          ].map(attr => (
            <div key={attr.key}>
              <label className="flex items-center gap-2 text-sm text-neutral-400 mb-1.5">
                <attr.icon size={14} />
                {attr.label}
                {attr.required && <span className="text-red-400">*</span>}
              </label>
              <input
                type="text"
                value={mapping[attr.key as keyof AttributeMapping] || ''}
                onChange={e => onChange({ ...mapping, [attr.key]: e.target.value })}
                placeholder={defaultMapping[attr.key as keyof AttributeMapping]}
                className="w-full px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none text-sm"
              />
            </div>
          ))}
        </div>
      </div>

      {/* JIT Provisioning */}
      <div className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-medium text-white">Just-In-Time Provisioning</h3>
            <p className="text-xs text-neutral-500">Automatically create users on first SSO login</p>
          </div>
          <button
            onClick={() => onJITChange({ ...jitConfig, enabled: !jitConfig.enabled })}
            className={`relative w-12 h-6 rounded-full transition-colors ${
              jitConfig.enabled ? 'bg-emerald-500' : 'bg-neutral-700'
            }`}
          >
            <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${
              jitConfig.enabled ? 'left-7' : 'left-1'
            }`} />
          </button>
        </div>

        {jitConfig.enabled && (
          <div className="space-y-4 pt-4 border-t border-neutral-700">
            <div>
              <label className="block text-sm text-neutral-400 mb-1.5">Default Role</label>
              <select
                value={jitConfig.defaultRole || 'member'}
                onChange={e => onJITChange({ ...jitConfig, defaultRole: e.target.value })}
                className="w-full px-4 py-2.5 bg-neutral-900 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
              >
                <option value="member">Member</option>
                <option value="admin">Admin</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={jitConfig.autoVerifyEmail ?? true}
                onChange={e => onJITChange({ ...jitConfig, autoVerifyEmail: e.target.checked })}
                className="w-4 h-4 accent-emerald-500"
              />
              <div>
                <p className="text-sm text-white">Auto-verify email</p>
                <p className="text-xs text-neutral-500">Trust email from IdP as verified</p>
              </div>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={jitConfig.syncGroups ?? false}
                onChange={e => onJITChange({ ...jitConfig, syncGroups: e.target.checked })}
                className="w-4 h-4 accent-emerald-500"
              />
              <div>
                <p className="text-sm text-white">Sync groups from IdP</p>
                <p className="text-xs text-neutral-500">Map IdP groups to Zalt roles</p>
              </div>
            </label>
          </div>
        )}
      </div>
    </div>
  );
}


function DomainsStep({
  domains,
  onAddDomain,
  onRemoveDomain,
  onVerifyDomain,
  enforced,
  onEnforcedChange
}: {
  domains: VerifiedDomain[];
  onAddDomain: (domain: string) => void;
  onRemoveDomain: (domain: string) => void;
  onVerifyDomain: (domain: string) => void;
  enforced: boolean;
  onEnforcedChange: (enforced: boolean) => void;
}) {
  const [newDomain, setNewDomain] = useState('');
  const [verifying, setVerifying] = useState<string | null>(null);

  const handleAddDomain = () => {
    if (newDomain && /^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$/.test(newDomain)) {
      onAddDomain(newDomain.toLowerCase());
      setNewDomain('');
    }
  };

  const handleVerify = async (domain: string) => {
    setVerifying(domain);
    await onVerifyDomain(domain);
    setVerifying(null);
  };

  const hasVerifiedDomain = domains.some(d => d.verificationStatus === 'verified');

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white mb-2">Domain Verification</h2>
        <p className="text-neutral-400">Verify email domains to enable SSO enforcement.</p>
      </div>

      {/* Add Domain */}
      <div className="flex gap-2">
        <input
          type="text"
          value={newDomain}
          onChange={e => setNewDomain(e.target.value)}
          placeholder="acme.com"
          className="flex-1 px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
          onKeyDown={e => e.key === 'Enter' && handleAddDomain()}
        />
        <button
          onClick={handleAddDomain}
          disabled={!newDomain}
          className="px-4 py-2.5 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
        >
          <Plus size={16} />
          Add Domain
        </button>
      </div>

      {/* Domain List */}
      {domains.length > 0 ? (
        <div className="space-y-3">
          {domains.map(domain => (
            <div
              key={domain.domain}
              className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700 flex items-center justify-between"
            >
              <div className="flex items-center gap-3">
                <Globe className="text-neutral-500" size={20} />
                <div>
                  <p className="text-white font-medium">{domain.domain}</p>
                  <div className="flex items-center gap-2 mt-1">
                    {domain.verificationStatus === 'verified' ? (
                      <span className="flex items-center gap-1 text-xs text-emerald-400">
                        <CheckCircle size={12} />
                        Verified
                      </span>
                    ) : domain.verificationStatus === 'failed' ? (
                      <span className="flex items-center gap-1 text-xs text-red-400">
                        <XCircle size={12} />
                        Verification failed
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs text-yellow-400">
                        <Clock size={12} />
                        Pending verification
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {domain.verificationStatus !== 'verified' && (
                  <button
                    onClick={() => handleVerify(domain.domain)}
                    disabled={verifying === domain.domain}
                    className="px-3 py-1.5 bg-emerald-500/10 text-emerald-400 rounded-lg hover:bg-emerald-500/20 text-sm flex items-center gap-1.5"
                  >
                    {verifying === domain.domain ? (
                      <Loader2 className="animate-spin" size={14} />
                    ) : (
                      <RefreshCw size={14} />
                    )}
                    Verify
                  </button>
                )}
                <button
                  onClick={() => onRemoveDomain(domain.domain)}
                  className="p-1.5 text-neutral-500 hover:text-red-400"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-8 text-neutral-500">
          <Globe className="mx-auto mb-3" size={32} />
          <p>No domains added yet</p>
          <p className="text-sm">Add your organization's email domain to enable SSO</p>
        </div>
      )}

      {/* DNS Instructions */}
      {domains.some(d => d.verificationStatus === 'pending') && (
        <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-xl">
          <h4 className="text-sm font-medium text-blue-400 mb-2">DNS Verification Instructions</h4>
          <p className="text-sm text-neutral-300 mb-3">
            Add a TXT record to your domain's DNS configuration:
          </p>
          {domains.filter(d => d.verificationStatus === 'pending').map(domain => (
            <div key={domain.domain} className="mb-3 last:mb-0">
              <p className="text-xs text-neutral-500 mb-1">For {domain.domain}:</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 px-3 py-2 bg-neutral-900 rounded text-xs text-neutral-300 font-mono">
                  _zalt-verify.{domain.domain} TXT "{domain.verificationToken}"
                </code>
                <button
                  onClick={() => navigator.clipboard.writeText(`_zalt-verify.${domain.domain} TXT "${domain.verificationToken}"`)}
                  className="p-1.5 text-neutral-500 hover:text-white"
                >
                  <Copy size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* SSO Enforcement */}
      <div className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-white flex items-center gap-2">
              <Lock size={16} className="text-emerald-400" />
              SSO Enforcement
            </h3>
            <p className="text-xs text-neutral-500 mt-1">
              Block password login for users with verified domain emails
            </p>
          </div>
          <button
            onClick={() => onEnforcedChange(!enforced)}
            disabled={!hasVerifiedDomain}
            className={`relative w-12 h-6 rounded-full transition-colors ${
              enforced ? 'bg-emerald-500' : 'bg-neutral-700'
            } ${!hasVerifiedDomain ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${
              enforced ? 'left-7' : 'left-1'
            }`} />
          </button>
        </div>
        {!hasVerifiedDomain && (
          <p className="text-xs text-yellow-400 mt-2">
            ⚠️ At least one verified domain is required to enable enforcement
          </p>
        )}
      </div>
    </div>
  );
}


function ReviewStep({
  ssoType,
  providerName,
  samlConfig,
  oidcConfig,
  domains,
  enforced,
  jitConfig,
  onTest,
  testResult,
  testing
}: {
  ssoType: SSOType;
  providerName: string;
  samlConfig?: Partial<SAMLConfig>;
  oidcConfig?: Partial<OIDCConfig>;
  domains: VerifiedDomain[];
  enforced: boolean;
  jitConfig: JITProvisioningConfig;
  onTest: () => void;
  testResult: TestConnectionResult | null;
  testing: boolean;
}) {
  const verifiedDomains = domains.filter(d => d.verificationStatus === 'verified');

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-white mb-2">Review & Test</h2>
        <p className="text-neutral-400">Review your SSO configuration and test the connection.</p>
      </div>

      {/* Configuration Summary */}
      <div className="space-y-4">
        <div className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700">
          <h3 className="text-sm font-medium text-white mb-3">SSO Configuration</h3>
          <div className="grid md:grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-neutral-500">Protocol</p>
              <p className="text-white">{ssoType.toUpperCase()}</p>
            </div>
            <div>
              <p className="text-neutral-500">Provider</p>
              <p className="text-white">{providerName || (oidcConfig?.providerPreset ? OIDC_PROVIDERS.find(p => p.value === oidcConfig.providerPreset)?.label : 'Custom')}</p>
            </div>
            {ssoType === 'saml' && samlConfig?.idpEntityId && (
              <div className="md:col-span-2">
                <p className="text-neutral-500">IdP Entity ID</p>
                <p className="text-white font-mono text-xs truncate">{samlConfig.idpEntityId}</p>
              </div>
            )}
            {ssoType === 'oidc' && oidcConfig?.clientId && (
              <div className="md:col-span-2">
                <p className="text-neutral-500">Client ID</p>
                <p className="text-white font-mono text-xs truncate">{oidcConfig.clientId}</p>
              </div>
            )}
          </div>
        </div>

        <div className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700">
          <h3 className="text-sm font-medium text-white mb-3">Domains & Enforcement</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-neutral-500">Verified Domains</span>
              <span className="text-white">{verifiedDomains.length > 0 ? verifiedDomains.map(d => d.domain).join(', ') : 'None'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-neutral-500">SSO Enforcement</span>
              <span className={enforced ? 'text-emerald-400' : 'text-neutral-400'}>{enforced ? 'Enabled' : 'Disabled'}</span>
            </div>
          </div>
        </div>

        <div className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700">
          <h3 className="text-sm font-medium text-white mb-3">JIT Provisioning</h3>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-neutral-500">Status</span>
              <span className={jitConfig.enabled ? 'text-emerald-400' : 'text-neutral-400'}>{jitConfig.enabled ? 'Enabled' : 'Disabled'}</span>
            </div>
            {jitConfig.enabled && (
              <>
                <div className="flex justify-between">
                  <span className="text-neutral-500">Default Role</span>
                  <span className="text-white capitalize">{jitConfig.defaultRole || 'member'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-neutral-500">Auto-verify Email</span>
                  <span className="text-white">{jitConfig.autoVerifyEmail ? 'Yes' : 'No'}</span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Test Connection */}
      <div className="p-4 bg-neutral-800/50 rounded-xl border border-neutral-700">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-medium text-white">Test SSO Connection</h3>
            <p className="text-xs text-neutral-500">Verify your IdP configuration is correct</p>
          </div>
          <button
            onClick={onTest}
            disabled={testing}
            className="px-4 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 disabled:opacity-50 flex items-center gap-2"
          >
            {testing ? (
              <Loader2 className="animate-spin" size={16} />
            ) : (
              <Play size={16} />
            )}
            Test Connection
          </button>
        </div>

        {testResult && (
          <div className={`p-3 rounded-lg ${testResult.success ? 'bg-emerald-500/10 border border-emerald-500/20' : 'bg-red-500/10 border border-red-500/20'}`}>
            <div className="flex items-center gap-2 mb-2">
              {testResult.success ? (
                <CheckCircle className="text-emerald-400" size={16} />
              ) : (
                <XCircle className="text-red-400" size={16} />
              )}
              <span className={testResult.success ? 'text-emerald-400' : 'text-red-400'}>
                {testResult.message}
              </span>
            </div>
            {testResult.details && (
              <div className="space-y-1 text-xs">
                {testResult.details.idpReachable !== undefined && (
                  <div className="flex items-center gap-2">
                    {testResult.details.idpReachable ? <Check size={12} className="text-emerald-400" /> : <XCircle size={12} className="text-red-400" />}
                    <span className="text-neutral-400">IdP Reachable</span>
                  </div>
                )}
                {testResult.details.metadataValid !== undefined && (
                  <div className="flex items-center gap-2">
                    {testResult.details.metadataValid ? <Check size={12} className="text-emerald-400" /> : <XCircle size={12} className="text-red-400" />}
                    <span className="text-neutral-400">Metadata Valid</span>
                  </div>
                )}
                {testResult.details.certificateValid !== undefined && (
                  <div className="flex items-center gap-2">
                    {testResult.details.certificateValid ? <Check size={12} className="text-emerald-400" /> : <XCircle size={12} className="text-red-400" />}
                    <span className="text-neutral-400">Certificate Valid</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Warning */}
      {enforced && verifiedDomains.length === 0 && (
        <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg flex items-center gap-2 text-yellow-400">
          <AlertTriangle size={16} />
          <span className="text-sm">SSO enforcement is enabled but no domains are verified. Users won't be able to login.</span>
        </div>
      )}
    </div>
  );
}


// ============================================================================
// Main Page Component
// ============================================================================

export default function SSOConfigurationPage() {
  // Wizard state
  const [currentStep, setCurrentStep] = useState(0);
  const [isEditing, setIsEditing] = useState(false);
  
  // SSO Configuration state
  const [ssoType, setSSOType] = useState<SSOType | null>(null);
  const [providerName, setProviderName] = useState('');
  const [samlConfig, setSAMLConfig] = useState<Partial<SAMLConfig>>({});
  const [oidcConfig, setOIDCConfig] = useState<Partial<OIDCConfig>>({});
  const [attributeMapping, setAttributeMapping] = useState<AttributeMapping>({});
  const [domains, setDomains] = useState<VerifiedDomain[]>([]);
  const [enforced, setEnforced] = useState(false);
  const [jitConfig, setJITConfig] = useState<JITProvisioningConfig>({
    enabled: true,
    defaultRole: 'member',
    autoVerifyEmail: true,
    syncGroups: false
  });
  
  // Test state
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null);
  
  // Loading state
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [existingConfig, setExistingConfig] = useState<OrgSSOConfig | null>(null);

  // Mock tenant/realm IDs - in production, get from context
  const tenantId = 'tenant_demo';
  const realmId = 'realm_demo';
  const spEntityId = `https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}`;
  const acsUrl = `https://api.zalt.io/v1/sso/saml/${realmId}/${tenantId}/acs`;

  // Load existing configuration
  useEffect(() => {
    const loadConfig = async () => {
      try {
        // In production, fetch from API
        // const response = await fetch(`/api/tenants/${tenantId}/sso`);
        // const data = await response.json();
        // if (data.config) setExistingConfig(data.config);
        
        // Mock: no existing config
        setExistingConfig(null);
      } catch (error) {
        console.error('Failed to load SSO config:', error);
      } finally {
        setLoading(false);
      }
    };
    loadConfig();
  }, [tenantId]);

  // Initialize from existing config
  useEffect(() => {
    if (existingConfig) {
      setSSOType(existingConfig.ssoType);
      setProviderName(existingConfig.providerName);
      if (existingConfig.samlConfig) setSAMLConfig(existingConfig.samlConfig);
      if (existingConfig.oidcConfig) setOIDCConfig(existingConfig.oidcConfig);
      if (existingConfig.attributeMapping) setAttributeMapping(existingConfig.attributeMapping);
      setDomains(existingConfig.domains);
      setEnforced(existingConfig.enforced);
      setJITConfig(existingConfig.jitProvisioning);
    }
  }, [existingConfig]);

  // Navigation
  const canProceed = useCallback(() => {
    switch (currentStep) {
      case 0: return ssoType !== null;
      case 1: 
        if (ssoType === 'saml') {
          return !!(samlConfig.idpEntityId && samlConfig.idpSsoUrl && samlConfig.idpCertificate);
        } else {
          return !!(oidcConfig.clientId && (oidcConfig.issuer || oidcConfig.providerPreset));
        }
      case 2: return !!attributeMapping.email;
      case 3: return true; // Domains are optional
      case 4: return true;
      default: return false;
    }
  }, [currentStep, ssoType, samlConfig, oidcConfig, attributeMapping]);

  const handleNext = () => {
    if (canProceed() && currentStep < WIZARD_STEPS.length - 1) {
      // Set default attribute mapping when moving from provider step
      if (currentStep === 1 && Object.keys(attributeMapping).length === 0) {
        setAttributeMapping(DEFAULT_ATTRIBUTE_MAPPINGS[ssoType!]);
      }
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  // Domain management
  const handleAddDomain = (domain: string) => {
    if (!domains.find(d => d.domain === domain)) {
      setDomains([...domains, {
        domain,
        verificationStatus: 'pending',
        verificationToken: `zalt-verify=${Math.random().toString(36).substring(2, 18)}`
      }]);
    }
  };

  const handleRemoveDomain = (domain: string) => {
    setDomains(domains.filter(d => d.domain !== domain));
  };

  const handleVerifyDomain = async (domain: string) => {
    // In production, call API to verify DNS
    // Simulate verification
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Mock: randomly succeed or fail
    const success = Math.random() > 0.3;
    
    setDomains(domains.map(d => 
      d.domain === domain 
        ? { ...d, verificationStatus: success ? 'verified' : 'failed', verifiedAt: success ? new Date().toISOString() : undefined }
        : d
    ));
  };

  // Test connection
  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    
    try {
      // In production, call API to test connection
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Mock successful test
      setTestResult({
        success: true,
        message: 'SSO connection test successful!',
        details: {
          idpReachable: true,
          metadataValid: true,
          certificateValid: true,
          attributesFound: ['email', 'firstName', 'lastName']
        }
      });
    } catch (error) {
      setTestResult({
        success: false,
        message: error instanceof Error ? error.message : 'Connection test failed',
        details: {
          idpReachable: false
        }
      });
    } finally {
      setTesting(false);
    }
  };

  // Save configuration
  const handleSave = async () => {
    setSaving(true);
    
    try {
      const config = {
        ssoType,
        providerName: providerName || (oidcConfig.providerPreset ? OIDC_PROVIDERS.find(p => p.value === oidcConfig.providerPreset)?.label : 'Custom'),
        samlConfig: ssoType === 'saml' ? samlConfig : undefined,
        oidcConfig: ssoType === 'oidc' ? oidcConfig : undefined,
        attributeMapping,
        domains,
        enforced,
        jitProvisioning: jitConfig
      };
      
      // In production, call API to save
      // await fetch(`/api/tenants/${tenantId}/sso`, {
      //   method: existingConfig ? 'PUT' : 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(config)
      // });
      
      console.log('Saving SSO config:', config);
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      alert('SSO configuration saved successfully!');
    } catch (error) {
      console.error('Failed to save SSO config:', error);
      alert('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="animate-spin text-emerald-400" size={32} />
      </div>
    );
  }

  // Show existing config view if not editing
  if (existingConfig && !isEditing) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">SSO Configuration</h1>
            <p className="text-neutral-500">Organization-level Single Sign-On</p>
          </div>
          <button
            onClick={() => setIsEditing(true)}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600"
          >
            <Edit2 size={16} />
            Edit Configuration
          </button>
        </div>

        {/* Existing config display would go here */}
        <div className="p-6 bg-neutral-900 border border-emerald-500/10 rounded-xl">
          <p className="text-neutral-400">SSO is configured and active.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">SSO Configuration Wizard</h1>
          <p className="text-neutral-500">Set up Single Sign-On for your organization</p>
        </div>
        <a
          href="/docs/configuration/sso-saml"
          target="_blank"
          className="flex items-center gap-1.5 text-emerald-400 hover:text-emerald-300 text-sm"
        >
          <FileText size={16} />
          Documentation
          <ExternalLink size={12} />
        </a>
      </div>

      {/* Step Indicator */}
      <StepIndicator 
        steps={WIZARD_STEPS} 
        currentStep={currentStep} 
        onStepClick={setCurrentStep}
      />

      {/* Step Content */}
      <motion.div
        key={currentStep}
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        exit={{ opacity: 0, x: -20 }}
        className="bg-neutral-900 border border-emerald-500/10 rounded-xl p-6"
      >
        {currentStep === 0 && (
          <SSOTypeStep ssoType={ssoType} onSelect={setSSOType} />
        )}
        
        {currentStep === 1 && ssoType === 'saml' && (
          <SAMLProviderStep
            config={samlConfig}
            onChange={setSAMLConfig}
            spEntityId={spEntityId}
            acsUrl={acsUrl}
          />
        )}
        
        {currentStep === 1 && ssoType === 'oidc' && (
          <OIDCProviderStep
            config={oidcConfig}
            onChange={setOIDCConfig}
          />
        )}
        
        {currentStep === 2 && ssoType && (
          <AttributeMappingStep
            ssoType={ssoType}
            mapping={attributeMapping}
            onChange={setAttributeMapping}
            jitConfig={jitConfig}
            onJITChange={setJITConfig}
          />
        )}
        
        {currentStep === 3 && (
          <DomainsStep
            domains={domains}
            onAddDomain={handleAddDomain}
            onRemoveDomain={handleRemoveDomain}
            onVerifyDomain={handleVerifyDomain}
            enforced={enforced}
            onEnforcedChange={setEnforced}
          />
        )}
        
        {currentStep === 4 && ssoType && (
          <ReviewStep
            ssoType={ssoType}
            providerName={providerName}
            samlConfig={samlConfig}
            oidcConfig={oidcConfig}
            domains={domains}
            enforced={enforced}
            jitConfig={jitConfig}
            onTest={handleTestConnection}
            testResult={testResult}
            testing={testing}
          />
        )}
      </motion.div>

      {/* Navigation Buttons */}
      <div className="flex items-center justify-between">
        <button
          onClick={handleBack}
          disabled={currentStep === 0}
          className="flex items-center gap-2 px-4 py-2 text-neutral-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <ChevronLeft size={16} />
          Back
        </button>
        
        <div className="flex items-center gap-3">
          {currentStep === WIZARD_STEPS.length - 1 ? (
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2 px-6 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 disabled:opacity-50"
            >
              {saving ? (
                <Loader2 className="animate-spin" size={16} />
              ) : (
                <CheckCircle size={16} />
              )}
              {existingConfig ? 'Update Configuration' : 'Save & Activate'}
            </button>
          ) : (
            <button
              onClick={handleNext}
              disabled={!canProceed()}
              className="flex items-center gap-2 px-6 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Continue
              <ChevronRight size={16} />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
