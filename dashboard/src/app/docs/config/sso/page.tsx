'use client';

import { motion } from 'framer-motion';
import { ArrowLeft, Key, Building } from 'lucide-react';
import Link from 'next/link';

export default function SSOConfigPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <Link href="/docs" className="inline-flex items-center gap-2 text-emerald-400 text-sm mb-6 hover:underline">
          <ArrowLeft size={14} /> Back to docs
        </Link>
        <h1 className="font-outfit text-3xl font-bold text-white mb-4">SSO / SAML Configuration</h1>
        <p className="text-neutral-400">Enable enterprise single sign-on for your realm.</p>
      </motion.div>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Supported Providers</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {['Okta', 'Azure AD', 'Google Workspace', 'OneLogin'].map((provider) => (
            <div key={provider} className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4 text-center">
              <Building className="text-emerald-500 mx-auto mb-2" size={24} />
              <span className="text-sm text-white">{provider}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">SAML Configuration</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "saml": {
    "enabled": true,
    "entityId": "https://api.zalt.io/saml/realm_xxx",
    "acsUrl": "https://api.zalt.io/saml/realm_xxx/acs",
    "idpMetadataUrl": "https://your-idp.com/metadata.xml",
    "signRequests": true,
    "wantAssertionsSigned": true,
    "attributeMapping": {
      "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "firstName": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
      "lastName": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    }
  }
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">OAuth / OIDC</h2>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`// Zalt as OAuth Provider
{
  "issuer": "https://api.zalt.io",
  "authorization_endpoint": "https://api.zalt.io/oauth/authorize",
  "token_endpoint": "https://api.zalt.io/oauth/token",
  "userinfo_endpoint": "https://api.zalt.io/oauth/userinfo",
  "jwks_uri": "https://api.zalt.io/.well-known/jwks.json"
}`}
          </pre>
        </div>
      </section>

      <section className="space-y-4">
        <h2 className="text-xl font-semibold text-white">Social Login</h2>
        <p className="text-neutral-400">Enable social login providers for your realm:</p>
        <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
          <pre className="text-sm font-mono text-neutral-300 overflow-x-auto">
{`{
  "socialProviders": {
    "google": {
      "enabled": true,
      "clientId": "xxx.apps.googleusercontent.com",
      "clientSecret": "stored-in-secrets-manager"
    },
    "apple": {
      "enabled": true,
      "clientId": "com.yourapp.auth",
      "teamId": "XXXXXXXXXX"
    }
  }
}`}
          </pre>
        </div>
      </section>
    </div>
  );
}
