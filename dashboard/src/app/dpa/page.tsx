'use client';

import { LegalPageLayout } from '@/components/legal/LegalPageLayout';

const tableOfContents = [
  { id: 'definitions', title: 'Definitions' },
  { id: 'processing', title: 'Data Processing' },
  { id: 'security', title: 'Security Measures' },
  { id: 'subprocessors', title: 'Sub-processors' },
  { id: 'transfers', title: 'International Transfers' },
  { id: 'rights', title: 'Data Subject Rights' },
  { id: 'breach', title: 'Data Breach' },
];

export default function DPAPage() {
  return (
    <LegalPageLayout
      title="Data Processing Agreement"
      lastUpdated="February 1, 2026"
      tableOfContents={tableOfContents}
    >
      <p className="text-neutral-300 lead">
        This Data Processing Agreement (&quot;DPA&quot;) forms part of the Terms of Service between 
        Zalt.io and Customer for the provision of authentication services.
      </p>

      <section id="definitions">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">1. Definitions</h2>
        <ul className="text-neutral-300 list-disc pl-6 space-y-2">
          <li><strong>&quot;Personal Data&quot;</strong> means any information relating to an identified or identifiable natural person.</li>
          <li><strong>&quot;Data Controller&quot;</strong> means the Customer who determines the purposes and means of processing.</li>
          <li><strong>&quot;Data Processor&quot;</strong> means Zalt.io, which processes Personal Data on behalf of the Controller.</li>
          <li><strong>&quot;Sub-processor&quot;</strong> means any third party engaged by Zalt.io to process Personal Data.</li>
          <li><strong>&quot;Data Subject&quot;</strong> means the individual to whom Personal Data relates.</li>
        </ul>
      </section>

      <section id="processing">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">2. Data Processing</h2>
        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Scope of Processing</h3>
        <p className="text-neutral-300">
          Zalt.io processes Personal Data solely for the purpose of providing authentication 
          services as described in the Terms of Service.
        </p>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Categories of Data</h3>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Email addresses</li>
          <li>Hashed passwords</li>
          <li>Authentication tokens</li>
          <li>Device identifiers</li>
          <li>IP addresses</li>
          <li>Session data</li>
        </ul>

        <h3 className="text-lg font-semibold text-white mt-6 mb-2">Processing Instructions</h3>
        <p className="text-neutral-300">
          Zalt.io will only process Personal Data in accordance with documented instructions 
          from the Customer, unless required by applicable law.
        </p>
      </section>

      <section id="security">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">3. Security Measures</h2>
        <p className="text-neutral-300">
          Zalt.io implements appropriate technical and organizational measures including:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Encryption of data in transit (TLS 1.3) and at rest (AES-256)</li>
          <li>Access controls and authentication</li>
          <li>Regular security assessments and penetration testing</li>
          <li>Employee security training</li>
          <li>Incident response procedures</li>
          <li>Business continuity and disaster recovery</li>
        </ul>
      </section>

      <section id="subprocessors">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">4. Sub-processors</h2>
        <p className="text-neutral-300">
          Customer authorizes Zalt.io to engage the following sub-processors:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li><strong>Amazon Web Services (AWS)</strong> - Cloud infrastructure (US, EU, Asia)</li>
          <li><strong>AWS SES</strong> - Email delivery</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          Zalt.io will notify Customer of any intended changes to sub-processors, allowing 
          Customer to object within 30 days.
        </p>
      </section>

      <section id="transfers">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">5. International Transfers</h2>
        <p className="text-neutral-300">
          Zalt.io offers data residency options in:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>European Union (eu-west-1)</li>
          <li>United States (us-east-1)</li>
          <li>Asia Pacific (ap-southeast-1)</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          For transfers outside the EEA, Zalt.io relies on Standard Contractual Clauses 
          approved by the European Commission.
        </p>
      </section>

      <section id="rights">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">6. Data Subject Rights</h2>
        <p className="text-neutral-300">
          Zalt.io will assist Customer in responding to Data Subject requests including:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Access to Personal Data</li>
          <li>Rectification of inaccurate data</li>
          <li>Erasure (&quot;right to be forgotten&quot;)</li>
          <li>Data portability</li>
          <li>Restriction of processing</li>
          <li>Objection to processing</li>
        </ul>
      </section>

      <section id="breach">
        <h2 className="text-xl font-bold text-white mt-8 mb-4">7. Data Breach Notification</h2>
        <p className="text-neutral-300">
          In the event of a Personal Data breach, Zalt.io will:
        </p>
        <ul className="text-neutral-300 list-disc pl-6 space-y-1">
          <li>Notify Customer without undue delay (within 72 hours)</li>
          <li>Provide details of the breach and affected data</li>
          <li>Describe measures taken to address the breach</li>
          <li>Assist Customer in meeting notification obligations</li>
        </ul>
        <p className="text-neutral-300 mt-4">
          For questions about this DPA, contact{' '}
          <a href="mailto:dpa@zalt.io" className="text-emerald-400">dpa@zalt.io</a>.
        </p>
      </section>
    </LegalPageLayout>
  );
}
