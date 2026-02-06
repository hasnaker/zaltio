'use client';

import React, { useState, useRef } from 'react';
import { motion, useInView, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { easings } from '@/lib/motion';
import { 
  Building2, Users, Shield, Key, UserPlus, 
  ChevronRight, Check, Crown, User, Settings
} from 'lucide-react';
import { OrgCard } from './OrgCard';

export interface OrganizationsSectionProps {
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

// Sample organization data
const sampleOrgs = [
  {
    id: 'org_1',
    name: 'Acme Corporation',
    slug: 'acme-corp',
    logo: 'A',
    memberCount: 156,
    plan: 'Enterprise' as const,
    roles: ['Admin', 'Developer', 'Viewer'],
  },
  {
    id: 'org_2',
    name: 'Startup Labs',
    slug: 'startup-labs',
    logo: 'S',
    memberCount: 24,
    plan: 'Pro' as const,
    roles: ['Owner', 'Member'],
  },
  {
    id: 'org_3',
    name: 'Tech Innovators',
    slug: 'tech-innovators',
    logo: 'T',
    memberCount: 89,
    plan: 'Pro' as const,
    roles: ['Admin', 'Engineer', 'Support'],
  },
];

// RBAC capabilities
const rbacFeatures = [
  { icon: Shield, label: 'Role-based access control', description: 'Define custom roles with granular permissions' },
  { icon: Key, label: 'Permission management', description: 'Control access at resource and action level' },
  { icon: Users, label: 'Team hierarchies', description: 'Nested teams with inherited permissions' },
  { icon: Settings, label: 'Custom policies', description: 'Create organization-specific security policies' },
];

// Invitation workflow steps
const invitationSteps = [
  { step: 1, label: 'Send Invite', description: 'Admin sends email invitation' },
  { step: 2, label: 'Accept', description: 'User clicks invitation link' },
  { step: 3, label: 'Join', description: 'User joins with assigned role' },
];

/**
 * Organizations Showcase Section
 * Demonstrates multi-tenant organization features, RBAC, and team management
 */
export function OrganizationsSection({
  className,
  'data-testid': testId = 'organizations-section',
}: OrganizationsSectionProps) {
  const [activeOrg, setActiveOrg] = useState(sampleOrgs[0]);
  const [activeTab, setActiveTab] = useState<'hierarchy' | 'rbac' | 'invite'>('hierarchy');
  const ref = useRef<HTMLElement>(null);
  const isInView = useInView(ref, { once: true, margin: '-100px' });
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: reducedMotion ? 0 : 0.1,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: reducedMotion ? 0 : 20 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { duration: reducedMotion ? 0.1 : 0.5, ease: easings.smoothOut },
    },
  };

  return (
    <section
      ref={ref}
      className={cn(
        'py-20 md:py-32 bg-white dark:bg-neutral-950',
        className
      )}
      data-testid={testId}
      data-reduced-motion={reducedMotion ? 'true' : 'false'}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate={isInView ? 'visible' : 'hidden'}
        >
          {/* Section Header */}
          <motion.div variants={itemVariants} className="text-center mb-12">
            <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/10 text-primary text-sm font-medium mb-4">
              <Building2 className="w-4 h-4" />
              Multi-tenant Ready
            </span>
            <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-neutral-900 dark:text-white mb-4">
              Organizations & Teams
            </h2>
            <p className="text-lg text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto">
              Built-in multi-tenancy with organization hierarchies, role-based access control, 
              and seamless team management.
            </p>
          </motion.div>

          {/* Tab Navigation */}
          <motion.div variants={itemVariants} className="flex justify-center mb-8">
            <div className="inline-flex items-center gap-1 p-1.5 bg-neutral-100 dark:bg-neutral-800 rounded-xl">
              <TabButton
                active={activeTab === 'hierarchy'}
                onClick={() => setActiveTab('hierarchy')}
                icon={<Building2 className="w-4 h-4" />}
                label="Hierarchy"
              />
              <TabButton
                active={activeTab === 'rbac'}
                onClick={() => setActiveTab('rbac')}
                icon={<Shield className="w-4 h-4" />}
                label="RBAC"
              />
              <TabButton
                active={activeTab === 'invite'}
                onClick={() => setActiveTab('invite')}
                icon={<UserPlus className="w-4 h-4" />}
                label="Invitations"
              />
            </div>
          </motion.div>

          {/* Content Area */}
          <motion.div variants={itemVariants} className="grid lg:grid-cols-2 gap-8">
            {/* Left Panel - Organization Cards */}
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-neutral-900 dark:text-white mb-4">
                Your Organizations
              </h3>
              {sampleOrgs.map((org) => (
                <OrgCard
                  key={org.id}
                  org={org}
                  isActive={activeOrg.id === org.id}
                  onClick={() => setActiveOrg(org)}
                />
              ))}
              
              {/* Create new org button */}
              <button className="w-full flex items-center justify-center gap-2 p-4 rounded-xl border-2 border-dashed border-neutral-300 dark:border-neutral-700 text-neutral-500 dark:text-neutral-400 hover:border-primary hover:text-primary transition-colors">
                <span className="text-xl">+</span>
                <span>Create Organization</span>
              </button>
            </div>

            {/* Right Panel - Feature Demo */}
            <div className="bg-neutral-50 dark:bg-neutral-900 rounded-2xl p-6 border border-neutral-200 dark:border-neutral-800">
              {activeTab === 'hierarchy' && (
                <HierarchyDemo org={activeOrg} reducedMotion={reducedMotion} />
              )}
              {activeTab === 'rbac' && (
                <RBACDemo features={rbacFeatures} reducedMotion={reducedMotion} />
              )}
              {activeTab === 'invite' && (
                <InvitationDemo steps={invitationSteps} reducedMotion={reducedMotion} />
              )}
            </div>
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}

// Tab button component
function TabButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all',
        active
          ? 'bg-white dark:bg-neutral-700 text-neutral-900 dark:text-white shadow-sm'
          : 'text-neutral-500 dark:text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-300'
      )}
      aria-pressed={active}
    >
      {icon}
      <span className="hidden sm:inline">{label}</span>
    </button>
  );
}

// Hierarchy visualization demo
function HierarchyDemo({ 
  org, 
  reducedMotion 
}: { 
  org: typeof sampleOrgs[0]; 
  reducedMotion: boolean;
}) {
  const teams = [
    { name: 'Engineering', members: 45, icon: '⚙️' },
    { name: 'Product', members: 12, icon: '📦' },
    { name: 'Design', members: 8, icon: '🎨' },
    { name: 'Marketing', members: 15, icon: '📢' },
  ];

  return (
    <div>
      <h4 className="text-lg font-semibold text-neutral-900 dark:text-white mb-4">
        Organization Structure
      </h4>
      
      {/* Root org */}
      <div className="flex items-center gap-3 p-3 bg-primary/10 rounded-lg mb-4">
        <div className="w-10 h-10 rounded-lg bg-primary flex items-center justify-center text-white font-bold">
          {org.logo}
        </div>
        <div>
          <p className="font-medium text-neutral-900 dark:text-white">{org.name}</p>
          <p className="text-sm text-neutral-500">{org.memberCount} members</p>
        </div>
      </div>

      {/* Teams */}
      <div className="ml-6 border-l-2 border-neutral-200 dark:border-neutral-700 pl-4 space-y-3">
        {teams.map((team, index) => (
          <motion.div
            key={team.name}
            initial={{ opacity: 0, x: reducedMotion ? 0 : -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: reducedMotion ? 0 : index * 0.1 }}
            className="flex items-center gap-3 p-2 rounded-lg hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
          >
            <span className="text-xl">{team.icon}</span>
            <div className="flex-1">
              <p className="font-medium text-neutral-900 dark:text-white text-sm">{team.name}</p>
              <p className="text-xs text-neutral-500">{team.members} members</p>
            </div>
            <ChevronRight className="w-4 h-4 text-neutral-400" />
          </motion.div>
        ))}
      </div>
    </div>
  );
}

// RBAC capabilities demo
function RBACDemo({ 
  features, 
  reducedMotion 
}: { 
  features: typeof rbacFeatures; 
  reducedMotion: boolean;
}) {
  return (
    <div>
      <h4 className="text-lg font-semibold text-neutral-900 dark:text-white mb-4">
        Access Control Features
      </h4>
      
      <div className="space-y-4">
        {features.map((feature, index) => {
          const Icon = feature.icon;
          return (
            <motion.div
              key={feature.label}
              initial={{ opacity: 0, y: reducedMotion ? 0 : 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: reducedMotion ? 0 : index * 0.1 }}
              className="flex items-start gap-3 p-3 rounded-lg bg-white dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700"
            >
              <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                <Icon className="w-5 h-5 text-primary" />
              </div>
              <div>
                <p className="font-medium text-neutral-900 dark:text-white">{feature.label}</p>
                <p className="text-sm text-neutral-500">{feature.description}</p>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Sample roles */}
      <div className="mt-6 p-4 bg-white dark:bg-neutral-800 rounded-lg border border-neutral-200 dark:border-neutral-700">
        <p className="text-sm font-medium text-neutral-900 dark:text-white mb-3">Sample Roles</p>
        <div className="flex flex-wrap gap-2">
          {['Admin', 'Developer', 'Viewer', 'Billing', 'Support'].map((role) => (
            <span
              key={role}
              className="px-3 py-1 rounded-full bg-neutral-100 dark:bg-neutral-700 text-sm text-neutral-700 dark:text-neutral-300"
            >
              {role}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// Invitation workflow demo
function InvitationDemo({ 
  steps, 
  reducedMotion 
}: { 
  steps: typeof invitationSteps; 
  reducedMotion: boolean;
}) {
  const [activeStep, setActiveStep] = useState(1);

  return (
    <div>
      <h4 className="text-lg font-semibold text-neutral-900 dark:text-white mb-4">
        Team Invitation Workflow
      </h4>

      {/* Steps */}
      <div className="flex items-center justify-between mb-8">
        {steps.map((step, index) => (
          <React.Fragment key={step.step}>
            <motion.div
              initial={{ scale: reducedMotion ? 1 : 0.8 }}
              animate={{ scale: 1 }}
              transition={{ delay: reducedMotion ? 0 : index * 0.2 }}
              className="flex flex-col items-center"
            >
              <div
                className={cn(
                  'w-10 h-10 rounded-full flex items-center justify-center font-bold transition-colors',
                  step.step <= activeStep
                    ? 'bg-primary text-white'
                    : 'bg-neutral-200 dark:bg-neutral-700 text-neutral-500'
                )}
              >
                {step.step < activeStep ? <Check className="w-5 h-5" /> : step.step}
              </div>
              <p className="text-sm font-medium text-neutral-900 dark:text-white mt-2">{step.label}</p>
              <p className="text-xs text-neutral-500 text-center max-w-[100px]">{step.description}</p>
            </motion.div>
            {index < steps.length - 1 && (
              <div className={cn(
                'flex-1 h-0.5 mx-2',
                step.step < activeStep ? 'bg-primary' : 'bg-neutral-200 dark:bg-neutral-700'
              )} />
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Demo controls */}
      <div className="flex gap-2">
        <button
          onClick={() => setActiveStep(Math.max(1, activeStep - 1))}
          className="flex-1 py-2 px-4 rounded-lg border border-neutral-300 dark:border-neutral-600 text-neutral-700 dark:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors"
          disabled={activeStep === 1}
        >
          Previous
        </button>
        <button
          onClick={() => setActiveStep(Math.min(3, activeStep + 1))}
          className="flex-1 py-2 px-4 rounded-lg bg-primary text-white hover:bg-primary/90 transition-colors"
          disabled={activeStep === 3}
        >
          {activeStep === 3 ? 'Complete!' : 'Next Step'}
        </button>
      </div>

      {/* Sample invitation */}
      <div className="mt-6 p-4 bg-white dark:bg-neutral-800 rounded-lg border border-neutral-200 dark:border-neutral-700">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-neutral-200 dark:bg-neutral-700 flex items-center justify-center">
            <User className="w-5 h-5 text-neutral-500" />
          </div>
          <div className="flex-1">
            <p className="font-medium text-neutral-900 dark:text-white">john@example.com</p>
            <p className="text-sm text-neutral-500">Invited as Developer</p>
          </div>
          <span className="px-2 py-1 rounded-full bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 text-xs">
            Pending
          </span>
        </div>
      </div>
    </div>
  );
}

export default OrganizationsSection;
