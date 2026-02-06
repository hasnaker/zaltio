'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Building2, Plus, Users, Settings, Trash2, Crown, 
  Shield, Mail, UserPlus, ChevronRight, Search, MoreVertical
} from 'lucide-react';

interface Organization {
  id: string;
  name: string;
  slug: string;
  logo?: string;
  memberCount: number;
  plan: 'free' | 'pro' | 'enterprise';
  role: 'owner' | 'admin' | 'member';
  createdAt: string;
}

interface Member {
  id: string;
  email: string;
  name?: string;
  role: 'owner' | 'admin' | 'member';
  joinedAt: string;
  lastActive?: string;
}

export default function OrganizationsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'member'>('member');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchOrganizations();
  }, []);

  useEffect(() => {
    if (selectedOrg) {
      fetchMembers(selectedOrg.id);
    }
  }, [selectedOrg]);

  const fetchOrganizations = async () => {
    try {
      const res = await fetch('/api/dashboard/organizations');
      if (res.ok) {
        const data = await res.json();
        setOrganizations(data.organizations || []);
        if (data.organizations?.length > 0 && !selectedOrg) {
          setSelectedOrg(data.organizations[0]);
        }
      }
    } catch (error) {
      console.error('Failed to fetch organizations:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchMembers = async (orgId: string) => {
    try {
      const res = await fetch(`/api/dashboard/organizations/${orgId}/members`);
      if (res.ok) {
        const data = await res.json();
        setMembers(data.members || []);
      }
    } catch (error) {
      console.error('Failed to fetch members:', error);
    }
  };

  const createOrganization = async () => {
    try {
      const res = await fetch('/api/dashboard/organizations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newOrgName }),
      });
      if (res.ok) {
        setShowCreateModal(false);
        setNewOrgName('');
        fetchOrganizations();
      }
    } catch (error) {
      console.error('Failed to create organization:', error);
    }
  };

  const inviteMember = async () => {
    if (!selectedOrg) return;
    try {
      const res = await fetch(`/api/dashboard/organizations/${selectedOrg.id}/invitations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      });
      if (res.ok) {
        setShowInviteModal(false);
        setInviteEmail('');
        fetchMembers(selectedOrg.id);
      }
    } catch (error) {
      console.error('Failed to invite member:', error);
    }
  };

  const removeMember = async (memberId: string) => {
    if (!selectedOrg) return;
    if (!confirm('Are you sure you want to remove this member?')) return;
    try {
      await fetch(`/api/dashboard/organizations/${selectedOrg.id}/members/${memberId}`, {
        method: 'DELETE',
      });
      fetchMembers(selectedOrg.id);
    } catch (error) {
      console.error('Failed to remove member:', error);
    }
  };

  const updateMemberRole = async (memberId: string, newRole: 'admin' | 'member') => {
    if (!selectedOrg) return;
    try {
      await fetch(`/api/dashboard/organizations/${selectedOrg.id}/members/${memberId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole }),
      });
      fetchMembers(selectedOrg.id);
    } catch (error) {
      console.error('Failed to update member role:', error);
    }
  };

  const filteredMembers = members.filter(m => 
    m.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    m.name?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const planColors = {
    free: 'bg-neutral-500/20 text-neutral-400',
    pro: 'bg-emerald-500/20 text-emerald-400',
    enterprise: 'bg-purple-500/20 text-purple-400',
  };

  const roleIcons = {
    owner: Crown,
    admin: Shield,
    member: Users,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Organizations</h1>
          <p className="text-neutral-400 mt-1">Manage your organizations and team members</p>
        </div>
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium"
        >
          <Plus size={18} />
          Create Organization
        </motion.button>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Organizations List */}
        <div className="lg:col-span-1 space-y-3">
          <h2 className="text-sm font-medium text-neutral-400 uppercase tracking-wider">Your Organizations</h2>
          {loading ? (
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-8 text-center">
              <div className="animate-spin w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full mx-auto" />
            </div>
          ) : organizations.length === 0 ? (
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-8 text-center">
              <Building2 size={48} className="text-neutral-600 mx-auto mb-4" />
              <h3 className="text-white font-medium">No organizations yet</h3>
              <p className="text-neutral-400 text-sm mt-1">Create your first organization</p>
            </div>
          ) : (
            organizations.map((org) => (
              <motion.button
                key={org.id}
                onClick={() => setSelectedOrg(org)}
                whileHover={{ scale: 1.01 }}
                className={`w-full text-left p-4 rounded-lg border transition-colors ${
                  selectedOrg?.id === org.id
                    ? 'bg-emerald-500/10 border-emerald-500/30'
                    : 'bg-neutral-900 border-emerald-500/10 hover:border-emerald-500/20'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-bold">
                    {org.name[0].toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="text-white font-medium truncate">{org.name}</h3>
                      {org.role === 'owner' && <Crown size={14} className="text-amber-400" />}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs text-neutral-500">{org.memberCount} members</span>
                      <span className={`px-2 py-0.5 rounded text-xs ${planColors[org.plan]}`}>
                        {org.plan}
                      </span>
                    </div>
                  </div>
                  <ChevronRight size={16} className="text-neutral-500" />
                </div>
              </motion.button>
            ))
          )}
        </div>

        {/* Organization Details */}
        <div className="lg:col-span-2">
          {selectedOrg ? (
            <div className="space-y-6">
              {/* Org Header */}
              <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-16 h-16 rounded-xl bg-emerald-500/20 flex items-center justify-center text-emerald-400 text-2xl font-bold">
                      {selectedOrg.name[0].toUpperCase()}
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-white">{selectedOrg.name}</h2>
                      <p className="text-neutral-400 text-sm">/{selectedOrg.slug}</p>
                      <div className="flex items-center gap-2 mt-2">
                        <span className={`px-2 py-0.5 rounded text-xs ${planColors[selectedOrg.plan]}`}>
                          {selectedOrg.plan}
                        </span>
                        <span className="text-xs text-neutral-500">
                          Created {new Date(selectedOrg.createdAt).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </div>
                  <button className="p-2 text-neutral-400 hover:text-white hover:bg-neutral-800 rounded-lg">
                    <Settings size={20} />
                  </button>
                </div>
              </div>

              {/* Members Section */}
              <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg">
                <div className="p-4 border-b border-emerald-500/10 flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <h3 className="text-white font-medium">Members</h3>
                    <div className="relative">
                      <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
                      <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search members..."
                        className="pl-9 pr-4 py-1.5 bg-neutral-800 border border-neutral-700 rounded-lg text-sm text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>
                  </div>
                  {(selectedOrg.role === 'owner' || selectedOrg.role === 'admin') && (
                    <button
                      onClick={() => setShowInviteModal(true)}
                      className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 text-emerald-400 rounded-lg text-sm hover:bg-emerald-500/20"
                    >
                      <UserPlus size={16} />
                      Invite
                    </button>
                  )}
                </div>
                <div className="divide-y divide-emerald-500/10">
                  {filteredMembers.map((member) => {
                    const RoleIcon = roleIcons[member.role];
                    return (
                      <div key={member.id} className="p-4 flex items-center justify-between hover:bg-neutral-800/50">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-medium">
                            {(member.name || member.email)[0].toUpperCase()}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <p className="text-white font-medium">{member.name || member.email.split('@')[0]}</p>
                              <RoleIcon size={14} className={
                                member.role === 'owner' ? 'text-amber-400' :
                                member.role === 'admin' ? 'text-emerald-400' : 'text-neutral-500'
                              } />
                            </div>
                            <p className="text-sm text-neutral-500">{member.email}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-1 rounded text-xs capitalize ${
                            member.role === 'owner' ? 'bg-amber-500/20 text-amber-400' :
                            member.role === 'admin' ? 'bg-emerald-500/20 text-emerald-400' :
                            'bg-neutral-700 text-neutral-400'
                          }`}>
                            {member.role}
                          </span>
                          {selectedOrg.role === 'owner' && member.role !== 'owner' && (
                            <div className="relative group">
                              <button className="p-1 text-neutral-500 hover:text-white">
                                <MoreVertical size={16} />
                              </button>
                              <div className="absolute right-0 top-full mt-1 w-40 bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                                {member.role === 'member' && (
                                  <button
                                    onClick={() => updateMemberRole(member.id, 'admin')}
                                    className="w-full px-3 py-2 text-left text-sm text-neutral-300 hover:bg-neutral-700"
                                  >
                                    Make Admin
                                  </button>
                                )}
                                {member.role === 'admin' && (
                                  <button
                                    onClick={() => updateMemberRole(member.id, 'member')}
                                    className="w-full px-3 py-2 text-left text-sm text-neutral-300 hover:bg-neutral-700"
                                  >
                                    Remove Admin
                                  </button>
                                )}
                                <button
                                  onClick={() => removeMember(member.id)}
                                  className="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-red-500/10"
                                >
                                  Remove Member
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-12 text-center">
              <Building2 size={48} className="text-neutral-600 mx-auto mb-4" />
              <h3 className="text-white font-medium">Select an organization</h3>
              <p className="text-neutral-400 text-sm mt-1">Choose an organization to view details</p>
            </div>
          )}
        </div>
      </div>

      {/* Create Organization Modal */}
      <AnimatePresence>
        {showCreateModal && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowCreateModal(false)}
              className="fixed inset-0 bg-black/60 z-50"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4"
            >
              <div className="bg-neutral-900 border border-emerald-500/20 rounded-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
                <h2 className="text-xl font-bold text-white mb-4">Create Organization</h2>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-neutral-400 mb-2">Organization Name</label>
                    <input
                      type="text"
                      value={newOrgName}
                      onChange={(e) => setNewOrgName(e.target.value)}
                      placeholder="e.g., Acme Inc"
                      className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                    />
                  </div>
                </div>
                <div className="flex gap-3 mt-6">
                  <button
                    onClick={() => setShowCreateModal(false)}
                    className="flex-1 px-4 py-2 border border-neutral-700 text-neutral-300 rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={createOrganization}
                    disabled={!newOrgName}
                    className="flex-1 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium disabled:opacity-50"
                  >
                    Create
                  </button>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Invite Member Modal */}
      <AnimatePresence>
        {showInviteModal && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowInviteModal(false)}
              className="fixed inset-0 bg-black/60 z-50"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4"
            >
              <div className="bg-neutral-900 border border-emerald-500/20 rounded-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
                <h2 className="text-xl font-bold text-white mb-4">Invite Member</h2>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-neutral-400 mb-2">Email Address</label>
                    <div className="relative">
                      <Mail size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
                      <input
                        type="email"
                        value={inviteEmail}
                        onChange={(e) => setInviteEmail(e.target.value)}
                        placeholder="colleague@company.com"
                        className="w-full pl-10 pr-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm text-neutral-400 mb-2">Role</label>
                    <div className="grid grid-cols-2 gap-3">
                      {(['member', 'admin'] as const).map(role => (
                        <button
                          key={role}
                          onClick={() => setInviteRole(role)}
                          className={`p-3 rounded-lg border text-left transition-colors ${
                            inviteRole === role
                              ? 'border-emerald-500 bg-emerald-500/10'
                              : 'border-neutral-700 hover:border-neutral-600'
                          }`}
                        >
                          <div className="flex items-center gap-2">
                            {role === 'admin' ? <Shield size={16} /> : <Users size={16} />}
                            <span className={`font-medium capitalize ${inviteRole === role ? 'text-white' : 'text-neutral-400'}`}>
                              {role}
                            </span>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="flex gap-3 mt-6">
                  <button
                    onClick={() => setShowInviteModal(false)}
                    className="flex-1 px-4 py-2 border border-neutral-700 text-neutral-300 rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={inviteMember}
                    disabled={!inviteEmail}
                    className="flex-1 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium disabled:opacity-50"
                  >
                    Send Invite
                  </button>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
