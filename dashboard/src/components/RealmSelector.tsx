'use client';

import { useState, useEffect, useRef } from 'react';
import { Realm } from '@/types/realm';

interface RealmSelectorProps {
  selectedRealmId: string | null;
  onRealmChange: (realmId: string | null) => void;
  showAllOption?: boolean;
  className?: string;
}

/**
 * RealmSelector Component
 * Provides realm selection and configuration UI
 * Validates: Requirements 3.2, 3.5
 */
export default function RealmSelector({
  selectedRealmId,
  onRealmChange,
  showAllOption = true,
  className = ''
}: RealmSelectorProps) {
  const [realms, setRealms] = useState<Realm[]>([]);
  const [loading, setLoading] = useState(true);
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch('/api/realms')
      .then(res => res.json())
      .then(data => {
        setRealms(data.realms || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const selectedRealm = realms.find(r => r.id === selectedRealmId);

  if (loading) {
    return (
      <div className={`animate-pulse bg-gray-200 h-10 w-48 rounded-md ${className}`} />
    );
  }

  return (
    <div className={`relative ${className}`} ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center justify-between w-full px-4 py-2 bg-white border border-gray-300 rounded-md shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-hsd-primary"
      >
        <div className="flex items-center">
          {selectedRealm ? (
            <>
              <div className="h-6 w-6 bg-hsd-primary rounded flex items-center justify-center text-white text-xs font-bold mr-2">
                {selectedRealm.name.charAt(0).toUpperCase()}
              </div>
              <span className="text-sm font-medium text-gray-900">{selectedRealm.name}</span>
            </>
          ) : (
            <>
              <div className="h-6 w-6 bg-gray-400 rounded flex items-center justify-center text-white text-xs mr-2">
                🏰
              </div>
              <span className="text-sm text-gray-500">All Realms</span>
            </>
          )}
        </div>
        <svg className={`h-5 w-5 text-gray-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} viewBox="0 0 20 20" fill="currentColor">
          <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
        </svg>
      </button>

      {isOpen && (
        <div className="absolute z-10 mt-1 w-full bg-white border border-gray-200 rounded-md shadow-lg max-h-60 overflow-auto">
          {showAllOption && (
            <button
              onClick={() => {
                onRealmChange(null);
                setIsOpen(false);
              }}
              className={`w-full px-4 py-2 text-left hover:bg-gray-100 flex items-center ${
                !selectedRealmId ? 'bg-hsd-primary/10' : ''
              }`}
            >
              <div className="h-6 w-6 bg-gray-400 rounded flex items-center justify-center text-white text-xs mr-2">
                🏰
              </div>
              <span className="text-sm">All Realms</span>
            </button>
          )}
          {realms.map(realm => (
            <button
              key={realm.id}
              onClick={() => {
                onRealmChange(realm.id);
                setIsOpen(false);
              }}
              className={`w-full px-4 py-2 text-left hover:bg-gray-100 flex items-center ${
                selectedRealmId === realm.id ? 'bg-hsd-primary/10' : ''
              }`}
            >
              <div className="h-6 w-6 bg-hsd-primary rounded flex items-center justify-center text-white text-xs font-bold mr-2">
                {realm.name.charAt(0).toUpperCase()}
              </div>
              <div>
                <span className="text-sm font-medium block">{realm.name}</span>
                <span className="text-xs text-gray-500">{realm.domain}</span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
