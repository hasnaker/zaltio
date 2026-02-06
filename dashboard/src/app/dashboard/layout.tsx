'use client';

import { useState, useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { ClerkSidebar } from '@/components/dashboard/ClerkSidebar';
import { ClerkHeader } from '@/components/dashboard/ClerkHeader';
import { AdminUser } from '@/types/auth';

// Page transition variants
const pageTransition = {
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -8 },
};

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<AdminUser | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [notifications, setNotifications] = useState(0);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch user data
  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await fetch('/api/auth/me');
        if (res.ok) {
          const data = await res.json();
          if (data?.user) {
            setUser(data.user);
          }
        }
      } catch {
        // Silent fail - user not authenticated
      } finally {
        setIsLoading(false);
      }
    };
    fetchUser();
  }, []);

  // Fetch notifications count
  useEffect(() => {
    const fetchNotifications = async () => {
      try {
        const res = await fetch('/api/dashboard/notifications/count');
        if (res.ok) {
          const data = await res.json();
          setNotifications(data.count || 0);
        }
      } catch {
        // Silent fail
      }
    };
    fetchNotifications();
  }, []);

  // Handle responsive sidebar
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth < 1024) {
        setSidebarCollapsed(true);
      }
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    router.push('/login');
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-neutral-50 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary to-accent animate-pulse" />
          <p className="text-sm text-neutral-500">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-neutral-50 flex">
      {/* Subtle gradient background */}
      <div 
        className="fixed inset-0 pointer-events-none"
        style={{
          background: 'radial-gradient(ellipse at top right, rgba(108, 71, 255, 0.03) 0%, transparent 50%), radial-gradient(ellipse at bottom left, rgba(0, 212, 255, 0.02) 0%, transparent 50%)',
        }}
      />

      {/* Sidebar - Desktop */}
      <div className="hidden lg:block relative z-20">
        <ClerkSidebar
          user={user}
          onLogout={handleLogout}
          defaultCollapsed={sidebarCollapsed}
        />
      </div>

      {/* Mobile Sidebar Overlay */}
      <MobileSidebar
        user={user}
        onLogout={handleLogout}
        pathname={pathname}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-h-screen relative z-10">
        {/* Header */}
        <ClerkHeader
          user={user}
          onLogout={handleLogout}
          notifications={notifications}
        />

        {/* Page Content with Transitions */}
        <main className="flex-1 p-6 overflow-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={pathname}
              initial="initial"
              animate="animate"
              exit="exit"
              variants={pageTransition}
              transition={{ duration: 0.2, ease: 'easeOut' }}
              className="h-full"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}

// Mobile Sidebar Component
function MobileSidebar({ 
  user, 
  onLogout, 
  pathname 
}: { 
  user: AdminUser | null; 
  onLogout: () => void; 
  pathname: string;
}) {
  const [isOpen, setIsOpen] = useState(false);

  // Close on route change
  useEffect(() => {
    setIsOpen(false);
  }, [pathname]);

  return (
    <>
      {/* Mobile Menu Button - shown in header on mobile */}
      <button
        onClick={() => setIsOpen(true)}
        className="lg:hidden fixed top-4 left-4 z-50 w-10 h-10 rounded-lg bg-white shadow-md 
                   border border-neutral-200 flex items-center justify-center text-neutral-600
                   hover:bg-neutral-50 transition-colors"
        aria-label="Open menu"
      >
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M3 12h18M3 6h18M3 18h18" />
        </svg>
      </button>

      {/* Overlay */}
      <AnimatePresence>
        {isOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsOpen(false)}
              className="lg:hidden fixed inset-0 bg-black/20 backdrop-blur-sm z-40"
            />
            <motion.div
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: 'spring', damping: 25, stiffness: 300 }}
              className="lg:hidden fixed left-0 top-0 h-full z-50"
            >
              <ClerkSidebar
                user={user}
                onLogout={onLogout}
                defaultCollapsed={false}
              />
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
