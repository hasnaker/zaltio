/**
 * SessionList Component Tests
 * @zalt/react
 * 
 * Tests for the SessionList component - session management UI.
 * Validates: Requirement 13.7
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Session } from '../../hooks/useSessions';

// Mock Data
const mockSessions: Session[] = [
  {
    id: 'session_1',
    device: 'MacBook Pro',
    browser: 'Chrome 120',
    ip_address: '192.168.1.1',
    location: { city: 'San Francisco', country: 'United States', country_code: 'US' },
    last_activity: new Date().toISOString(),
    created_at: '2026-01-25T10:00:00Z',
    is_current: true,
    user_agent: 'Mozilla/5.0 (Macintosh)',
  },
  {
    id: 'session_2',
    device: 'iPhone 15',
    browser: 'Safari 17',
    ip_address: '10.0.0.1',
    location: { city: 'New York', country: 'United States', country_code: 'US' },
    last_activity: new Date(Date.now() - 3600000).toISOString(),
    created_at: '2026-01-24T08:00:00Z',
    is_current: false,
    user_agent: 'Mozilla/5.0 (iPhone)',
  },
  {
    id: 'session_3',
    device: 'Pixel 8',
    browser: 'Chrome 120',
    ip_address: '172.16.0.1',
    location: { city: 'London', country: 'United Kingdom', country_code: 'GB' },
    last_activity: new Date(Date.now() - 86400000).toISOString(),
    created_at: '2026-01-23T14:00:00Z',
    is_current: false,
    user_agent: 'Mozilla/5.0 (Linux; Android)',
  },
];

// Mock Setup
const mockRevokeSession = vi.fn().mockResolvedValue(true);
const mockRevokeAllSessions = vi.fn().mockResolvedValue(2);
const mockClearError = vi.fn();
const mockFetchSessions = vi.fn();

const createMockReturn = (overrides = {}) => ({
  sessions: mockSessions,
  currentSession: mockSessions[0],
  otherSessions: mockSessions.filter(s => !s.is_current),
  totalSessions: mockSessions.length,
  impossibleTravelDetected: false,
  isLoading: false,
  error: null,
  fetchSessions: mockFetchSessions,
  revokeSession: mockRevokeSession,
  revokeAllSessions: mockRevokeAllSessions,
  clearError: mockClearError,
  ...overrides,
});

vi.mock('../../hooks/useSessions', () => ({
  useSessions: vi.fn(() => createMockReturn()),
}));

import { SessionList } from '../SessionList';
import { useSessions } from '../../hooks/useSessions';

const mockConfirm = vi.fn();
global.confirm = mockConfirm;

describe('SessionList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfirm.mockReturnValue(true);
    mockRevokeSession.mockResolvedValue(true);
    mockRevokeAllSessions.mockResolvedValue(2);
    (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn());
  });

  describe('rendering', () => {
    it('should render session list with title', () => {
      render(<SessionList accessToken="test" />);
      expect(screen.getByText('Active Sessions')).toBeDefined();
    });

    it('should render custom title', () => {
      render(<SessionList accessToken="test" title="My Sessions" />);
      expect(screen.getByText('My Sessions')).toBeDefined();
    });

    it('should hide title when hideTitle is true', () => {
      render(<SessionList accessToken="test" hideTitle />);
      expect(screen.queryByText('Active Sessions')).toBeNull();
    });

    it('should render all sessions', () => {
      render(<SessionList accessToken="test" />);
      expect(screen.getByTestId('session-session_1')).toBeDefined();
      expect(screen.getByTestId('session-session_2')).toBeDefined();
      expect(screen.getByTestId('session-session_3')).toBeDefined();
    });

    it('should show current session indicator', () => {
      render(<SessionList accessToken="test" />);
      expect(screen.getByText('Current')).toBeDefined();
    });

    it('should show device names', () => {
      render(<SessionList accessToken="test" />);
      expect(screen.getByText(/MacBook Pro/)).toBeDefined();
      expect(screen.getByText(/iPhone 15/)).toBeDefined();
      expect(screen.getByText(/Pixel 8/)).toBeDefined();
    });

    it('should show location info when showLocation is true', () => {
      render(<SessionList accessToken="test" showLocation />);
      expect(screen.getByText('San Francisco, United States')).toBeDefined();
      expect(screen.getByText('New York, United States')).toBeDefined();
      expect(screen.getByText('London, United Kingdom')).toBeDefined();
    });
  });

  describe('revoke session', () => {
    it('should show revoke button for non-current sessions', () => {
      render(<SessionList accessToken="test" />);
      const revokeButtons = screen.getAllByText('Revoke');
      expect(revokeButtons).toHaveLength(2);
    });

    it('should call revokeSession when revoke button is clicked', async () => {
      render(<SessionList accessToken="test" confirmRevoke={false} />);
      const revokeButtons = screen.getAllByText('Revoke');
      fireEvent.click(revokeButtons[0]);
      await waitFor(() => {
        expect(mockRevokeSession).toHaveBeenCalledWith('session_2');
      });
    });

    it('should show confirmation dialog when confirmRevoke is true', async () => {
      render(<SessionList accessToken="test" confirmRevoke />);
      const revokeButtons = screen.getAllByText('Revoke');
      fireEvent.click(revokeButtons[0]);
      expect(mockConfirm).toHaveBeenCalled();
    });

    it('should not revoke when confirmation is cancelled', async () => {
      mockConfirm.mockReturnValue(false);
      render(<SessionList accessToken="test" confirmRevoke />);
      const revokeButtons = screen.getAllByText('Revoke');
      fireEvent.click(revokeButtons[0]);
      expect(mockRevokeSession).not.toHaveBeenCalled();
    });
  });

  describe('revoke all sessions', () => {
    it('should show revoke all button when showRevokeAll is true', () => {
      render(<SessionList accessToken="test" showRevokeAll />);
      expect(screen.getByText('Revoke All Others')).toBeDefined();
    });

    it('should hide revoke all button when showRevokeAll is false', () => {
      render(<SessionList accessToken="test" showRevokeAll={false} />);
      expect(screen.queryByText('Revoke All Others')).toBeNull();
    });

    it('should call revokeAllSessions when revoke all button is clicked', async () => {
      render(<SessionList accessToken="test" showRevokeAll confirmRevoke={false} />);
      const revokeAllButton = screen.getByText('Revoke All Others');
      fireEvent.click(revokeAllButton);
      await waitFor(() => {
        expect(mockRevokeAllSessions).toHaveBeenCalled();
      });
    });

    it('should not show revoke all button when only current session exists', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        sessions: [mockSessions[0]],
        otherSessions: [],
      }));
      render(<SessionList accessToken="test" showRevokeAll />);
      expect(screen.queryByText('Revoke All Others')).toBeNull();
    });
  });

  describe('loading state', () => {
    it('should show loading spinner when loading', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        sessions: [],
        isLoading: true,
      }));
      render(<SessionList accessToken="test" />);
      const container = document.querySelector('.zalt-session-list');
      expect(container).toBeDefined();
    });
  });

  describe('empty state', () => {
    it('should show empty message when no sessions', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        sessions: [],
        otherSessions: [],
        totalSessions: 0,
        currentSession: null,
        isLoading: false,
      }));
      render(<SessionList accessToken="test" />);
      expect(screen.getByText('No active sessions found.')).toBeDefined();
    });

    it('should show custom empty message', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        sessions: [],
        otherSessions: [],
        totalSessions: 0,
        currentSession: null,
        isLoading: false,
      }));
      render(<SessionList accessToken="test" emptyMessage="Custom empty message" />);
      expect(screen.getByText('Custom empty message')).toBeDefined();
    });
  });

  describe('error state', () => {
    it('should show error message when error occurs', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        error: 'Failed to load sessions',
      }));
      render(<SessionList accessToken="test" />);
      expect(screen.getByText('Failed to load sessions')).toBeDefined();
    });

    it('should clear error when dismiss button is clicked', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        error: 'Failed to load sessions',
      }));
      render(<SessionList accessToken="test" />);
      const dismissButton = screen.getByLabelText('Dismiss error');
      fireEvent.click(dismissButton);
      expect(mockClearError).toHaveBeenCalled();
    });
  });

  describe('impossible travel warning', () => {
    it('should show impossible travel warning when detected', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        impossibleTravelDetected: true,
      }));
      render(<SessionList accessToken="test" />);
      expect(screen.getByText(/Security Alert/)).toBeDefined();
    });

    it('should not show warning when not detected', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn());
      render(<SessionList accessToken="test" />);
      expect(screen.queryByText(/Security Alert/)).toBeNull();
    });
  });

  describe('custom class name', () => {
    it('should apply custom class name', () => {
      (useSessions as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn());
      const { container } = render(<SessionList accessToken="test" className="custom-class" />);
      expect(container.querySelector('.custom-class')).toBeDefined();
    });
  });
});
