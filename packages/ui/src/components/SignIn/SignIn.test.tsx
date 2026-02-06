import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { SignIn } from './index';
import { ThemeProvider } from '../../theme/ThemeProvider';

const renderWithTheme = (ui: React.ReactElement) => {
  return render(<ThemeProvider>{ui}</ThemeProvider>);
};

describe('SignIn', () => {
  it('renders sign in form', () => {
    renderWithTheme(<SignIn />);
    
    expect(screen.getByRole('heading', { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/enter your password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  it('renders custom header text', () => {
    renderWithTheme(<SignIn headerText="Welcome back" />);
    
    expect(screen.getByRole('heading', { name: 'Welcome back' })).toBeInTheDocument();
  });

  it('renders sign up link', () => {
    renderWithTheme(<SignIn signUpUrl="/register" />);
    
    const link = screen.getByText(/sign up/i);
    expect(link).toHaveAttribute('href', '/register');
  });

  it('renders forgot password link', () => {
    renderWithTheme(<SignIn forgotPasswordUrl="/reset" />);
    
    const link = screen.getByText(/forgot your password/i);
    expect(link).toHaveAttribute('href', '/reset');
  });

  it('renders social buttons when providers are specified', () => {
    renderWithTheme(
      <SignIn 
        socialProviders={['google', 'github']} 
        socialSignInHandler={vi.fn()}
      />
    );
    
    expect(screen.getByText(/continue with google/i)).toBeInTheDocument();
    expect(screen.getByText(/continue with github/i)).toBeInTheDocument();
  });

  it('calls signInHandler on form submit', async () => {
    const mockHandler = vi.fn().mockResolvedValue({
      success: true,
      userId: 'user_123',
      accessToken: 'token_123',
    });

    renderWithTheme(<SignIn signInHandler={mockHandler} />);

    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'test@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText(/enter your password/i), {
      target: { value: 'password123' },
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(mockHandler).toHaveBeenCalledWith('test@example.com', 'password123');
    });
  });

  it('displays error message on failed sign in', async () => {
    const mockHandler = vi.fn().mockResolvedValue({
      success: false,
      error: 'Invalid credentials',
    });

    renderWithTheme(<SignIn signInHandler={mockHandler} />);

    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'test@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText(/enter your password/i), {
      target: { value: 'wrongpassword' },
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText('Invalid credentials')).toBeInTheDocument();
    });
  });

  it('shows MFA challenge when mfaRequired is true', async () => {
    const mockHandler = vi.fn().mockResolvedValue({
      success: false,
      mfaRequired: true,
      mfaSessionId: 'mfa_session_123',
      mfaMethods: ['totp'],
    });

    renderWithTheme(<SignIn signInHandler={mockHandler} />);

    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'test@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText(/enter your password/i), {
      target: { value: 'password123' },
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText('Two-Factor Authentication')).toBeInTheDocument();
    });
  });

  it('disables form while loading', async () => {
    const mockHandler = vi.fn().mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 1000))
    );

    renderWithTheme(<SignIn signInHandler={mockHandler} />);

    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'test@example.com' },
    });
    fireEvent.change(screen.getByPlaceholderText(/enter your password/i), {
      target: { value: 'password123' },
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByLabelText(/email/i)).toBeDisabled();
      expect(screen.getByPlaceholderText(/enter your password/i)).toBeDisabled();
    });
  });
});
