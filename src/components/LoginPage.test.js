import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import LoginPage from './LoginPage';

describe('LoginPage', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
    delete window.location;
    window.location = { href: '' };
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('renders login page with title', () => {
    global.fetch.mockResolvedValueOnce({
      json: async () => ({ identityProviders: [] })
    });

    render(<LoginPage />);
    expect(screen.getByText('SAML/OIDC Test Application')).toBeInTheDocument();
    expect(screen.getByText('Select an identity provider to log in')).toBeInTheDocument();
  });

  test('fetches and displays identity providers', async () => {
    const mockIdPs = {
      identityProviders: [
        {
          protocol: 'saml20',
          name: 'Test SAML IdP'
        },
        {
          protocol: 'oidc',
          name: 'Test OIDC IdP'
        }
      ]
    };

    global.fetch.mockResolvedValueOnce({
      json: async () => mockIdPs
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(screen.getByText('Test SAML IdP')).toBeInTheDocument();
      expect(screen.getByText('Test OIDC IdP')).toBeInTheDocument();
    });
  });

  test('displays loading message when no providers loaded', () => {
    global.fetch.mockImplementationOnce(() => new Promise(() => {}));

    render(<LoginPage />);
    expect(screen.getByText('Loading identity providers...')).toBeInTheDocument();
  });

  test('displays error message on fetch failure', async () => {
    global.fetch.mockRejectedValueOnce(new Error('Network error'));

    render(<LoginPage />);

    await waitFor(() => {
      expect(screen.getByText('Failed to load identity providers')).toBeInTheDocument();
    });
  });

  test('redirects to SAML login on SAML button click', async () => {
    const mockIdPs = {
      identityProviders: [
        {
          protocol: 'saml20',
          name: 'Test SAML IdP'
        }
      ]
    };

    global.fetch.mockResolvedValueOnce({
      json: async () => mockIdPs
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(screen.getByText('Test SAML IdP')).toBeInTheDocument();
    });

    const button = screen.getByText('Test SAML IdP');
    fireEvent.click(button);

    expect(window.location.href).toContain('/auth/saml/login');
    expect(window.location.href).toContain('idp=Test%20SAML%20IdP');
  });

  test('redirects to OIDC login on OIDC button click', async () => {
    const mockIdPs = {
      identityProviders: [
        {
          protocol: 'oidc',
          name: 'Test OIDC IdP'
        }
      ]
    };

    global.fetch.mockResolvedValueOnce({
      json: async () => mockIdPs
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(screen.getByText('Test OIDC IdP')).toBeInTheDocument();
    });

    const button = screen.getByText('Test OIDC IdP');
    fireEvent.click(button);

    expect(window.location.href).toContain('/auth/oidc/login');
    expect(window.location.href).toContain('idp=Test%20OIDC%20IdP');
  });

  test('applies correct CSS classes to buttons', async () => {
    const mockIdPs = {
      identityProviders: [
        {
          protocol: 'saml20',
          name: 'SAML IdP'
        },
        {
          protocol: 'oidc',
          name: 'OIDC IdP'
        }
      ]
    };

    global.fetch.mockResolvedValueOnce({
      json: async () => mockIdPs
    });

    render(<LoginPage />);

    await waitFor(() => {
      const samlButton = screen.getByText('SAML IdP').closest('button');
      const oidcButton = screen.getByText('OIDC IdP').closest('button');

      expect(samlButton).toHaveClass('saml20');
      expect(oidcButton).toHaveClass('oidc');
    });
  });
});
