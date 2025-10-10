import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import ProtectedPage from './ProtectedPage';

const mockNavigate = jest.fn();

jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useNavigate: () => mockNavigate
}));

describe('ProtectedPage', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
    mockNavigate.mockClear();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const renderProtectedPage = () => {
    return render(
      <BrowserRouter>
        <ProtectedPage />
      </BrowserRouter>
    );
  };

  test('displays loading state initially', () => {
    global.fetch.mockImplementationOnce(() => new Promise(() => {}));

    renderProtectedPage();
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  test('redirects to home page when not authenticated', async () => {
    global.fetch.mockRejectedValueOnce(new Error('Not authenticated'));

    renderProtectedPage();

    await waitFor(() => {
      expect(screen.getByText('Not authenticated. Please log in.')).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/');
    }, { timeout: 3000 });
  });

  test('displays SAML credential information', async () => {
    const mockCredential = {
      protocol: 'saml20',
      idpName: 'Test SAML IdP',
      user: {
        id: 'user123',
        nameID: 'user@example.com',
        email: 'user@example.com',
        name: 'Test User'
      },
      samlAssertion: '<saml:Assertion>...</saml:Assertion>'
    };

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockCredential
    });

    renderProtectedPage();

    await waitFor(() => {
      expect(screen.getByText('Protected Page')).toBeInTheDocument();
      expect(screen.getByText('You have successfully authenticated!')).toBeInTheDocument();
      expect(screen.getByText(/Protocol:/)).toBeInTheDocument();
      expect(screen.getByText('saml20')).toBeInTheDocument();
      expect(screen.getByText('Test SAML IdP')).toBeInTheDocument();
    });
  });

  test('displays OIDC credential information', async () => {
    const mockCredential = {
      protocol: 'oidc',
      idpName: 'Test OIDC IdP',
      user: {
        id: 'user456',
        email: 'oidc@example.com',
        name: 'OIDC User'
      },
      jwtToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
    };

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockCredential
    });

    renderProtectedPage();

    await waitFor(() => {
      expect(screen.getByText('oidc')).toBeInTheDocument();
      expect(screen.getByText('Test OIDC IdP')).toBeInTheDocument();
      expect(screen.getByText(/JWT Token/)).toBeInTheDocument();
    });
  });

  test('displays full credential information in JSON format', async () => {
    const mockCredential = {
      protocol: 'saml20',
      idpName: 'Test IdP',
      user: {
        email: 'test@example.com'
      }
    };

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockCredential
    });

    renderProtectedPage();

    await waitFor(() => {
      const jsonElement = screen.getByText((content, element) => {
        return element.tagName.toLowerCase() === 'pre' &&
               content.includes('"protocol"');
      });
      expect(jsonElement).toBeInTheDocument();
    });
  });

  test('logout button calls logout API and redirects', async () => {
    const mockCredential = {
      protocol: 'oidc',
      idpName: 'Test IdP',
      user: { email: 'test@example.com' }
    };

    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockCredential
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true })
      });

    renderProtectedPage();

    await waitFor(() => {
      expect(screen.getByText('Logout')).toBeInTheDocument();
    });

    const logoutButton = screen.getByText('Logout');
    fireEvent.click(logoutButton);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/logout', { method: 'POST' });
      expect(mockNavigate).toHaveBeenCalledWith('/');
    });
  });

  test('handles logout error gracefully', async () => {
    const mockCredential = {
      protocol: 'oidc',
      idpName: 'Test IdP',
      user: { email: 'test@example.com' }
    };

    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => mockCredential
      })
      .mockRejectedValueOnce(new Error('Logout failed'));

    renderProtectedPage();

    await waitFor(() => {
      expect(screen.getByText('Logout')).toBeInTheDocument();
    });

    const logoutButton = screen.getByText('Logout');
    fireEvent.click(logoutButton);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/');
    });
  });
});
