import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

function ProtectedPage() {
  const [credential, setCredential] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    // Fetch credential information from session
    fetch('/api/session')
      .then(response => {
        if (!response.ok) {
          throw new Error('Not authenticated');
        }
        return response.json();
      })
      .then(data => {
        setCredential(data);
        setLoading(false);
      })
      .catch(err => {
        setError('Not authenticated. Please log in.');
        setLoading(false);
        setTimeout(() => navigate('/'), 2000);
      });
  }, [navigate]);

  const handleLogout = () => {
    // For SAML, redirect to SAML logout endpoint to send LogoutRequest to IdP
    // For OIDC, redirect to OIDC logout endpoint
    // Otherwise, use the generic API logout
    if (credential?.protocol === 'saml20') {
      // Redirect to SAML logout - this will generate a LogoutRequest and send to IdP
      window.location.href = '/auth/saml/logout';
    } else if (credential?.protocol === 'oidc') {
      // Redirect to OIDC logout
      window.location.href = '/auth/oidc/logout';
    } else {
      // Generic logout for other protocols or local-only logout
      fetch('/api/logout', { method: 'POST' })
        .then(() => {
          navigate('/');
        })
        .catch(err => {
          console.error('Logout error:', err);
          navigate('/');
        });
    }
  };

  if (loading) {
    return (
      <div className="container">
        <h1>Loading...</h1>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container">
        <h1>Protected Page</h1>
        <div className="error-message">{error}</div>
      </div>
    );
  }

  return (
    <div className="container">
      <h1>Protected Page</h1>
      <p style={{ textAlign: 'center', color: '#666', marginBottom: '2rem' }}>
        You have successfully authenticated!
      </p>

      {credential && (
        <>
          <div className="info-section">
            <h2>Authentication Details</h2>
            <p><strong>Protocol:</strong> {credential.protocol}</p>
            {credential.idpName && (
              <p><strong>Identity Provider:</strong> {credential.idpName}</p>
            )}
            {credential.verifiedBy && (
              <p><strong>Verified By Certificate:</strong> {credential.verifiedBy}</p>
            )}
            {credential.authenticatedAt && (
              <p><strong>Authenticated At:</strong> {new Date(credential.authenticatedAt).toLocaleString()}</p>
            )}
          </div>

          {credential.user && (
            <div className="info-section">
              <h2>User Information</h2>
              <p><strong>User ID:</strong> {credential.user.id || credential.user.nameID || 'N/A'}</p>
              {credential.user.email && (
                <p><strong>Email:</strong> {credential.user.email}</p>
              )}
              {credential.user.name && (
                <p><strong>Name:</strong> {credential.user.name}</p>
              )}
              {credential.user.firstName && (
                <p><strong>First Name:</strong> {credential.user.firstName}</p>
              )}
              {credential.user.lastName && (
                <p><strong>Last Name:</strong> {credential.user.lastName}</p>
              )}
              {credential.user.displayName && (
                <p><strong>Display Name:</strong> {credential.user.displayName}</p>
              )}
            </div>
          )}

          <div className="credential-info">
            <h2>Full Credential Information</h2>
            <pre>{JSON.stringify(credential, null, 2)}</pre>
          </div>

          {credential.samlAssertion && (
            <div className="credential-info">
              <h2>SAML Assertion</h2>
              <pre>{credential.samlAssertion}</pre>
            </div>
          )}

          {credential.jwtToken && (
            <div className="credential-info">
              <h2>JWT Token</h2>
              <pre>{credential.jwtToken}</pre>
            </div>
          )}

          <button className="logout-button" onClick={handleLogout}>
            Logout
          </button>
        </>
      )}
    </div>
  );
}

export default ProtectedPage;
