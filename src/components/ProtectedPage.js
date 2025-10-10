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
    fetch('/api/logout', { method: 'POST' })
      .then(() => {
        navigate('/');
      })
      .catch(err => {
        console.error('Logout error:', err);
        navigate('/');
      });
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
            <p><strong>Identity Provider:</strong> {credential.idpName}</p>
            {credential.user && (
              <>
                <p><strong>User ID:</strong> {credential.user.id || credential.user.nameID || 'N/A'}</p>
                <p><strong>Email:</strong> {credential.user.email || 'N/A'}</p>
                <p><strong>Name:</strong> {credential.user.name || credential.user.displayName || 'N/A'}</p>
              </>
            )}
          </div>

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
