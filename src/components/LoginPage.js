import React, { useState, useEffect } from 'react';

function LoginPage() {
  const [identityProviders, setIdentityProviders] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Fetch identity providers from backend
    fetch('/api/config')
      .then(response => response.json())
      .then(data => {
        setIdentityProviders(data.identityProviders);
      })
      .catch(err => {
        setError('Failed to load identity providers');
        console.error(err);
      });
  }, []);

  const handleLogin = (idp) => {
    if (idp.protocol === 'saml20') {
      // Redirect to SAML login endpoint
      window.location.href = `/auth/saml/login?idp=${encodeURIComponent(idp.name)}`;
    } else if (idp.protocol === 'oidc') {
      // Redirect to OIDC login endpoint
      window.location.href = `/auth/oidc/login?idp=${encodeURIComponent(idp.name)}`;
    }
  };

  return (
    <div className="container">
      <h1>SAML/OIDC Test Application</h1>
      <p style={{ textAlign: 'center', color: '#666', marginBottom: '2rem' }}>
        Select an identity provider to log in
      </p>

      {error && <div className="error-message">{error}</div>}

      <div className="login-buttons">
        {identityProviders.map((idp, index) => (
          <button
            key={index}
            className={`idp-button ${idp.protocol}`}
            onClick={() => handleLogin(idp)}
          >
            {idp.name}
            <br />
            <small style={{ fontSize: '0.8rem', opacity: 0.9 }}>
              ({idp.protocol === 'saml20' ? 'SAML 2.0' : 'OIDC'})
            </small>
          </button>
        ))}
      </div>

      {identityProviders.length === 0 && !error && (
        <p style={{ textAlign: 'center', color: '#999', marginTop: '2rem' }}>
          Loading identity providers...
        </p>
      )}
    </div>
  );
}

export default LoginPage;
