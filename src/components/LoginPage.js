import React, { useState, useEffect } from 'react';

function LoginPage() {
  const [identityProviders, setIdentityProviders] = useState([]);
  const [appConfig, setAppConfig] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Fetch identity providers and application config from backend
    fetch('/api/config')
      .then(response => response.json())
      .then(data => {
        setIdentityProviders(data.identityProviders);
        setAppConfig(data.application);
      })
      .catch(err => {
        setError('Failed to load identity providers');
        console.error(err);
      });
  }, []);

  const handleLogin = (idp) => {
    // Frontend is served by backend on same port, so use relative URLs
    if (idp.protocol === 'saml20') {
      // Redirect to SAML login endpoint
      window.location.href = `/auth/saml/login?idp=${encodeURIComponent(idp.name)}`;
    } else if (idp.protocol === 'oidc') {
      // Redirect to OIDC login endpoint
      window.location.href = `/auth/oidc/login?idp=${encodeURIComponent(idp.name)}`;
    }
  };

  const handleDownloadMetadata = async (idpName = null) => {
    try {
      // Determine which metadata endpoint to use
      const endpoint = idpName ? `/saml/metadata/${encodeURIComponent(idpName)}` : '/saml/metadata';

      // Fetch the metadata from the backend
      const response = await fetch(endpoint);

      if (!response.ok) {
        throw new Error('Failed to fetch metadata');
      }

      // Get the XML content as blob
      const blob = await response.blob();

      // Get filename from Content-Disposition header if available
      let filename = 'metadata.xml';
      const contentDisposition = response.headers.get('Content-Disposition');
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="([^"]+)"/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Create a temporary download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;

      // Trigger the download
      document.body.appendChild(link);
      link.click();

      // Cleanup
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading metadata:', error);
      setError('Failed to download metadata. Please try again.');
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
          <div key={index} style={{ position: 'relative', display: 'inline-block', width: '100%' }}>
            <button
              className={`idp-button ${idp.protocol}`}
              onClick={() => handleLogin(idp)}
              style={{ width: '100%', textAlign: 'left', paddingRight: '120px' }}
            >
              <span style={{ display: 'block' }}>
                {idp.name}
                <br />
                <small style={{ fontSize: '0.8rem', opacity: 0.9 }}>
                  ({idp.protocol === 'saml20' ? 'SAML 2.0' : 'OIDC'})
                </small>
              </span>
            </button>

            {/* Per-IdP metadata download button for SAML */}
            {idp.protocol === 'saml20' && idp.hasCustomMetadata && (
              <button
                onClick={() => handleDownloadMetadata(idp.name)}
                title={`Download metadata for ${idp.name}`}
                style={{
                  position: 'absolute',
                  right: '8px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  backgroundColor: '#17a2b8',
                  color: 'white',
                  padding: '6px 10px',
                  border: 'none',
                  borderRadius: '3px',
                  cursor: 'pointer',
                  fontSize: '12px',
                  whiteSpace: 'nowrap',
                  fontWeight: '500'
                }}
              >
                ⬇ Metadata
              </button>
            )}
          </div>
        ))}
      </div>

      {identityProviders.length === 0 && !error && (
        <p style={{ textAlign: 'center', color: '#999', marginTop: '2rem' }}>
          Loading identity providers...
        </p>
      )}

      <div style={{ marginTop: '3rem', paddingTop: '2rem', borderTop: '1px solid #ddd' }}>
        <h2 style={{ fontSize: '1.2rem', color: '#666', textAlign: 'center', marginBottom: '1rem' }}>
          Service Provider Metadata
        </h2>
        <p style={{ textAlign: 'center', color: '#888', fontSize: '0.9rem', marginBottom: '1rem' }}>
          Download the SAML metadata file to configure this application as a Service Provider in your Identity Provider
        </p>
        <div style={{ textAlign: 'center' }}>
          <button
            className="metadata-button"
            onClick={handleDownloadMetadata}
            style={{
              backgroundColor: '#28a745',
              color: 'white',
              padding: '12px 24px',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '16px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            <span style={{ fontSize: '1.2rem' }}>⬇</span>
            Download SAML Metadata
          </button>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
