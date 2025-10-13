const fs = require('fs');
const path = require('path');

function loadConfig() {
  const configPath = path.join(__dirname, '../../data/config.json');

  try {
    const configData = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(configData);

    // Validate application configuration if present
    if (config.application) {
      validateApplicationConfig(config.application);
    }

    // Validate configuration
    if (!config.identityProviders || !Array.isArray(config.identityProviders)) {
      throw new Error('Invalid configuration: identityProviders array is required');
    }

    // Validate each IdP configuration
    config.identityProviders.forEach((idp, index) => {
      if (!idp.protocol || !['saml20', 'oidc'].includes(idp.protocol)) {
        throw new Error(`Invalid protocol for IdP at index ${index}: must be 'saml20' or 'oidc'`);
      }

      if (!idp.name) {
        throw new Error(`Missing name for IdP at index ${index}`);
      }

      if (idp.protocol === 'saml20') {
        validateSamlConfig(idp, index);
      } else if (idp.protocol === 'oidc') {
        validateOidcConfig(idp, index);
      }
    });

    return config;
  } catch (error) {
    console.error('Error loading configuration:', error.message);
    throw error;
  }
}

function validateSamlConfig(idp, index) {
  const required = ['loginUrl', 'logoutUrl', 'certificate'];
  required.forEach(field => {
    if (!idp[field]) {
      throw new Error(`Missing ${field} for SAML IdP at index ${index}`);
    }
  });

  // Validate binding if provided, default to 'redirect'
  if (idp.binding && !['redirect', 'post'].includes(idp.binding)) {
    throw new Error(`Invalid binding for SAML IdP at index ${index}: must be 'redirect' or 'post'`);
  }

  // Set default binding to 'redirect' if not specified
  if (!idp.binding) {
    idp.binding = 'redirect';
  }
}

function validateOidcConfig(idp, index) {
  const required = ['tenantUrl', 'issuerUrl', 'authorizationUrl', 'tokenUrl',
                    'clientId', 'clientSecret', 'scope'];
  required.forEach(field => {
    if (!idp[field]) {
      throw new Error(`Missing ${field} for OIDC IdP at index ${index}`);
    }
  });
}

function validateApplicationConfig(app) {
  // Set default publicPort to match port if not specified
  if (!app.publicPort) {
    app.publicPort = app.port || 3001;
  }

  // Validate HTTPS configuration
  if (app.useHttps) {
    const required = ['serverCertificate', 'serverPrivateKey'];
    required.forEach(field => {
      if (!app[field]) {
        throw new Error(`Missing ${field} in application configuration when useHttps is true`);
      }
    });

    // Verify certificate and key files exist
    const certPath = path.join(__dirname, '../../data', app.serverCertificate);
    const keyPath = path.join(__dirname, '../../data', app.serverPrivateKey);

    if (!fs.existsSync(certPath)) {
      throw new Error(`Server certificate file not found: ${certPath}`);
    }

    if (!fs.existsSync(keyPath)) {
      throw new Error(`Server private key file not found: ${keyPath}`);
    }
  }
}

function loadCertificate(filename) {
  const certPath = path.join(__dirname, '../../data/certificates', filename);

  try {
    return fs.readFileSync(certPath, 'utf8');
  } catch (error) {
    console.error(`Error loading certificate ${filename}:`, error.message);
    throw new Error(`Failed to load certificate: ${filename}`);
  }
}

module.exports = {
  loadConfig,
  loadCertificate
};
