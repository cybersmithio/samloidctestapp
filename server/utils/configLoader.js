const fs = require('fs');
const path = require('path');

function loadConfig() {
  const configPath = path.join(__dirname, '../../data/config.json');

  try {
    const configData = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(configData);

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
}

function validateOidcConfig(idp, index) {
  const required = ['tenantUrl', 'issuerUrl', 'authorizationUrl', 'tokenUrl',
                    'clientId', 'clientSecret', 'callbackUrl', 'scope'];
  required.forEach(field => {
    if (!idp[field]) {
      throw new Error(`Missing ${field} for OIDC IdP at index ${index}`);
    }
  });
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
