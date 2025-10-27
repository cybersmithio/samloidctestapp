/**
 * Configuration display utility
 * Logs configuration to terminal with sensitive values masked
 */

// List of sensitive keys to mask
const SENSITIVE_KEYS = ['clientSecret', 'samlSigningPrivateKey', 'serverPrivateKey'];

/**
 * Masks sensitive values in configuration
 * @param {string} key - The configuration key
 * @param {*} value - The configuration value
 * @returns {*} - The value or masked string
 */
function maskSensitiveValue(key, value) {
  if (typeof value === 'string' && SENSITIVE_KEYS.some(sensitive => key.includes(sensitive))) {
    return '***' + (value.length > 3 ? value.slice(-3) : '***');
  }
  return value;
}

/**
 * Formats a boolean value for display
 * @param {boolean} value - The boolean value
 * @returns {string} - Formatted string
 */
function formatBoolean(value) {
  if (value) {
    return '[enabled]';
  }
  return '[disabled]';
}

/**
 * Displays application configuration
 * @param {Object} config - The loaded configuration object
 */
function displayConfig(config) {
  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║     SAML/OIDC Test Application Config       ║');
  console.log('╚════════════════════════════════════════════╝\n');

  if (config.application) {
    console.log('Application Settings:');
    console.log('  ├─ Hostname:', config.application.hostname);
    console.log('  ├─ Backend Port:', config.application.port);
    console.log('  ├─ Public Port:', config.application.publicPort);
    console.log('  ├─ Entity ID:', config.application.entityId);
    console.log('  ├─ HTTPS (Backend):', formatBoolean(config.application.useHttps));
    console.log('  ├─ HTTPS (Public):', formatBoolean(config.application.useHttpsPublicly));
    console.log('  ├─ Sign SAML Requests:', formatBoolean(config.application.signSamlRequests));
    if (config.application.baseUrl) {
      console.log('  └─ Base URL:', config.application.baseUrl);
    }
  }

  if (config.identityProviders && config.identityProviders.length > 0) {
    console.log('\nIdentity Providers:');
    console.log(`  Total: ${config.identityProviders.length}\n`);

    config.identityProviders.forEach((idp, index) => {
      const isLast = index === config.identityProviders.length - 1;
      const prefix = isLast ? '  └─ ' : '  ├─ ';

      console.log(prefix + `[${idp.protocol.toUpperCase()}] ${idp.name}`);

      const indentPrefix = isLast ? '     ' : '  │  ';

      if (idp.protocol === 'saml20') {
        console.log(indentPrefix + '├─ Binding:', idp.binding || 'redirect');
        console.log(indentPrefix + '├─ Login URL:', idp.loginUrl);
        console.log(indentPrefix + '├─ Logout URL:', idp.logoutUrl);
        console.log(indentPrefix + '├─ Certificate:', idp.certificate);
        if (idp.authNContextClassRef) {
          console.log(indentPrefix + '├─ AuthN Context:', idp.authNContextClassRef);
        }
        if (idp.forceAuthn !== undefined) {
          console.log(indentPrefix + '├─ Force AuthN:', idp.forceAuthn);
        }
        if (idp.entityId) {
          console.log(indentPrefix + '├─ Entity ID:', idp.entityId);
        }
        if (idp.signSamlRequests !== undefined || idp.samlSigningCertificate) {
          console.log(indentPrefix + '├─ Sign Requests:', idp.signSamlRequests !== undefined ? idp.signSamlRequests : 'inherits from app');
          if (idp.samlSigningCertificate) {
            console.log(indentPrefix + '├─ Signing Cert:', idp.samlSigningCertificate);
            console.log(indentPrefix + '└─ Signing Key:', maskSensitiveValue('samlSigningPrivateKey', idp.samlSigningPrivateKey));
          }
        }
      } else if (idp.protocol === 'oidc') {
        console.log(indentPrefix + '├─ Response Type:', idp.responseType || 'code');
        console.log(indentPrefix + '├─ Tenant URL:', idp.tenantUrl);
        console.log(indentPrefix + '├─ Issuer URL:', idp.issuerUrl);
        console.log(indentPrefix + '├─ Auth URL:', idp.authorizationUrl);
        console.log(indentPrefix + '├─ Token URL:', idp.tokenUrl);
        console.log(indentPrefix + '├─ Client ID:', idp.clientId);
        console.log(indentPrefix + '├─ Client Secret:', maskSensitiveValue('clientSecret', idp.clientSecret));
        console.log(indentPrefix + '├─ Scope:', idp.scope);
        if (idp.userInfoUrl) {
          console.log(indentPrefix + '├─ UserInfo URL:', idp.userInfoUrl);
        }
        if (idp.jwksUrl) {
          console.log(indentPrefix + '├─ JWKS URL:', idp.jwksUrl);
        }
        if (idp.idpCertificate) {
          console.log(indentPrefix + '└─ IdP Certificate:', idp.idpCertificate);
        }
      }
    });
  }

  console.log('\n═══════════════════════════════════════════════\n');
}

module.exports = {
  displayConfig,
  maskSensitiveValue,
  formatBoolean
};
