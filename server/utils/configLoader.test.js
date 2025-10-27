const fs = require('fs');
const path = require('path');
const configLoader = require('./configLoader');

jest.mock('fs');

describe('configLoader', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('loadConfig', () => {
    test('loads valid configuration successfully', () => {
      const mockConfig = {
        identityProviders: [
          {
            protocol: 'saml20',
            name: 'Test SAML',
            loginUrl: 'https://idp.example.com/sso',
            logoutUrl: 'https://idp.example.com/logout',
            certificate: 'cert.pem',
            binding: 'redirect'
          },
          {
            protocol: 'oidc',
            name: 'Test OIDC',
            responseType: 'code',
            tenantUrl: 'https://login.example.com/tenant',
            issuerUrl: 'https://login.example.com/issuer',
            authorizationUrl: 'https://login.example.com/auth',
            tokenUrl: 'https://login.example.com/token',
            userInfoUrl: 'https://login.example.com/userinfo',
            metadataUrl: 'https://login.example.com/.well-known',
            clientId: 'client123',
            clientSecret: 'secret123',
            scope: 'openid profile email'
          }
        ]
      };

      fs.readFileSync.mockReturnValue(JSON.stringify(mockConfig));

      const config = configLoader.loadConfig();

      // The loader adds default authNContextClassRef and responseType
      const expectedConfig = JSON.parse(JSON.stringify(mockConfig));
      expectedConfig.identityProviders[0].authNContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

      expect(config).toEqual(expectedConfig);
      expect(fs.readFileSync).toHaveBeenCalledWith(
        expect.stringContaining('config.json'),
        'utf8'
      );
    });

    test('throws error when identityProviders is missing', () => {
      const invalidConfig = { someOtherField: 'value' };
      fs.readFileSync.mockReturnValue(JSON.stringify(invalidConfig));

      expect(() => configLoader.loadConfig()).toThrow(
        'Invalid configuration: identityProviders array is required'
      );
    });

    test('throws error when identityProviders is not an array', () => {
      const invalidConfig = { identityProviders: 'not-an-array' };
      fs.readFileSync.mockReturnValue(JSON.stringify(invalidConfig));

      expect(() => configLoader.loadConfig()).toThrow(
        'Invalid configuration: identityProviders array is required'
      );
    });

    test('throws error for invalid protocol', () => {
      const invalidConfig = {
        identityProviders: [
          {
            protocol: 'invalid-protocol',
            name: 'Test'
          }
        ]
      };
      fs.readFileSync.mockReturnValue(JSON.stringify(invalidConfig));

      expect(() => configLoader.loadConfig()).toThrow(
        "Invalid protocol for IdP at index 0: must be 'saml20' or 'oidc'"
      );
    });

    test('throws error when IdP name is missing', () => {
      const invalidConfig = {
        identityProviders: [
          {
            protocol: 'saml20'
          }
        ]
      };
      fs.readFileSync.mockReturnValue(JSON.stringify(invalidConfig));

      expect(() => configLoader.loadConfig()).toThrow(
        'Missing name for IdP at index 0'
      );
    });

    test('throws error when SAML IdP is missing required fields', () => {
      const invalidConfig = {
        identityProviders: [
          {
            protocol: 'saml20',
            name: 'Test SAML',
            loginUrl: 'https://example.com'
            // missing logoutUrl and certificate
          }
        ]
      };
      fs.readFileSync.mockReturnValue(JSON.stringify(invalidConfig));

      expect(() => configLoader.loadConfig()).toThrow(
        'Missing logoutUrl for SAML IdP at index 0'
      );
    });

    test('throws error when OIDC IdP is missing required fields', () => {
      const invalidConfig = {
        identityProviders: [
          {
            protocol: 'oidc',
            name: 'Test OIDC',
            tenantUrl: 'https://example.com'
            // missing other required fields
          }
        ]
      };
      fs.readFileSync.mockReturnValue(JSON.stringify(invalidConfig));

      expect(() => configLoader.loadConfig()).toThrow(/Missing .* for OIDC IdP at index 0/);
    });

    test('throws error when config file cannot be read', () => {
      fs.readFileSync.mockImplementation(() => {
        throw new Error('File not found');
      });

      expect(() => configLoader.loadConfig()).toThrow();
    });

    test('throws error when config JSON is invalid', () => {
      fs.readFileSync.mockReturnValue('invalid json{');

      expect(() => configLoader.loadConfig()).toThrow();
    });
  });

  describe('loadCertificate', () => {
    test('loads certificate successfully', () => {
      const mockCert = '-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----';
      fs.readFileSync.mockReturnValue(mockCert);

      const cert = configLoader.loadCertificate('test-cert.pem');

      expect(cert).toBe(mockCert);
      expect(fs.readFileSync).toHaveBeenCalledWith(
        expect.stringContaining('test-cert.pem'),
        'utf8'
      );
    });

    test('throws error when certificate file cannot be read', () => {
      fs.readFileSync.mockImplementation(() => {
        throw new Error('File not found');
      });

      expect(() => configLoader.loadCertificate('nonexistent.pem')).toThrow(
        'Failed to load certificate: nonexistent.pem'
      );
    });
  });
});
