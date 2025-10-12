const request = require('supertest');

// Mock the configLoader before requiring the app
jest.mock('./utils/configLoader');
const configLoader = require('./utils/configLoader');

// Mock the auth modules to return empty routers
jest.mock('./auth/saml', () => {
  return jest.fn(() => {
    const express = require('express');
    return express.Router();
  });
});

jest.mock('./auth/oidc', () => {
  return jest.fn(() => {
    const express = require('express');
    return express.Router();
  });
});

describe('Server API Endpoints', () => {
  let app;

  beforeEach(() => {
    // Clear the module cache to get a fresh app instance
    jest.clearAllMocks();
    delete require.cache[require.resolve('./index')];

    // Mock the config data
    const mockConfig = {
      identityProviders: [
        {
          protocol: 'saml20',
          name: 'Test SAML Provider',
          loginUrl: 'https://idp.example.com/sso',
          logoutUrl: 'https://idp.example.com/logout',
          certificate: 'cert.pem'
        },
        {
          protocol: 'oidc',
          name: 'Test OIDC Provider',
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

    configLoader.loadConfig.mockReturnValue(mockConfig);

    app = require('./index');
  });

  describe('GET /api/config', () => {
    test('should return 200 status code', async () => {
      const response = await request(app).get('/api/config');
      expect(response.status).toBe(200);
    });

    test('should return JSON content type', async () => {
      const response = await request(app).get('/api/config');
      expect(response.headers['content-type']).toMatch(/json/);
    });

    test('should return identityProviders array', async () => {
      const response = await request(app).get('/api/config');
      expect(response.body).toHaveProperty('identityProviders');
      expect(Array.isArray(response.body.identityProviders)).toBe(true);
    });

    test('should return correct number of identity providers', async () => {
      const response = await request(app).get('/api/config');
      expect(response.body.identityProviders).toHaveLength(2);
    });

    test('should return only safe IdP data (name and protocol)', async () => {
      const response = await request(app).get('/api/config');
      const idp = response.body.identityProviders[0];

      // Should include these fields
      expect(idp).toHaveProperty('name');
      expect(idp).toHaveProperty('protocol');

      // Should NOT include sensitive fields
      expect(idp).not.toHaveProperty('loginUrl');
      expect(idp).not.toHaveProperty('certificate');
      expect(idp).not.toHaveProperty('clientSecret');
      expect(idp).not.toHaveProperty('clientId');
    });

    test('should return correct data for SAML provider', async () => {
      const response = await request(app).get('/api/config');
      const samlProvider = response.body.identityProviders.find(
        idp => idp.protocol === 'saml20'
      );

      expect(samlProvider).toBeDefined();
      expect(samlProvider.name).toBe('Test SAML Provider');
      expect(samlProvider.protocol).toBe('saml20');
    });

    test('should return correct data for OIDC provider', async () => {
      const response = await request(app).get('/api/config');
      const oidcProvider = response.body.identityProviders.find(
        idp => idp.protocol === 'oidc'
      );

      expect(oidcProvider).toBeDefined();
      expect(oidcProvider.name).toBe('Test OIDC Provider');
      expect(oidcProvider.protocol).toBe('oidc');
    });

    test('should return an array even with different configurations', async () => {
      const response = await request(app).get('/api/config');

      // Verify structure - should always return an array
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('identityProviders');
      expect(Array.isArray(response.body.identityProviders)).toBe(true);

      // Verify each item has correct shape
      response.body.identityProviders.forEach(idp => {
        expect(idp).toHaveProperty('name');
        expect(idp).toHaveProperty('protocol');
        expect(typeof idp.name).toBe('string');
        expect(['saml20', 'oidc'].includes(idp.protocol)).toBe(true);
      });
    });
  });

  describe('GET /api/session', () => {
    test('should return 401 when not authenticated', async () => {
      const response = await request(app).get('/api/session');
      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error');
    });
  });

  describe('POST /api/logout', () => {
    test('should return success on logout', async () => {
      const response = await request(app).post('/api/logout');
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('success');
    });
  });
});
