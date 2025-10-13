const request = require('supertest');
const express = require('express');
const session = require('express-session');
const createOidcRouter = require('./oidc');

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('jwks-rsa');
jest.mock('../utils/configLoader', () => ({
  loadCertificate: jest.fn(() => '-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----')
}));

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

describe('OIDC Authentication Router', () => {
  let app;
  const mockConfig = {
    application: {
      hostname: 'localhost',
      port: 3001,
      useHttps: false,
      baseUrl: 'http://localhost:3001'
    },
    identityProviders: [
      {
        protocol: 'oidc',
        name: 'Test OIDC IdP',
        tenantUrl: 'https://login.example.com/tenant',
        issuerUrl: 'https://login.example.com/issuer',
        authorizationUrl: 'https://login.example.com/authorize',
        tokenUrl: 'https://login.example.com/token',
        userInfoUrl: 'https://login.example.com/userinfo',
        metadataUrl: 'https://login.example.com/.well-known/openid-configuration',
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        scope: 'openid profile email'
      }
    ]
  };

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(session({
      secret: 'test-secret',
      resave: false,
      saveUninitialized: true
    }));
    app.use('/auth/oidc', createOidcRouter(mockConfig));

    // Reset all mocks
    jest.clearAllMocks();
  });

  describe('GET /auth/oidc/login', () => {
    test('initiates OIDC login with correct parameters', async () => {
      const response = await request(app)
        .get('/auth/oidc/login')
        .query({ idp: 'Test OIDC IdP' });

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('https://login.example.com/authorize');
      expect(response.headers.location).toContain('client_id=test-client-id');
      expect(response.headers.location).toContain('response_type=code');
      expect(response.headers.location).toContain('scope=openid+profile+email');
      expect(response.headers.location).toContain('state=');
      expect(response.headers.location).toContain('nonce=');
    });

    test('returns 404 for unknown IdP', async () => {
      const response = await request(app)
        .get('/auth/oidc/login')
        .query({ idp: 'Unknown IdP' });

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Identity provider not found');
    });
  });

  describe('GET /auth/oidc/callback', () => {
    beforeEach(() => {
      // Mock fetch for token exchange
      global.fetch = jest.fn();

      // Mock JWT verification
      jwt.decode.mockReturnValue({
        header: { kid: 'test-key-id' },
        payload: {
          sub: 'user123',
          email: 'user@example.com',
          name: 'Test User',
          nonce: 'test-nonce'
        }
      });

      // Mock JWKS client
      jwksClient.mockReturnValue({
        getSigningKey: jest.fn((kid, callback) => {
          callback(null, {
            getPublicKey: () => 'mock-public-key'
          });
        })
      });

      jwt.verify.mockImplementation((token, key, options, callback) => {
        callback(null, {
          sub: 'user123',
          email: 'user@example.com',
          name: 'Test User',
          nonce: 'test-nonce'
        });
      });
    });

    afterEach(() => {
      delete global.fetch;
    });

    test('returns error when error parameter is present', async () => {
      const response = await request(app)
        .get('/auth/oidc/callback')
        .query({
          error: 'access_denied',
          error_description: 'User denied access'
        });

      expect(response.status).toBe(302);
      expect(response.headers.location).toBe('http://localhost:3001/?error=User%20denied%20access');
    });

    test('returns error when state is invalid', async () => {
      const response = await request(app)
        .get('/auth/oidc/callback')
        .query({
          code: 'test-code',
          state: 'invalid-state'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Invalid state parameter');
    });

    test('exchanges code for tokens and creates session', async () => {
      const agent = request.agent(app);

      // First, initiate login
      const loginResponse = await agent
        .get('/auth/oidc/login')
        .query({ idp: 'Test OIDC IdP' });

      // Extract state and nonce from redirect URL
      const location = loginResponse.headers.location;
      const stateMatch = location.match(/state=([^&]+)/);
      const state = stateMatch ? stateMatch[1] : '';
      const nonceMatch = location.match(/nonce=([^&]+)/);
      const nonce = nonceMatch ? nonceMatch[1] : '';

      // Update JWT mock to return the correct nonce for this test
      jwt.verify.mockImplementationOnce((token, key, options, callback) => {
        callback(null, {
          sub: 'user123',
          email: 'user@example.com',
          name: 'Test User',
          nonce: nonce  // Use the actual nonce from the login session
        });
      });

      // Mock successful token exchange
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id_token: 'mock.jwt.token',
          access_token: 'mock-access-token'
        })
      });

      // Mock user info fetch
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          preferred_username: 'testuser',
          picture: 'https://example.com/avatar.jpg'
        })
      });

      const response = await agent
        .get('/auth/oidc/callback')
        .query({
          code: 'test-auth-code',
          state: state
        });

      expect(response.status).toBe(302);
      // Redirect uses absolute URL from config
      expect(response.headers.location).toBe('http://localhost:3001/protected');
    });

    test('handles token exchange failure', async () => {
      const agent = request.agent(app);

      // Initiate login
      const loginResponse = await agent
        .get('/auth/oidc/login')
        .query({ idp: 'Test OIDC IdP' });

      const location = loginResponse.headers.location;
      const stateMatch = location.match(/state=([^&]+)/);
      const state = stateMatch ? stateMatch[1] : '';

      // Mock failed token exchange
      global.fetch.mockResolvedValueOnce({
        ok: false,
        text: async () => 'Token exchange failed'
      });

      const response = await agent
        .get('/auth/oidc/callback')
        .query({
          code: 'test-auth-code',
          state: state
        });

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('error=');
    });
  });

  describe('GET /auth/oidc/logout', () => {
    test('destroys session and redirects to home', async () => {
      const response = await request(app).get('/auth/oidc/logout');

      expect(response.status).toBe(302);
      // Redirect uses absolute URL from config
      expect(response.headers.location).toBe('http://localhost:3001/');
    });
  });
});
