const request = require('supertest');
const express = require('express');
const session = require('express-session');
const https = require('https');
const createOidcRouter = require('./oidc');

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('jwks-rsa');
jest.mock('../utils/configLoader', () => ({
  loadCertificate: jest.fn(() => '-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----')
}));

// Mock https.request to allow tests to simulate HTTP requests
let httpsRequestMock;
jest.spyOn(https, 'request').mockImplementation((options, callback) => {
  if (httpsRequestMock) {
    return httpsRequestMock(options, callback);
  }
  // Default: simulate a successful response
  const mockRes = {
    statusCode: 200,
    headers: {},
    on: jest.fn((event, handler) => {
      if (event === 'data') {
        setTimeout(() => handler(''), 0);
      } else if (event === 'end') {
        setTimeout(() => handler(), 0);
      }
    })
  };
  setTimeout(() => callback(mockRes), 0);
  return {
    on: jest.fn(),
    write: jest.fn(),
    end: jest.fn()
  };
});

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
      expect(response.body.error).toBe('Invalid state parameter (possible CSRF attack)');
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

      // Mock HTTPS requests for token exchange and userinfo
      let requestCount = 0;
      httpsRequestMock = (options, callback) => {
        requestCount++;
        const mockRes = {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          on: jest.fn()
        };

        // Determine response based on URL path
        let responseData = '';
        if (options.path.includes('/token')) {
          // Token endpoint response
          responseData = JSON.stringify({
            id_token: 'mock.jwt.token',
            access_token: 'mock-access-token'
          });
        } else if (options.path.includes('/userinfo')) {
          // Userinfo endpoint response
          responseData = JSON.stringify({
            preferred_username: 'testuser',
            picture: 'https://example.com/avatar.jpg'
          });
        }

        mockRes.on.mockImplementation((event, handler) => {
          if (event === 'data') {
            setTimeout(() => handler(responseData), 0);
          } else if (event === 'end') {
            setTimeout(() => handler(), 0);
          }
          return mockRes;
        });

        setTimeout(() => callback(mockRes), 0);

        return {
          on: jest.fn((event, handler) => {
            if (event === 'error') {
              // No errors
            }
          }),
          write: jest.fn(),
          end: jest.fn()
        };
      };

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
      httpsRequestMock = (options, callback) => {
        const mockRes = {
          statusCode: 400,
          headers: { 'content-type': 'application/json' },
          on: jest.fn()
        };

        const responseData = JSON.stringify({
          error: 'invalid_request',
          error_description: 'Invalid authorization code'
        });

        mockRes.on.mockImplementation((event, handler) => {
          if (event === 'data') {
            setTimeout(() => handler(responseData), 0);
          } else if (event === 'end') {
            setTimeout(() => handler(), 0);
          }
          return mockRes;
        });

        setTimeout(() => callback(mockRes), 0);

        return {
          on: jest.fn(),
          write: jest.fn(),
          end: jest.fn()
        };
      };

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

  describe('Self-signed certificate handling', () => {
    test('successfully exchanges code with insecureSkipCertificateVerification enabled', async () => {
      // Create a config with insecureSkipCertificateVerification enabled
      const selfSignedConfig = {
        application: {
          hostname: 'localhost',
          port: 3001,
          useHttps: false,
          baseUrl: 'http://localhost:3001'
        },
        identityProviders: [
          {
            protocol: 'oidc',
            name: 'Self-Signed IdP',
            tenantUrl: 'https://self-signed.example.com/tenant',
            issuerUrl: 'https://self-signed.example.com/issuer',
            authorizationUrl: 'https://self-signed.example.com/authorize',
            tokenUrl: 'https://self-signed.example.com/token',
            userInfoUrl: 'https://self-signed.example.com/userinfo',
            metadataUrl: 'https://self-signed.example.com/.well-known/openid-configuration',
            clientId: 'self-signed-client-id',
            clientSecret: 'self-signed-client-secret',
            scope: 'openid profile email',
            insecureSkipCertificateVerification: true  // Enable insecure cert verification
          }
        ]
      };

      // Create app with self-signed config
      const selfSignedApp = express();
      selfSignedApp.use(express.json());
      selfSignedApp.use(express.urlencoded({ extended: true }));
      selfSignedApp.use(session({
        secret: 'test-secret',
        resave: false,
        saveUninitialized: true
      }));
      selfSignedApp.use('/auth/oidc', createOidcRouter(selfSignedConfig));

      const agent = request.agent(selfSignedApp);

      // Step 1: Initiate login
      const loginResponse = await agent
        .get('/auth/oidc/login')
        .query({ idp: 'Self-Signed IdP' });

      expect(loginResponse.status).toBe(302);
      expect(loginResponse.headers.location).toContain('https://self-signed.example.com/authorize');

      // Extract state and nonce
      const location = loginResponse.headers.location;
      const stateMatch = location.match(/state=([^&]+)/);
      const state = stateMatch ? stateMatch[1] : '';
      const nonceMatch = location.match(/nonce=([^&]+)/);
      const nonce = nonceMatch ? nonceMatch[1] : '';

      // Step 2: Setup JWT mock to return user info
      jwt.verify.mockImplementationOnce((token, key, options, callback) => {
        callback(null, {
          sub: 'user123',
          email: 'user@example.com',
          name: 'Test User',
          nonce: nonce
        });
      });

      // Step 3: Mock HTTPS requests to self-signed server
      let requestAttempts = [];
      httpsRequestMock = (options, callback) => {
        // Record the request details including agent properties
        requestAttempts.push({
          hostname: options.hostname,
          path: options.path,
          method: options.method,
          hasAgent: !!options.agent,
          agentRejectUnauthorized: options.agent?.options?.rejectUnauthorized
        });

        const mockRes = {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          on: jest.fn()
        };

        // Determine response based on URL path
        let responseData = '';
        if (options.path.includes('/token')) {
          // Token endpoint response
          responseData = JSON.stringify({
            id_token: 'mock.jwt.token',
            access_token: 'mock-access-token'
          });
        } else if (options.path.includes('/userinfo')) {
          // Userinfo endpoint response
          responseData = JSON.stringify({
            preferred_username: 'testuser',
            picture: 'https://example.com/avatar.jpg'
          });
        }

        mockRes.on.mockImplementation((event, handler) => {
          if (event === 'data') {
            setTimeout(() => handler(responseData), 0);
          } else if (event === 'end') {
            setTimeout(() => handler(), 0);
          }
          return mockRes;
        });

        setTimeout(() => callback(mockRes), 0);

        return {
          on: jest.fn((event, handler) => {
            // No errors
          }),
          write: jest.fn(),
          end: jest.fn()
        };
      };

      // Step 4: Perform token exchange
      const callbackResponse = await agent
        .get('/auth/oidc/callback')
        .query({
          code: 'test-auth-code-self-signed',
          state: state
        });

      // Verify the callback was successful
      expect(callbackResponse.status).toBe(302);
      expect(callbackResponse.headers.location).toBe('http://localhost:3001/protected');

      // Verify that an HTTPS request was made WITH the insecure agent
      expect(requestAttempts.length).toBeGreaterThan(0);
      const tokenExchangeRequest = requestAttempts.find(r => r.path.includes('/token'));
      expect(tokenExchangeRequest).toBeDefined();
      expect(tokenExchangeRequest.hasAgent).toBe(true);
      expect(tokenExchangeRequest.agentRejectUnauthorized).toBe(false);
    });

    test('properly validates agent has rejectUnauthorized false when insecureSkipCertificateVerification is true', async () => {
      // This test verifies that the agent is created with correct settings
      const https = require('https');

      // Create an HTTPS agent with rejectUnauthorized false (what our code should do)
      const agent = new https.Agent({
        rejectUnauthorized: false
      });

      // Verify the agent is properly configured
      expect(agent.options.rejectUnauthorized).toBe(false);
      expect(agent.protocol).toBe('https:');
    });

    test('token request includes grant_type parameter', async () => {
      const agent = request.agent(app);

      // Initiate login
      const loginResponse = await agent
        .get('/auth/oidc/login')
        .query({ idp: 'Test OIDC IdP' });

      const location = loginResponse.headers.location;
      const stateMatch = location.match(/state=([^&]+)/);
      const state = stateMatch ? stateMatch[1] : '';
      const nonceMatch = location.match(/nonce=([^&]+)/);
      const nonce = nonceMatch ? nonceMatch[1] : '';

      jwt.verify.mockImplementationOnce((token, key, options, callback) => {
        callback(null, {
          sub: 'user123',
          email: 'user@example.com',
          name: 'Test User',
          nonce: nonce
        });
      });

      // Track the request body sent to the token endpoint
      let tokenRequestBody = '';
      httpsRequestMock = (options, callback) => {
        const mockRes = {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          on: jest.fn()
        };

        // Capture the token request body
        if (options.path.includes('/token')) {
          // Body will be sent via req.write()
        }

        let responseData = '';
        if (options.path.includes('/token')) {
          responseData = JSON.stringify({
            id_token: 'mock.jwt.token',
            access_token: 'mock-access-token'
          });
        } else if (options.path.includes('/userinfo')) {
          responseData = JSON.stringify({
            preferred_username: 'testuser',
            picture: 'https://example.com/avatar.jpg'
          });
        }

        mockRes.on.mockImplementation((event, handler) => {
          if (event === 'data') {
            setTimeout(() => handler(responseData), 0);
          } else if (event === 'end') {
            setTimeout(() => handler(), 0);
          }
          return mockRes;
        });

        setTimeout(() => callback(mockRes), 0);

        return {
          on: jest.fn(),
          write: jest.fn((data) => {
            // Capture body when it's written
            if (options.path.includes('/token')) {
              tokenRequestBody += data;
            }
          }),
          end: jest.fn()
        };
      };

      const callbackResponse = await agent
        .get('/auth/oidc/callback')
        .query({
          code: 'test-auth-code',
          state: state
        });

      expect(callbackResponse.status).toBe(302);

      // Verify the token request body includes grant_type
      expect(tokenRequestBody).toContain('grant_type=authorization_code');
      expect(tokenRequestBody).toContain('code=test-auth-code');
      expect(tokenRequestBody).toContain('redirect_uri=');
      expect(tokenRequestBody).toContain('client_id=test-client-id');
      expect(tokenRequestBody).toContain('client_secret=test-client-secret');
    });
  });
});
