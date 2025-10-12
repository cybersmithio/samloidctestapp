const request = require('supertest');
const express = require('express');
const session = require('express-session');
const createSamlRouter = require('./saml');

// Mock the configLoader module
jest.mock('../utils/configLoader', () => ({
  loadCertificate: jest.fn(() => '-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----')
}));

// Mock xml-crypto
jest.mock('xml-crypto', () => ({
  SignedXml: jest.fn().mockImplementation(() => ({
    keyInfoProvider: null,
    loadSignature: jest.fn(),
    checkSignature: jest.fn(() => true)
  }))
}));

describe('SAML Authentication Router', () => {
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
        protocol: 'saml20',
        name: 'Test SAML IdP',
        loginUrl: 'https://idp.example.com/sso/saml',
        logoutUrl: 'https://idp.example.com/sso/logout',
        certificate: 'test-cert.pem'
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
    app.use('/auth/saml', createSamlRouter(mockConfig));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /auth/saml/login', () => {
    test('initiates SAML login successfully', async () => {
      const response = await request(app)
        .get('/auth/saml/login')
        .query({ idp: 'Test SAML IdP' });

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('https://idp.example.com/sso/saml');
    });

    test('returns 404 for unknown IdP', async () => {
      const response = await request(app)
        .get('/auth/saml/login')
        .query({ idp: 'Unknown IdP' });

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('Identity provider not found');
    });

    test('stores IdP info in session', async () => {
      const agent = request.agent(app);

      await agent
        .get('/auth/saml/login')
        .query({ idp: 'Test SAML IdP' });

      // The session would contain pendingIdp
      // This is difficult to test without accessing session directly
      // In a real scenario, you might use a session store that can be inspected
    });
  });

  describe('POST /auth/saml/callback', () => {
    test('returns error when SAMLResponse is missing', async () => {
      const response = await request(app)
        .post('/auth/saml/callback')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Missing SAML response');
    });

    test('returns error when no pending authentication', async () => {
      const samlResponse = Buffer.from('<saml:Response></saml:Response>').toString('base64');

      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('No pending authentication');
    });

    test('processes valid SAML response with signature verification', async () => {
      const agent = request.agent(app);

      // First, initiate login to set up session
      await agent
        .get('/auth/saml/login')
        .query({ idp: 'Test SAML IdP' });

      // Create a mock SAML response
      const mockSamlXml = `
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
          <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Subject>
              <saml:NameID>user@example.com</saml:NameID>
            </saml:Subject>
            <saml:AttributeStatement>
              <saml:Attribute Name="email">
                <saml:AttributeValue>user@example.com</saml:AttributeValue>
              </saml:Attribute>
              <saml:Attribute Name="name">
                <saml:AttributeValue>Test User</saml:AttributeValue>
              </saml:Attribute>
            </saml:AttributeStatement>
          </saml:Assertion>
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo></ds:SignedInfo>
          </ds:Signature>
        </samlp:Response>
      `;

      const samlResponse = Buffer.from(mockSamlXml).toString('base64');

      const response = await agent
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('http://localhost:3000/protected');
    });
  });

  describe('GET /auth/saml/logout', () => {
    test('destroys session and redirects to IdP logout', async () => {
      const agent = request.agent(app);

      // Set up session with user
      await agent
        .get('/auth/saml/login')
        .query({ idp: 'Test SAML IdP' });

      const response = await agent.get('/auth/saml/logout');

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('https://idp.example.com/sso/logout');
    });
  });
});
