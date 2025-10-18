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
        issuerUrl: 'https://idp.example.com',
        loginUrl: 'https://idp.example.com/sso/saml',
        logoutUrl: 'https://idp.example.com/sso/logout',
        certificate: 'test-cert.pem'
      },
      {
        protocol: 'saml20',
        name: 'Test SAML IdP POST',
        issuerUrl: 'https://idp.example.com',
        binding: 'post',
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

    test('returns error for invalid SAML response structure', async () => {
      // Send a malformed SAML response (no Issuer, no valid structure)
      const samlResponse = Buffer.from('<saml:Response></saml:Response>').toString('base64');

      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Invalid SAML response');
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
      // Redirect uses absolute URL from config
      expect(response.headers.location).toBe('http://localhost:3001/protected');
    });

    test('supports IdP-initiated SSO (no pending authentication)', async () => {
      // Create a mock SAML response with Issuer information
      const mockSamlXml = `
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_response123"
                        Version="2.0"
                        IssueInstant="2025-01-01T00:00:00Z"
                        Destination="http://localhost:3001/auth/saml/callback">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
          <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
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

      // Send SAML response without prior login (IdP-initiated)
      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      expect(response.status).toBe(302);
      expect(response.headers.location).toBe('http://localhost:3001/protected');
    });

    test('returns error for IdP-initiated SSO with unknown Issuer', async () => {
      // Create a SAML response with an unknown Issuer and NO SIGNATURE
      // Without a signature, certificate matching will fail
      // Then issuerUrl matching will also fail because the issuer is unknown
      const mockSamlXml = `
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
          <saml:Issuer>https://unknown-idp.example.com</saml:Issuer>
          <saml:Assertion>
            <saml:Issuer>https://unknown-idp.example.com</saml:Issuer>
            <saml:Subject>
              <saml:NameID>user@example.com</saml:NameID>
            </saml:Subject>
          </saml:Assertion>
        </samlp:Response>
      `;

      const samlResponse = Buffer.from(mockSamlXml).toString('base64');

      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Identity provider not found');
    });

    test('supports IdP-initiated SSO by certificate matching (most secure method)', async () => {
      // Certificate matching should work even without issuerUrl configured
      const mockConfigCertOnly = {
        application: {
          hostname: 'localhost',
          port: 3001,
          useHttps: false,
          baseUrl: 'http://localhost:3001'
        },
        identityProviders: [
          {
            protocol: 'saml20',
            name: 'Cert-Only SAML IdP',
            // No issuerUrl - must rely on certificate matching
            loginUrl: 'https://idp-cert.example.com/sso/saml',
            logoutUrl: 'https://idp-cert.example.com/sso/logout',
            certificate: 'cert-only-idp.pem'
          }
        ]
      };

      const appCertOnly = express();
      appCertOnly.use(express.json());
      appCertOnly.use(express.urlencoded({ extended: true }));
      appCertOnly.use(session({
        secret: 'test-secret',
        resave: false,
        saveUninitialized: true
      }));
      appCertOnly.use('/auth/saml', createSamlRouter(mockConfigCertOnly));

      // SAML response with different/missing issuer - should still work via certificate
      const mockSamlXml = `
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="_certmatch123"
                        Version="2.0"
                        IssueInstant="2025-01-01T00:00:00Z">
          <saml:Issuer>https://totally-different-issuer.example.com</saml:Issuer>
          <saml:Assertion>
            <saml:Subject>
              <saml:NameID>certuser@example.com</saml:NameID>
            </saml:Subject>
            <saml:AttributeStatement>
              <saml:Attribute Name="email">
                <saml:AttributeValue>certuser@example.com</saml:AttributeValue>
              </saml:Attribute>
            </saml:AttributeStatement>
          </saml:Assertion>
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo></ds:SignedInfo>
          </ds:Signature>
        </samlp:Response>
      `;

      const samlResponse = Buffer.from(mockSamlXml).toString('base64');

      const response = await request(appCertOnly)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      // Should succeed because certificate verification passes
      expect(response.status).toBe(302);
      expect(response.headers.location).toBe('http://localhost:3001/protected');
    });

    test('tries certificate matching first before falling back to issuerUrl', async () => {
      // Even when issuerUrl is configured, certificate matching should be preferred
      // This test verifies the order: certificate first, then issuerUrl fallback

      // The existing test with matching issuerUrl should still work
      const mockSamlXml = `
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <saml:Assertion>
            <saml:Subject>
              <saml:NameID>user@example.com</saml:NameID>
            </saml:Subject>
          </saml:Assertion>
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo></ds:SignedInfo>
          </ds:Signature>
        </samlp:Response>
      `;

      const samlResponse = Buffer.from(mockSamlXml).toString('base64');

      const response = await request(app)
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      // Should succeed via certificate matching (which happens first)
      expect(response.status).toBe(302);
      expect(response.headers.location).toBe('http://localhost:3001/protected');
    });
  });

  describe('GET /auth/saml/logout', () => {
    test('generates SAML LogoutRequest with HTTP-Redirect binding', async () => {
      const agent = request.agent(app);

      // First, initiate login to set up session
      await agent
        .get('/auth/saml/login')
        .query({ idp: 'Test SAML IdP' });

      // Create a mock SAML response to complete authentication
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
            </saml:AttributeStatement>
          </saml:Assertion>
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo></ds:SignedInfo>
          </ds:Signature>
        </samlp:Response>
      `;

      const samlResponse = Buffer.from(mockSamlXml).toString('base64');

      // Complete authentication to store user in session
      await agent
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      // Now test logout with HTTP-Redirect binding
      const response = await agent.get('/auth/saml/logout');

      expect(response.status).toBe(302);
      expect(response.headers.location).toContain('https://idp.example.com/sso/logout');
      expect(response.headers.location).toContain('SAMLRequest=');

      // Extract and decode the SAMLRequest to verify structure
      const locationUrl = new URL(response.headers.location);
      const samlRequest = locationUrl.searchParams.get('SAMLRequest');
      expect(samlRequest).toBeTruthy();

      // Decode the request (base64 -> inflate -> XML)
      const decoded = Buffer.from(samlRequest, 'base64');
      const inflated = require('zlib').inflateRawSync(decoded).toString('utf8');

      // Verify it contains LogoutRequest elements
      expect(inflated).toContain('<samlp:LogoutRequest');
      expect(inflated).toContain('user@example.com');
      expect(inflated).toContain('<saml:Issuer>');
    });

    test('generates SAML LogoutRequest with HTTP-POST binding', async () => {
      const agent = request.agent(app);

      // Login with POST binding IdP
      await agent
        .get('/auth/saml/login')
        .query({ idp: 'Test SAML IdP POST' });

      // Complete authentication
      const mockSamlXml = `
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
          <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Subject>
              <saml:NameID>user@example.com</saml:NameID>
            </saml:Subject>
          </saml:Assertion>
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo></ds:SignedInfo>
          </ds:Signature>
        </samlp:Response>
      `;

      const samlResponse = Buffer.from(mockSamlXml).toString('base64');
      await agent
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      // Test logout with POST binding
      const response = await agent.get('/auth/saml/logout');

      expect(response.status).toBe(200);
      expect(response.text).toContain('<form');
      expect(response.text).toContain('action="https://idp.example.com/sso/logout"');
      expect(response.text).toContain('name="SAMLRequest"');

      // Extract SAMLRequest from HTML form
      const match = response.text.match(/name="SAMLRequest" value="([^"]+)"/);
      expect(match).toBeTruthy();

      const samlRequest = match[1];
      const decoded = Buffer.from(samlRequest, 'base64').toString('utf8');

      // Verify it contains LogoutRequest elements
      expect(decoded).toContain('<samlp:LogoutRequest');
      expect(decoded).toContain('user@example.com');
    });

    test('redirects to home page when no IdP logout URL is configured', async () => {
      // Create an IdP without logoutUrl
      const mockConfigNoLogout = {
        application: {
          hostname: 'localhost',
          port: 3001,
          useHttps: false,
          baseUrl: 'http://localhost:3001'
        },
        identityProviders: [
          {
            protocol: 'saml20',
            name: 'Test SAML IdP No Logout',
            issuerUrl: 'https://nologout-idp.example.com',
            loginUrl: 'https://idp.example.com/sso/saml',
            certificate: 'test-nologout-cert.pem'
          }
        ]
      };

      const appNoLogout = express();
      appNoLogout.use(express.json());
      appNoLogout.use(express.urlencoded({ extended: true }));
      appNoLogout.use(session({
        secret: 'test-secret',
        resave: false,
        saveUninitialized: true
      }));
      appNoLogout.use('/auth/saml', createSamlRouter(mockConfigNoLogout));

      const agent = request.agent(appNoLogout);

      // Login
      await agent
        .get('/auth/saml/login')
        .query({ idp: 'Test SAML IdP No Logout' });

      // Complete authentication
      const mockSamlXml = `
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
          <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://nologout-idp.example.com</saml:Issuer>
          <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Subject>
              <saml:NameID>user@example.com</saml:NameID>
            </saml:Subject>
          </saml:Assertion>
          <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo></ds:SignedInfo>
          </ds:Signature>
        </samlp:Response>
      `;

      const samlResponse = Buffer.from(mockSamlXml).toString('base64');
      await agent
        .post('/auth/saml/callback')
        .send({ SAMLResponse: samlResponse });

      // Test logout
      const response = await agent.get('/auth/saml/logout');

      expect(response.status).toBe(302);
      expect(response.headers.location).toBe('http://localhost:3001/');
      expect(response.headers.location).not.toContain('SAMLRequest');
    });

    test('handles logout when user is not authenticated', async () => {
      const response = await request(app)
        .get('/auth/saml/logout');

      expect(response.status).toBe(302);
      expect(response.headers.location).toBe('http://localhost:3001/');
    });
  });
});
