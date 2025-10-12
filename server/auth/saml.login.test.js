const request = require('supertest');
const app = require('../index');
const configLoader = require('../utils/configLoader');

describe('GET /auth/saml/login', () => {
  let config;

  beforeAll(() => {
    config = configLoader.loadConfig();
  });
  test('should redirect to IdP with SAMLRequest parameter', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=Verify IdP');

    expect(response.status).toBe(302);
    expect(response.headers.location).toContain('cybersmith.verify.ibm.com');
    expect(response.headers.location).toContain('SAMLRequest=');
    expect(response.headers.location).toContain('RelayState=');
  });

  test('should generate valid SAML AuthnRequest XML', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=Verify IdP');

    expect(response.status).toBe(302);

    // Extract SAMLRequest parameter from redirect URL
    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');

    expect(samlRequest).toBeTruthy();

    // Decode and verify it's valid XML
    const decodedRequest = Buffer.from(samlRequest, 'base64').toString('utf8');

    expect(decodedRequest).toContain('<?xml version="1.0"');
    expect(decodedRequest).toContain('<samlp:AuthnRequest');
    expect(decodedRequest).toContain('xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"');
    expect(decodedRequest).toContain('<saml:Issuer>');
    expect(decodedRequest).toContain('AssertionConsumerServiceURL');
    expect(decodedRequest).toContain('/assert');
  });

  test('should include signature in signed requests', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=Verify IdP');

    expect(response.status).toBe(302);

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const decodedRequest = Buffer.from(samlRequest, 'base64').toString('utf8');

    // Check if signing is enabled in config
    if (decodedRequest.includes('<ds:Signature')) {
      expect(decodedRequest).toContain('xmlns:ds="http://www.w3.org/2000/09/xmldsig#"');
      expect(decodedRequest).toContain('<ds:SignatureValue>');
      expect(decodedRequest).toContain('<ds:X509Certificate>');
    }
  });

  test('should include required SAML elements', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=Verify IdP');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const decodedRequest = Buffer.from(samlRequest, 'base64').toString('utf8');

    // Verify required attributes
    expect(decodedRequest).toContain('ID="_');
    expect(decodedRequest).toContain('Version="2.0"');
    expect(decodedRequest).toContain('IssueInstant=');
    expect(decodedRequest).toContain('Destination=');
    expect(decodedRequest).toContain('ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"');
    expect(decodedRequest).toContain('<samlp:NameIDPolicy');
  });

  test('should return 404 for unknown IdP', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=NonExistentIdP');

    expect(response.status).toBe(404);
    expect(response.body.error).toContain('Identity provider not found');
  });

  test('should set destination to IdP login URL', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=Verify IdP');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const decodedRequest = Buffer.from(samlRequest, 'base64').toString('utf8');

    expect(decodedRequest).toContain('Destination="https://cybersmith.verify.ibm.com/saml/sps/saml20ip/saml20/login"');
  });

  test('should include entityId as Issuer', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=Verify IdP');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const decodedRequest = Buffer.from(samlRequest, 'base64').toString('utf8');

    const expectedIssuer = config.application?.entityId || `http://${config.application?.hostname || 'localhost'}:3001/saml/metadata`;
    expect(decodedRequest).toContain(`<saml:Issuer>${expectedIssuer}</saml:Issuer>`);
  });
});
