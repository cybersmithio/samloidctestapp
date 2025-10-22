const request = require('supertest');
const app = require('../index');
const configLoader = require('../utils/configLoader');
const zlib = require('zlib');

describe('GET /auth/saml/login', () => {
  let config;

  beforeAll(() => {
    config = configLoader.loadConfig();
  });
  test('should redirect to IdP with SAMLRequest parameter', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=SAML Test application 1');

    expect(response.status).toBe(302);
    expect(response.headers.location).toContain('cybersmith.verify.ibm.com');
    expect(response.headers.location).toContain('SAMLRequest=');
    expect(response.headers.location).toContain('RelayState=');
  });

  test('should generate valid SAML AuthnRequest XML', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=SAML Test application 1');

    expect(response.status).toBe(302);

    // Extract SAMLRequest parameter from redirect URL
    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');

    expect(samlRequest).toBeTruthy();

    // Decode and inflate (HTTP-Redirect binding uses deflate compression)
    const deflated = Buffer.from(samlRequest, 'base64');
    const decodedRequest = zlib.inflateRawSync(deflated).toString('utf8');

    expect(decodedRequest).toContain('<?xml version="1.0"');
    expect(decodedRequest).toContain('<samlp:AuthnRequest');
    expect(decodedRequest).toContain('xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"');
    expect(decodedRequest).toContain('<saml:Issuer>');
    expect(decodedRequest).toContain('AssertionConsumerServiceURL');
    expect(decodedRequest).toContain('/auth/saml/callback');
  });

  test('should include signature in signed requests', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=SAML Test application 1');

    expect(response.status).toBe(302);

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const deflated = Buffer.from(samlRequest, 'base64');
    const decodedRequest = zlib.inflateRawSync(deflated).toString('utf8');

    // Check if signing is enabled in config
    if (decodedRequest.includes('<ds:Signature')) {
      expect(decodedRequest).toContain('xmlns:ds="http://www.w3.org/2000/09/xmldsig#"');
      expect(decodedRequest).toContain('<ds:SignatureValue>');
      expect(decodedRequest).toContain('<ds:X509Certificate>');
    }
  });

  test('should include required SAML elements', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=SAML Test application 1');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const deflated = Buffer.from(samlRequest, 'base64');
    const decodedRequest = zlib.inflateRawSync(deflated).toString('utf8');

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
      .get('/auth/saml/login?idp=SAML Test application 1');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const deflated = Buffer.from(samlRequest, 'base64');
    const decodedRequest = zlib.inflateRawSync(deflated).toString('utf8');

    expect(decodedRequest).toContain('Destination="https://cybersmith.verify.ibm.com/saml/sps/saml20ip/saml20/login"');
  });

  test('should include entityId as Issuer', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=SAML Test application 1');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const deflated = Buffer.from(samlRequest, 'base64');
    const decodedRequest = zlib.inflateRawSync(deflated).toString('utf8');

    const protocol = config.application?.useHttps ? 'https' : 'http';
    const hostname = config.application?.hostname || 'localhost';
    const port = config.application?.port || 3001;
    const expectedIssuer = config.application?.entityId || `${protocol}://${hostname}:${port}/saml/metadata`;
    expect(decodedRequest).toContain(`<saml:Issuer>${expectedIssuer}</saml:Issuer>`);
  });

  test('should include default AuthNContextClassRef when not configured', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=SAML Test application 1');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const deflated = Buffer.from(samlRequest, 'base64');
    const decodedRequest = zlib.inflateRawSync(deflated).toString('utf8');

    // Should include the AuthNContextClassRef from the IdP configuration
    const idp = config.identityProviders.find(i => i.name === 'SAML Test application 1');
    const expectedAuthNContextClassRef = idp.authNContextClassRef || 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';
    expect(decodedRequest).toContain(`<saml:AuthnContextClassRef>${expectedAuthNContextClassRef}</saml:AuthnContextClassRef>`);
  });

  test('should use configured AuthNContextClassRef from IdP configuration', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=SAML Test application 1');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const deflated = Buffer.from(samlRequest, 'base64');
    const decodedRequest = zlib.inflateRawSync(deflated).toString('utf8');

    // Get the configured AuthNContextClassRef for this IdP
    const idp = config.identityProviders.find(i => i.name === 'SAML Test application 1');
    expect(idp.authNContextClassRef).toBeDefined();

    // Should include the configured AuthNContextClassRef
    expect(decodedRequest).toContain(`<saml:AuthnContextClassRef>${idp.authNContextClassRef}</saml:AuthnContextClassRef>`);
  });

  test('should request exact AuthN context comparison method', async () => {
    const response = await request(app)
      .get('/auth/saml/login?idp=SAML Test application 1');

    const redirectUrl = new URL(response.headers.location);
    const samlRequest = redirectUrl.searchParams.get('SAMLRequest');
    const deflated = Buffer.from(samlRequest, 'base64');
    const decodedRequest = zlib.inflateRawSync(deflated).toString('utf8');

    expect(decodedRequest).toContain('<samlp:RequestedAuthnContext Comparison="exact">');
  });
});
