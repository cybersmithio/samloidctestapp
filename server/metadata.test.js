const request = require('supertest');
const app = require('./index');

describe('GET /saml/metadata', () => {
  test('should return SAML metadata XML', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toContain('application/xml');
    expect(response.headers['content-disposition']).toContain('attachment');
    expect(response.headers['content-disposition']).toContain('metadata.xml');
    expect(response.text).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    expect(response.text).toContain('EntityDescriptor');
    expect(response.text).toContain('SPSSODescriptor');
  });

  test('should include AssertionConsumerService with /auth/saml/callback endpoint', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    expect(response.text).toContain('AssertionConsumerService');
    expect(response.text).toContain('/auth/saml/callback');
    expect(response.text).toContain('HTTP-POST');
  });

  test('should include correct NameID formats', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    expect(response.text).toContain('NameIDFormat');
    expect(response.text).toContain('emailAddress');
    expect(response.text).toContain('unspecified');
  });

  test('should include organization information', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    expect(response.text).toContain('Organization');
    expect(response.text).toContain('SAML/OIDC Test Application');
  });

  test('should include contact information', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    expect(response.text).toContain('ContactPerson');
    expect(response.text).toContain('technical');
  });

  test('should set WantAssertionsSigned to true', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    expect(response.text).toContain('WantAssertionsSigned="true"');
  });

  test('should set AuthnRequestsSigned based on config', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    expect(response.text).toContain('AuthnRequestsSigned=');
  });

  test('should include KeyDescriptor with certificate when signing enabled', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    // If signing is enabled and certificate exists, should have KeyDescriptor
    if (response.text.includes('AuthnRequestsSigned="true"')) {
      expect(response.text).toContain('KeyDescriptor');
      expect(response.text).toContain('X509Certificate');
    }
  });

  test('should have validUntil attribute with future date', async () => {
    const response = await request(app)
      .get('/saml/metadata');

    expect(response.status).toBe(200);
    expect(response.text).toContain('validUntil');

    // Extract the validUntil date
    const validUntilMatch = response.text.match(/validUntil="([^"]+)"/);
    expect(validUntilMatch).toBeTruthy();

    const validUntilDate = new Date(validUntilMatch[1]);
    const now = new Date();

    // Should be in the future
    expect(validUntilDate.getTime()).toBeGreaterThan(now.getTime());
  });
});
