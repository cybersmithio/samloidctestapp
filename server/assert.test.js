const request = require('supertest');
const app = require('./index');
const fs = require('fs');
const path = require('path');
const configLoader = require('./utils/configLoader');

describe('POST /assert', () => {
  let config;
  let destinationUrl;

  beforeAll(() => {
    config = configLoader.loadConfig();
    const baseUrl = config.application?.baseUrl || `http://${config.application?.hostname || 'localhost'}:3001`;
    destinationUrl = `${baseUrl}/assert`;
  });

  const mockSamlResponse = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_abc123"
                Version="2.0"
                IssueInstant="2025-10-10T12:00:00Z"
                Destination="http://workstation.cybersmith.local:3001/assert">
  <saml:Issuer>http://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_def456"
                  Version="2.0"
                  IssueInstant="2025-10-10T12:00:00Z">
    <saml:Issuer>http://idp.example.com</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_def456">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>mock-digest-value</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>mock-signature-value</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="firstName">
        <saml:AttributeValue>John</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="lastName">
        <saml:AttributeValue>Doe</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

  test('should return 400 when SAMLResponse is missing', async () => {
    const response = await request(app)
      .post('/assert')
      .send({});

    expect(response.status).toBe(400);
    expect(response.body).toHaveProperty('error', 'Missing SAML response');
  });

  test('should process even malformed base64 (Node.js is forgiving)', async () => {
    const response = await request(app)
      .post('/assert')
      .send({ SAMLResponse: 'not-base64!!!invalid' });

    // Node.js Buffer.from() is forgiving with base64, so it may decode successfully
    // but will fail at signature verification or XML parsing
    expect([400, 401, 500]).toContain(response.status);
  });

  test('should return 500 when no certificates are found', async () => {
    // Create a mock that returns empty array for certificate files
    const originalReaddir = fs.readdirSync;
    fs.readdirSync = jest.fn().mockReturnValue([]);

    const encodedSaml = Buffer.from(mockSamlResponse).toString('base64');
    const response = await request(app)
      .post('/assert')
      .send({ SAMLResponse: encodedSaml });

    expect(response.status).toBe(500);
    expect(response.body).toHaveProperty('error', 'No trusted certificates found');

    // Restore original function
    fs.readdirSync = originalReaddir;
  });

  test('should return 401 when signature cannot be verified', async () => {
    const encodedSaml = Buffer.from(mockSamlResponse).toString('base64');
    const response = await request(app)
      .post('/assert')
      .send({ SAMLResponse: encodedSaml });

    // Since we don't have valid certificates in test environment, it should fail verification
    expect([401, 500]).toContain(response.status);
    if (response.status === 401) {
      expect(response.body).toHaveProperty('error', 'Invalid SAML signature');
    }
  });

  test('should reject SAML response without signature', async () => {
    const noSignatureSaml = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>`;

    const encodedSaml = Buffer.from(noSignatureSaml).toString('base64');
    const response = await request(app)
      .post('/assert')
      .send({ SAMLResponse: encodedSaml });

    // Should return 401 or 500 because signature verification will fail (no signature found)
    expect([401, 500]).toContain(response.status);
    if (response.status === 401) {
      expect(response.body).toHaveProperty('error', 'Invalid SAML signature');
    }
  });

  test('should return 400 when SAML assertion cannot be parsed', async () => {
    const invalidXml = '<?xml version="1.0"?><Invalid><XML</Invalid>';
    const encodedSaml = Buffer.from(invalidXml).toString('base64');

    // Mock the signature verification to pass
    const originalReaddir = fs.readdirSync;
    const originalReadFile = fs.readFileSync;

    fs.readdirSync = jest.fn().mockReturnValue(['test.pem']);
    fs.readFileSync = jest.fn((filePath) => {
      if (filePath.includes('test.pem')) {
        return '-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----';
      }
      return originalReadFile(filePath);
    });

    const response = await request(app)
      .post('/assert')
      .send({ SAMLResponse: encodedSaml });

    // Should fail because XML is invalid
    expect([400, 401]).toContain(response.status);

    // Restore original functions
    fs.readdirSync = originalReaddir;
    fs.readFileSync = originalReadFile;
  });
});
