const express = require('express');
const { parseString } = require('xml2js');
const { SignedXml } = require('xml-crypto');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const configLoader = require('../utils/configLoader');

const router = express.Router();

function createSamlRouter(config) {
  // SAML login initiation
  router.get('/login', (req, res) => {
    try {
      const idpName = req.query.idp;
      const idp = config.identityProviders.find(
        i => i.protocol === 'saml20' && i.name === idpName
      );

      if (!idp) {
        return res.status(404).json({ error: 'Identity provider not found' });
      }

      // Store IdP info in session for callback
      req.session.pendingIdp = {
        name: idp.name,
        protocol: 'saml20',
        certificate: idp.certificate
      };

      // Generate SAML AuthnRequest
      const appConfig = config.application || {
        entityId: `${req.protocol}://${req.get('host')}/saml/metadata`,
        baseUrl: `${req.protocol}://${req.get('host')}`
      };

      const acsUrl = `${appConfig.baseUrl}/assert`;
      const requestId = '_' + crypto.randomBytes(16).toString('hex');
      const issueInstant = new Date().toISOString();

      // Store request ID in session for validation
      req.session.samlRequestId = requestId;

      // Generate the SAML AuthnRequest XML
      const authnRequest = generateAuthnRequest({
        requestId,
        issueInstant,
        destination: idp.loginUrl,
        entityId: appConfig.entityId,
        acsUrl,
        //signRequest: appConfig.signSamlRequests || false,
        //certificate: appConfig.samlSigningCertificate,
        //privateKey: appConfig.samlSigningPrivateKey
      });

      // Base64 encode the request
      const samlRequest = Buffer.from(authnRequest).toString('base64');

      // Build redirect URL
      const redirectUrl = new URL(idp.loginUrl);
      redirectUrl.searchParams.append('SAMLRequest', samlRequest);
      redirectUrl.searchParams.append('RelayState', req.sessionID);

      // Redirect to IdP
      res.redirect(redirectUrl.toString());
    } catch (error) {
      console.error('SAML login error:', error);
      res.status(500).json({ error: 'Failed to initiate SAML login', details: error.message });
    }
  });

  // SAML assertion consumer service (callback)
  router.post('/callback', async (req, res) => {
    try {
      const samlResponse = req.body.SAMLResponse;

      if (!samlResponse) {
        return res.status(400).json({ error: 'Missing SAML response' });
      }

      // Decode the SAML response (base64 encoded)
      const decodedSaml = Buffer.from(samlResponse, 'base64').toString('utf8');

      // Get IdP configuration from session
      const pendingIdp = req.session.pendingIdp;
      if (!pendingIdp) {
        return res.status(400).json({ error: 'No pending authentication' });
      }

      // Load the certificate for signature verification
      const certificate = configLoader.loadCertificate(pendingIdp.certificate);

      // Verify SAML signature
      const isValid = await verifySamlSignature(decodedSaml, certificate);

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid SAML signature' });
      }

      // Parse SAML assertion
      const userInfo = await parseSamlAssertion(decodedSaml);

      // Store user info in session
      req.session.user = {
        protocol: 'saml20',
        idpName: pendingIdp.name,
        user: userInfo,
        samlAssertion: decodedSaml,
        authenticatedAt: new Date().toISOString()
      };

      // Clear pending IdP
      delete req.session.pendingIdp;

      // Redirect to protected page
      res.redirect('http://localhost:3000/protected');
    } catch (error) {
      console.error('SAML authentication error:', error);
      res.status(500).json({ error: 'SAML authentication failed' });
    }
  });

  // SAML logout
  router.get('/logout', (req, res) => {
    const idpName = req.session?.user?.idpName;
    const idp = config.identityProviders.find(
      i => i.protocol === 'saml20' && i.name === idpName
    );

    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }

      if (idp && idp.logoutUrl) {
        // Redirect to IdP logout
        res.redirect(idp.logoutUrl);
      } else {
        res.redirect('http://localhost:3000');
      }
    });
  });

  return router;
}

async function verifySamlSignature(samlXml, certificate) {
  try {
    // Extract public key from certificate
    const publicKey = certificate
      .replace('-----BEGIN CERTIFICATE-----', '')
      .replace('-----END CERTIFICATE-----', '')
      .replace(/\s/g, '');

    // Find signature in SAML response
    const signatureRegex = /<ds:Signature[^>]*>[\s\S]*?<\/ds:Signature>/;
    const signatureMatch = samlXml.match(signatureRegex);

    if (!signatureMatch) {
      console.warn('No signature found in SAML response');
      return false;
    }

    // Verify signature using xml-crypto
    const sig = new SignedXml();
    sig.keyInfoProvider = {
      getKeyInfo: () => `<X509Data><X509Certificate>${publicKey}</X509Certificate></X509Data>`,
      getKey: () => certificate
    };

    sig.loadSignature(signatureMatch[0]);
    const isValid = sig.checkSignature(samlXml);

    return isValid;
  } catch (error) {
    console.error('SAML signature verification error:', error);
    return false;
  }
}

async function parseSamlAssertion(samlXml) {
  return new Promise((resolve, reject) => {
    parseString(samlXml, { explicitArray: false }, (err, result) => {
      if (err) {
        return reject(err);
      }

      try {
        // Navigate SAML structure to extract user attributes
        const response = result['samlp:Response'] || result.Response;
        const assertion = response?.Assertion || response?.['saml:Assertion'];

        if (!assertion) {
          throw new Error('No assertion found in SAML response');
        }

        const subject = assertion.Subject || assertion['saml:Subject'];
        const nameID = subject?.NameID || subject?.['saml:NameID'];

        const attributeStatement = assertion.AttributeStatement ||
                                   assertion['saml:AttributeStatement'];
        const attributes = attributeStatement?.Attribute ||
                          attributeStatement?.['saml:Attribute'] || [];

        // Extract attributes
        const userInfo = {
          nameID: typeof nameID === 'string' ? nameID : nameID?._ || 'Unknown'
        };

        // Parse attributes (can be array or single object)
        const attrArray = Array.isArray(attributes) ? attributes : [attributes];

        attrArray.forEach(attr => {
          const name = attr.$ ?.Name || attr.Name;
          const value = attr.AttributeValue || attr['saml:AttributeValue'];

          if (name && value) {
            const attrValue = typeof value === 'string' ? value : value._;

            // Map common SAML attributes
            if (name.includes('email') || name.includes('emailaddress')) {
              userInfo.email = attrValue;
            } else if (name.includes('name') && !name.includes('username')) {
              userInfo.name = attrValue;
            } else if (name.includes('firstname') || name.includes('givenname')) {
              userInfo.firstName = attrValue;
            } else if (name.includes('lastname') || name.includes('surname')) {
              userInfo.lastName = attrValue;
            } else {
              userInfo[name] = attrValue;
            }
          }
        });

        resolve(userInfo);
      } catch (parseError) {
        reject(parseError);
      }
    });
  });
}

function generateAuthnRequest(options) {
  const {
    requestId,
    issueInstant,
    destination,
    entityId,
    acsUrl,
    signRequest,
    certificate,
    privateKey
  } = options;

  // Build the SAML AuthnRequest XML with only essential elements
  let authnRequest = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="${requestId}"
                    Version="2.0"
                    IssueInstant="${issueInstant}"
                    Destination="${destination}"
                    AssertionConsumerServiceURL="${acsUrl}"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>${entityId}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`;

  // Sign the request if signing is enabled
  if (signRequest && certificate && privateKey) {
    try {
      authnRequest = signAuthnRequest(authnRequest, certificate, privateKey);
    } catch (error) {
      console.warn('Failed to sign SAML AuthnRequest:', error.message);
      // Continue with unsigned request
    }
  }

  return authnRequest;
}

function signAuthnRequest(xml, certificatePath, privateKeyPath) {
  // Load the private key and certificate
  const keyPath = path.join(__dirname, '../../data', privateKeyPath);
  const certPath = path.join(__dirname, '../../data', certificatePath);

  if (!fs.existsSync(keyPath)) {
    throw new Error(`Private key file not found: ${keyPath}`);
  }
  if (!fs.existsSync(certPath)) {
    throw new Error(`Certificate file not found: ${certPath}`);
  }

  const privateKey = fs.readFileSync(keyPath, 'utf8');
  const certificate = fs.readFileSync(certPath, 'utf8');

  // Validate that we actually read the key
  if (!privateKey || !privateKey.includes('PRIVATE KEY')) {
    throw new Error('Invalid private key format');
  }

  // Extract certificate content (remove BEGIN/END lines)
  const certContent = certificate
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s/g, '');

  // Create signature using xml-crypto with options
  const sig = new SignedXml({
    privateKey: privateKey,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#'
  });

  // Set key info provider
  sig.keyInfoProvider = {
    getKeyInfo: () => {
      return `<X509Data><X509Certificate>${certContent}</X509Certificate></X509Data>`;
    }
  };

  // Add reference to the root element with transforms and digest method
  sig.addReference({
    xpath: "//*[local-name(.)='AuthnRequest']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256'
  });

  // Compute and embed signature
  sig.computeSignature(xml, {
    location: { reference: "//*[local-name(.)='Issuer']", action: 'after' }
  });

  return sig.getSignedXml();
}

module.exports = createSamlRouter;
