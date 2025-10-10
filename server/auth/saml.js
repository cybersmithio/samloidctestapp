const express = require('express');
const { parseString } = require('xml2js');
const { SignedXml } = require('xml-crypto');
const configLoader = require('../utils/configLoader');

const router = express.Router();

function createSamlRouter(config) {
  // SAML login initiation
  router.get('/login', (req, res) => {
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

    // In a real implementation, you would generate a SAML AuthnRequest
    // and redirect to the IdP's login URL
    // For testing, we'll redirect to a callback with mock data
    res.redirect(`${idp.loginUrl}?RelayState=${encodeURIComponent(req.sessionID)}`);
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

module.exports = createSamlRouter;
