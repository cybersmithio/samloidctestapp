const express = require('express');
const { parseString } = require('xml2js');
const { SignedXml } = require('xml-crypto');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const configLoader = require('../utils/configLoader');

function createSamlRouter(config) {
  const router = express.Router();

  // Helper function to build absolute URLs from config
  const buildAbsoluteUrl = (path = '/') => {
    // Use useHttpsPublicly for public URLs (handles proxy SSL termination)
    const protocol = config.application?.useHttpsPublicly ? 'https' : 'http';
    const hostname = config.application?.hostname || 'localhost';
    const publicPort = config.application?.publicPort || config.application?.port || 3001;
    // Only include port in URL if it's not the default for the protocol
    const portPart = (protocol === 'https' && publicPort === 443) || (protocol === 'http' && publicPort === 80)
      ? ''
      : `:${publicPort}`;
    return `${protocol}://${hostname}${portPart}${path}`;
  };

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

      // Store request ID in session for validation
      const requestId = '_' + crypto.randomBytes(16).toString('hex');
      req.session.samlRequestId = requestId;

      // Generate SAML AuthnRequest
      const appConfig = config.application || {
        entityId: `${req.protocol}://${req.get('host')}/saml/metadata`,
        baseUrl: `${req.protocol}://${req.get('host')}`
      };

      const acsUrl = `${appConfig.baseUrl}/auth/saml/callback`;
      const issueInstant = new Date().toISOString();

      // Generate the SAML AuthnRequest XML
      const authnRequest = generateAuthnRequest({
        requestId,
        issueInstant,
        destination: idp.loginUrl,
        entityId: appConfig.entityId,
        acsUrl,
        authNContextClassRef: idp.authNContextClassRef,
        //signRequest: appConfig.signSamlRequests || false,
        //certificate: appConfig.samlSigningCertificate,
        //privateKey: appConfig.samlSigningPrivateKey
      });

      // Encode based on binding type (default to 'redirect')
      const binding = idp.binding || 'redirect';

      // Save session before sending response to ensure session data is persisted
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.status(500).json({ error: 'Failed to save session' });
        }

        let samlRequest;

        if (binding === 'redirect') {
          // HTTP-Redirect binding: deflate compress, then base64 encode
          const deflated = zlib.deflateRawSync(Buffer.from(authnRequest, 'utf8'));
          samlRequest = deflated.toString('base64');

          // Build redirect URL
          const redirectUrl = new URL(idp.loginUrl);
          redirectUrl.searchParams.append('SAMLRequest', samlRequest);
          redirectUrl.searchParams.append('RelayState', req.sessionID);

          // Redirect to IdP
          res.redirect(redirectUrl.toString());
        } else if (binding === 'post') {
          // HTTP-POST binding: just base64 encode (no deflate)
          samlRequest = Buffer.from(authnRequest, 'utf8').toString('base64');

          // Send HTML form that auto-submits to IdP
          const html = `
<!DOCTYPE html>
<html>
<head><title>SAML Request</title></head>
<body onload="document.forms[0].submit()">
  <form method="POST" action="${idp.loginUrl}">
    <input type="hidden" name="SAMLRequest" value="${samlRequest}" />
    <input type="hidden" name="RelayState" value="${req.sessionID}" />
    <noscript><button type="submit">Continue</button></noscript>
  </form>
</body>
</html>`;
          res.send(html);
        }
      });
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

      // Get IdP configuration from session (SP-initiated flow)
      let pendingIdp = req.session.pendingIdp;

      // If no pending IdP, this is IdP-initiated SSO
      // Try to identify the IdP using certificate matching (most secure method)
      if (!pendingIdp) {
        // Get all SAML IdPs
        const samlIdps = config.identityProviders.filter(i => i.protocol === 'saml20');

        // Try certificate matching first (cryptographically secure)
        let matchedIdp = null;
        for (const idp of samlIdps) {
          try {
            const certificate = configLoader.loadCertificate(idp.certificate);
            const isValid = await verifySamlSignature(decodedSaml, certificate);

            if (isValid) {
              matchedIdp = idp;
              break;
            }
          } catch (certError) {
            // Certificate verification failed, try next IdP
            continue;
          }
        }

        // If certificate matching failed, fall back to issuerUrl matching
        if (!matchedIdp) {
          try {
            const issuer = await extractIssuerFromSamlResponse(decodedSaml);

            // Find the IdP configuration by matching the issuer URL
            matchedIdp = samlIdps.find(i => i.issuerUrl === issuer);

            if (!matchedIdp) {
              return res.status(400).json({
                error: 'Identity provider not found',
                details: `No configured IdP found with issuer: ${issuer} or matching certificate`
              });
            }
          } catch (extractError) {
            console.error('Failed to extract issuer from SAML response:', extractError);
            return res.status(400).json({
              error: 'Invalid SAML response',
              details: 'Could not identify identity provider by certificate or issuer'
            });
          }
        }

        // Create a pendingIdp object for IdP-initiated flow
        pendingIdp = {
          name: matchedIdp.name,
          protocol: 'saml20',
          certificate: matchedIdp.certificate
        };
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

      // Save session before redirect to ensure it's persisted
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.status(500).json({ error: 'Failed to save session' });
        }
        // Redirect to protected page using absolute URL from config
        res.redirect(buildAbsoluteUrl('/protected'));
      });
    } catch (error) {
      console.error('SAML authentication error:', error);
      res.status(500).json({ error: 'SAML authentication failed' });
    }
  });

  // SAML logout
  router.get('/logout', (req, res) => {
    console.log('SAML /logout has been called');

    try {
      const idpName = req.session?.user?.idpName;
      console.log(`idpName: ${idpName}`);
      const nameID = req.session?.user?.user?.nameID;
      console.log(`nameId: ${nameID}`);

      const idp = config.identityProviders.find(
        i => i.protocol === 'saml20' && i.name === idpName
      );

      // Capture user info before destroying session
      const userInfo = {
        idp,
        nameID
      };

      console.log(`userInfo`);
      console.log(userInfo);


      req.session.destroy((err) => {
        if (err) {
          console.error('Session destruction error:', err);
        }

        if (userInfo.idp && userInfo.idp.logoutUrl) {
          console.log(`The IdP has a logout Url: ${userInfo.idp.logoutUrl}`);

          // Generate SAML LogoutRequest
          const appConfig = config.application || {
            entityId: `${req.protocol}://${req.get('host')}/saml/metadata`,
            baseUrl: `${req.protocol}://${req.get('host')}`
          };

          const requestId = '_' + crypto.randomBytes(16).toString('hex');
          const issueInstant = new Date().toISOString();

          const logoutRequest = generateLogoutRequest({
            requestId,
            issueInstant,
            destination: userInfo.idp.logoutUrl,
            entityId: appConfig.entityId,
            nameID: userInfo.nameID || 'unknown'
          });

          // Encode based on binding type (default to 'redirect')
          const binding = userInfo.idp.binding || 'redirect';
          let samlRequest;

          if (binding === 'redirect') {
            console.log(`The binding for logout is an HTTP redirect`);

            // HTTP-Redirect binding: deflate compress, then base64 encode
            const deflated = zlib.deflateRawSync(Buffer.from(logoutRequest, 'utf8'));
            samlRequest = deflated.toString('base64');

            // Build redirect URL
            const redirectUrl = new URL(userInfo.idp.logoutUrl);
            redirectUrl.searchParams.append('SAMLRequest', samlRequest);

            // Redirect to IdP logout
            console.log(`Sending a redirect back to the user for logout`);

            res.redirect(redirectUrl.toString());
          } else if (binding === 'post') {
            console.log(`The binding for logout is an HTTP POST`);
            // HTTP-POST binding: just base64 encode (no deflate)
            samlRequest = Buffer.from(logoutRequest, 'utf8').toString('base64');

            // Send HTML form that auto-submits to IdP
            const html = `
<!DOCTYPE html>
<html>
<head><title>SAML Logout Request</title></head>
<body onload="document.forms[0].submit()">
  <form method="POST" action="${userInfo.idp.logoutUrl}">
    <input type="hidden" name="SAMLRequest" value="${samlRequest}" />
    <noscript><button type="submit">Continue</button></noscript>
  </form>
</body>
</html>`;
            console.log(`Sending an HTML page back to the user for logout`);
            res.send(html);
          }
        } else {
          console.log(`There is no logout URL for the IdP, so just sending the user home`);

          // Redirect to home page using absolute URL from config
          res.redirect(buildAbsoluteUrl('/'));
        }
      });
    } catch (error) {
      console.error('SAML logout error:', error);
      // Attempt to destroy session even on error
      req.session.destroy(() => {
        res.redirect(buildAbsoluteUrl('/'));
      });
    }
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

async function extractIssuerFromSamlResponse(samlXml) {
  return new Promise((resolve, reject) => {
    parseString(samlXml, { explicitArray: false }, (err, result) => {
      if (err) {
        return reject(err);
      }

      try {
        // Navigate SAML structure to extract Issuer
        const response = result['samlp:Response'] || result.Response;

        if (!response) {
          throw new Error('Invalid SAML response structure');
        }

        // Get Issuer from Response element
        const issuer = response.Issuer || response['saml:Issuer'];

        if (!issuer) {
          throw new Error('No Issuer found in SAML response');
        }

        // Issuer can be a string or an object with _
        const issuerValue = typeof issuer === 'string' ? issuer : issuer._;

        if (!issuerValue) {
          throw new Error('Issuer value is empty');
        }

        resolve(issuerValue);
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
    authNContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
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
    <saml:AuthnContextClassRef>${authNContextClassRef}</saml:AuthnContextClassRef>
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

function generateLogoutRequest(options) {
  const {
    requestId,
    issueInstant,
    destination,
    entityId,
    nameID
  } = options;

  // Build the SAML LogoutRequest XML
  const logoutRequest = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="${requestId}"
                     Version="2.0"
                     IssueInstant="${issueInstant}"
                     Destination="${destination}">
  <saml:Issuer>${entityId}</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameID}</saml:NameID>
</samlp:LogoutRequest>`;

  return logoutRequest;
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
