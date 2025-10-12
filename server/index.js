const express = require('express');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const samlAuth = require('./auth/saml');
const oidcAuth = require('./auth/oidc');
const configLoader = require('./utils/configLoader');
const { SignedXml } = require('xml-crypto');
const { parseString } = require('xml2js');

// Load configuration first (needed by middleware)
const config = configLoader.loadConfig();

const app = express();
const PORT = process.env.PORT || config.application?.port || 3001;

// Trust proxy headers - important for correct URL construction in redirects
app.set('trust proxy', true);

// Middleware
// Configure CORS - frontend is served by backend on same port
const getCorsOrigin = () => {
  return true;  // Allow same-origin requests (frontend served by backend)
};

app.use(cors({
  origin: getCorsOrigin(),
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// API Routes
app.get('/api/config', (req, res) => {
  // Return only safe configuration data to the client
  const safeConfig = {
    application: {
      hostname: config.application?.hostname,
      port: PORT,
      useHttps: config.application?.useHttps
    },
    identityProviders: config.identityProviders.map(idp => ({
      name: idp.name,
      protocol: idp.protocol
    }))
  };
  res.json(safeConfig);
});

app.get('/api/session', (req, res) => {
  if (req.session && req.session.user) {
    res.json(req.session.user);
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// SAML metadata endpoint
app.get('/saml/metadata', (req, res) => {
  try {
    const appConfig = config.application || {
      entityId: `${req.protocol}://${req.get('host')}/saml/metadata`,
      baseUrl: `${req.protocol}://${req.get('host')}`
    };

    const metadata = generateSAMLMetadata(appConfig);

    res.set('Content-Type', 'application/xml');
    res.set('Content-Disposition', 'attachment; filename="metadata.xml"');
    res.send(metadata);
  } catch (error) {
    console.error('Error generating SAML metadata:', error);
    res.status(500).json({ error: 'Failed to generate metadata' });
  }
});

// Helper function to generate SAML metadata
function generateSAMLMetadata(appConfig) {
  const entityId = appConfig.entityId;
  const baseUrl = appConfig.baseUrl;
  const acsUrl = `${baseUrl}/assert`;
  const signRequests = appConfig.signSamlRequests || false;

  // Load SAML signing certificate if signing is enabled
  let certificateContent = '';
  if (signRequests && appConfig.samlSigningCertificate) {
    try {
      const certPath = path.join(__dirname, '../data', appConfig.samlSigningCertificate);
      const cert = fs.readFileSync(certPath, 'utf8');
      // Extract certificate content (remove BEGIN/END lines and whitespace)
      certificateContent = cert
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s/g, '');
    } catch (error) {
      console.warn('Could not load SAML signing certificate for metadata:', error.message);
    }
  }

  // Build KeyDescriptor if certificate is available
  const keyDescriptor = certificateContent ? `
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>${certificateContent}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>` : '';

  const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="${entityId}"
                     validUntil="${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()}">

  <md:SPSSODescriptor AuthnRequestsSigned="${signRequests}" WantAssertionsSigned="true"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keyDescriptor}

    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>

    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="${acsUrl}"
                                 index="1"
                                 isDefault="true"/>
  </md:SPSSODescriptor>

  <md:Organization>
    <md:OrganizationName xml:lang="en">SAML/OIDC Test Application</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">SAML/OIDC Test Application</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">${appConfig.baseUrl}</md:OrganizationURL>
  </md:Organization>

  <md:ContactPerson contactType="technical">
    <md:GivenName>Technical Support</md:GivenName>
    <md:EmailAddress>support@example.com</md:EmailAddress>
  </md:ContactPerson>

</md:EntityDescriptor>`;

  return metadata;
}

// SAML assertion endpoint - receives and validates SAML assertions
app.post('/assert', async (req, res) => {
  try {
    const samlResponse = req.body.SAMLResponse;

    if (!samlResponse) {
      return res.status(400).json({
        error: 'Missing SAML response',
        details: 'SAMLResponse parameter is required'
      });
    }

    // Decode the SAML response (base64 encoded)
    let decodedSaml;
    try {
      decodedSaml = Buffer.from(samlResponse, 'base64').toString('utf8');
    } catch (decodeError) {
      return res.status(400).json({
        error: 'Invalid SAML response encoding',
        details: 'SAMLResponse must be base64 encoded'
      });
    }

    // Load all known certificates from the certificates directory
    const certificatesDir = path.join(__dirname, '../data/certificates');
    let certificateFiles;

    try {
      certificateFiles = fs.readdirSync(certificatesDir)
        .filter(file => file.endsWith('.pem') || file.endsWith('.crt') || file.endsWith('.cer'));
    } catch (readError) {
      return res.status(500).json({
        error: 'Failed to read certificates directory',
        details: readError.message
      });
    }

    if (certificateFiles.length === 0) {
      return res.status(500).json({
        error: 'No trusted certificates found',
        details: 'Please add certificate files (.pem, .crt, or .cer) to the data/certificates directory'
      });
    }

    // Try to verify the signature with each known certificate
    let isValid = false;
    let validCertificate = null;

    for (const certFile of certificateFiles) {
      try {
        const certificate = fs.readFileSync(path.join(certificatesDir, certFile), 'utf8');
        const verified = await verifySamlSignature(decodedSaml, certificate);

        if (verified) {
          isValid = true;
          validCertificate = certFile;
          break;
        }
      } catch (certError) {
        console.warn(`Error verifying with certificate ${certFile}:`, certError.message);
        // Continue trying other certificates
      }
    }

    if (!isValid) {
      return res.status(401).json({
        error: 'Invalid SAML signature',
        details: 'SAML assertion signature could not be verified with any known certificate',
        certificatesChecked: certificateFiles
      });
    }

    // Parse SAML assertion to extract user information
    let userInfo;
    try {
      userInfo = await parseSamlAssertion(decodedSaml);
    } catch (parseError) {
      return res.status(400).json({
        error: 'Failed to parse SAML assertion',
        details: parseError.message
      });
    }

    // Store the validated assertion in session
    req.session.user = {
      protocol: 'saml20',
      user: userInfo,
      verifiedBy: validCertificate,
      samlAssertion: decodedSaml,
      authenticatedAt: new Date().toISOString()
    };

    // Save session before redirect
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({
          error: 'Failed to save session',
          details: err.message
        });
      }

      // Construct absolute redirect URL using config
      const protocol = config.application?.useHttps ? 'https' : 'http';
      const hostname = config.application?.hostname || req.hostname || 'localhost';
      const port = PORT;
      const redirectUrl = `${protocol}://${hostname}:${port}/protected`;

      res.redirect(redirectUrl);
    });

  } catch (error) {
    console.error('SAML assertion validation error:', error);
    res.status(500).json({
      error: 'SAML assertion validation failed',
      details: error.message
    });
  }
});

// Helper function to verify SAML signature
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

// Helper function to parse SAML assertion
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
          const name = attr.$?.Name || attr.Name;
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

// SAML authentication routes
app.use('/auth/saml', samlAuth(config));

// OIDC authentication routes
app.use('/auth/oidc', oidcAuth(config));

// Serve static files from the React build folder
const buildPath = path.join(__dirname, '../build');
if (fs.existsSync(buildPath)) {
  app.use(express.static(buildPath));

  // Handle React routing - return index.html for all non-API routes
  app.get('*', (req, res) => {
    res.sendFile(path.join(buildPath, 'index.html'));
  });
} else {
  console.warn('Build folder not found. Run "npm run build" to create it.');
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// Start server only if not in test environment
if (process.env.NODE_ENV !== 'test') {
  const useHttps = config.application?.useHttps || false;
  const protocol = useHttps ? 'https' : 'http';
  const hostname = config.application?.hostname || 'localhost';

  if (useHttps) {
    // Load SSL certificate and key
    const certPath = path.join(__dirname, '../data', config.application.serverCertificate);
    const keyPath = path.join(__dirname, '../data', config.application.serverPrivateKey);

    const httpsOptions = {
      cert: fs.readFileSync(certPath, 'utf8'),
      key: fs.readFileSync(keyPath, 'utf8')
    };

    https.createServer(httpsOptions, app).listen(PORT, () => {
      console.log(`Server running on ${protocol}://${hostname}:${PORT}`);
      console.log(`Loaded ${config.identityProviders.length} identity provider(s)`);
      console.log('HTTPS enabled');
    });
  } else {
    http.createServer(app).listen(PORT, () => {
      console.log(`Server running on ${protocol}://${hostname}:${PORT}`);
      console.log(`Loaded ${config.identityProviders.length} identity provider(s)`);
      console.log('HTTP mode (HTTPS disabled)');
    });
  }
}

module.exports = app;
