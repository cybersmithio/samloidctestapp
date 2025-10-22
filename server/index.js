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
const { displayConfig } = require('./utils/configDisplay');

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
  const acsUrl = `${baseUrl}/auth/saml/callback`;
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
  const publicProtocol = config.application?.useHttpsPublicly ? 'https' : 'http';
  const publicPort = config.application?.publicPort || PORT;


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
      console.log(`Server publicly known as ${publicProtocol}://${hostname}:${publicPort}`);
      console.log(`Loaded ${config.identityProviders.length} identity provider(s)`);
      console.log('HTTPS enabled');
      displayConfig(config);
    });
  } else {
    http.createServer(app).listen(PORT, () => {
      console.log(`Server running on ${protocol}://${hostname}:${PORT}`);
      console.log(`Server publicly known as ${publicProtocol}://${hostname}:${publicPort}`);
      console.log(`Loaded ${config.identityProviders.length} identity provider(s)`);
      console.log('HTTP mode (HTTPS disabled)');
      displayConfig(config);
    });
  }
}

module.exports = app;
