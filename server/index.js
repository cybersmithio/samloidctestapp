const express = require('express');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const samlAuth = require('./auth/saml');
const oidcAuth = require('./auth/oidc');
const configLoader = require('./utils/configLoader');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: 'http://localhost:3000',
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

// Load configuration
const config = configLoader.loadConfig();

// API Routes
app.get('/api/config', (req, res) => {
  // Return only safe configuration data to the client
  const safeConfig = {
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

// SAML authentication routes
app.use('/auth/saml', samlAuth(config));

// OIDC authentication routes
app.use('/auth/oidc', oidcAuth(config));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Loaded ${config.identityProviders.length} identity provider(s)`);
});

module.exports = app;
