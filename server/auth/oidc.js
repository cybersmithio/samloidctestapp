const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const crypto = require('crypto');
const configLoader = require('../utils/configLoader');

const router = express.Router();

function createOidcRouter(config) {
  // Helper function to get protocol based on config
  const getProtocol = () => {
    return config.application?.useHttps ? 'https' : 'http';
  };

  // Helper function to get the frontend dev server URL (only used in development)
  const getFrontendDevUrl = () => {
    const hostname = config.application?.hostname || 'localhost';
    const protocol = getProtocol();
    // In development, React dev server typically runs on port 3000
    return `${protocol}://${hostname}:3000`;
  };

  // OIDC login initiation
  router.get('/login', (req, res) => {
    const idpName = req.query.idp;
    const idp = config.identityProviders.find(
      i => i.protocol === 'oidc' && i.name === idpName
    );

    if (!idp) {
      return res.status(404).json({ error: 'Identity provider not found' });
    }

    // Generate state and nonce for CSRF protection
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');

    // Construct callback URL from application baseUrl
    const baseUrl = config.application?.baseUrl || `${req.protocol}://${req.get('host')}`;
    const callbackUrl = `${baseUrl}/auth/oidc/callback`;

    // Store state, nonce, and IdP info in session
    req.session.oidcState = state;
    req.session.oidcNonce = nonce;
    req.session.pendingIdp = {
      name: idp.name,
      protocol: 'oidc',
      config: idp
    };

    // Build authorization URL
    const authUrl = new URL(idp.authorizationUrl);
    authUrl.searchParams.append('client_id', idp.clientId);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('redirect_uri', callbackUrl);
    authUrl.searchParams.append('scope', idp.scope);
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('nonce', nonce);

    res.redirect(authUrl.toString());
  });

  // OIDC callback
  router.get('/callback', async (req, res) => {
    try {
      const { code, state, error, error_description } = req.query;

      // Check for error from IdP
      if (error) {
        console.error('OIDC error:', error, error_description);
        if (process.env.NODE_ENV === 'production') {
          return res.redirect(`/?error=${encodeURIComponent(error_description || error)}`);
        } else {
          return res.redirect(`${getFrontendDevUrl()}?error=${encodeURIComponent(error_description || error)}`);
        }
      }

      // Verify state parameter
      if (!state || state !== req.session.oidcState) {
        return res.status(400).json({ error: 'Invalid state parameter' });
      }

      const pendingIdp = req.session.pendingIdp;
      if (!pendingIdp || pendingIdp.protocol !== 'oidc') {
        return res.status(400).json({ error: 'No pending OIDC authentication' });
      }

      const idpConfig = pendingIdp.config;

      // Construct callback URL from application baseUrl
      const baseUrl = config.application?.baseUrl || `${req.protocol}://${req.get('host')}`;
      const callbackUrl = `${baseUrl}/auth/oidc/callback`;

      // Exchange authorization code for tokens
      const tokenResponse = await fetch(idpConfig.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: callbackUrl,
          client_id: idpConfig.clientId,
          client_secret: idpConfig.clientSecret
        })
      });

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        throw new Error(`Token exchange failed: ${errorText}`);
      }

      const tokens = await tokenResponse.json();
      const { id_token, access_token } = tokens;

      if (!id_token) {
        throw new Error('No ID token received');
      }

      // Verify JWT signature and decode
      const decodedToken = await verifyJwt(id_token, idpConfig);

      // Verify nonce
      if (decodedToken.nonce !== req.session.oidcNonce) {
        throw new Error('Invalid nonce');
      }

      // Fetch user info if userInfoUrl is provided
      let userInfo = {
        id: decodedToken.sub,
        email: decodedToken.email,
        name: decodedToken.name,
        ...decodedToken
      };

      if (idpConfig.userInfoUrl && access_token) {
        try {
          const userInfoResponse = await fetch(idpConfig.userInfoUrl, {
            headers: {
              'Authorization': `Bearer ${access_token}`
            }
          });

          if (userInfoResponse.ok) {
            const additionalUserInfo = await userInfoResponse.json();
            userInfo = { ...userInfo, ...additionalUserInfo };
          }
        } catch (err) {
          console.warn('Failed to fetch user info:', err);
        }
      }

      // Store user info in session
      req.session.user = {
        protocol: 'oidc',
        idpName: pendingIdp.name,
        user: userInfo,
        jwtToken: id_token,
        accessToken: access_token,
        authenticatedAt: new Date().toISOString()
      };

      // Clear pending authentication data
      delete req.session.oidcState;
      delete req.session.oidcNonce;
      delete req.session.pendingIdp;

      // Redirect to protected page
      if (process.env.NODE_ENV === 'production') {
        res.redirect('/protected');
      } else {
        res.redirect(`${getFrontendDevUrl()}/protected`);
      }
    } catch (error) {
      console.error('OIDC authentication error:', error);
      if (process.env.NODE_ENV === 'production') {
        res.redirect(`/?error=${encodeURIComponent(error.message)}`);
      } else {
        res.redirect(`${getFrontendDevUrl()}?error=${encodeURIComponent(error.message)}`);
      }
    }
  });

  // OIDC logout
  router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
      if (process.env.NODE_ENV === 'production') {
        res.redirect('/');
      } else {
        res.redirect(getFrontendDevUrl());
      }
    });
  });

  return router;
}

async function verifyJwt(token, idpConfig) {
  return new Promise((resolve, reject) => {
    // Decode header to get kid (key ID)
    const decodedHeader = jwt.decode(token, { complete: true });

    if (!decodedHeader) {
      return reject(new Error('Invalid JWT token'));
    }

    // Create JWKS client
    const client = jwksClient({
      jwksUri: idpConfig.metadataUrl.replace('/.well-known/openid-configuration', '/discovery/keys'),
      cache: true,
      cacheMaxAge: 86400000 // 24 hours
    });

    // Get signing key
    client.getSigningKey(decodedHeader.header.kid, (err, key) => {
      if (err) {
        // If JWKS fetch fails, try using certificate-based verification
        return verifyCertificateBased(token, idpConfig, resolve, reject);
      }

      const signingKey = key.getPublicKey();

      // Verify token
      jwt.verify(token, signingKey, {
        issuer: idpConfig.issuerUrl,
        audience: idpConfig.clientId,
        algorithms: ['RS256', 'RS384', 'RS512']
      }, (verifyErr, decoded) => {
        if (verifyErr) {
          return reject(new Error(`JWT verification failed: ${verifyErr.message}`));
        }

        resolve(decoded);
      });
    });
  });
}

function verifyCertificateBased(token, idpConfig, resolve, reject) {
  try {
    // If a certificate is configured, use it for verification
    if (idpConfig.certificate) {
      const certificate = configLoader.loadCertificate(idpConfig.certificate);

      jwt.verify(token, certificate, {
        issuer: idpConfig.issuerUrl,
        audience: idpConfig.clientId,
        algorithms: ['RS256', 'RS384', 'RS512']
      }, (err, decoded) => {
        if (err) {
          return reject(new Error(`JWT verification failed: ${err.message}`));
        }
        resolve(decoded);
      });
    } else {
      reject(new Error('No signing key or certificate available for JWT verification'));
    }
  } catch (error) {
    reject(error);
  }
}

module.exports = createOidcRouter;
