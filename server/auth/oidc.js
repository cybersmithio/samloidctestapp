const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');
const configLoader = require('../utils/configLoader');

function createOidcRouter(config) {
  const router = express.Router();

  // Helper function to make HTTP/HTTPS requests with custom certificate handling
  // Uses native http/https modules instead of fetch to properly handle rejectUnauthorized
  const makeRequest = (urlString, options) => {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(urlString);
      const protocol = parsedUrl.protocol === 'https:' ? https : http;

      const requestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port,
        path: parsedUrl.pathname + parsedUrl.search,
        method: options.method || 'GET',
        headers: options.headers || {},
        agent: options.agent
      };

      // Set Content-Length header if there's a body
      // This is important for POST requests with form-encoded data
      if (options.body) {
        const bodyBuffer = Buffer.isBuffer(options.body) ? options.body : Buffer.from(String(options.body));
        requestOptions.headers['Content-Length'] = bodyBuffer.length;
      }

      const req = protocol.request(requestOptions, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          // Return a Response-like object compatible with fetch API
          resolve({
            status: res.statusCode,
            statusCode: res.statusCode,
            ok: res.statusCode >= 200 && res.statusCode < 300,
            text: () => Promise.resolve(data),
            json: () => Promise.resolve(JSON.parse(data)),
            headers: res.headers
          });
        });
      });

      req.on('error', reject);
      if (options.body) {
        const bodyStr = String(options.body);
        console.log('[makeRequest] Writing body to request:', bodyStr.substring(0, 200));
        req.write(options.body);
      }
      req.end();
    });
  };

  // Helper function to build request options with custom CA certificate if provided
  const buildRequestOptions = (idpConfig, baseOptions = {}) => {
    const options = { ...baseOptions };

    // Check if certificate verification should be skipped (insecure, development only)
    if (idpConfig.insecureSkipCertificateVerification) {
      console.warn('[OIDC] WARNING: Certificate verification DISABLED for IdP:', idpConfig.name);
      console.warn('[OIDC] This is insecure and should ONLY be used for development/testing!');

      // Create HTTPS agent with disabled certificate verification
      options.agent = new https.Agent({
        rejectUnauthorized: false
      });
    }
    // If IdP has a custom certificate specified, use custom CA
    else if (idpConfig.idpCertificate) {
      try {
        // Certificate path is relative to data/certificates/ directory
        const certPath = path.join(__dirname, '../../data/certificates', idpConfig.idpCertificate);
        const certContent = fs.readFileSync(certPath, 'utf8');

        // Create HTTPS agent with custom CA certificate
        options.agent = new https.Agent({
          ca: certContent,
          rejectUnauthorized: true
        });

        console.log('[OIDC] Using custom CA certificate for IdP:', idpConfig.idpCertificate);
      } catch (error) {
        console.warn('[OIDC] Could not load IdP certificate:', idpConfig.idpCertificate, error.message);
        // Continue without custom cert - will fail if certificate is invalid
      }
    }

    return options;
  };

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
    const baseUrl = config.application?.baseUrl || buildAbsoluteUrl('');
    const callbackUrl = `${baseUrl}/auth/oidc/callback`;

    // Determine response mode based on response type
    const responseType = idp.responseType || 'code';
    const usesFragmentResponse = responseType !== 'code' && responseType !== 'none';
    const responseMode = usesFragmentResponse ? 'fragment' : 'query';

    // Store state, nonce, and IdP info in session
    req.session.oidcState = state;
    req.session.oidcNonce = nonce;
    req.session.pendingIdp = {
      name: idp.name,
      protocol: 'oidc',
      config: idp,
      responseType: responseType
    };

    // Build authorization URL
    const authUrl = new URL(idp.authorizationUrl);
    authUrl.searchParams.append('client_id', idp.clientId);
    authUrl.searchParams.append('response_type', responseType);
    authUrl.searchParams.append('redirect_uri', callbackUrl);
    authUrl.searchParams.append('scope', idp.scope);
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('nonce', nonce);
    authUrl.searchParams.append('response_mode', responseMode);

    res.redirect(authUrl.toString());
  });

  // OIDC callback - handles both query parameters (code flow) and fragments (implicit/hybrid)
  router.get('/callback', async (req, res) => {
    // If no query parameters, return HTML page to extract fragment parameters
    if (Object.keys(req.query).length === 0) {
      return res.send(`<!DOCTYPE html>
<html>
<head>
  <title>Processing Authentication...</title>
  <script>
    // Extract parameters from URL fragment and POST to server
    const fragment = window.location.hash.substring(1);
    if (fragment) {
      const params = new URLSearchParams(fragment);

      // Send as application/x-www-form-urlencoded (compatible with express.urlencoded)
      fetch(window.location.pathname, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: params.toString()
      }).then(response => {
        if (!response.ok) {
          // Try to extract error message from response
          return response.json().then(data => {
            throw new Error(data.error || 'Authentication failed with status ' + response.status);
          }).catch(jsonErr => {
            // If JSON parsing fails, throw generic error
            throw new Error('Authentication failed with status ' + response.status);
          });
        }
        // Check if response is redirect (3xx) or success
        if (response.redirected) {
          window.location.href = response.url;
        } else {
          // For successful non-redirect responses, go to protected page
          window.location.href = '/protected';
        }
      }).catch(err => {
        console.error('Authentication error:', err);
        window.location.href = '/?error=' + encodeURIComponent(err.message);
      });
    } else {
      // No fragment params, likely an error or direct access
      window.location.href = '/?error=no_auth_response';
    }
  </script>
</head>
<body>
  <p>Processing authentication response...</p>
</body>
</html>`);
    }

    await handleOidcCallback(req, res, req.query);
  });

  // POST handler for fragment-based responses (implicit/hybrid flows)
  router.post('/callback', async (req, res) => {
    console.log('[OIDC Callback POST] Content-Type:', req.get('Content-Type'));
    console.log('[OIDC Callback POST] Body keys:', Object.keys(req.body));
    console.log('[OIDC Callback POST] Has state:', !!req.body.state);
    console.log('[OIDC Callback POST] Has id_token:', !!req.body.id_token);
    await handleOidcCallback(req, res, req.body);
  });

  // Shared callback handler
  async function handleOidcCallback(req, res, params) {
    try {
      console.log('[OIDC Callback] Received parameters:', Object.keys(params).join(', '));
      const { code, id_token, access_token, token_type, state, error, error_description } = params;

      // Check for error from IdP
      if (error) {
        console.error('[OIDC Callback] Error from IdP:', error, error_description);
        // Redirect to home page with error using absolute URL from config
        return res.redirect(buildAbsoluteUrl(`/?error=${encodeURIComponent(error_description || error)}`));
      }

      // Verify state parameter
      if (!state || state !== req.session.oidcState) {
        const errorMsg = !state ? 'Missing state parameter' : 'Invalid state parameter (possible CSRF attack)';
        console.error('[OIDC Callback] State validation failed:', errorMsg);
        console.error('[OIDC Callback] Expected state:', req.session.oidcState);
        console.error('[OIDC Callback] Received state:', state);
        return res.status(400).json({ error: errorMsg });
      }

      const pendingIdp = req.session.pendingIdp;
      if (!pendingIdp || pendingIdp.protocol !== 'oidc') {
        const errorMsg = 'No pending OIDC authentication - session may have expired';
        console.error('[OIDC Callback] Session validation failed:', errorMsg);
        console.error('[OIDC Callback] Session data:', {
          hasPendingIdp: !!pendingIdp,
          protocol: pendingIdp?.protocol,
          sessionID: req.sessionID
        });
        return res.status(400).json({ error: errorMsg });
      }

      console.log('[OIDC Callback] Authenticated with IdP:', pendingIdp.name);
      console.log('[OIDC Callback] Response type:', pendingIdp.responseType);

      const idpConfig = pendingIdp.config;
      const responseType = pendingIdp.responseType || 'code';

      // Determine what tokens we should have based on response type
      const usesCode = responseType.includes('code');
      const expectsIdToken = responseType.includes('id_token');
      const expectsAccessToken = responseType.includes('token');

      let finalIdToken = id_token;
      let finalAccessToken = access_token;

      // Handle authorization code flow - exchange code for tokens
      if (usesCode && code) {
        const baseUrl = config.application?.baseUrl || buildAbsoluteUrl('');
        const callbackUrl = `${baseUrl}/auth/oidc/callback`;

        // Debug: Log token exchange details
        const tokenBody = new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: callbackUrl,
          client_id: idpConfig.clientId,
          client_secret: idpConfig.clientSecret
        });

        console.log('[OIDC Callback] Token exchange request:', {
          tokenUrl: idpConfig.tokenUrl,
          redirectUri: callbackUrl,
          clientId: idpConfig.clientId,
          code: code.substring(0, 20) + '...' // Log first 20 chars only
        });

        let tokenResponse;
        try {
          const requestOptions = buildRequestOptions(idpConfig, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: tokenBody.toString()
          });

          console.log('[OIDC Callback] Request options:', {
            method: requestOptions.method,
            headers: requestOptions.headers,
            hasAgent: !!requestOptions.agent,
            bodyLength: requestOptions.body?.length
          });

          // Use makeRequest instead of fetch to properly handle certificate verification
          tokenResponse = await makeRequest(idpConfig.tokenUrl, requestOptions);
        } catch (fetchError) {
          console.error('[OIDC Callback] Fetch error during token exchange:', fetchError.message);
          console.error('[OIDC Callback] Full error object:', {
            name: fetchError.name,
            message: fetchError.message,
            code: fetchError.code,
            errno: fetchError.errno,
            syscall: fetchError.syscall,
            cause: fetchError.cause?.message
          });
          throw new Error(`Token exchange failed: ${fetchError.message}`);
        }

        if (!tokenResponse.ok) {
          const errorText = await tokenResponse.text();
          console.error('[OIDC Callback] Token endpoint returned error:', {
            status: tokenResponse.status,
            statusText: tokenResponse.statusText,
            body: errorText.substring(0, 200)
          });
          throw new Error(`Token exchange failed: ${errorText}`);
        }

        const tokens = await tokenResponse.json();
        console.log('[OIDC Callback] Token exchange successful, received tokens');
        // Tokens from token endpoint take precedence
        finalIdToken = tokens.id_token || finalIdToken;
        finalAccessToken = tokens.access_token || finalAccessToken;
      }

      // Validate that we received expected tokens
      console.log('[OIDC Callback] Token validation:', {
        expectsIdToken,
        hasIdToken: !!finalIdToken,
        expectsAccessToken,
        hasAccessToken: !!finalAccessToken
      });

      if (expectsIdToken && !finalIdToken) {
        const errorMsg = 'Expected ID token but none received';
        console.error('[OIDC Callback]', errorMsg);
        throw new Error(errorMsg);
      }

      // Verify and decode ID token if present
      let decodedToken = null;
      if (finalIdToken) {
        console.log('[OIDC Callback] Verifying ID token...');
        try {
          decodedToken = await verifyJwt(finalIdToken, idpConfig);
          console.log('[OIDC Callback] ID token verified successfully. Subject:', decodedToken.sub);
        } catch (verifyError) {
          console.error('[OIDC Callback] ID token verification failed:', verifyError.message);
          throw verifyError;
        }

        // Verify nonce
        if (decodedToken.nonce !== req.session.oidcNonce) {
          console.error('[OIDC Callback] Nonce mismatch - Expected:', req.session.oidcNonce, 'Got:', decodedToken.nonce);
          throw new Error('Invalid nonce in ID token');
        }
        console.log('[OIDC Callback] Nonce verified successfully');
      }

      // Build user info from ID token claims or fetch from userinfo endpoint
      let userInfo = {};

      if (decodedToken) {
        userInfo = {
          id: decodedToken.sub,
          email: decodedToken.email,
          name: decodedToken.name,
          ...decodedToken
        };
      }

      // Fetch user info from userinfo endpoint if available and we have an access token
      if (idpConfig.userInfoUrl && finalAccessToken) {
        try {
          const userInfoRequestOptions = buildRequestOptions(idpConfig, {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${finalAccessToken}`
            }
          });

          const userInfoResponse = await makeRequest(idpConfig.userInfoUrl, userInfoRequestOptions);

          if (userInfoResponse.ok) {
            const additionalUserInfo = await userInfoResponse.json();
            userInfo = { ...userInfo, ...additionalUserInfo };
          }
        } catch (err) {
          console.warn('Failed to fetch user info:', err);
        }
      }

      // For token-only flows without ID token, we need at least something from userinfo
      if (!decodedToken && Object.keys(userInfo).length === 0) {
        throw new Error('Unable to obtain user information - no ID token and userinfo fetch failed');
      }

      // Store user info in session
      req.session.user = {
        protocol: 'oidc',
        idpName: pendingIdp.name,
        responseType: responseType,
        user: userInfo,
        jwtToken: finalIdToken,
        accessToken: finalAccessToken,
        tokenType: token_type,
        authenticatedAt: new Date().toISOString()
      };

      // Clear pending authentication data
      delete req.session.oidcState;
      delete req.session.oidcNonce;
      delete req.session.pendingIdp;

      console.log('[OIDC Callback] Authentication successful - redirecting to /protected');
      // Redirect to protected page using absolute URL from config
      res.redirect(buildAbsoluteUrl('/protected'));
    } catch (error) {
      console.error('[OIDC Callback] Authentication error:', error.message);
      console.error('[OIDC Callback] Error stack:', error.stack);
      // Redirect to home page with error using absolute URL from config
      res.redirect(buildAbsoluteUrl(`/?error=${encodeURIComponent(error.message)}`));
    }
  }

  // OIDC logout
  router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
      // Redirect to home page using absolute URL from config
      res.redirect(buildAbsoluteUrl('/'));
    });
  });

  return router;
}

async function verifyJwt(token, idpConfig) {
  return new Promise((resolve, reject) => {
    // Decode header to get kid (key ID)
    const decodedHeader = jwt.decode(token, { complete: true });

    if (!decodedHeader) {
      console.error('[JWT Verify] Failed to decode JWT token header');
      return reject(new Error('Invalid JWT token - unable to decode'));
    }

    console.log('[JWT Verify] Token header:', {
      alg: decodedHeader.header.alg,
      kid: decodedHeader.header.kid,
      typ: decodedHeader.header.typ
    });

    // Use configured jwksUrl or try to derive from metadataUrl
    const jwksUri = idpConfig.jwksUrl || idpConfig.metadataUrl?.replace('/.well-known/openid-configuration', '/discovery/keys');

    if (!jwksUri) {
      console.error('[JWT Verify] No jwksUrl configured and cannot derive from metadataUrl');
      return verifyCertificateBased(token, idpConfig, resolve, reject);
    }

    console.log('[JWT Verify] Fetching JWKS from:', jwksUri);

    // Build JWKS client options with custom CA if provided
    const jwksOptions = {
      jwksUri: jwksUri,
      cache: true,
      cacheMaxAge: 86400000, // 24 hours
      timeout: 10000 // 10 second timeout
    };

    // Check if certificate verification should be skipped (insecure, development only)
    if (idpConfig.insecureSkipCertificateVerification) {
      console.warn('[JWT Verify] WARNING: Certificate verification DISABLED for JWKS endpoint');
      console.warn('[JWT Verify] This is insecure and should ONLY be used for development/testing!');

      jwksOptions.agent = new https.Agent({
        rejectUnauthorized: false
      });
    }
    // If IdP has a custom certificate, add it to the JWKS client
    else if (idpConfig.idpCertificate) {
      try {
        // Certificate path is relative to data/certificates/ directory
        const certPath = path.join(__dirname, '../../data/certificates', idpConfig.idpCertificate);
        const certContent = fs.readFileSync(certPath, 'utf8');
        // jwks-rsa supports agent configuration
        jwksOptions.agent = new https.Agent({
          ca: certContent,
          rejectUnauthorized: true
        });
        console.log('[JWT Verify] Using custom CA certificate for JWKS');
      } catch (error) {
        console.warn('[JWT Verify] Could not load IdP certificate for JWKS:', error.message);
      }
    }

    const client = jwksClient(jwksOptions);

    // Get signing key
    client.getSigningKey(decodedHeader.header.kid, (err, key) => {
      if (err) {
        console.error('[JWT Verify] JWKS fetch failed:', err.message);
        // If JWKS fetch fails, try using certificate-based verification
        return verifyCertificateBased(token, idpConfig, resolve, reject);
      }

      const signingKey = key.getPublicKey();
      console.log('[JWT Verify] Retrieved signing key successfully');

      // Verify token
      jwt.verify(token, signingKey, {
        issuer: idpConfig.issuerUrl,
        audience: idpConfig.clientId,
        algorithms: ['RS256', 'RS384', 'RS512']
      }, (verifyErr, decoded) => {
        if (verifyErr) {
          console.error('[JWT Verify] Verification failed:', verifyErr.message);
          return reject(new Error(`JWT verification failed: ${verifyErr.message}`));
        }

        console.log('[JWT Verify] Token verified successfully');
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
