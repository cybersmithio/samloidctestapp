# OIDC Token Exchange "Fetch Failed" Troubleshooting Guide

When using OIDC with the authorization code flow, you may encounter an "Authentication error: fetch failed" message. This guide helps you diagnose and resolve the issue.

## Enhanced Debugging

The backend now includes detailed logging to help diagnose token exchange issues. When a token exchange fails, you should see logs like:

```
[OIDC Callback] Token exchange request: {
  tokenUrl: 'https://idp.example.com/oauth2/token',
  redirectUri: 'https://myapp.example.com/auth/oidc/callback',
  clientId: 'my-client-id',
  code: 'ABC123...'
}
[OIDC Callback] Fetch error during token exchange: getaddrinfo ENOTFOUND idp.example.com
[OIDC Callback] Fetch error details: {
  code: 'ENOTFOUND',
  errno: undefined,
  syscall: 'getaddrinfo'
}
```

## Common Causes and Solutions

### 1. Invalid Token URL (Most Common)

**Error:** `Fetch error details: { code: 'ENOTFOUND', errno: undefined, syscall: 'getaddrinfo' }`

**Cause:** The `tokenUrl` in your OIDC IdP configuration is incorrect or the hostname cannot be resolved.

**Solution:**
- Verify the `tokenUrl` in `data/config.json` is exactly correct
- Test DNS resolution: `nslookup idp.example.com` (from your server)
- Ensure the URL uses `https://` not `http://`
- Example correct format: `https://auth.example.com/oauth2/token`

**Config Example:**
```json
{
  "protocol": "oidc",
  "name": "My OIDC Provider",
  "tokenUrl": "https://auth.example.com/oauth2/token",
  "authorizationUrl": "https://auth.example.com/oauth2/authorize",
  ...
}
```

### 2. Network Connectivity / Firewall

**Error:** `Fetch error: timeout` or `Fetch error: connection refused`

**Cause:**
- Backend server cannot reach the IdP's token endpoint
- Firewall blocks outbound HTTPS connections
- IdP server is down or unreachable

**Solution:**
- Test connectivity from the backend server: `curl -v https://idp.example.com/oauth2/token`
- Check firewall rules allow outbound HTTPS (port 443)
- Verify IdP token endpoint is accessible
- Check if a proxy server is required (not currently supported in this app)

### 3. Self-Signed or Custom Certificates

**Error:** `Fetch error: unable to verify the first certificate` or `SSL certificate problem`

**Cause:** The IdP uses a self-signed certificate that Node.js won't verify by default.

**Solution:**
1. For development/testing only, you can disable certificate verification by setting an environment variable:
   ```bash
   NODE_TLS_REJECT_UNAUTHORIZED=0 npm run start:prod
   ```

2. For production, use a proper certificate from a trusted CA, or:
   - Add the certificate to Node.js's trusted CA store
   - Use a reverse proxy that handles SSL termination

**Note:** This is a security risk - only use in controlled test environments!

### 4. Incorrect Redirect URI

**Error:** Token exchange returns HTTP 400 with message like: `invalid redirect_uri` or `redirect_uri mismatch`

**Cause:** The `redirect_uri` sent to the token endpoint doesn't match what was registered with the IdP.

**Debugging:**
Look for logs showing:
```
[OIDC Callback] Token exchange request: {
  redirectUri: 'https://myapp.example.com:3001/auth/oidc/callback'
}
```

**Solution:**
1. Verify the URL matches exactly what you registered with the IdP:
   - Same protocol (http vs https)
   - Same hostname
   - Same port (or no port for defaults 80/443)
   - Same path: `/auth/oidc/callback`

2. Check your application configuration in `data/config.json`:
   ```json
   {
     "application": {
       "hostname": "myapp.example.com",
       "port": 3001,
       "publicPort": 443,
       "useHttps": false,
       "useHttpsPublicly": true
     }
   }
   ```

3. For proxy/reverse proxy scenarios:
   - `port`: Port the backend server listens on (e.g., 3001)
   - `publicPort`: Port users connect to (e.g., 443)
   - `useHttpsPublicly`: Whether the public-facing URL uses HTTPS

### 5. Wrong Client ID or Secret

**Error:** Token exchange returns HTTP 401 with message: `invalid client credentials` or `unauthorized_client`

**Cause:** The `clientId` or `clientSecret` in the config doesn't match what's registered with the IdP.

**Solution:**
1. Verify credentials in `data/config.json`:
   ```json
   {
     "protocol": "oidc",
     "clientId": "correct-client-id",
     "clientSecret": "correct-client-secret",
     ...
   }
   ```

2. Double-check with the IdP provider:
   - Are these the correct credentials for this application?
   - Have credentials been rotated recently?
   - Are they enabled/active in the IdP?

**Security Note:** Never commit credentials to version control. Use environment variables for production:
```json
{
  "clientId": "${OIDC_CLIENT_ID}",
  "clientSecret": "${OIDC_CLIENT_SECRET}"
}
```

### 6. Authorization Code Already Used or Expired

**Error:** Token exchange returns HTTP 400: `invalid authorization code` or `code expired`

**Cause:**
- The authorization code is only valid for a short time (typically 5-10 minutes)
- The code was already exchanged for tokens
- User took too long to complete the authorization flow

**Solution:**
- This is normal behavior - codes are single-use and short-lived
- If consistently happening, check for network delays between IdP redirect and token exchange
- Look at logs to see timing: check when callback is received vs when token exchange is attempted

## Debugging Checklist

When troubleshooting token exchange failures:

1. **Check the logs:**
   ```
   [OIDC Callback] Token exchange request: {...}
   [OIDC Callback] Fetch error during token exchange: [error message]
   [OIDC Callback] Token endpoint returned error: {...}
   ```

2. **Verify configuration:**
   - [ ] `tokenUrl` is correct and accessible
   - [ ] `clientId` matches IdP registration
   - [ ] `clientSecret` matches IdP registration
   - [ ] `redirectUri` matches IdP registration exactly

3. **Test connectivity:**
   ```bash
   curl -X POST https://idp.example.com/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=test&client_id=ID&client_secret=SECRET&redirect_uri=https://myapp.example.com/auth/oidc/callback"
   ```

4. **Check network/firewall:**
   - Can your server reach the IdP?
   - Are there any proxies or VPNs in the way?
   - Are inbound/outbound firewall rules correct?

5. **Review authorization flow:**
   - Did you get redirected to the IdP login?
   - Did you successfully log in and get redirected back?
   - Is the `code` parameter in the redirect query string?

## Getting More Help

If the debugging logs still don't reveal the issue:

1. Capture the full log output when the error occurs
2. Check the server console for any error messages
3. Test the token endpoint manually with `curl` (see Debugging Checklist above)
4. Contact your IdP provider to verify:
   - Your client credentials are valid
   - The redirect URI is registered correctly
   - Token endpoint is working properly

## Request Body Format

The token exchange sends a `application/x-www-form-urlencoded` request with:
```
grant_type=authorization_code
&code=AUTHORIZATION_CODE
&redirect_uri=https://myapp.example.com/auth/oidc/callback
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
```

If the IdP expects a different format (e.g., JSON body), the token exchange will fail.
