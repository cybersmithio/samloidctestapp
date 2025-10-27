# OIDC with Self-Signed Certificates

This guide explains how to configure the application to work with OIDC identity providers that use self-signed or custom CA certificates.

## Overview

When an OIDC IdP uses a self-signed certificate (not signed by a trusted Certificate Authority), Node.js will reject connections by default with an error like:

```
Fetch error: unable to verify the first certificate
```

The application now supports specifying a custom CA certificate per IdP using the `idpCertificate` configuration option. This certificate is used for both:
1. **Token endpoint** - During authorization code flow token exchange
2. **JWKS endpoint** - When validating JWT signatures

## Configuration

### Step 1: Obtain the IdP Certificate

If you don't already have the IdP's certificate, you can download it from the IdP server:

```bash
# Download the certificate from the IdP (example)
openssl s_client -connect idp.example.com:443 -showcerts </dev/null 2>/dev/null | openssl x509 -outform PEM > idp-ca-cert.pem
```

Or if you have access to the IdP configuration, look for the certificate in the metadata or contact your IdP administrator.

### Step 2: Place the Certificate in the Data Directory

Copy your IdP certificate to the `data/certificates/` directory:

```bash
cp /path/to/idp-ca-cert.pem data/certificates/
```

### Step 3: Update Configuration

Add the `idpCertificate` field to your OIDC IdP configuration in `data/config.json`:

```json
{
  "identityProviders": [
    {
      "protocol": "oidc",
      "name": "My OIDC IdP with Self-Signed Cert",
      "responseType": "code",
      "tenantUrl": "https://idp.example.com",
      "issuerUrl": "https://idp.example.com/oauth2",
      "authorizationUrl": "https://idp.example.com/oauth2/authorize",
      "tokenUrl": "https://idp.example.com/oauth2/token",
      "userInfoUrl": "https://idp.example.com/oauth2/userinfo",
      "metadataUrl": "https://idp.example.com/oauth2/.well-known/openid-configuration",
      "jwksUrl": "https://idp.example.com/oauth2/jwks",
      "clientId": "your-client-id",
      "clientSecret": "your-client-secret",
      "scope": "openid profile email",
      "idpCertificate": "certificates/idp-ca-cert.pem"
    }
  ]
}
```

**Note:** The `idpCertificate` path is relative to the `data/` directory.

## How It Works

When the application performs OIDC token exchange or JWKS validation:

1. The `buildFetchOptions()` function checks if `idpCertificate` is specified
2. If provided, it reads the certificate file from `data/certificates/`
3. Creates an HTTPS agent with the custom CA certificate
4. Uses this agent for all connections to that IdP's endpoints
5. The custom certificate is used for verifying the IdP server's SSL certificate

## Example: Self-Signed Certificate Workflow

### 1. Generate a Self-Signed Certificate (for testing)

```bash
# Generate a self-signed certificate valid for 365 days
openssl req -x509 -newkey rsa:2048 -keyout idp-key.pem -out idp-cert.pem -days 365 -nodes \
  -subj "/CN=idp.example.com"
```

### 2. Configure Your IdP to Use the Certificate

Set up your OIDC IdP (e.g., IBM Verify, Okta, custom IdP) to use this certificate for HTTPS connections.

### 3. Add to Application Configuration

Copy the certificate:
```bash
cp idp-cert.pem data/certificates/
```

Update `data/config.json`:
```json
{
  "protocol": "oidc",
  "name": "Test IdP with Self-Signed Cert",
  "idpCertificate": "certificates/idp-cert.pem",
  ...
}
```

### 4. Restart the Application

```bash
npm run start:prod
```

You should see in the logs:
```
[OIDC] Using custom CA certificate for IdP: certificates/idp-cert.pem
```

### 5. Test the Authorization Flow

1. Navigate to the application login page
2. Click the OIDC IdP button
3. Proceed through the authorization flow
4. The token exchange should succeed (no certificate verification errors)

## Certificate Chain Support

If your IdP uses a certificate signed by a private CA, you can include the full certificate chain in a single PEM file:

```bash
# Combine certificate chain (leaf cert + intermediate CAs + root CA)
cat idp-leaf.pem idp-intermediate.pem idp-root.pem > idp-chain.pem
```

Then configure:
```json
"idpCertificate": "certificates/idp-chain.pem"
```

## Troubleshooting

### Certificate Not Found

**Error:** `Could not load IdP certificate: certificates/my-cert.pem`

**Solution:**
- Verify the file exists in `data/certificates/`
- Check the filename in the configuration matches exactly
- Paths are relative to the `data/` directory

### Certificate Verification Still Fails

**Error:** `Fetch error: unable to verify the first certificate`

**Solution:**
- Verify you have the correct certificate for the IdP
- Check if the certificate is expired: `openssl x509 -in idp-cert.pem -noout -dates`
- If the IdP uses a certificate chain, ensure all intermediate CAs are included

### Wrong Certificate Format

**Error:** `Error in custom CA certificate`

**Solution:**
- Ensure the certificate is in PEM format (not DER)
- Certificate should have `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` headers
- Convert DER to PEM if needed:
  ```bash
  openssl x509 -inform DER -in cert.der -out cert.pem
  ```

## Security Considerations

### Development vs. Production

- **Development/Testing**: Using self-signed certificates is acceptable for testing
- **Production**:
  - Obtain certificates from a trusted CA when possible
  - If using self-signed certificates in production, ensure:
    - Certificate management and rotation procedures are in place
    - Certificates are securely stored with appropriate file permissions
    - Changes are tracked and auditable
    - Access to `data/certificates/` is restricted

### File Permissions

Ensure the certificate file has appropriate permissions:

```bash
# Make certificate readable by application (Unix/Linux)
chmod 644 data/certificates/idp-ca-cert.pem
```

## Advanced Configuration

### Multiple Self-Signed IdPs

You can configure multiple OIDC IdPs, each with their own self-signed certificate:

```json
{
  "identityProviders": [
    {
      "protocol": "oidc",
      "name": "IdP 1 - Self-Signed",
      "idpCertificate": "certificates/idp1-cert.pem",
      ...
    },
    {
      "protocol": "oidc",
      "name": "IdP 2 - Self-Signed",
      "idpCertificate": "certificates/idp2-cert.pem",
      ...
    }
  ]
}
```

### IdPs with Public Certificates

If some IdPs use certificates from trusted CAs, simply omit the `idpCertificate` field:

```json
{
  "protocol": "oidc",
  "name": "IdP 3 - Trusted CA",
  // No idpCertificate needed - will use system CA store
  ...
}
```

## Debugging

Enable detailed logging to see certificate usage:

1. Restart the server: `npm run start:prod`
2. Look for messages like:
   ```
   [OIDC] Using custom CA certificate for IdP: certificates/idp-custom-ca.pem
   ```

3. If token exchange fails, check for error messages like:
   ```
   [OIDC Callback] Fetch error during token exchange: [error details]
   ```

## Related Documentation

- [OIDC Troubleshooting Guide](./OIDC_TROUBLESHOOTING.md) - For debugging token exchange issues
- [Configuration Guide](./README.md) - For general configuration options
