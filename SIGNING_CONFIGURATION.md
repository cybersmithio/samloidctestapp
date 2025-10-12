# SAML Request Signing Configuration

## Overview

This document explains how to configure the application to sign SAML authentication requests using the Service Provider's private key and certificate.

## Configuration Parameters

Add the following parameters to your `data/config.json` file under the `application` section:

```json
{
  "application": {
    "entityId": "http://localhost:3001/saml/metadata",
    "baseUrl": "http://localhost:3001",
    "samlSigningCertificate": "certsAndKeys/sp-cert.pem",
    "samlSigningPrivateKey": "certsAndKeys/sp-key.pem",
    "signSamlRequests": true
  },
  "identityProviders": [...]
}
```

**Note**: The assertion consumer service URL is automatically constructed as `{baseUrl}/assert`, so you don't need to specify it separately.

### Parameters Explained

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `samlSigningCertificate` | string | Conditional | Path to SAML signing certificate (relative to `data/` directory) |
| `samlSigningPrivateKey` | string | Conditional | Path to SAML signing private key (relative to `data/` directory) |
| `signSamlRequests` | boolean | No | Enable/disable SAML request signing (default: false) |

**Note**: `samlSigningCertificate` and `samlSigningPrivateKey` are required if `signSamlRequests` is set to `true`.

**Important**: These are specifically for SAML signing operations, separate from any web server TLS/SSL certificates.

## Certificate and Key Files

The application expects certificate and key files in PEM format:

### Certificate (`sp-cert.pem`)
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKNfMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----
```

### Private Key (`sp-key.pem`)
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYw3M06tNJXgqW
...
-----END PRIVATE KEY-----
```

## Metadata Changes

When signing is enabled, the SAML metadata will be updated to reflect this capability:

### Without Signing (signSamlRequests: false)
```xml
<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
                    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
```

### With Signing (signSamlRequests: true)
```xml
<md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"
                    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  <md:KeyDescriptor use="signing">
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:X509Data>
        <ds:X509Certificate>MIID6zCCAtOgAwIBAgIU...</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </md:KeyDescriptor>
  ...
</md:SPSSODescriptor>
```

## How It Works

### 1. Metadata Generation

When `signSamlRequests` is enabled:
1. Server reads the certificate file from `data/certsAndKeys/sp-cert.pem`
2. Extracts the certificate content (removes BEGIN/END headers)
3. Includes certificate in metadata's `<KeyDescriptor>` element
4. Sets `AuthnRequestsSigned="true"` in metadata

### 2. Request Signing (Future Implementation)

When SAML authentication requests are generated:
1. Create SAML `<AuthnRequest>` XML
2. Canonicalize the XML (C14N)
3. Generate digest (SHA-256 hash) of the request
4. Sign the digest using the private key
5. Embed the signature in the request
6. Send signed request to IdP

**Note**: Request signing implementation is prepared but not yet active. The metadata correctly advertises the signing capability.

## Identity Provider Configuration

After enabling signing, you need to configure your IdP:

### 1. Upload Metadata

Upload the updated metadata to your IdP:
- Download from: `http://localhost:3001/saml/metadata`
- Or use the "Download SAML Metadata" button on the login page

### 2. IdP Will:
- Extract the certificate from `<KeyDescriptor use="signing">`
- Use it to verify signatures on SAML requests
- Trust requests signed by this certificate

### 3. Configure Signature Requirements (IdP-specific)

Some IdPs require additional configuration:

#### Okta
- Navigate to SAML app settings
- Advanced Settings → "Request Signature" → "Verified"
- Upload or paste the SP certificate

#### Azure AD
- Automatically reads from metadata
- Ensure "Sign SAML request" is enabled in app settings

#### ADFS
- Run PowerShell command:
  ```powershell
  Set-AdfsRelyingPartyTrust -TargetName "YourApp" -SignedSamlRequestsRequired $true
  ```

## Security Best Practices

### 1. Private Key Protection

⚠️ **Critical**: Protect your private key

```bash
# Set restrictive permissions
chmod 600 data/certsAndKeys/sp-key.pem

# Verify permissions
ls -l data/certsAndKeys/sp-key.pem
```

### 2. Key Storage

**Development**:
- File system storage is acceptable
- Ensure `.gitignore` excludes private keys

**Production**:
- Use Hardware Security Module (HSM)
- Use Key Management Service (KMS):
  - Azure Key Vault
  - AWS KMS
  - Google Cloud KMS
  - HashiCorp Vault

### 3. Certificate Rotation

Plan for certificate rotation:

1. **Before Expiration**:
   - Generate new certificate/key pair
   - Update configuration
   - Upload new metadata to IdP
   - Test with new certificate

2. **Transition Period**:
   - Keep old certificate active during transition
   - IdPs may cache old certificate

3. **Cleanup**:
   - Remove old certificate after all IdPs updated
   - Revoke old certificate if using CA

## Troubleshooting

### Metadata doesn't include KeyDescriptor

**Possible causes**:
1. `signSamlRequests` not set to `true`
2. Certificate file not found
3. Certificate path incorrect

**Solution**:
```bash
# Check certificate exists
ls -l data/certsAndKeys/sp-cert.pem

# Check configuration
cat data/config.json | grep -A 3 "application"

# Check server logs
# Look for: "Could not load certificate for metadata"
```

### IdP rejects signed requests

**Possible causes**:
1. Certificate mismatch
2. Clock skew
3. Signature algorithm not supported

**Solution**:
1. Verify certificate in metadata matches actual certificate
2. Sync server time with NTP
3. Check IdP signature algorithm requirements

### "AuthnRequestsSigned" shows false

**Check**:
1. `signSamlRequests` parameter in config.json
2. Restart server after configuration change
3. Clear any cached metadata

## Configuration Examples

### Development (Local Testing)

```json
{
  "application": {
    "entityId": "http://localhost:3001/saml/metadata",
    "baseUrl": "http://localhost:3001",
    "samlSigningCertificate": "certsAndKeys/sp-cert.pem",
    "samlSigningPrivateKey": "certsAndKeys/sp-key.pem",
    "signSamlRequests": true
  }
}
```

### Production

```json
{
  "application": {
    "entityId": "https://your-app.example.com/saml/metadata",
    "baseUrl": "https://your-app.example.com",
    "samlSigningCertificate": "certsAndKeys/sp-prod-cert.pem",
    "samlSigningPrivateKey": "certsAndKeys/sp-prod-key.pem",
    "signSamlRequests": true
  }
}
```

### Signing Disabled

```json
{
  "application": {
    "entityId": "https://your-app.example.com/saml/metadata",
    "baseUrl": "https://your-app.example.com",
    "signSamlRequests": false
  }
}
```

## Testing

### Verify Configuration

```bash
# Check metadata includes certificate
curl http://localhost:3001/saml/metadata | grep "KeyDescriptor"

# Check AuthnRequestsSigned attribute
curl http://localhost:3001/saml/metadata | grep "AuthnRequestsSigned"

# Run automated tests
npm test -- server/metadata.test.js
```

### Expected Output

With signing enabled:
```xml
<md:SPSSODescriptor AuthnRequestsSigned="true" ...>
  <md:KeyDescriptor use="signing">
    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:X509Data>
        <ds:X509Certificate>...</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </md:KeyDescriptor>
```

## Related Documentation

- [METADATA.md](./METADATA.md) - SAML metadata documentation
- [data/certsAndKeys/README.md](./data/certsAndKeys/README.md) - Certificate management
- [SAML 2.0 Technical Overview](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [XML Signature Syntax](https://www.w3.org/TR/xmldsig-core/)

## Future Enhancements

The following features are planned for future releases:

1. **Actual Request Signing**: Implement XML signature generation for AuthnRequest
2. **Logout Request Signing**: Sign LogoutRequest messages
3. **Assertion Decryption**: Use private key to decrypt encrypted assertions
4. **Multiple Signing Algorithms**: Support SHA-256, SHA-384, SHA-512
5. **HSM Integration**: Direct integration with hardware security modules
6. **Key Rotation Automation**: Automated certificate renewal and rotation
