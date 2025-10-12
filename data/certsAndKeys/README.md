# Service Provider Certificates and Keys

This directory contains the cryptographic materials for the SAML Service Provider (SP).

## Files

### `sp-cert.pem` - Service Provider Certificate
- **Type**: X.509 Certificate (PEM format)
- **Key Size**: 2048-bit RSA
- **Validity**: 10 years (2025-2035)
- **Subject**: CN=localhost, OU=Development, O=SAML-OIDC-Test-App, L=City, ST=State, C=US
- **Purpose**: Public certificate used for SAML metadata and can be shared with Identity Providers
- **Self-Signed**: Yes (for development/testing purposes)

### `sp-key.pem` - Service Provider Private Key
- **Type**: RSA Private Key (PEM format)
- **Key Size**: 2048-bit
- **Encryption**: None (unencrypted for development)
- **Purpose**: Private key for signing SAML requests and decrypting encrypted assertions
- **⚠️ SECURITY**: Keep this file private and never commit to version control

## Usage

### In SAML Metadata

The certificate (`sp-cert.pem`) can be included in the SAML metadata to:
1. Allow IdPs to verify signed authentication requests (if enabled)
2. Enable IdPs to encrypt SAML assertions for this SP

To include the certificate in metadata, the application would need to read and embed it in the `<KeyDescriptor>` element.

### For Signing (Future Enhancement)

If SAML request signing is enabled, the private key (`sp-key.pem`) would be used to sign:
- Authentication requests (AuthnRequest)
- Logout requests (LogoutRequest)

### For Decryption (Future Enhancement)

If assertion encryption is enabled, the private key would be used to decrypt:
- Encrypted SAML assertions
- Encrypted attributes

## Regenerating the Certificate

If you need to regenerate the certificate (e.g., after expiration), run:

```bash
cd data/certsAndKeys
openssl req -x509 -newkey rsa:2048 -keyout sp-key.pem -out sp-cert.pem -days 3650 -nodes \
  -subj "/C=US/ST=State/L=City/O=SAML-OIDC-Test-App/OU=Development/CN=localhost"
```

## Production Considerations

### ⚠️ Important for Production Use

1. **Use a proper CA-signed certificate**: Self-signed certificates are only suitable for development/testing
2. **Encrypt the private key**: Use a passphrase to protect the private key
3. **Secure storage**: Store private keys in a secure key management system (e.g., Azure Key Vault, AWS KMS, HashiCorp Vault)
4. **Regular rotation**: Rotate certificates before expiration (ideally annually)
5. **Backup**: Maintain secure backups of private keys
6. **Access control**: Restrict file permissions on the private key:
   ```bash
   chmod 600 sp-key.pem
   ```

### Production Certificate Generation

For production, consider:

1. **Using a Certificate Authority (CA)**:
   - Commercial CA (DigiCert, GlobalSign, etc.)
   - Internal enterprise CA
   - Let's Encrypt (for web servers)

2. **Generate a Certificate Signing Request (CSR)**:
   ```bash
   openssl req -new -newkey rsa:2048 -nodes -keyout sp-key.pem -out sp.csr \
     -subj "/C=US/ST=State/L=City/O=SAML-OIDC-Test-App/OU=Development/CN=localhost"
   ```

3. **Submit CSR to CA**: The CA will verify your identity and issue a certificate

4. **Install CA-signed certificate**: Replace `sp-cert.pem` with the CA-signed certificate

## Certificate Information

To view certificate details:

```bash
# View certificate
openssl x509 -in sp-cert.pem -text -noout

# View certificate dates
openssl x509 -in sp-cert.pem -noout -dates

# View certificate subject
openssl x509 -in sp-cert.pem -noout -subject

# Verify certificate and key match
openssl x509 -in sp-cert.pem -noout -modulus | openssl md5
openssl rsa -in sp-key.pem -noout -modulus | openssl md5
```

## Security Notes

1. **Private Key Security**:
   - Never share the private key
   - Never commit to version control
   - Add `sp-key.pem` to `.gitignore`

2. **Development vs Production**:
   - These self-signed certificates are for development only
   - Production systems must use proper CA-signed certificates
   - Self-signed certificates will trigger browser warnings

3. **Key Management**:
   - In production, use hardware security modules (HSM) or key management services
   - Implement key rotation policies
   - Maintain audit logs for key access

## File Permissions

Recommended permissions:
```bash
# Certificate (readable by all)
chmod 644 sp-cert.pem

# Private key (readable only by owner)
chmod 600 sp-key.pem
```

## Integration with Application

To use these certificates in the application:

1. **Update `data/config.json`** to reference the SAML signing certificate:
   ```json
   {
     "application": {
       "samlSigningCertificate": "certsAndKeys/sp-cert.pem",
       "samlSigningPrivateKey": "certsAndKeys/sp-key.pem",
       "signSamlRequests": true
     }
   }
   ```

2. **Metadata will include the certificate** for IdP verification
3. **SAML requests can be signed** using the private key (if signing is enabled)

**Note**: These parameters are specifically for SAML signing operations, separate from any web server TLS/SSL certificates.

## Related Documentation

- [METADATA.md](../../METADATA.md) - Information about SAML metadata
- [ASSERT_ENDPOINT.md](../../ASSERT_ENDPOINT.md) - Information about the assertion endpoint
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [SAML 2.0 Technical Overview](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
