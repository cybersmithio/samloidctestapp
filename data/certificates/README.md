# Certificates Directory

This directory stores all trusted certificates for validating SAML assertions and JWT tokens.

## Usage

1. Place your IdP's public certificates (in PEM format) in this directory
2. Reference the certificate filename in the `config.json` file
3. The application will use these certificates to verify signatures

## Example Certificate Files

- `saml-idp-cert.pem` - Example SAML IdP certificate
- `oidc-idp-cert.pem` - Example OIDC IdP certificate (if using certificate-based JWT validation)

## Certificate Format

Certificates should be in PEM format:

```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKN...
...
-----END CERTIFICATE-----
```
