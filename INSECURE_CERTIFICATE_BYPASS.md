# Insecure Certificate Verification Bypass for OIDC

This document explains how to disable certificate verification for OIDC IdPs when dealing with certificate chain issues during development and testing.

## WARNING: Security Risk

**`insecureSkipCertificateVerification` SHOULD ONLY BE USED FOR DEVELOPMENT AND TESTING.**

Disabling certificate verification makes the application vulnerable to man-in-the-middle (MITM) attacks. Any attacker on the network can intercept HTTPS connections and impersonate the IdP server.

## When to Use

Use this option **only** when:
- You're testing against a local or internal IdP
- You cannot obtain the complete certificate chain
- You're in a development/testing environment
- Network traffic is isolated/trusted

**NEVER use this in production.**

## Configuration

Add `insecureSkipCertificateVerification: true` to your OIDC IdP configuration:

```json
{
  "protocol": "oidc",
  "name": "OIDC Test App 1",
  "responseType": "code",
  "tenantUrl": "https://cybersmith.verify.ibm.com",
  "issuerUrl": "https://cybersmith.verify.ibm.com/oauth2",
  "authorizationUrl": "https://cybersmith.verify.ibm.com/oauth2/authorize",
  "tokenUrl": "https://cybersmith.verify.ibm.com/oauth2/token",
  "userInfoUrl": "https://cybersmith.verify.ibm.com/oauth2/userinfo",
  "jwksUrl": "https://cybersmith.verify.ibm.com/oauth2/jwks",
  "clientId": "8d005df8-5f44-44b3-a3a7-9383c0cd75ec",
  "clientSecret": "eHCXWcC4x2v6JL1W3Ax4",
  "scope": "openid profile email",
  "insecureSkipCertificateVerification": true
}
```

## What It Does

When enabled, the application will:

1. **Token Endpoint**: Accept the IdP's certificate without verification
2. **JWKS Endpoint**: Accept the IdP's certificate without verification
3. Log warnings to console when enabled

Example log output:
```
[OIDC] WARNING: Certificate verification DISABLED for IdP: OIDC Test App 1
[OIDC] This is insecure and should ONLY be used for development/testing!
[OIDC Callback] Token exchange request: {...}
[JWT Verify] WARNING: Certificate verification DISABLED for JWKS endpoint
[JWT Verify] This is insecure and should ONLY be used for development/testing!
```

## Precedence

The configuration follows this precedence for HTTPS verification:

1. **`insecureSkipCertificateVerification: true`** (highest priority)
   - Disables all certificate verification
   - Takes precedence over `idpCertificate`

2. **`idpCertificate`** (recommended)
   - Uses a custom CA certificate chain
   - Recommended for testing with real certificate chains

3. **Default** (lowest priority)
   - Uses system CA certificate store
   - Fails for self-signed or private CA certificates

## Recommended Alternatives

Before using certificate verification bypass, try these better options:

### 1. Use Complete Certificate Chain (Recommended)

```json
{
  "idpCertificate": "ibm-verify-chain.pem"
}
```

This is more secure and verifies the server's certificate properly. See [CERTIFICATE_CHAIN_EXTRACTION.md](./CERTIFICATE_CHAIN_EXTRACTION.md) for how to extract the chain.

### 2. Fix the Certificate Chain

If you're getting "self signed certificate in certificate chain" error:
- Ensure you have the **complete chain** (leaf, intermediates, root)
- Not just the root CA certificate alone

### 3. Use Environment Variable (Node.js Level)

For a quick workaround at the process level:

```bash
NODE_TLS_REJECT_UNAUTHORIZED=0 npm run start:prod
```

This disables certificate verification **globally** for the entire process, affecting all HTTPS connections. Less granular than the per-IdP option.

## Enabling in Development

Example development config:

```json
{
  "identityProviders": [
    {
      "protocol": "oidc",
      "name": "OIDC Test App 1",
      "responseType": "code",
      "tenantUrl": "https://cybersmith.verify.ibm.com",
      "issuerUrl": "https://cybersmith.verify.ibm.com/oauth2",
      "authorizationUrl": "https://cybersmith.verify.ibm.com/oauth2/authorize",
      "tokenUrl": "https://cybersmith.verify.ibm.com/oauth2/token",
      "userInfoUrl": "https://cybersmith.verify.ibm.com/oauth2/userinfo",
      "jwksUrl": "https://cybersmith.verify.ibm.com/oauth2/jwks",
      "clientId": "your-client-id",
      "clientSecret": "your-client-secret",
      "scope": "openid profile email",
      "insecureSkipCertificateVerification": true
    }
  ]
}
```

## Removing the Bypass

Once you have the proper certificate chain:

1. Extract the complete certificate chain (see [CERTIFICATE_CHAIN_EXTRACTION.md](./CERTIFICATE_CHAIN_EXTRACTION.md))
2. Place it in `data/certificates/`
3. Update your config to use `idpCertificate` instead:

```json
{
  "idpCertificate": "ibm-verify-chain.pem"
}
```

4. Remove `insecureSkipCertificateVerification`
5. Test the flow
6. Remove from version control if it was committed

## Security Considerations

### Development Systems

- Ensure development systems are on trusted networks
- Keep development configs in `.gitignore` (don't commit to version control)
- Regularly rotate development IdP credentials

### Test Systems

- Use test environments for integration testing, not production IdPs
- Document why insecure bypass is needed
- Plan for migration to proper certificate chains

### Audit Trail

The application logs warnings when certificate verification is disabled:
```
[OIDC] WARNING: Certificate verification DISABLED for IdP: ...
[OIDC] This is insecure and should ONLY be used for development/testing!
```

Enable application logging to detect when this is accidentally enabled in production.

## Troubleshooting

### Still Getting Certificate Errors?

Even with `insecureSkipCertificateVerification: true`, you might get errors if:

1. The IdP server is down or unreachable
2. The hostname/port is incorrect
3. Network connectivity is blocked by firewall

Check:
```bash
# Test connectivity to the token endpoint
curl -v -k https://cybersmith.verify.ibm.com/oauth2/token

# -k flag skips certificate verification in curl (same as our option)
```

### Accidental Production Use

If `insecureSkipCertificateVerification: true` makes it to production:

1. **Immediate**: Check server logs for the warning messages
2. **Urgent**: Update config to remove the flag
3. **Review**: Audit token exchange logs for potential MITM
4. **Prevent**: Add pre-deployment validation to reject this setting

## Alternative: Environment-Based Configuration

To prevent accidental production use, you could make this conditional:

```javascript
// NOT implemented in current version, but possible approach:
const isDevelopment = process.env.NODE_ENV === 'development';
const insecureBypass = isDevelopment ? config.insecureSkipCertificateVerification : false;
```

Contact development team if this feature is needed.

## References

- [Node.js HTTPS Agent - rejectUnauthorized](https://nodejs.org/api/https.html#https_class_https_agent)
- [OWASP: Man-in-the-Middle (MITM) Attack](https://owasp.org/www-community/attacks/man-in-the-middle_attack)
- [Certificate Chain Extraction Guide](./CERTIFICATE_CHAIN_EXTRACTION.md)
