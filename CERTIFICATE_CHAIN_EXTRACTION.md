# Extracting and Using Certificate Chains for Private CAs

When an OIDC IdP uses a certificate signed by a private CA (not a public certificate authority), Node.js needs the complete certificate chain to validate it.

## Understanding Certificate Chains

A certificate chain typically consists of:
1. **Leaf Certificate** - The certificate actually used by the IdP server
2. **Intermediate Certificates** - CAs that signed the leaf certificate (may be multiple levels)
3. **Root Certificate** - The self-signed root CA that anchors the chain

Node.js needs all certificates in the chain to validate the server's certificate.

## Method 1: Extract Chain from the Live Server (Recommended)

This method downloads the actual certificate chain that the server presents:

```bash
# Connect to the server and extract all certificates in the chain
openssl s_client -connect cybersmith.verify.ibm.com:443 -showcerts </dev/null 2>/dev/null | \
  grep -A 30 "BEGIN CERTIFICATE" | \
  awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ { print }' > /tmp/chain.pem

# Verify you got all certificates
openssl crl2pkcs7 -nocrl -certfile /tmp/chain.pem | openssl pkcs7 -print_certs -noout
```

Then copy to your data directory:
```bash
cp /tmp/chain.pem data/certificates/ibm-verify-chain.pem
```

## Method 2: Manual Chain Construction

If you have the certificates separately:

```bash
# Combine all certificates in order: leaf → intermediates → root
cat /path/to/leaf-cert.pem \
    /path/to/intermediate-ca.pem \
    /path/to/root-ca.pem > data/certificates/ibm-verify-chain.pem
```

The order matters:
- **Start with the leaf certificate** (the one actually used by IBM Verify)
- **Then add any intermediate CAs** (in order from leaf to root)
- **End with the root certificate**

## Method 3: Export from IBM Verify Web Console

If IBM Verify provides a way to download certificates:

1. Log in to IBM Verify admin console
2. Navigate to certificate settings
3. Download the certificate chain (usually as PKCS#7 or PEM bundle)
4. Convert to PEM if needed:
   ```bash
   openssl pkcs7 -in chain.p7b -print_certs -out chain.pem
   ```

## Verifying Your Certificate Chain

Before using it, verify the chain is valid:

```bash
# Check all certificates in the file
openssl crl2pkcs7 -nocrl -certfile data/certificates/ibm-verify-chain.pem | \
  openssl pkcs7 -print_certs -text -noout

# Verify the chain is complete
openssl verify -CAfile data/certificates/ibm-verify-chain.pem \
  data/certificates/ibm-verify-chain.pem

# Test connection with the chain
openssl s_client -connect cybersmith.verify.ibm.com:443 \
  -CAfile data/certificates/ibm-verify-chain.pem
```

Expected output should show:
- `Verify return code: 0 (ok)` - Chain is valid
- All certificates in the chain properly displayed
- No "self signed certificate in certificate chain" error

## Configuration

Once you have the complete chain file, configure it simply:

```json
{
  "protocol": "oidc",
  "name": "OIDC Test App 1",
  "tokenUrl": "https://cybersmith.verify.ibm.com/oauth2/token",
  "jwksUrl": "https://cybersmith.verify.ibm.com/oauth2/jwks",
  "idpCertificate": "ibm-verify-chain.pem",
  ...
}
```

## Common Issues

### "self signed certificate in certificate chain"

**Cause:** Missing intermediate certificates or wrong order in the chain.

**Solution:**
- Ensure ALL certificates (leaf, intermediates, root) are in the PEM file
- Verify order: leaf first, root last
- Re-extract from the live server using Method 1

### "Error in self_and_peer_cert verification"

**Cause:** The leaf certificate in the chain doesn't match the server's actual certificate.

**Solution:**
- Verify you extracted from the correct server
- Make sure you have the leaf certificate first in the chain

### "unable to get local issuer certificate"

**Cause:** Missing intermediate or root certificate.

**Solution:**
- Ensure the complete chain is included
- Re-extract from the server to get all intermediates

## What If You Can't Get the Full Chain?

If the IdP administrator won't provide the full chain, you have a few options:

1. **Ask for it explicitly** - Request "the complete certificate chain for cybersmith.verify.ibm.com including all intermediate and root CAs"

2. **Use the server's own certificate as a workaround** (less secure, only for testing):
   - Extract just the leaf certificate
   - This works if the IdP's certificate is self-signed (not in your case)

3. **Temporarily disable certificate verification** (development only):
   ```bash
   NODE_TLS_REJECT_UNAUTHORIZED=0 npm run start:prod
   ```
   **WARNING: This is extremely insecure and should ONLY be used for development/testing**

## Testing with Your Configuration

Once configured:

1. Restart the application:
   ```bash
   npm run start:prod
   ```

2. Look for logs:
   ```
   [OIDC] Using custom CA certificate for IdP: ibm-verify-chain.pem
   ```

3. Try the OIDC flow - it should now work without certificate errors

## References

- [OpenSSL Certificate Chain Documentation](https://www.openssl.org/docs/manmaster/man1/openssl-verify.html)
- [Node.js HTTPS Agent Documentation](https://nodejs.org/api/https.html#https_class_https_agent)
- [Node.js TLS/SSL Documentation](https://nodejs.org/api/tls.html)
