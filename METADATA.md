# SAML Metadata Documentation

## Overview

The application provides a SAML metadata endpoint that generates a Service Provider (SP) metadata XML file. This metadata file can be used to configure this application as a trusted Service Provider in your Identity Provider (IdP).

## Accessing the Metadata

### Via Web Interface

1. Navigate to the login page of the application (http://localhost:3000)
2. Scroll to the bottom of the page
3. Click the **"Download SAML Metadata"** button
4. The file `metadata.xml` will be downloaded to your computer

### Via Direct URL

Access the metadata endpoint directly:
```
GET /saml/metadata
```

Example:
```bash
curl http://localhost:3001/saml/metadata > saml-metadata.xml
```

## Metadata Contents

The generated metadata includes:

### 1. Entity Descriptor
- **Entity ID**: Unique identifier for this Service Provider
- **Valid Until**: Expiration date (1 year from generation)

### 2. Service Provider SSO Descriptor
- **Protocol Support**: SAML 2.0 protocol
- **AuthnRequestsSigned**: false (does not sign authentication requests)
- **WantAssertionsSigned**: true (requires signed assertions)

### 3. Name ID Formats
Supported formats:
- `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`

### 4. Assertion Consumer Service (ACS)
- **Binding**: HTTP-POST
- **Location**: `{baseUrl}/assert`
- **Index**: 1 (default)

This is the endpoint where the IdP will send SAML assertions after successful authentication.

### 5. Organization Information
- **Name**: SAML/OIDC Test Application
- **Display Name**: SAML/OIDC Test Application
- **URL**: Base URL of the application

### 6. Contact Information
- **Type**: Technical
- **Name**: Technical Support
- **Email**: support@example.com

## Configuration

### Default Configuration

If no configuration is provided, the metadata uses the request URL to generate default values:
```javascript
{
  entityId: "http://localhost:3001/saml/metadata",
  baseUrl: "http://localhost:3001",
  assertionConsumerServiceUrl: "http://localhost:3001/assert"
}
```

### Custom Configuration

To customize the metadata, add an `application` section to your `data/config.json`:

```json
{
  "application": {
    "entityId": "https://your-app-domain.com/saml/metadata",
    "baseUrl": "https://your-app-domain.com",
    "assertionConsumerServiceUrl": "https://your-app-domain.com/assert"
  },
  "identityProviders": [...]
}
```

**Important**: Use the Fully Qualified Domain Name (FQDN) of your application in production.

## Example Metadata XML

```xml
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://your-app-domain.com/saml/metadata"
                     validUntil="2026-10-10T12:00:00.000Z">

  <md:SPSSODescriptor AuthnRequestsSigned="false"
                      WantAssertionsSigned="true"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>

    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="https://your-app-domain.com/assert"
                                 index="1"
                                 isDefault="true"/>
  </md:SPSSODescriptor>

  <md:Organization>
    <md:OrganizationName xml:lang="en">SAML/OIDC Test Application</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">SAML/OIDC Test Application</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://your-app-domain.com</md:OrganizationURL>
  </md:Organization>

  <md:ContactPerson contactType="technical">
    <md:GivenName>Technical Support</md:GivenName>
    <md:EmailAddress>support@example.com</md:EmailAddress>
  </md:ContactPerson>

</md:EntityDescriptor>
```

## Using the Metadata with Your IdP

### General Steps

1. **Download the metadata**: Use the download button or direct URL
2. **Upload to IdP**: Most IdPs have a "Import Metadata" or "Add Service Provider" feature
3. **Configure trust**: The IdP will parse the metadata and configure the trust relationship
4. **Add certificates**: Place the IdP's signing certificate in `data/certificates/`
5. **Test**: Send a SAML assertion to the `/assert` endpoint

### Common IdP-Specific Instructions

#### Okta
1. Admin Console → Applications → Create App Integration
2. Select "SAML 2.0"
3. Upload the metadata file or enter the ACS URL manually
4. Configure attribute statements (email, firstName, lastName)

#### Azure AD / Entra ID
1. Azure Portal → Enterprise Applications → New Application
2. Create your own application → SAML
3. Upload the metadata file
4. Configure user attributes and claims

#### ADFS
1. AD FS Management Console
2. Relying Party Trusts → Add Relying Party Trust
3. Import data from a file → select the metadata XML
4. Configure claim rules

#### Auth0
1. Dashboard → Applications → Create Application
2. Select "Regular Web Application"
3. Settings → Show Advanced Settings → Endpoints
4. Use the metadata URL or upload the file

## Security Considerations

### Assertion Signing Requirement
The metadata specifies `WantAssertionsSigned="true"`, which means:
- The IdP **must** sign all SAML assertions
- Unsigned assertions will be rejected by the `/assert` endpoint
- The signing certificate must be in `data/certificates/`

### Entity ID
- The Entity ID should be unique and consistent
- Use your application's FQDN in production
- Don't change the Entity ID after IdP configuration (requires reconfiguration)

### HTTPS Requirement
- In production, always use HTTPS
- Update the `assertionConsumerServiceUrl` to use `https://`
- Ensure SSL/TLS certificates are valid

### Metadata Expiration
- The metadata is valid for 1 year from generation
- Regenerate and re-upload if the metadata expires
- Some IdPs may cache metadata

## Troubleshooting

### Issue: IdP cannot import metadata
**Solution**:
- Verify the XML is well-formed
- Check that the ACS URL is accessible from the IdP
- Ensure all required fields are present

### Issue: "Invalid SAML signature" error
**Solution**:
- Verify the IdP's signing certificate is in `data/certificates/`
- Check that the certificate matches the one used by the IdP
- Ensure the certificate is in PEM format

### Issue: IdP shows "ACS URL not reachable"
**Solution**:
- Verify the application is running and accessible
- Check firewall rules
- Ensure the FQDN in the metadata matches your actual domain
- For local testing, the IdP must be able to reach localhost (may require tunneling)

## Testing

Run the automated tests:
```bash
npm test -- server/metadata.test.js
```

Manual testing:
```bash
# Download metadata
curl http://localhost:3001/saml/metadata > metadata.xml

# Validate XML structure
xmllint --noout metadata.xml

# View formatted XML
xmllint --format metadata.xml
```

## Related Documentation

- [ASSERT_ENDPOINT.md](./ASSERT_ENDPOINT.md) - Documentation for the `/assert` endpoint
- [SAML 2.0 Metadata Specification](http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
