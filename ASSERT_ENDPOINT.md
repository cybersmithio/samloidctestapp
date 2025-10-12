# SAML Assertion Endpoint Documentation

## Endpoint: `POST /assert`

This endpoint receives and validates SAML assertions, verifying their signatures against trusted certificates stored in the `/data/certificates` directory.

## Features

- **Signature Verification**: Validates SAML assertion signatures using trusted certificates
- **Multiple Certificate Support**: Automatically checks against all certificates in the certificates directory
- **Secure Validation**: Rejects assertions that cannot be verified by any known certificate
- **Session Management**: Stores validated user information in the session
- **Detailed Error Reporting**: Provides clear error messages for debugging

## Request Format

### HTTP Method
`POST`

### Content-Type
`application/x-www-form-urlencoded` or `application/json`

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| SAMLResponse | string | Yes | Base64-encoded SAML response/assertion |

### Example Request (JSON)
```bash
curl -X POST http://localhost:3001/assert \
  -H "Content-Type: application/json" \
  -d '{
    "SAMLResponse": "PD94bWwgdmVyc2lvbj0iMS4wIj8+PHNhbWxwOlJlc3BvbnNlIC4uLg=="
  }'
```

### Example Request (Form URL Encoded)
```bash
curl -X POST http://localhost:3001/assert \
  -d "SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIj8+PHNhbWxwOlJlc3BvbnNlIC4uLg=="
```

## Response Format

### Success Response (302 Redirect)

Upon successful validation, the endpoint redirects the user to the protected page where their details are displayed:

**Development Mode:**
```
HTTP/1.1 302 Found
Location: http://localhost:3000/protected
```

**Production Mode:**
```
HTTP/1.1 302 Found
Location: /protected
```

The protected page (`/protected`) will display:
- Authentication protocol used
- Certificate that verified the signature
- User details extracted from the SAML assertion (nameID, email, first name, last name, etc.)
- Full credential information
- Complete SAML assertion XML

### Error Responses

#### 400 Bad Request - Missing SAML Response
```json
{
  "error": "Missing SAML response",
  "details": "SAMLResponse parameter is required"
}
```

#### 400 Bad Request - Invalid Encoding
```json
{
  "error": "Invalid SAML response encoding",
  "details": "SAMLResponse must be base64 encoded"
}
```

#### 400 Bad Request - Parse Error
```json
{
  "error": "Failed to parse SAML assertion",
  "details": "No assertion found in SAML response"
}
```

#### 401 Unauthorized - Invalid Signature
```json
{
  "error": "Invalid SAML signature",
  "details": "SAML assertion signature could not be verified with any known certificate",
  "certificatesChecked": ["saml-idp-cert.pem", "backup-cert.pem"]
}
```

#### 500 Internal Server Error - No Certificates
```json
{
  "error": "No trusted certificates found",
  "details": "Please add certificate files (.pem, .crt, or .cer) to the data/certificates directory"
}
```

#### 500 Internal Server Error - Server Error
```json
{
  "error": "SAML assertion validation failed",
  "details": "Error message details"
}
```

## Certificate Management

### Certificate Directory
Place trusted IdP certificates in: `/data/certificates/`

### Supported Certificate Formats
- `.pem` - PEM format (preferred)
- `.crt` - Certificate format
- `.cer` - Certificate format

### Certificate Format Example
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKNfMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
...
-----END CERTIFICATE-----
```

## Signature Verification Process

1. **Load Certificates**: Reads all certificate files from `/data/certificates/`
2. **Decode SAML**: Decodes the base64-encoded SAML response
3. **Find Signature**: Locates the `<ds:Signature>` element in the SAML XML
4. **Verify**: Attempts verification with each trusted certificate
5. **Match**: Accepts the first certificate that successfully verifies the signature
6. **Parse**: Extracts user attributes from the validated assertion

## Security Considerations

- **Certificate Validation**: Only SAML assertions signed by certificates in the `/data/certificates` directory are accepted
- **Signature Required**: Assertions without signatures are rejected
- **No Replay Protection**: This endpoint does not implement replay attack protection (consider adding timestamp/nonce validation)
- **Session Storage**: Successfully validated assertions are stored in the session

## User Attribute Mapping

The endpoint automatically maps common SAML attributes:

| SAML Attribute (contains) | Mapped Field |
|---------------------------|--------------|
| email, emailaddress | email |
| firstname, givenname | firstName |
| lastname, surname | lastName |
| name (not username) | name |
| NameID | nameID |

Additional attributes are stored using their original attribute names.

## Testing

### Test the endpoint with curl:
```bash
# Create a test SAML response (properly signed)
SAML_RESPONSE=$(echo '<samlp:Response>...</samlp:Response>' | base64)

# Send to endpoint
curl -X POST http://localhost:3001/assert \
  -H "Content-Type: application/json" \
  -d "{\"SAMLResponse\": \"$SAML_RESPONSE\"}"
```

### Run automated tests:
```bash
npm test -- server/assert.test.js
```

## Integration with Authentication Flow

### Automatic Redirect to Protected Page

After successful validation, the user is automatically redirected to `/protected` where they can view:

1. **Authentication Details Section:**
   - Protocol used (saml20)
   - Certificate that verified the signature
   - Timestamp of authentication

2. **User Information Section:**
   - User ID / NameID
   - Email address
   - First and last name
   - Any additional SAML attributes

3. **Full Credential Information:**
   - Complete JSON representation of session data
   - Full SAML assertion XML

### Session Data

The validated user information is stored in the session and can be retrieved via:

```bash
GET /api/session
```

This returns the authenticated user data:
```json
{
  "protocol": "saml20",
  "user": {
    "nameID": "user@example.com",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
  },
  "verifiedBy": "saml-idp-cert.pem",
  "samlAssertion": "<full SAML XML>",
  "authenticatedAt": "2025-10-10T12:00:00.000Z"
}
```

### Testing with HTML Form

A test form is provided in `test-assert.html`. Open it in your browser to:
1. Paste a base64-encoded SAML response
2. Submit it to the `/assert` endpoint
3. See automatic redirect to the protected page on success

## Troubleshooting

### Error: "No trusted certificates found"
- Ensure certificate files exist in `/data/certificates/`
- Verify file extensions are `.pem`, `.crt`, or `.cer`

### Error: "Invalid SAML signature"
- Verify the certificate matches the IdP that signed the assertion
- Ensure the certificate is in correct PEM format
- Check that the SAML response includes a signature

### Error: "Failed to parse SAML assertion"
- Verify the SAML XML structure is valid
- Ensure the response contains an Assertion element
- Check that the XML namespace declarations are correct
