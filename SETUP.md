# Setup Guide

This guide will help you set up and run the SAML/OIDC Test Application.

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn package manager

## Installation

1. Clone or download this repository

2. Install dependencies:
```bash
npm install
```

## Configuration

### 1. Configure Identity Providers

Edit `data/config.json` to add your identity providers:

```json
{
  "identityProviders": [
    {
      "protocol": "saml20",
      "name": "Your SAML Provider",
      "loginUrl": "https://your-idp.com/sso/saml",
      "logoutUrl": "https://your-idp.com/sso/logout",
      "certificate": "your-saml-cert.pem"
    },
    {
      "protocol": "oidc",
      "name": "Your OIDC Provider",
      "tenantUrl": "https://login.provider.com/tenant-id",
      "issuerUrl": "https://login.provider.com/tenant-id/v2.0",
      "authorizationUrl": "https://login.provider.com/tenant-id/oauth2/v2.0/authorize",
      "tokenUrl": "https://login.provider.com/tenant-id/oauth2/v2.0/token",
      "userInfoUrl": "https://graph.provider.com/oidc/userinfo",
      "metadataUrl": "https://login.provider.com/tenant-id/v2.0/.well-known/openid-configuration",
      "clientId": "your-client-id",
      "clientSecret": "your-client-secret",
      "callbackUrl": "http://localhost:3000/auth/oidc/callback",
      "scope": "openid profile email"
    }
  ]
}
```

### 2. Add Certificates

Place your IdP's public certificates in the `data/certificates/` directory:

```bash
cp your-idp-cert.pem data/certificates/
```

Certificates must be in PEM format and referenced in `config.json`.

### 3. Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` to configure:
- `SESSION_SECRET`: A strong secret key for session encryption
- `PORT`: Server port (default: 3001)

## Running the Application

### Development Mode

1. Start the backend server:
```bash
node server/index.js
```

2. In a separate terminal, start the React frontend:
```bash
npm start
```

3. Open your browser to `http://localhost:3000`

### Production Mode

1. Build the React application:
```bash
npm run build
```

2. Serve the built files and run the backend server with a production server like nginx or serve the static files through Express.

## Running Tests

Run all tests:
```bash
npm test
```

Run tests in watch mode:
```bash
npm run test:watch
```

Run tests with coverage:
```bash
npm test -- --coverage
```

## How It Works

### SAML 2.0 Authentication Flow

1. User clicks on a SAML IdP button on the login page
2. Application redirects to IdP's login URL
3. User authenticates with the IdP
4. IdP posts a SAML assertion to the callback URL
5. Application verifies the SAML signature using the trusted certificate
6. Application parses user information from the assertion
7. User is redirected to the protected page

### OIDC Authentication Flow

1. User clicks on an OIDC IdP button on the login page
2. Application redirects to IdP's authorization endpoint with state and nonce
3. User authenticates with the IdP
4. IdP redirects back with an authorization code
5. Application exchanges the code for ID and access tokens
6. Application verifies the JWT signature
7. Application fetches user info using the access token
8. User is redirected to the protected page

## Security Features

- **SAML Signature Verification**: All SAML assertions are verified against trusted certificates
- **JWT Signature Verification**: JWT tokens are verified using JWKS or configured certificates
- **State Parameter**: CSRF protection for OIDC flows
- **Nonce Verification**: Replay attack protection for OIDC
- **Session Security**: HTTP-only cookies with secure flag in production
- **Certificate Management**: Centralized certificate storage with validation

## Troubleshooting

### Certificate Errors

If you see certificate verification errors:
- Ensure the certificate is in PEM format
- Verify the certificate filename matches the config
- Check that the certificate is from the correct IdP

### SAML Signature Verification Fails

- Verify the certificate matches the IdP's signing certificate
- Check that the SAML response includes a signature
- Ensure the certificate is not expired

### OIDC Token Verification Fails

- Check that the issuer URL matches the token's `iss` claim
- Verify the client ID matches the token's `aud` claim
- Ensure the IdP's JWKS endpoint is accessible

### Session Issues

- Clear browser cookies and try again
- Check that SESSION_SECRET is set in .env
- Verify session middleware is properly configured

## Contributing

This application was created with AI assistance for testing SAML and OIDC authentication flows. Feel free to modify and extend it for your needs.
