# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a full-stack SAML/OIDC authentication test application built with React (frontend) and Express (backend). The backend serves both the API and the compiled React frontend on a single port (3001). The application supports multiple identity providers using either SAML 2.0 or OpenID Connect (OIDC) protocols.

## Common Commands

### Development
```bash
# Start backend server (serves API + built frontend)
npm run start:server

# Start React development server (port 3000 proxy to backend)
npm start

# Start production server
npm run start:prod
```

### Building
```bash
# Build React frontend
npm run build

# Build and serve in production mode
npm run build:serve
```

### Testing
```bash
# Run all tests (client + server)
npm test

# Run tests in watch mode
npm run test:watch

# Run specific test file
npm test -- server/auth/saml.test.js

# Run tests for specific project (client or server)
npm test -- --selectProjects=server
npm test -- --selectProjects=client
```

### Docker
```bash
# Build Docker image (no cache)
npm run docker:build

# Run container
npm run docker:run

# Start with Docker Compose
npm run docker:up

# Stop Docker Compose
npm run docker:down

# View logs
npm run docker:logs
```

## Architecture

### Request Flow

**SAML Authentication:**
1. User clicks IdP button → `/auth/saml/login?idp=<name>`
2. Server generates AuthnRequest XML, encodes based on binding (redirect/post)
3. User redirected to IdP login URL
4. IdP authenticates and POSTs SAMLResponse to `/assert`
5. Server verifies signature against all certificates in `data/certificates/`
6. Session created, user redirected to `/protected`

**OIDC Authentication:**
1. User clicks IdP button → `/auth/oidc/login?idp=<name>`
2. Server generates state/nonce, redirects to IdP authorization URL
3. IdP authenticates and redirects to `/auth/oidc/callback?code=...`
4. Server exchanges code for tokens at IdP token endpoint
5. Server verifies JWT signature using JWKS or certificate
6. Session created, user redirected to `/protected`

### Configuration System

Configuration is loaded from `data/config.json` at server startup via `server/utils/configLoader.js`. The loader validates:
- Application settings (hostname, port, publicPort, HTTPS config, certificates)
- Identity provider configurations (required fields per protocol)
- SAML binding types (defaults to 'redirect' if not specified)

**Critical:** The configuration distinguishes between:
- `port`: The port the backend server listens on (e.g., 3001)
- `publicPort`: The port users connect to via proxy/ingress (e.g., 443 in Azure)

All absolute URLs are constructed using `publicPort` for external redirects, ensuring correct behavior when Azure (or other proxies) forwards 443 → 3001. The `buildAbsoluteUrl()` helper automatically omits standard ports (80/443) from URLs.

### Authentication Modules

**`server/auth/saml.js`** - SAML 2.0 authentication router
- Supports both HTTP-Redirect (deflate+base64) and HTTP-POST (base64 only) bindings
- Generates AuthnRequest XML with optional signing
- Signature verification using xml-crypto library
- Parses assertions using xml2js to extract user attributes

**`server/auth/oidc.js`** - OIDC/OAuth2 authentication router
- Implements authorization code flow
- State and nonce validation for CSRF protection
- JWT verification via JWKS endpoint or certificate-based fallback
- Optional UserInfo endpoint fetching

**`server/index.js`** - Main application server
- Serves React frontend from `/build` directory
- Provides `/assert` endpoint for direct SAML response posting
- Generates SAML metadata XML at `/saml/metadata`
- Session management with express-session
- Can run HTTP or HTTPS based on `config.application.useHttps`

### Certificate Management

**Trusted IdP Certificates:**
- Located in `data/certificates/`
- Files with extensions: `.pem`, `.crt`, `.cer`
- The `/assert` endpoint tries ALL certificates until one validates successfully
- Each IdP config references a certificate file by name

**Application Certificates:**
- Located in `data/certsAndKeys/`
- SAML signing cert/key: Used to sign AuthnRequests if `signSamlRequests: true`
- Server cert/key: Used for HTTPS if `useHttps: true`

### Frontend Architecture

React app with two main routes:
- `/` - LoginPage: Displays IdP buttons, downloads metadata
- `/protected` - ProtectedPage: Shows authenticated user info

Frontend uses relative URLs for API calls since it's served by the backend. After build, all traffic goes through Express on port 3001.

## Testing

Tests use Jest with two projects configured:
- **client**: jsdom environment for React components (`src/**/*.test.js`)
- **server**: node environment for Express/auth logic (`server/**/*.test.js`)

Test philosophy: "Build tests first, ensure they fail, then implement code to make them pass." When adding features, write failing tests before implementation.

Coverage thresholds: 70% for branches, functions, lines, and statements.

## Development Workflow

### Adding a New Identity Provider

1. Add IdP configuration to `data/config.json` under `identityProviders` array
2. For SAML: Place IdP certificate in `data/certificates/`
3. For OIDC: Ensure all required URLs and credentials are configured
4. Restart server to load new config
5. New login button will appear automatically on frontend

### Modifying Authentication Flow

1. SAML logic: Edit `server/auth/saml.js`
2. OIDC logic: Edit `server/auth/oidc.js`
3. Assertion processing: Edit `/assert` endpoint in `server/index.js`
4. Always update corresponding test files first (test-driven development)

### URL Construction

When building redirect URLs or absolute URLs:
- Use `buildAbsoluteUrl()` helper in auth routers (uses `publicPort`)
- Or construct from `config.application.baseUrl`
- Never hardcode hostnames or protocols
- The helpers automatically use `publicPort` for user-facing URLs
- The server listens on `port`, but generates URLs with `publicPort`
- Standard ports (80/443) are automatically omitted from URLs
- This ensures compatibility with proxies, Docker, and Azure Container Apps

**Example:** In Azure, users connect to `https://myapp.azurecontainerapps.io` (port 443), but the container runs on port 3001. Set `publicPort: 443` and `port: 3001` in config.

## Important Notes

- The application uses a **single port (3001)** for both API and frontend in production
- SAML binding type is configurable per IdP (`redirect` or `post`)
- The `/assert` endpoint attempts signature verification with ALL certificates in `data/certificates/` directory
- Session data includes the full SAML assertion or JWT token for debugging
- Line endings: Git converts LF to CRLF on Windows (warnings are normal)
- Docker uses multi-stage build: frontend build stage + production runtime stage
- The `data/` directory should be mounted as a volume in production for config updates without rebuilds
