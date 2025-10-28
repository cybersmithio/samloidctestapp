# SAML/OIDC Test Application
This is an application used to test SAML and OIDC authentication.  The code has been created with the assistance of an AI coding agent.

The container requires a data directory to be mounted into /app/data.  This data directory must have a directory named "certificates" for storing certificates that the application will trust.  It must also have a directory named "certsAndKeys" that will have the private keys and certificates used by the application for encryption and signing.

# Example of a config.json
The application reads /app/data/config.json.  An example of what that file would look like:
```
{
  "application": {
    "hostname": "workstation.local",
    "port": 3001,
    "publicPort": 443,
    "entityId": "https://workstation.local/saml/metadata",
    "baseUrl": "https://workstation.local",
    "samlSigningCertificate": "certsAndKeys/sp-cert.pem",
    "samlSigningPrivateKey": "certsAndKeys/sp-key.pem",
    "signSamlRequests": true,
    "useHttps": false,
    "useHttpsPublicly": true,
    "serverCertificate": "certsAndKeys/server-cert.pem",
    "serverPrivateKey": "certsAndKeys/server-key.pem"
  },
  "identityProviders": [
    {
      "protocol": "saml20",
      "name": "Example SAML IdP with RP using unique entityId and signed SAML requests",
      "issuerUrl": "https://idp.example.local",
      "binding": "redirect",
      "loginUrl": "https://idp.example.local/sso/saml",
      "logoutUrl": "https://idp.example.local/sso/logout",
      "certificate": "saml-idp-cert.pem",
      "authNContextClassRef": "urn:oasis:names:tc:SAML:1.0:am:password",
      "forceAuthn": false,
      "entityId": "samltestapp1",
      "samlSigningCertificate": "certsAndKeys/sp-cert.pem",
      "samlSigningPrivateKey": "certsAndKeys/sp-key.pem",
      "signSamlRequests": true
    },
    {
      "protocol": "saml20",
      "name": "Example SAML IdP with RP using globally defined entityId and unsigned SAML requests",
      "issuerUrl": "https://idp.example.local",
      "binding": "redirect",
      "loginUrl": "https://idp.example.local/sso/saml",
      "logoutUrl": "https://idp.example.local/sso/logout",
      "certificate": "saml-idp-cert.pem",
      "authNContextClassRef": "urn:oasis:names:tc:SAML:1.0:am:password",
      "forceAuthn": false,
      "signSamlRequests": false
    },    
    {
      "protocol": "oidc",
      "name": "Example OIDC IdP that uses implicit flow",
      "responseType": "id_token",
      "tenantUrl": "https://login.example.local/tenant-id",
      "issuerUrl": "https://login.example.local/tenant-id/v2.0",
      "authorizationUrl": "https://login.example.local/tenant-id/oauth2/v2.0/authorize",
      "tokenUrl": "https://login.example.local/tenant-id/oauth2/v2.0/token",
      "userInfoUrl": "https://graph.example.local/oidc/userinfo",
      "metadataUrl": "https://login.example.local/tenant-id/v2.0/.well-known/openid-configuration",
      "jwksUrl": "https://login.example.local/tenant-id/discovery/v2.0/keys",
      "clientId": "your-client-id1",
      "clientSecret": "your-client-secret",
      "scope": "openid profile email"
    },
    {
      "protocol": "oidc",
      "name": "Example OIDC IdP that uses authorization code flow and does not validate TLS cert of IdP token URL",
      "responseType": "code",
      "tenantUrl": "https://login.example.local/tenant-id",
      "issuerUrl": "https://login.example.local/tenant-id/v2.0",
      "authorizationUrl": "https://login.example.local/tenant-id/oauth2/v2.0/authorize",
      "tokenUrl": "https://login.example.local/tenant-id/oauth2/v2.0/token",
      "userInfoUrl": "https://graph.example.local/oidc/userinfo",
      "metadataUrl": "https://login.example.local/tenant-id/v2.0/.well-known/openid-configuration",
      "jwksUrl": "https://login.example.local/tenant-id/discovery/v2.0/keys",
      "clientId": "your-client-id2",
      "clientSecret": "your-client-secret",
      "scope": "openid profile email",
      "insecureSkipCertificateVerification": true
    }    
  ]
}

```

# Quickstart
To run with Docker using the 'data' directory in /home/jsmith/samloidctestapp/ and listen on port 3001
```
docker run -it  --rm --name saml-oidc-test-app -p 3001:3001 -v /home/jsmith/samloidctestapp/data:/app/data"  cybersmithio/saml-oidc-test-app:latest
```

