# Example SAML Setup 1
* Use the Custom Application
* General
* Sign-on
    * Sign-on method: SAML2.0
    * Provide the metadata file from the application
    * Use identity provider initiated single sign-on: Enabled

# Example OIDC Setup 1

* Use the OpenID Connect
* General
* Sign-on
    * Application URL: https://appFQDN:appPort
    * Grant types: Implicit
    * Response types: id_token
    * Response modes: Fragment, Form POST
    * Redirect URIs: https://appFQDN:appPort/auth/oidc/callback
    * Require proof key for code exchange (PKCE) verification: Disabled
