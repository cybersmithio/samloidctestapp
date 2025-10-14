# Example SAML Setup 1
* Use the Custom Application
* General
* Sign-on
    * Sign-on method: SAML2.0
    * Provider ID: samlapp1
        * This is the unique identifier of the application with it's IdP
    * Target URL (a.k.a. "Assertion consumer service URL (HTTP-POST):") https://appFQDN:appPort/assert
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
