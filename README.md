# SAML/OIDC Test Application
This is an application used to test SAML and OIDC authentication.  Code has been created with the assistance of an AI coding agent.

# Requirements
* An application that has a main page that displays login buttons for a user to log in using one of the configure identify providers.
* The application can use React javascript framework.
* A protected page that can only be accessed when the user provides a valid access credential.
* Valid access credentials include valid SAML assertions or JWT tokens.
* The protected page should display the information contained in the access credential provide by the user.
* The application should be able to handle multiple identity providers (IdPs)
* SAML assertions coming from the IdP should have the signature checked against a list of known certificate signers.
* JWT tokens coming from the IdP should have the signature checked against a list of known certificate signers.
* The application should have a folder that stores all the configuration data for the application.
* In the data folder there should be a subfolder for all certificates that the application trusts for the purpose of access credential signing.
* In the data folder there should be a config.json file
* The config.json file should have an array of identity providers.
  * Each element in the array represents a single IdP.
  * Each IdP will have a 'protocol' value that should be either "saml20" or "oidc"
  * For saml20 IdPs, the array element should have values for:
    * Application name
    * login url
    * logout url
    * certificate to trust for SAML assertions for that IdP
  * For oidc IdPs, the array element should have values for:
    * Application name
    * Tenant URL
    * Issuer URL
    * authorication URL
    * token URL
    * user info URL
    * metadata URL
    * client ID
    * client secret
    * callback URL
    * scope
  * For each element in the array, the main application page should display a login button with the IdP name.
