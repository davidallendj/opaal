# OIDC Provider Authentication/Authorization Login (OPAAL)

This is a small, simple, experimental OIDC login helper tool that automates the authorization code flow defined by [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) for social sign-in with identity providers (IdP) like Google, Facebook, or GitHub. This tool is made to work when your issuer/identity provider is separate from your authorization server, and we only use the IdP to receive an ID token. In this document, the identity provider/authentication server is strictly the OIDC implementation that identifies the resource owner (ID token) whereas the authorization server is the OIDC implementation that grants access to a resource (access token). This tool is tested using Ory Kratos and Hydra for user identity and session management and OAuth2/OIDC implementation respectively.

Note: This tool acts as an OAuth client, contains client secrets, and is not be exposed to users!

## Build and Usage

Clone the repository and build:

```bash
git clone https://github.com/davidallendj/opaal.git
cd opaal/
go mod tidy && go build
```

To use this tool, you will have to register an OAuth2 application with you identity provider. Make sure you register the application first before proceeding, then set the callback URL to `{your host}/oauth/callback`.

To get started with the authentication flow, run the following commands:

```bash
./opaal config ./config.yaml
./opaal login --config config.yaml
```

These commands will create a default config, then start the login process. Maybe sure to change the config file to match your setup!

1. Click the authorization link or navigate to the hosted endpoint in your browser (127.0.0.1:3333 by default)
2. Login using identity provider credentials
3. Authorize application registered with IdP
4. IdP redirects to specified redirect URI
5. Opaal completes the rest of the authorization flow by...
	- ...making a request to the IdP with the authorization code to receive bearer/ID token
	- ...making a request to a user identity and management server to create a new identity (optional)
	- ...making a request to the authorization server to trust the identity provider (optional)
	- ...making a request to the authorization server to receive an access token (optional)

*After receiving the ID token, the rest of the flow requires the appropriate URLs to be set

## TODO

- When the process is complete, `opaal` will present the user with a "Success!" page along with the access token and a message indicating that the process is completed.

- Add unit tests