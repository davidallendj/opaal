# OIDC Provider Authentication/Authorization Login (OPAAL)

This is a small, simple, experimental OIDC login helper tool that automates the authorization flows defined by [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) for social sign-in with identity providers (IdP) like Google, Facebook, or GitHub. This tool is made to work when your identity provider is separate from your authorization server, and we only need the IdP to receive an ID token. In this document, the identity provider (or authentication server) is strictly the OIDC implementation that identifies the resource owner (ID token) whereas the resource provider (or authorization server) is the OIDC implementation that grants access to a resource (access token). OPAAL assumes that the authentication server is external and the authorization server is owned. This tool is tested with Ory Kratos and Hydra for user identity and session management and OAuth2/OIDC implementation respectively.

Note: This tool acts as an OAuth client, contains client secrets, and should not to be exposed to users! It would probably also be a good idea to use a reverse proxy and firewall to protect admin endpoints.

## Build and Usage

Clone the repository and build:

```bash
git clone https://github.com/davidallendj/opaal.git
cd opaal/
go mod tidy && go build
```

To use this tool, you will have to register an OAuth2 application with you identity provider. Make sure you register the application first before proceeding, then set the callback URL to `{your host}/oauth/callback`.

To start the authentication flow, run the following commands:

```bash
./opaal config ./config.yaml
./opaal login  --flow authorization_code --config config.yaml
```

These commands will create a default config, then start the login process. Maybe sure to change the config file to match your setup! The tool has been tested and confirmed to work with the following identity providers so far:

- [Gitlab](https://about.gitlab.com/)
- [Forgejo](https://forgejo.org/) (fork of Gitea)

### Authorization Code Flow

`opaal` has the ability to completely execute the authorization code and return an access token from an authorization server using social sign-in. The process works as follows:

1. Click the authorization link or navigate to the hosted endpoint in your browser (127.0.0.1:3333 by default)
	- Alternatively, you can use a link produced 
2. Login using identity provider credentials
3. Authorize application registered with IdP
4. IdP redirects to specified redirect URI
5. Opaal completes the rest of the authorization flow by...
	- ...verifying the authenticity of the ID token from identity provider with its JWKS
	- ...adds itself as a trusted issuer to the authorization server with it's own JWK
	- ...creates a new signed JWT to send to the authorization server with the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant type
	- ... returns an access token that can be used by services protected by the authorization server 

*After receiving the ID token, the rest of the flow requires the appropriate URLs to be set to continue.

### Client Credentials Flow

`opaal` also has


## Configuration

Here is an example configuration file:

```yaml
version: "0.0.1"
server:
  host: "127.0.0.1"
  port: 3333
  callback: "/oidc/callback"

providers:
  forgejo: "http://127.0.0.1:3000"

authentication:
  clients:
    - id: "my_client_id"
      secret: "my_client_secret"
      name: "forgejo"
      issuer: "http://127.0.0.1:3000"
      scope:
        - "openid"
        - "profile"
        - "read"
        - "email"
      redirect-uris:
        - "http://127.0.0.1:3333/oidc/callback"
  flows:
    authorization-code:
      state: ""
    client-credentials:

authorization:
  urls:
    #identities: http://127.0.0.1:4434/admin/identities
    trusted-issuers: http://127.0.0.1:4445/admin/trust/grants/jwt-bearer/issuers
    login: http://127.0.0.1:4433/self-service/login/api
    clients: http://127.0.0.1:4445/admin/clients
    authorize: http://127.0.0.1:4444/oauth2/auth
    register: http://127.0.0.1:4444/oauth2/register
    token: http://127.0.0.1:4444/oauth2/token


options:
  decode-id-token: true
  decode-access-token: true
  run-once: true
  open-browser: false
  forward: false
```

## Troubleshooting

- Make sure all remote hosts in config file are reachable.
- If you get a CSRF violation error, try clearing the cookies in your browser.
- If you only want to receive an ID token, comment out the other URLs in config. This may be changed in the future.
- The JWKS url can be found from your authentication server's OpenID configuration
`curl https://<your authetication server>/.well-known/openid-configuration`

## TODO

- When the process is complete, `opaal` will present the user with a "Success!" page along with the access token and a message indicating that the process is completed.
- Add functional login page example
- Add unit tests
- Allow repeat logins
- Add details about configuration parameters
- Implement client credentials flow to easily fetch tokens
- Fix how OAuth clients are managed with the authorization server
- Fix how the trusted issuer is added to the authorization server
- Allow signing JWTs by supplying key pair
- Separate `jwt_bearer` grant type from the authorization code flow