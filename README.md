# OIDC Provider Authentication/Authorization Login (OPAAL)

This is a small, simple, experimental OIDC login helper tool that automates the authorization code flow defined by [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1) for social sign-in with identity providers like Google, Facebook, or GitHub. This tool is made to work when your issuer/identity provider is separate from your authorization server. 

Note: This tool acts as an OAuth client, contains client secrets, and should not be exposed to users!

## Build and Usage

Clone the repository and build:

```bash
git clone https://github.com/davidallendj/opal.git
cd opal/
go mod tidy && go build
```

To use this tool, you will have to register an OAuth2 application with you identity provider. Make sure you register the application first before proceeding, then set the callback URL to `{your host}/oauth/callback`.

To get started with the authentication flow, run the following commands:

```bash
./oidc config ./config.yaml
./oidc login --config config.yaml
```

These commands will create a default config, then start the login process. Initially, you'll have to click on the link created based on you configuration, login with your IdP, then authorize the client to within the set scope.