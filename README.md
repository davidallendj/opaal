# OpenID Connect Authentication Helper

This is a small, simple, experimental helper tool that automates the authorization code flow for logging in with an identity provider like GitHub or GitLab. To use this tool, you will have to register an OAuth2 application with you identity provider. Make sure you register the application first before proceeding, then set the callback URL to `{your host}/oauth/callback`.

To get started with the authentication flow, run the following commands:

```bash
./oidc config ./config.yaml
./oidc login --config config.yaml
```

These commands will create a default config, then start the login process. Initially, you'll have to click on the link created based on you configuration, login with your IdP, then authorize the client to within the set scope.