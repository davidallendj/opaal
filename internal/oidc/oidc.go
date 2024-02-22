package oidc

type OpenIDConnectProvider struct {
	Host              string
	AuthorizeEndpoint string
	TokenEndpoint     string
	ConfigEndpoint    string
}

func NewOIDCProvider() *OpenIDConnectProvider {
	return &OpenIDConnectProvider{
		Host:              "https://gitlab.newmexicoconsortium.org",
		AuthorizeEndpoint: "/oauth/authorize",
		TokenEndpoint:     "/oauth/token",
	}
}

func (oidc *OpenIDConnectProvider) GetAuthorizeUrl() string {
	return oidc.Host + oidc.AuthorizeEndpoint
}

func (oidc *OpenIDConnectProvider) GetTokenUrl() string {
	return oidc.Host + oidc.TokenEndpoint
}

func (oidc *OpenIDConnectProvider) FetchServerConfiguration(url string) {
	// make a request to a server's openid-configuration
}
