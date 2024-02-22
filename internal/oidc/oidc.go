package oidc

import "fmt"

type OpenIDConnectProvider struct {
	Host              string
	Port              int
	AuthorizeEndpoint string
	TokenEndpoint     string
	ConfigEndpoint    string
}

func NewOIDCProvider() *OpenIDConnectProvider {
	return &OpenIDConnectProvider{
		Host:              "127.0.0.1",
		Port:              80,
		AuthorizeEndpoint: "/oauth/authorize",
		TokenEndpoint:     "/oauth/token",
	}
}

func (oidc *OpenIDConnectProvider) GetAuthorizeUrl() string {
	if oidc.Port != 80 {
		return fmt.Sprintf("%s:%d", oidc.Host, oidc.Port) + oidc.AuthorizeEndpoint
	}
	return oidc.Host + oidc.AuthorizeEndpoint
}

func (oidc *OpenIDConnectProvider) GetTokenUrl() string {
	if oidc.Port != 80 {
		return fmt.Sprintf("%s:%d", oidc.Host, oidc.Port) + oidc.TokenEndpoint
	}
	return oidc.Host + oidc.TokenEndpoint
}

func (oidc *OpenIDConnectProvider) FetchServerConfiguration(url string) {
	// make a request to a server's openid-configuration
}
