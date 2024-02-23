package oidc

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

type IdentityProvider struct {
	Issuer    string    `json:"issuer" yaml:"issuer"`
	Endpoints Endpoints `json:"endpoints" yaml:"endpoints"`
	Supported Supported `json:"supported" yaml:"supported"`
	Key       jwk.Key
}

type Endpoints struct {
	Authorize     string `json:"authorize_endpoint" yaml:"authorize"`
	Token         string `json:"token_endpoint" yaml:"token"`
	Revocation    string `json:"revocation_endpoint" yaml:"revocation"`
	Introspection string `json:"introspection_endpoint" yaml:"introspection"`
	UserInfo      string `json:"userinfo_endpoint" yaml:"userinfo"`
	Jwks          string `json:"jwks_uri" yaml:"jwks_uri"`
}
type Supported struct {
	ResponseTypes            []string `json:"response_types_supported"`
	ResponseModes            []string `json:"response_modes_supported"`
	GrantTypes               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	SubjectTypes             []string `json:"subject_types_supported"`
	IdTokenSigningAlgValues  []string `json:"id_token_signing_alg_values_supported"`
	ClaimTypes               []string `json:"claim_types_supported"`
	Claims                   []string `json:"claims_supported"`
}

func NewIdentityProvider() *IdentityProvider {
	p := &IdentityProvider{Issuer: "127.0.0.1"}
	p.Endpoints = Endpoints{
		Authorize:     p.Issuer + "/oauth/authorize",
		Token:         p.Issuer + "/oauth/token",
		Revocation:    p.Issuer + "/oauth/revocation",
		Introspection: p.Issuer + "/oauth/introspect",
		UserInfo:      p.Issuer + "/oauth/userinfo",
		Jwks:          p.Issuer + "/oauth/discovery/keys",
	}
	p.Supported = Supported{
		ResponseTypes: []string{"code"},
		ResponseModes: []string{"query"},
		GrantTypes: []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
		},
		TokenEndpointAuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
		},
		SubjectTypes:            []string{"public"},
		IdTokenSigningAlgValues: []string{"RS256"},
		ClaimTypes:              []string{"normal"},
		Claims: []string{
			"iss",
			"sub",
			"aud",
			"exp",
			"iat",
		},
	}
	return p
}

func (p *IdentityProvider) FetchServerConfig(url string) {
	// make a request to a server's openid-configuration
}

func (p *IdentityProvider) FetchJwk(url string) error {
	//
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	set, err := jwk.Fetch(ctx, url)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	// get the first JWK from set
	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		p.Key = pair.Value.(jwk.Key)
		return nil
	}

	return fmt.Errorf("failed to load public key: %v", err)
}

func (p *IdentityProvider) GetRawJwk() (any, error) {
	var rawkey any
	if err := p.Key.Raw(&rawkey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %v", err)
	}
	return rawkey, nil
}
