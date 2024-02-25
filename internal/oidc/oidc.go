package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/jwk"
)

type IdentityProvider struct {
	Issuer    string    `json:"issuer" yaml:"issuer"`
	Endpoints Endpoints `json:"endpoints" yaml:"endpoints"`
	Supported Supported `json:"supported" yaml:"supported"`
	Key       jwk.Key
}

type Endpoints struct {
	Authorization string `json:"authorization_endpoint" yaml:"authorization"`
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
		Authorization: p.Issuer + "/oauth/authorize",
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

func (p *IdentityProvider) ParseServerConfig(data []byte) error {
	// parse JSON into IdentityProvider fields
	var ep Endpoints
	var s Supported
	var e error
	epErr := json.Unmarshal(data, &ep)
	if epErr != nil {
		e = fmt.Errorf("%v", epErr)
	}
	sErr := json.Unmarshal(data, &s)
	if sErr != nil {
		e = fmt.Errorf("%v %v", e, sErr)
	}
	err := json.Unmarshal(data, p)
	if err != nil {
		e = fmt.Errorf("%v %v", e, err)
	}
	p.Endpoints = ep
	p.Supported = s
	return e
}

func (p *IdentityProvider) LoadServerConfig(path string) error {
	// load server config from local file i
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read server config: %v", err)
	}
	err = p.ParseServerConfig(data)
	if err != nil {
		return fmt.Errorf("failed to parse server config: %v", err)
	}
	return nil
}

func (p *IdentityProvider) FetchServerConfig(url string) error {
	// make a request to a server's openid-configuration
	req, err := http.NewRequest("GET", url, bytes.NewBuffer([]byte{}))
	if err != nil {
		return fmt.Errorf("failed to create a new request: %v", err)
	}

	client := &http.Client{} // temp client to get info and not used in flow
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %v", err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}
	err = p.ParseServerConfig(body)
	if err != nil {
		return fmt.Errorf("failed to parse server config: %v", err)
	}
	return nil
}

func (p *IdentityProvider) FetchJwk(url string) error {
	if url == "" {
		url = p.Endpoints.Jwks
	}
	// fetch JWKS from identity provider
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
