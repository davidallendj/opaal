package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type IdentityProvider struct {
	Issuer    string    `db:"issuer" json:"issuer" yaml:"issuer"`
	Endpoints Endpoints `db:"endpoints" json:"endpoints" yaml:"endpoints"`
	Supported Supported `db:"supported" json:"supported" yaml:"supported"`
	KeySet    jwk.Set
}

type Endpoints struct {
	Config        string `db:"config_endpoint" json:"config_endpoint" yaml:"config"`
	Authorization string `db:"authorization_endpoint" json:"authorization_endpoint" yaml:"authorization"`
	Token         string `db:"token_endpoint" json:"token_endpoint" yaml:"token"`
	Revocation    string `db:"revocation_endpoint" json:"revocation_endpoint" yaml:"revocation"`
	Introspection string `db:"introspection_endpoint" json:"introspection_endpoint" yaml:"introspection"`
	UserInfo      string `db:"userinfo_endpoint" json:"userinfo_endpoint" yaml:"userinfo"`
	JwksUri       string `db:"jwks_uri" json:"jwks_uri" yaml:"jwks_uri"`
}
type Supported struct {
	ResponseTypes            []string `db:"response_types_supported" json:"response_types_supported"`
	ResponseModes            []string `db:"response_modes_supported" json:"response_modes_supported"`
	GrantTypes               []string `db:"grant_types_supported" json:"grant_types_supported"`
	TokenEndpointAuthMethods []string `db:"token_endpoint_auth_methods_supported" json:"token_endpoint_auth_methods_supported"`
	SubjectTypes             []string `db:"subject_types_supported" json:"subject_types_supported"`
	IdTokenSigningAlgValues  []string `db:"id_token_signing_alg_values_supported" json:"id_token_signing_alg_values_supported"`
	ClaimTypes               []string `db:"claim_types_supported" json:"claim_types_supported"`
	Claims                   []string `db:"claims_supported" json:"claims_supported"`
}

func NewIdentityProvider() *IdentityProvider {
	p := &IdentityProvider{Issuer: "127.0.0.1"}
	p.Endpoints = Endpoints{
		Authorization: p.Issuer + "/oauth/authorize",
		Token:         p.Issuer + "/oauth/token",
		Revocation:    p.Issuer + "/oauth/revocation",
		Introspection: p.Issuer + "/oauth/introspect",
		UserInfo:      p.Issuer + "/oauth/userinfo",
		JwksUri:       p.Issuer + "/oauth/discovery/keys",
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

func (p *IdentityProvider) FetchServerConfig() error {
	tmp, err := FetchServerConfig(p.Issuer)
	if err != nil {
		return err
	}
	p = tmp
	return nil
}

func FetchServerConfig(issuer string) (*IdentityProvider, error) {
	// make a request to a server's openid-configuration
	req, err := http.NewRequest(http.MethodGet, issuer+"/.well-known/openid-configuration", bytes.NewBuffer([]byte{}))
	if err != nil {
		return nil, fmt.Errorf("failed to create a new request: %v", err)
	}

	client := &http.Client{} // temp client to get info and not used in flow
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code: %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var p IdentityProvider
	err = p.ParseServerConfig(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server config: %v", err)
	}
	return &p, nil
}

func (p *IdentityProvider) FetchJwks() error {
	if p.Endpoints.JwksUri == "" {
		return fmt.Errorf("JWKS endpoint not set")
	}
	// fetch JWKS from identity provider
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var err error
	p.KeySet, err = jwk.Fetch(ctx, p.Endpoints.JwksUri)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %v", err)
	}

	return nil
}
