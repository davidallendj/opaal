package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/davidallendj/go-utils/httpx"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type TrustedIssuer struct {
	Id              string    `db:"id" yaml:"id"`
	AllowAnySubject bool      `db:"allow_any_subject" yaml:"allow-any-subject"`
	ExpiresAt       time.Time `db:"expires_at" yaml:"expires-at"`
	Issuer          string    `db:"issuer" yaml:"issuer"`
	PublicKey       jwk.Key   `db:"public_key" yaml:"public-key"`
	Scope           []string  `db:"scope" yaml:"scope"`
	Subject         string    `db:"subject" yaml:"subject"`
}

func NewTrustedIssuer() *TrustedIssuer {
	return &TrustedIssuer{
		AllowAnySubject: false,
		ExpiresAt:       time.Now().Add(time.Hour),
		Scope:           []string{"openid"},
		Subject:         "1",
	}
}

func (ti *TrustedIssuer) IsTrustedIssuerValid() bool {
	err := ti.PublicKey.Validate()
	return ti.Issuer != "" && err == nil && ti.Subject != ""
}

func ParseString(b []byte) (*TrustedIssuer, error) {
	// take data from JSON to populate fields
	ti := &TrustedIssuer{}
	data := map[string]any{}
	json.Unmarshal(b, &data)
	return ti, nil
}

func (client *Client) ListTrustedIssuers(url string) ([]TrustedIssuer, error) {
	// hydra endpoint: GET /admin/trust/grants/jwt-bearer/issuers
	_, b, err := httpx.MakeHttpRequest(url, http.MethodGet, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	// unmarshal results into TrustedIssuers objects
	trustedIssuers := []TrustedIssuer{}
	err = json.Unmarshal(b, &trustedIssuers)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}
	return trustedIssuers, nil
}

func (client *Client) AddTrustedIssuer(url string, ti *TrustedIssuer) ([]byte, error) {
	// hydra endpoint: POST /admin/trust/grants/jwt-bearer/issuers
	if ti == nil {
		return nil, fmt.Errorf("no valid trusted issuer provided")
	}

	// add the client's scope to trusted issuer
	ti.Scope = append(ti.Scope, client.Scope...)

	quotedScopes := make([]string, len(ti.Scope))
	for i, s := range ti.Scope {
		quotedScopes[i] = fmt.Sprintf("\"%s\"", s)
	}

	// NOTE: Can also include "jwks_uri" instead of "jwk"
	body := map[string]any{
		"allow_any_subject": ti.AllowAnySubject,
		"issuer":            ti.Issuer,
		"expires_at":        ti.ExpiresAt,
		"jwk":               ti.PublicKey,
		"scope":             ti.Scope,
	}
	if !ti.AllowAnySubject {
		body["subject"] = ti.Subject
	}
	b, err := json.Marshal(body)
	// fmt.Printf("request: %v\n", string(b))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer res.Body.Close()

	return io.ReadAll(res.Body)
}
