package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"

	"github.com/davidallendj/go-utils/httpx"
	"github.com/davidallendj/go-utils/util"
	"golang.org/x/net/publicsuffix"
)

type GrantType = string

const (
	AuthorizationCode GrantType = "authorization_code"
	ClientCredentials GrantType = "client_credentials"
	JwtBearer         GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type Client struct {
	http.Client
	Id                      string   `db:"id" yaml:"id"`
	Secret                  string   `db:"secret" yaml:"secret"`
	Name                    string   `db:"name" yaml:"name"`
	Description             string   `db:"description" yaml:"description"`
	Issuer                  string   `db:"issuer" yaml:"issuer"`
	RegistrationAccessToken string   `db:"registration_access_token" yaml:"registration-access-token"`
	RedirectUris            []string `db:"redirect_uris" yaml:"redirect-uris"`
	Scope                   []string `db:"scope" yaml:"scope"`
	Audience                []string `db:"audience" yaml:"audience"`
	FlowId                  string
	CsrfToken               string
}

func NewClient() *Client {
	return &Client{
		RedirectUris: []string{},
		Scope:        []string{},
		Audience:     []string{},
	}
}

func (client *Client) ClearCookies() {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client.Jar = jar
}

func (client *Client) IsOAuthClientRegistered(clientUrl string) (bool, error) {
	_, _, err := httpx.MakeHttpRequest(clientUrl, http.MethodGet, nil, nil)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %v", err)
	}
	// TODO: need to check contents of actual response
	return true, nil
}

func (client *Client) GetOAuthClient(clientUrl string) error {
	_, b, err := httpx.MakeHttpRequest(clientUrl, http.MethodGet, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}

	fmt.Printf("GetOAuthClient: %v\n", string(b))

	var data []map[string]any
	err = json.Unmarshal(b, &data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	index := slices.IndexFunc(data, func(c map[string]any) bool {
		if c["client_id"] == nil {
			return false
		}
		return c["client_id"].(string) == client.Id
	})
	if index < 0 {
		return fmt.Errorf("client not found")
	}

	// cast the redirect_uris from []any to []string and extract registration token
	foundClient := data[index]
	for _, uri := range foundClient["redirect_uris"].([]any) {
		client.RedirectUris = append(client.RedirectUris, uri.(string))
	}
	if foundClient["registration-access-token"] != nil {
		client.RegistrationAccessToken = foundClient["registration-access-token"].(string)
	}

	return nil
}

func (client *Client) CreateOAuthClient(registerUrl string, grantTypes []GrantType) ([]byte, error) {
	// hydra endpoint: POST /clients
	if client == nil {
		return nil, fmt.Errorf("invalid client")
	}
	audience := util.QuoteArrayStrings(client.Audience)
	grantTypes = util.QuoteArrayStrings(grantTypes)
	body := httpx.Body(fmt.Sprintf(`{
		"client_id":                  "%s",
		"client_name":                "%s",
		"client_secret":              "%s",
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      "%s",
		"grant_types":                [%s],
		"response_types":             ["token"],
		"redirect_uris":              ["http://127.0.0.1:3333/callback"],
		"state":                      12345678910,
		"audience":                   [%s]
		}`, client.Id, client.Id, client.Secret, strings.Join(client.Scope, " "), strings.Join(grantTypes, ","), strings.Join(audience, ","),
	))
	headers := httpx.Headers{
		"Content-Type": "application/json",
	}

	_, b, err := httpx.MakeHttpRequest(registerUrl, http.MethodPost, []byte(body), headers)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	var rjson map[string]any
	err = json.Unmarshal(b, &rjson)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %v", err)
	}

	// check for error first
	errJson := rjson["error"]
	if errJson == nil {
		// set the client ID and secret of registered client
		client.Id = rjson["client_id"].(string)
		client.Secret = rjson["client_secret"].(string)
		client.RegistrationAccessToken = rjson["registration_access_token"].(string)
	} else {
		return b, nil
	}

	return b, err
}

func (client *Client) RegisterOAuthClient(registerUrl string, grantTypes []GrantType) ([]byte, error) {
	// hydra endpoint: POST /oauth2/register
	if registerUrl == "" {
		return nil, fmt.Errorf("no URL provided")
	}
	audience := util.QuoteArrayStrings(client.Audience)
	grantTypes = util.QuoteArrayStrings(grantTypes)
	body := httpx.Body(fmt.Sprintf(`{
		"client_name":                "opaal",
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      "%s",
		"grant_types":                [%s],
		"response_types":             ["token"],
		"redirect_uris":              ["http://127.0.0.1:3333/callback"],
		"state":                      12345678910,
		"audience":                   [%s]
		}`, strings.Join(client.Scope, " "), strings.Join(grantTypes, ","), strings.Join(audience, ","),
	))
	headers := httpx.Headers{
		"Content-Type": "application/json",
	}
	_, b, err := httpx.MakeHttpRequest(registerUrl, http.MethodPost, body, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	var rjson map[string]any
	err = json.Unmarshal(b, &rjson)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %v", err)
	}

	// check for error first
	errJson := rjson["error"]
	if errJson == nil {
		// set the client ID and secret of registered client
		client.Id = rjson["client_id"].(string)
		client.Secret = rjson["client_secret"].(string)
		client.RegistrationAccessToken = rjson["registration_access_token"].(string)
	} else {
		return b, nil
	}
	return b, err
}

func (client *Client) AuthorizeOAuthClient(authorizeUrl string) ([]byte, error) {
	// set the authorization header
	body := []byte("grant_type=" + url.QueryEscape("urn:ietf:params:oauth:grant-type:jwt-bearer") +
		"&scope=" + strings.Join(client.Scope, "+") +
		"&client_id=" + client.Id +
		"&client_secret=" + client.Secret +
		"&redirect_uri=" + url.QueryEscape("http://127.0.0.1:3333/callback") + // FIXME: needs to not be hardcorded
		"&response_type=token" +
		"&state=12345678910",
	)
	headers := httpx.Headers{
		"Authorization": "Bearer " + client.RegistrationAccessToken,
		"Content-Type":  "application/x-www-form-urlencoded",
	}
	_, b, err := httpx.MakeHttpRequest(authorizeUrl, http.MethodPost, body, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)
	}

	return b, nil
}

func (client *Client) PerformJwtBearerTokenGrant(clientUrl string, encodedJwt string) ([]byte, error) {
	// hydra endpoint: /oauth/token
	body := "grant_type=" + url.QueryEscape("urn:ietf:params:oauth:grant-type:jwt-bearer") +
		"&client_id=" + client.Id +
		"&client_secret=" + client.Secret +
		"&redirect_uri=" + url.QueryEscape("http://127.0.0.1:3333/callback")
	// add optional params if valid
	if encodedJwt != "" {
		body += "&assertion=" + encodedJwt
	}
	if client.Scope != nil || len(client.Scope) > 0 {
		body += "&scope=" + strings.Join(client.Scope, "+")
	}
	headers := httpx.Headers{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Bearer " + client.RegistrationAccessToken,
	}

	_, b, err := httpx.MakeHttpRequest(clientUrl, http.MethodPost, []byte(body), headers)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)

	}

	return b, err
}

func (client *Client) PerformClientCredentialsTokenGrant(clientUrl string) ([]byte, error) {
	// hydra endpoint: /oauth/token
	body := "grant_type=" + url.QueryEscape("client_credentials") +
		"&client_id=" + client.Id +
		"&client_secret=" + client.Secret +
		"&redirect_uri=" + url.QueryEscape("http://127.0.0.1:3333/callback")
	// add optional params if valid
	if client.Scope != nil || len(client.Scope) > 0 {
		body += "&scope=" + strings.Join(client.Scope, "+")
	}
	headers := httpx.Headers{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Bearer " + client.RegistrationAccessToken,
	}

	_, b, err := httpx.MakeHttpRequest(clientUrl, http.MethodPost, []byte(body), headers)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)

	}

	return b, err
}

func (client *Client) PerformRefreshTokenGrant(url string, refreshToken string) ([]byte, error) {
	body := httpx.Body("grant_type=refresh_token" +
		"&refresh_token=" + refreshToken +
		"&scope" + strings.Join(client.Scope, "+"))
	headers := httpx.Headers{}
	_, b, err := httpx.MakeHttpRequest(url, http.MethodPost, body, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)
	}
	return b, err
}

func (client *Client) DeleteOAuthClient(clientUrl string) error {
	_, _, err := httpx.MakeHttpRequest(clientUrl+"/"+client.Id, http.MethodDelete, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	return nil
}
