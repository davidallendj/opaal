package opaal

import (
	"bytes"
	"davidallendj/opaal/internal/oidc"
	"davidallendj/opaal/internal/util"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type Client struct {
	http.Client
	Id           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	RedirectUris []string `yaml:"redirect-uris"`
	FlowId       string
	CsrfToken    string
}

func NewClientWithConfig(config *Config) *Client {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &Client{
		Id:           config.Client.Id,
		Secret:       config.Client.Secret,
		RedirectUris: config.Client.RedirectUris,
		Client:       http.Client{Jar: jar},
	}
}

func (client *Client) IsFlowInitiated() bool {
	return client.FlowId != ""
}

func (client *Client) BuildAuthorizationUrl(authEndpoint string, state string, responseType string, scope []string) string {
	return authEndpoint + "?" + "client_id=" + client.Id +
		"&redirect_uri=" + util.URLEscape(strings.Join(client.RedirectUris, ",")) +
		"&response_type=" + responseType +
		"&state=" + state +
		"&scope=" + strings.Join(scope, "+")
}

func (client *Client) InitiateLoginFlow(loginUrl string) error {
	// kratos: GET /self-service/login/api
	req, err := http.NewRequest("GET", loginUrl, bytes.NewBuffer([]byte{}))
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %v", err)
	}
	defer res.Body.Close()

	// get the flow ID from response
	body, err := io.ReadAll(res.Body)

	var flowData map[string]any
	err = json.Unmarshal(body, &flowData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal flow data: %v\n%v", err, string(body))
	} else {
		client.FlowId = flowData["id"].(string)
	}
	return nil
}

func (client *Client) FetchFlowData(flowUrl string) (map[string]any, error) {
	//kratos: GET /self-service/login/flows?id={flowId}

	// replace {id} in string with actual value
	flowUrl = strings.ReplaceAll(flowUrl, "{id}", client.FlowId)
	req, err := http.NewRequest("GET", flowUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer res.Body.Close()

	// get the flow data from response
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var flowData map[string]any
	err = json.Unmarshal(body, &flowData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal flow data: %v", err)
	}
	return flowData, nil
}

func (client *Client) FetchCSRFToken(flowUrl string) error {
	data, err := client.FetchFlowData(flowUrl)
	if err != nil {
		return fmt.Errorf("failed to fetch flow data: %v", err)
	}

	// iterate through nodes and extract the CSRF token attribute from the flow data
	ui := data["ui"].(map[string]any)
	nodes := ui["nodes"].([]any)
	for _, node := range nodes {
		attrs := node.(map[string]any)["attributes"].(map[string]any)
		name := attrs["name"].(string)
		if name == "csrf_token" {
			client.CsrfToken = attrs["value"].(string)
			return nil
		}
	}
	return fmt.Errorf("failed to extract CSRF token: not found")
}

func (client *Client) FetchTokenFromAuthenticationServer(code string, remoteUrl string, state string) ([]byte, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {client.Id},
		"client_secret": {client.Secret},
		"state":         {state},
		"redirect_uri":  {strings.Join(client.RedirectUris, ",")},
	}
	res, err := http.PostForm(remoteUrl, data)
	if err != nil {
		return nil, fmt.Errorf("failed to get ID token: %s", err)
	}
	defer res.Body.Close()

	domain, _ := url.Parse("http://127.0.0.1")
	client.Jar.SetCookies(domain, res.Cookies())

	return io.ReadAll(res.Body)
}

func (client *Client) FetchTokenFromAuthorizationServer(remoteUrl string, jwt string, scope []string) ([]byte, error) {
	// hydra endpoint: /oauth/token
	data := "grant_type=" + util.URLEscape("urn:ietf:params:oauth:grant-type:jwt-bearer") +
		"&client_id=" + client.Id +
		"&client_secret=" + client.Secret +
		"&scope=" + strings.Join(scope, "+") +
		"&assertion=" + jwt
	fmt.Printf("encoded params: %v\n\n", data)
	req, err := http.NewRequest("POST", remoteUrl, bytes.NewBuffer([]byte(data)))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %s", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer res.Body.Close()

	// set flow ID back to empty string to indicate a completed flow
	client.FlowId = ""

	return io.ReadAll(res.Body)
}

func (client *Client) AddTrustedIssuer(remoteUrl string, idp *oidc.IdentityProvider, subject string, duration time.Duration, scope []string) ([]byte, error) {
	// hydra endpoint: POST /admin/trust/grants/jwt-bearer/issuers
	if idp == nil {
		return nil, fmt.Errorf("identity provided is nil")
	}
	jwkstr, err := json.Marshal(idp.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %v", err)
	}
	quotedScopes := make([]string, len(scope))
	for i, s := range scope {
		quotedScopes[i] = fmt.Sprintf("\"%s\"", s)
	}
	// NOTE: Can also include "jwks_uri" instead
	data := []byte(fmt.Sprintf(`{
		"allow_any_subject": false,
		"issuer": "%s",
		"subject": "%s",
		"expires_at": "%v",
		"jwk": %v,
		"scope": [ %s ]
	}`, idp.Issuer, subject, time.Now().Add(duration).Format(time.RFC3339), string(jwkstr), strings.Join(quotedScopes, ",")))
	fmt.Printf("%v\n", string(data))

	req, err := http.NewRequest("POST", remoteUrl, bytes.NewBuffer(data))
	// req.Header.Add("X-CSRF-Token", client.CsrfToken.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	// req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", idToken))
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer res.Body.Close()

	return io.ReadAll(res.Body)
}

func (client *Client) RegisterOAuthClient(registerUrl string) ([]byte, error) {
	// hydra endpoint: POST /clients
	data := []byte(fmt.Sprintf(`{
		"client_name":                "%s",
		"client_secret":              "%s",
		"token_endpoint_auth_method": "client_secret_post",
		"scope":                      "openid email profile",
		"grant_types":                ["client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
		"response_types":             ["token"]
	}`, client.Id, client.Secret))

	req, err := http.NewRequest("POST", registerUrl, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	// req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", idToken))
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer res.Body.Close()

	return io.ReadAll(res.Body)
}

func (client *Client) CreateIdentity(remoteUrl string, idToken string) ([]byte, error) {
	// kratos endpoint: /admin/identities
	data := []byte(`{
		"schema_id": "preset://email",
		"traits": {
			"email": "docs@example.org"
		}
	}`)

	req, err := http.NewRequest("POST", remoteUrl, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create a new request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", idToken))
	// req.Header.Add("X-CSRF-Token", client.CsrfToken.Value)
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}

	return io.ReadAll(res.Body)
}

func (client *Client) FetchIdentities(remoteUrl string) ([]byte, error) {
	req, err := http.NewRequest("GET", remoteUrl, bytes.NewBuffer([]byte{}))
	if err != nil {
		return nil, fmt.Errorf("failed to create a new request: %v", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}

	return io.ReadAll(res.Body)
}

func (client *Client) ClearCookies() {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client.Jar = jar
}
