package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/davidallendj/go-utils/httpx"
)

func (client *Client) IsFlowInitiated() bool {
	return client.FlowId != ""
}

func (client *Client) BuildAuthorizationUrl(issuer string, state string) string {
	return issuer + "?" + "client_id=" + client.Id +
		"&redirect_uri=" + url.QueryEscape(strings.Join(client.RedirectUris, ",")) +
		"&response_type=code" + // this has to be set to "code"
		"&state=" + state +
		"&scope=" + strings.Join(client.Scope, "+") +
		"&resource=" + url.QueryEscape("http://127.0.0.1:4444/oauth2/token")
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
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	var flowData map[string]any
	err = json.Unmarshal(body, &flowData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal flow data: %v\n%v", err, string(body))
	} else {
		client.FlowId = flowData["id"].(string)
	}
	return nil
}

func (client *Client) FetchFlowData(url string) (map[string]any, error) {
	//kratos: GET /self-service/login/flows?id={flowId}

	// replace {id} in string with actual value
	url = strings.ReplaceAll(url, "{id}", client.FlowId)
	_, b, err := httpx.MakeHttpRequest(url, http.MethodGet, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	var flowData map[string]any
	err = json.Unmarshal(b, &flowData)
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
	body := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.Id},
		"client_secret": {client.Secret},
		"redirect_uri":  {strings.Join(client.RedirectUris, ",")},
	}
	// add optional params if valid
	if code != "" {
		body["code"] = []string{code}
	}
	if state != "" {
		body["state"] = []string{state}
	}
	res, err := http.PostForm(remoteUrl, body)
	if err != nil {
		return nil, fmt.Errorf("failed to get ID token: %s", err)
	}
	defer res.Body.Close()

	// domain, _ := url.Parse("http://127.0.0.1")
	// client.Jar.SetCookies(domain, res.Cookies())

	return io.ReadAll(res.Body)
}
