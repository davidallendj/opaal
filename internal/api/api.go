package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func WaitForAuthorizationCode(host string, port int) (string, error) {
	var code string
	s := &http.Server{
		Addr: fmt.Sprintf("%s:%d", host, port),
	}
	http.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		// get the code from the OIDC provider
		if r != nil {
			code = r.URL.Query().Get("code")
			fmt.Printf("Authorization Code: %v\n", code)
		}
		s.Close()

	})
	return code, s.ListenAndServe()
}

func FetchToken(code string, remoteUrl string, clientId string, clientSecret string, state string, redirectUri []string) (string, error) {
	var token string
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientId},
		"client_secret": {clientSecret},
		"state":         {state},
		"redirect_uri":  {strings.Join(redirectUri, ",")},
	}
	res, err := http.PostForm(remoteUrl, data)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %s", err)
	}
	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}
	token = string(b)

	fmt.Printf("%v\n", token)
	return token, nil
}

func CreateIdentity(remoteUrl string, idToken string) error {
	data := []byte(`{
		"schema_id": "preset://email",
		"traits": {
			"email": "docs@example.org"
		}
	}`)

	req, err := http.NewRequest("POST", remoteUrl, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create a new request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", idToken))
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %v", err)
	}
	fmt.Printf("%d\n", res.StatusCode)
	return nil
}

func FetchIdentities(remoteUrl string) error {
	req, err := http.NewRequest("GET", remoteUrl, bytes.NewBuffer([]byte{}))
	if err != nil {
		return fmt.Errorf("failed to create a new request: %v", err)
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %v", err)
	}
	fmt.Printf("%v\n", res)
	return nil
}
