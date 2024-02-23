package api

import (
	"bytes"
	"davidallendj/opal/internal/oauth"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func WaitForAuthorizationCode(serverAddr string, loginUrl string) (string, error) {
	var code string
	s := &http.Server{Addr: serverAddr}
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// redirect directly to identity provider with this endpoint
		http.Redirect(w, r, loginUrl, http.StatusSeeOther)
	})
	http.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		// get the code from the OIDC provider
		if r != nil {
			code = r.URL.Query().Get("code")
			fmt.Printf("Authorization code: %v\n", code)
		}
		s.Close()
	})
	return code, s.ListenAndServe()
}

func FetchIssuerToken(code string, remoteUrl string, client oauth.Client, state string) (string, error) {
	var token string
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
		return "", fmt.Errorf("failed to get ID token: %s", err)
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

func FetchAccessToken(remoteUrl string, clientId string, jwt string, scopes []string) (string, error) {
	// hydra endpoint: /oauth/token
	var token string
	data := url.Values{
		"grant_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"assertion":  {jwt},
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

func AddTrustedIssuer(remoteUrl string, issuer string, subject string, duration time.Duration, jwk string, scope []string) error {
	// hydra endpoint: /admin/trust/grants/jwt-bearer/issuers
	data := []byte(fmt.Sprintf(`{
		"allow_any_subject": false,
		"issuer": "%s",
		"subject": "%s"
		"expires_at": "%v"
		"jwk": %v,
		"scope": [ j%s ],
	}`, issuer, subject, time.Now().Add(duration), jwk, strings.Join(scope, ",")))

	req, err := http.NewRequest("POST", remoteUrl, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create a new request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	// req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", idToken))
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %v", err)
	}
	fmt.Printf("%d\n", res.StatusCode)
	return nil
}

func CreateIdentity(remoteUrl string, idToken string) error {
	// kratos endpoint: /admin/identities
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

func RedirectSuccess() {
	// show a success page with the user's access token
}
