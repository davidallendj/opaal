package server

import (
	"davidallendj/oidc-auth/internal/util"
	"fmt"
	"net/http"
	"net/url"
	"os"
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
		"redirect_uri":  {util.EncodeURL(strings.Join(redirectUri, ","))},
	}
	res, err := http.PostForm(remoteUrl, data)
	if err != nil {
		fmt.Printf("failed to get token: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("request URL: %s\n", remoteUrl)
	fmt.Printf("token response: %v\n", res)
	return token, nil
}
