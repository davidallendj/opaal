package opaal

import (
	"bytes"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"davidallendj/opaal/internal/util"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Server struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type ActionUrls struct {
	Identities     string `yaml:"identities"`
	TrustedIssuers string `yaml:"trusted-issuers"`
	AccessToken    string `yaml:"access-token"`
	ServerConfig   string `yaml:"server-config"`
	JwksUri        string `yaml:"jwks_uri"`
}

func Login(config *Config) error {
	if config == nil {
		return fmt.Errorf("config is not valid")
	}
	// try and fetch server configuration if provided URL
	idp := oidc.NewIdentityProvider()
	if config.ActionUrls.ServerConfig != "" {
		fmt.Printf("Fetching server configuration: %s\n", config.ActionUrls.ServerConfig)
		err := idp.FetchServerConfig(config.ActionUrls.ServerConfig)
		if err != nil {
			return fmt.Errorf("failed to fetch server config: %v", err)
		}
	} else {
		// otherwise, use what's provided in config file
		idp.Issuer = config.IdentityProvider.Issuer
		idp.Endpoints = config.IdentityProvider.Endpoints
		idp.Supported = config.IdentityProvider.Supported
	}

	// check if all appropriate parameters are set in config
	if !hasRequiredParams(config) {
		return fmt.Errorf("client ID must be set")
	}

	// build the authorization URL to redirect user for social sign-in
	var authorizationUrl = util.BuildAuthorizationUrl(
		idp.Endpoints.Authorization,
		config.Client.Id,
		config.Client.RedirectUris,
		config.State,
		config.ResponseType,
		config.Scope,
	)

	// print the authorization URL for sharing
	serverAddr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	fmt.Printf("Login with identity provider:\n\n  %s/login\n  %s\n\n",
		serverAddr, authorizationUrl,
	)

	// automatically open browser to initiate login flow (only useful for testing)
	if config.OpenBrowser {
		util.OpenUrl(authorizationUrl)
	}

	// authorize oauth client and listen for callback from provider
	fmt.Printf("Waiting for authorization code redirect @%s/oidc/callback...\n", serverAddr)
	code, err := WaitForAuthorizationCode(serverAddr, authorizationUrl)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("Server closed.\n")
	} else if err != nil {
		return fmt.Errorf("failed to start server: %s", err)
	}

	// use code from response and exchange for bearer token (with ID token)
	tokenString, err := FetchIssuerToken(
		code,
		idp.Endpoints.Token,
		config.Client,
		config.State,
	)
	if err != nil {
		return fmt.Errorf("failed to fetch token from issuer: %v", err)
	}

	// unmarshal data to get id_token and access_token
	var data map[string]any
	err = json.Unmarshal([]byte(tokenString), &data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal token: %v", err)
	}

	// extract ID token from bearer as JSON string for easy consumption
	idToken := data["id_token"].(string)
	idJwtSegments, err := util.DecodeJwt(idToken)
	if err != nil {
		fmt.Printf("failed to parse ID token: %v\n", err)
	} else {
		if config.DecodeIdToken {
			if err != nil {
				fmt.Printf("failed to decode JWT: %v\n", err)
			} else {
				fmt.Printf("id_token.header: %s\nid_token.payload: %s\n", string(idJwtSegments[0]), string(idJwtSegments[1]))
			}
		}
	}

	// extract the access token to get the scopes
	// accessToken := data["access_token"].(string)
	// accessJwtSegments, err := util.DecodeJwt(accessToken)
	// if err != nil || len(accessJwtSegments) <=  {
	// 	fmt.Printf("failed to parse access token: %v\n", err)
	// } else {
	// 	if config.DecodeIdToken {
	// 		if err != nil {
	// 			fmt.Printf("failed to decode JWT: %v\n", err)
	// 		} else {
	// 			fmt.Printf("access_token.header: %s\naccess_token.payload: %s\n", string(accessJwtSegments[0]), string(accessJwtSegments[1]))
	// 		}
	// 	}
	// }

	// create a new identity with identity and session manager if url is provided
	if config.ActionUrls.Identities != "" {
		CreateIdentity(config.ActionUrls.Identities, idToken)
		FetchIdentities(config.ActionUrls.Identities)
	}

	// extract the subject from ID token claims
	var subject string
	var idJsonPayload map[string]any
	var idJwtPayload []byte = idJwtSegments[1]
	if idJwtPayload != nil {
		err := json.Unmarshal(idJwtPayload, &idJsonPayload)
		if err != nil {
			return fmt.Errorf("failed to unmarshal JWT: %v", err)
		}
		subject = idJsonPayload["sub"].(string)
	} else {
		return fmt.Errorf("failed to extract subject from ID token claims")
	}

	// extract the scope from access token claims
	// var scope []string
	// var accessJsonPayload map[string]any
	// var accessJwtPayload []byte = accessJwtSegments[1]
	// if accessJsonPayload != nil {
	// 	err := json.Unmarshal(accessJwtPayload, &accessJsonPayload)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to unmarshal JWT: %v", err)
	// 	}
	// 	scope = idJsonPayload["scope"].([]string)
	// }

	// fetch JWKS and add issuer to authentication server to submit ID token
	fmt.Printf("Fetching JWKS for verification...\n")
	err = idp.FetchJwk(config.ActionUrls.JwksUri)
	if err != nil {
		fmt.Printf("failed to fetch JWK: %v\n", err)
	} else {
		fmt.Printf("Attempting to add issuer to authorization server...\n")
		err = AddTrustedIssuer(config.ActionUrls.TrustedIssuers, *idp, subject, time.Duration(1000), config.Scope)
		if err != nil {
			return fmt.Errorf("failed to add trusted issuer: %v", err)
		}
	}

	// use ID token/user info to fetch access token from authentication server
	if config.ActionUrls.AccessToken != "" {
		fmt.Printf("Fetching access token from authorization server...")
		accessToken, err := FetchAccessToken(config.ActionUrls.AccessToken, config.Client.Id, idToken, config.Scope)
		if err != nil {
			return fmt.Errorf("failed to fetch access token: %v", err)
		}
		fmt.Printf("%s\n", accessToken)
	}

	fmt.Printf("Success!")
	return nil
}

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

func AddTrustedIssuer(remoteUrl string, idp oidc.IdentityProvider, subject string, duration time.Duration, scope []string) error {
	// hydra endpoint: /admin/trust/grants/jwt-bearer/issuers
	jwkstr, err := json.Marshal(idp.Key)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %v", err)
	}
	data := []byte(fmt.Sprintf(`{
		"allow_any_subject": false,
		"issuer": "%s",
		"subject": "%s"
		"expires_at": "%v"
		"jwk": %v,
		"scope": [ j%s ],
	}`, idp.Issuer, subject, time.Now().Add(duration), string(jwkstr), strings.Join(scope, ",")))

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

func hasRequiredParams(config *Config) bool {
	return config.Client.Id != "" && config.Client.Secret != ""
}
