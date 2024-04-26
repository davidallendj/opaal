package server

import (
	"crypto/rand"
	"crypto/rsa"
	"davidallendj/opaal/internal/flows"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/davidallendj/go-utils/cryptox"
	"github.com/davidallendj/go-utils/httpx"
	"github.com/davidallendj/go-utils/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/exec"
)

type Server struct {
	*http.Server
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Callback string `yaml:"callback"`
	State    string `yaml:"state"`
	Issuer   Issuer `yaml:"issuer"`
}

type Issuer struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type ServerParams struct {
	AuthProvider               *oidc.IdentityProvider
	Verbose                    bool
	ClientCredentialsEndpoints flows.ClientCredentialsFlowEndpoints
	ClientCredentialsParams    flows.ClientCredentialsFlowParams
	JwtBearerEndpoints         flows.JwtBearerFlowEndpoints
	JwtBearerParams            flows.JwtBearerFlowParams
}

func (s *Server) SetListenAddr(host string, port int) {
	s.Addr = s.GetListenAddr()
}

func (s *Server) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *Server) StartLogin(clients []oauth.Client, params ServerParams) error {
	var (
		target   string
		callback string
		client   *oauth.Client
		sso      string
	)

	// check if callback is set
	if s.Callback == "" {
		callback = "/oidc/callback"
	}

	// make the login page SSO buttons and authorization URLs to write to stdout
	buttons := ""
	fmt.Printf("Login with external identity providers: \n")
	for i, client := range clients {
		// fetch provider configuration before adding button
		p, err := oidc.FetchServerConfig(client.Provider.Issuer)
		if err != nil {
			fmt.Printf("failed to fetch server config: %v\n", err)
			continue
		}

		// if we're able to get the config, go ahead and try to fetch jwks too
		if err = p.FetchJwks(); err != nil {
			fmt.Printf("failed to fetch JWKS: %v\n", err)
			continue
		}

		clients[i].Provider = *p
		buttons += makeButton(fmt.Sprintf("/login?sso=%s", client.Id), client.Name)
		url := client.BuildAuthorizationUrl(s.State)
		fmt.Printf("\t%s\n", url)
	}

	var code string
	var accessToken string
	r := chi.NewRouter()
	r.Use(middleware.RedirectSlashes)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		target = r.Header.Get("target")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	r.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data := map[string]any{
			"code":    200,
			"message": "OPAAL is healthy",
		}
		err := json.NewEncoder(w).Encode(data)
		if err != nil {
			fmt.Printf("failed to encode JSON: %v\n", err)
			return
		}
	})
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// add target if query exists
		if r != nil {
			target = r.URL.Query().Get("target")
			sso = r.URL.Query().Get("sso")

			// TODO: get client from list and build the authorization URL string
			index := slices.IndexFunc(clients, func(c oauth.Client) bool {
				return c.Id == sso
			})

			// TODO: redirect the user to authorization URL and return from func
			foundClient := index >= 0
			if foundClient {
				client = &clients[index]

				url := client.BuildAuthorizationUrl(s.State)
				fmt.Printf("Redirect URL: %s\n", url)
				http.Redirect(w, r, url, http.StatusFound)
				return
			}
		}

		// show login page with notice to redirect
		template, err := gonja.FromFile("pages/index.html")
		if err != nil {
			panic(err)
		}

		data := exec.NewContext(map[string]interface{}{
			"loginButtons": buttons,
		})

		if err = template.Execute(w, data); err != nil { // Prints: Hello Bob!
			panic(err)
		}
	})
	r.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		var (
			p    = params.AuthProvider
			jwks []byte
		)
		// try and get the JWKS from param first
		if p.Endpoints.JwksUri != "" {
			err := p.FetchJwks()
			if err != nil {
				fmt.Printf("failed to fetch keys using JWKS url...trying to fetch config and try again...\n")
			}
			jwks, err = json.Marshal(p.KeySet)
			if err != nil {
				fmt.Printf("failed to marshal JWKS: %v\n", err)
			}
		} else if p.Endpoints.Config != "" && jwks == nil {
			// otherwise, try and fetch the whole config and try again
			err := p.FetchServerConfig()
			if err != nil {
				fmt.Printf("failed to fetch server config: %v\n", err)
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}
			err = p.FetchJwks()
			if err != nil {
				fmt.Printf("failed to fetch JWKS after fetching server config: %v\n", err)
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}
		}

		// forward the JWKS from the authorization server
		if jwks == nil {
			fmt.Printf("no JWKS was fetched from authorization server\n")
			http.Redirect(w, r, "/error", http.StatusInternalServerError)
			return
		}
		w.Write(jwks)
	})
	r.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// use refresh token provided to do a refresh token grant
		refreshToken := r.URL.Query().Get("refresh-token")
		if refreshToken != "" {
			_, err := params.JwtBearerParams.Client.PerformRefreshTokenGrant(client.Provider.Endpoints.Token, refreshToken)
			if err != nil {
				fmt.Printf("failed to perform refresh token grant: %v\n", err)
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}

			// return token to target if set or the sending client
			returnTarget := r.URL.Query().Get("target")
			if returnTarget == "" {
				returnTarget = r.URL.Host
			}
			_, _, err = httpx.MakeHttpRequest(returnTarget, http.MethodPost, httpx.Body{}, httpx.Headers{})
			if err != nil {
				fmt.Printf("failed to make request")
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}
		}
		// FIXME: I think this probably needs to reworked or removed
		// else {
		// 	// perform a client credentials grant and return a token
		// 	var err error
		// 	accessToken, err = flows.NewClientCredentialsFlow(params.ClientCredentialsEndpoints, params.ClientCredentialsParams)
		// 	if err != nil {
		// 		fmt.Printf("failed to perform client credentials flow: %v\n", err)
		// 		http.Redirect(w, r, "/error", http.StatusInternalServerError)
		// 		return
		// 	}
		// 	w.Write([]byte(accessToken))
		// }
	})
	r.HandleFunc(callback, func(w http.ResponseWriter, r *http.Request) {
		// get the code from the OIDC provider
		if r != nil {
			code = r.URL.Query().Get("code")
			if params.Verbose {
				fmt.Printf("Authorization code: %v\n", code)
			}

			// make sure we have the correct client to use
			if client == nil {
				fmt.Printf("failed to find valid client")
				return
			}

			// use code from response and exchange for bearer token (with ID token)
			bearerToken, err := client.FetchTokenFromAuthenticationServer(
				code,
				s.State,
			)
			if err != nil {
				fmt.Printf("failed to fetch token from authentication server: %v\n", err)
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}

			// extract ID and access tokens from bearer
			var data map[string]any
			err = json.Unmarshal([]byte(bearerToken), &data)
			if err != nil {
				fmt.Printf("failed to unmarshal token: %v\n", err)
				return
			}
			if data["error"] != nil {
				fmt.Printf("the response from the authentication server returned an error (%v): %v", data["error"], data["error_description"])
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}
			if data["id_token"] == nil {
				fmt.Printf("no ID token found\n")
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}

			// complete JWT bearer flow to receive access token from authorization server
			// fmt.Printf("bearer: %v\n", string(bearerToken))
			params.JwtBearerParams.IdToken = data["id_token"].(string)
			params.JwtBearerParams.Client = client
			accessToken, err = flows.NewJwtBearerFlow(params.JwtBearerEndpoints, params.JwtBearerParams)
			if err != nil {
				fmt.Printf("failed to complete JWT bearer flow: %v\n", err)
				w.Header().Add("Content-type", "text/html")
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/success", http.StatusSeeOther)
	})
	r.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
		if params.Verbose {
			fmt.Printf("Serving success page.\n")
		}

		// return only the token with no web page if "no-browser" header is set
		noBrowser := r.Header.Get("no-browser")
		if noBrowser != "" {
			return
		}

		template, err := gonja.FromFile("pages/success.html")
		if err != nil {
			panic(err)
		}

		data := exec.NewContext(map[string]interface{}{
			"accessToken": accessToken,
		})

		if err = template.Execute(w, data); err != nil { // Prints: Hello Bob!
			panic(err)
		}
		// try and send access code to target if set
		if target != "" {
			if params.Verbose {
				fmt.Printf("Sending access token to target: %s\n", target)
			}
			_, _, err := httpx.MakeHttpRequest(target, http.MethodPost, nil, httpx.Headers{"access_token": accessToken})
			if err != nil {
				fmt.Printf("failed to make request: %v", err)
			}
		}
	})
	r.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		if params.Verbose {
			fmt.Printf("Serving error page.")
		}
		template, err := gonja.FromFile("pages/error.html")
		if err != nil {
			panic(err)
		}

		data := exec.NewContext(map[string]interface{}{
			"index": fmt.Sprintf("<a href=\"%s\">try logging in again?</a>", s.Addr),
		})
		if err = template.Execute(w, data); err != nil { // Prints: Hello Bob!
			panic(err)
		}
	})
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("./pages/static"))))
	s.Handler = r
	return s.ListenAndServe()
}

func (s *Server) StartIdentityProvider() error {
	// NOTE: this example does NOT implement CSRF tokens nor use them

	// create an example identity provider
	var (
		r = chi.NewRouter()
		// clients  = []oauth.Client{}
		callback    = ""
		activeCodes = []string{}
	)

	// check if callback is set
	if s.Callback == "" {
		callback = "/oidc/callback"
	}

	// generate key pair used to sign JWKS and create JWTs
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate new RSA key: %v", err)
	}
	privateJwk, publicJwk, err := cryptox.GenerateJwkKeyPairFromPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to generate JWK pair from private key: %v", err)
	}
	kid, _ := privateJwk.Get("kid")
	publicJwk.Set("kid", kid)
	publicJwk.Set("use", "sig")
	publicJwk.Set("kty", "RSA")
	publicJwk.Set("alg", "RS256")
	if err := publicJwk.Validate(); err != nil {
		return fmt.Errorf("failed to validate public JWK: %v", err)
	}

	// TODO: create .well-known JWKS endpoint with json
	r.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		// TODO: generate new JWKs from a private key

		jwks := map[string]any{
			"keys": []jwk.Key{
				publicJwk,
			},
		}
		b, err := json.Marshal(jwks)
		if err != nil {
			return
		}
		w.Write(b)
	})

	// TODO: create .well-known openid configuration
	r.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// create config JSON to serve with GET request
		config := map[string]any{
			"issuer":                 "http://" + s.Addr,
			"authorization_endpoint": "http://" + s.Addr + "/oauth/authorize",
			"token_endpoint":         "http://" + s.Addr + "/oauth/token",
			"jwks_uri":               "http://" + s.Addr + "/.well-known/jwks.json",
			"scopes_supported": []string{
				"openid",
				"profile",
				"email",
			},
			"response_types_supported": []string{
				"code",
			},
			"grant_types_supported": []string{
				"authorization_code",
			},
			"id_token_signing_alg_values_supported": []string{
				"RS256",
			},
			"claims_supported": []string{
				"iss",
				"sub",
				"aud",
				"exp",
				"iat",
				"name",
				"email",
			},
		}

		b, err := json.Marshal(config)
		if err != nil {
			return
		}
		w.Write(b)
	})
	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		// serve up a simple login page
	})
	r.HandleFunc("/consent", func(w http.ResponseWriter, r *http.Request) {
		// give consent for app to use
	})
	r.HandleFunc("/browser/login", func(w http.ResponseWriter, r *http.Request) {
		// serve up a login page for user creds
		form, err := os.ReadFile("pages/login.html")
		if err != nil {
			fmt.Printf("failed to load login form: %v", err)
		}
		w.Write(form)
	})
	r.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		// check for example identity with POST request
		r.ParseForm()
		username := r.Form.Get("username")
		password := r.Form.Get("password")

		// example username and password so do simplified authorization code flow
		if username == "ochami" && password == "ochami" {
			client := oauth.Client{
				Id:     "ochami",
				Secret: "ochami",
				Name:   "ochami",
				Provider: oidc.IdentityProvider{
					Issuer: "http://127.0.0.1:3333",
				},
				RedirectUris: []string{fmt.Sprintf("http://%s:%d%s", s.Host, s.Port, callback)},
			}

			// check if there are any redirect URIs supplied
			if len(client.RedirectUris) <= 0 {
				fmt.Printf("no redirect URIs found")
				return
			}
			for _, url := range client.RedirectUris {
				// send an authorization code to each URI
				code := util.RandomString(64)
				activeCodes = append(activeCodes, code)
				redirectUrl := fmt.Sprintf("%s?code=%s", url, code)
				fmt.Printf("redirect URL: %s\n", redirectUrl)
				http.Redirect(w, r, redirectUrl, http.StatusFound)
				// _, _, err := httpx.MakeHttpRequest(fmt.Sprintf("%s?code=%s", url, code), http.MethodGet, nil, nil)
				// if err != nil {
				// 	fmt.Printf("failed to make request: %v\n", err)
				// 	continue
				// }
			}
		} else {
			w.Write([]byte("error logging in"))
			http.Redirect(w, r, "/browser/login", http.StatusUnauthorized)
		}
	})
	r.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		// check for authorization code and make sure it's valid
		var code = r.Form.Get("code")
		index := slices.IndexFunc(activeCodes, func(s string) bool { return s == code })
		if index < 0 {
			fmt.Printf("invalid authorization code: %s\n", code)
			return
		}

		// now create and return a JWT that can be verified with by authorization server
		iat := time.Now().Unix()
		exp := time.Now().Add(time.Second * 3600 * 16).Unix()
		t := jwt.New()
		t.Set(jwt.IssuerKey, s.Addr)
		t.Set(jwt.SubjectKey, "ochami")
		t.Set(jwt.AudienceKey, "ochami")
		t.Set(jwt.IssuedAtKey, iat)
		t.Set(jwt.ExpirationKey, exp)
		t.Set("name", "ochami")
		t.Set("email", "example@ochami.org")
		t.Set("email_verified", true)
		t.Set("scope", []string{
			"openid",
			"profile",
			"email",
			"example",
		})
		// payload := map[string]any{}
		// payload["iss"] = s.Addr
		// payload["aud"] = "ochami"
		// payload["iat"] = iat
		// payload["nbf"] = iat
		// payload["exp"] = exp
		// payload["sub"] = "ochami"
		// payload["name"] = "ochami"
		// payload["email"] = "example@ochami.org"
		// payload["email_verified"] = true
		// payload["scope"] = []string{
		// 	"openid",
		// 	"profile",
		// 	"email",
		// 	"example",
		// }
		payloadJson, err := json.MarshalIndent(t, "", "\t")
		if err != nil {
			fmt.Printf("failed to marshal payload: %v", err)
			return
		}
		signed, err := jws.Sign(payloadJson, jws.WithKey(jwa.RS256, privateJwk))
		if err != nil {
			fmt.Printf("failed to sign token: %v\n", err)
			return
		}

		// construct the bearer token with required fields
		scope, _ := t.Get("scope")
		bearer := map[string]any{
			"token_type": "Bearer",
			"id_token":   string(signed),
			"expires_in": exp,
			"created_at": iat,
			"scope":      strings.Join(scope.([]string), " "),
		}

		b, err := json.MarshalIndent(bearer, "", "\t")
		if err != nil {
			fmt.Printf("failed to marshal bearer token: %v\n", err)
			return
		}
		fmt.Printf("bearer: %s\n", string(b))
		w.Write(b)
	})
	r.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		var (
			responseType = r.URL.Query().Get("response_type")
			clientId     = r.URL.Query().Get("client_id")
			redirectUris = r.URL.Query().Get("redirect_uri")
		)

		// check for required authorization code params
		if responseType != "code" {
			fmt.Printf("invalid response type\n")
			return
		}

		// check that we're using the default registered client
		if clientId != "ochami" {
			fmt.Printf("invalid client\n")
			return
		}

		// TODO: check that our redirect URIs all match
		for _, uri := range redirectUris {
			_ = uri
		}

		// redirect to browser login since we don't do session management here
		http.Redirect(w, r, "/browser/login", http.StatusFound)
	})

	s.Handler = r
	return s.ListenAndServe()
}

func makeButton(url string, text string) string {
	// check if we have http:// a
	// html := "<input type=\"button\" "
	// html += fmt.Sprintf("onclick=\"window.location.href='%s';\" ", url)
	// html += fmt.Sprintf("value=\"%s\">", text)
	html := "<a "
	html += "class=\"button\" "
	html += fmt.Sprintf("href=\"%s\">%s", url, text)
	html += "</a>"
	return html
}
