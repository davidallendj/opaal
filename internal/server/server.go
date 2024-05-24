package server

import (
	"davidallendj/opaal/internal/flows"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/davidallendj/go-utils/httpx"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/exec"
)

type Server struct {
	*http.Server
	Host     string                 `yaml:"host"`
	Port     int                    `yaml:"port"`
	Callback string                 `yaml:"callback"`
	State    string                 `yaml:"state"`
	Issuer   IdentityProviderServer `yaml:"issuer"`
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
	fmt.Printf("Login with an identity provider: \n")
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
		fmt.Printf("\t%s: /login?sso=%s\n", client.Name, client.Id)
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
				if params.Verbose {
					fmt.Printf("Redirect URL: %s\n", url)
				}
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

		fetchAndMarshal := func() (err error) {
			err = p.FetchJwks()
			if err != nil {
				fmt.Printf("failed to fetch keys: %v\n", err)
				return
			}
			jwks, err = json.Marshal(p.KeySet)
			if err != nil {
				fmt.Printf("failed to marshal JWKS: %v\n", err)
			}
			return
		}

		// try and get the JWKS from param first
		if p.Endpoints.JwksUri != "" {
			if err := fetchAndMarshal(); err != nil {
				w.Write(jwks)
				return
			}
		}

		// otherwise or if fetching the JWKS failed, try and fetch the whole config first and try again
		if p.Endpoints.Config != "" {
			if err := p.FetchServerConfig(); err != nil {
				fmt.Printf("failed to fetch server config: %v\n", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			fmt.Printf("getting JWKS from param failed and endpoints config unavailable\n")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if err := fetchAndMarshal(); err != nil {
			fmt.Printf("failed to fetch and marshal JWKS after config update: %v\n", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		} else {
			// FIXME: I think this probably needs to reworked or removed
			// NOTE: this logic fetches a token for services to retrieve like BSS
			// perform a client credentials grant and return a token
			var err error
			accessToken, err = flows.NewClientCredentialsFlow(params.ClientCredentialsEndpoints, params.ClientCredentialsParams)
			if err != nil {
				fmt.Printf("failed to perform client credentials flow: %v\n", err)
				http.Redirect(w, r, "/error", http.StatusInternalServerError)
				return
			}
			w.Write([]byte(accessToken))
		}
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
