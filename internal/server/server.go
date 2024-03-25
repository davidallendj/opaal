package server

import (
	"davidallendj/opaal/internal/flows"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/davidallendj/go-utils/httpx"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/exec"
)

type Server struct {
	*http.Server
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Callback string `yaml:"callback"`
	State    string `yaml:"state"`
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

func (s *Server) Start(buttons string, provider *oidc.IdentityProvider, client *oauth.Client, params ServerParams) error {
	var target = ""

	// check if callback is set
	if s.Callback == "" {
		s.Callback = "/oidc/callback"
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
			_, err := params.JwtBearerParams.Client.PerformRefreshTokenGrant(provider.Endpoints.Token, refreshToken)
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
	r.HandleFunc(s.Callback, func(w http.ResponseWriter, r *http.Request) {
		// get the code from the OIDC provider
		if r != nil {
			code = r.URL.Query().Get("code")
			if params.Verbose {
				fmt.Printf("Authorization code: %v\n", code)
			}

			// use code from response and exchange for bearer token (with ID token)
			bearerToken, err := client.FetchTokenFromAuthenticationServer(
				code,
				provider.Endpoints.Token,
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
