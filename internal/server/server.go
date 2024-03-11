package server

import (
	"davidallendj/opaal/internal/flows"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

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

func (s *Server) SetListenAddr(host string, port int) {
	s.Addr = s.GetListenAddr()
}

func (s *Server) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *Server) Login(buttons string, provider *oidc.IdentityProvider, client *oauth.Client, eps flows.JwtBearerEndpoints, params flows.JwtBearerFlowParams) error {
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
	r.HandleFunc(s.Callback, func(w http.ResponseWriter, r *http.Request) {
		// get the code from the OIDC provider
		if r != nil {
			code = r.URL.Query().Get("code")
			fmt.Printf("Authorization code: %v\n", code)

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

			// extract scopes from ID token and add to trusted issuer

			// complete JWT bearer flow to receive access token from authorization server
			// fmt.Printf("bearer: %v\n", string(bearerToken))
			params.IdToken = data["id_token"].(string)
			accessToken, err = flows.NewJwtBearerFlow(eps, params)
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
		fmt.Printf("Serving success page.\n")
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
			fmt.Printf("Send access token to target: %s\n", target)
			_, _, err := httpx.MakeHttpRequest(target, http.MethodPost, []byte(accessToken), httpx.Headers{})
			if err != nil {
				fmt.Printf("failed to make request: %v", err)
			}
		}
	})
	r.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Serving error page.")
		errorPage, err := os.ReadFile("pages/error.html")
		if err != nil {
			fmt.Printf("failed to load error page: %v\n", err)
		}
		w.Write(errorPage)
	})
	s.Handler = r

	return s.ListenAndServe()
}

func (s *Server) Serve(data chan []byte) error {
	output, ok := <-data
	if !ok {
		return fmt.Errorf("failed to receive data")
	}

	fmt.Printf("Received data: %v\n", string(output))
	// http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {

	// })
	r := chi.NewRouter()

	s.Handler = r
	return s.ListenAndServe()
}
