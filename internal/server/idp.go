package server

import (
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/davidallendj/go-utils/util"
	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

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

	// update endpoints that have values set
	defaultEps := oidc.Endpoints{
		Authorization: "http://" + s.Addr + "/oauth/authorize",
		Token:         "http://" + s.Addr + "/oauth/token",
		JwksUri:       "http://" + s.Addr + "/.well-known/jwks.json",
	}
	oidc.UpdateEndpoints(&s.Issuer.Endpoints, &defaultEps)

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

	r.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// create config JSON to serve with GET request
		config := map[string]any{
			"issuer":                 "http://" + s.Addr,
			"authorization_endpoint": s.Issuer.Endpoints.Authorization,
			"token_endpoint":         s.Issuer.Endpoints.Token,
			"jwks_uri":               s.Issuer.Endpoints.JwksUri,
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
