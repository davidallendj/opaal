package opaal

import (
	"bytes"
	"davidallendj/opaal/internal/oidc"
	"davidallendj/opaal/internal/util"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type Server struct {
	http.Server
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Client struct {
	http.Client
	Id           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	RedirectUris []string `yaml:"redirect-uris"`
}

type ActionUrls struct {
	Identities     string `yaml:"identities"`
	TrustedIssuers string `yaml:"trusted-issuers"`
	AccessToken    string `yaml:"access-token"`
	ServerConfig   string `yaml:"server-config"`
	JwksUri        string `yaml:"jwks_uri"`
}

func NewServerWithConfig(config *Config) *Server {
	host := config.Server.Host
	port := config.Server.Port
	server := &Server{
		Host: host,
		Port: port,
	}
	server.Addr = fmt.Sprintf("%s:%d", host, port)
	return server
}

func NewClientWithConfig(config *Config) *Client {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &Client{
		Id:           config.Client.Id,
		Secret:       config.Client.Secret,
		RedirectUris: config.Client.RedirectUris,
		Client:       http.Client{Jar: jar},
	}
}

func (s *Server) SetListenAddr(host string, port int) {
	s.Host = host
	s.Port = port
	s.Addr = s.GetListenAddr()
}

func (s *Server) GetListenAddr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *Server) WaitForAuthorizationCode(loginUrl string) (string, error) {
	var code string
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// show login page with notice to redirect
		loginPage, err := os.ReadFile("pages/index.html")
		if err != nil {
			fmt.Printf("failed to load login page: %v\n", err)
		}
		loginPage = []byte(strings.ReplaceAll(string(loginPage), "{{loginUrl}}", loginUrl))
		w.WriteHeader(http.StatusSeeOther)
		w.Write(loginPage)
	})
	http.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		// get the code from the OIDC provider
		if r != nil {
			code = r.URL.Query().Get("code")
			fmt.Printf("Authorization code: %v\n", code)
		}
		http.Redirect(w, r, s.Addr+"/success", http.StatusSeeOther)
		s.Close()
	})
	return code, s.ListenAndServe()
}

func (s *Server) ShowSuccessPage() error {
	http.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {

	})
	return s.ListenAndServe()
}

func (client *Client) BuildAuthorizationUrl(authEndpoint string, state string, responseType string, scope []string) string {
	return authEndpoint + "?" + "client_id=" + client.Id +
		"&redirect_uri=" + util.URLEscape(strings.Join(client.RedirectUris, ",")) +
		"&response_type=" + responseType +
		"&state=" + state +
		"&scope=" + strings.Join(scope, "+")
}

func (client *Client) FetchTokenFromAuthenticationServer(code string, remoteUrl string, state string) ([]byte, error) {
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
		return nil, fmt.Errorf("failed to get ID token: %s", err)
	}
	defer res.Body.Close()

	return io.ReadAll(res.Body)
}

func (client *Client) FetchTokenFromAuthorizationServer(remoteUrl string, jwt string, scope []string) ([]byte, error) {
	// hydra endpoint: /oauth/token
	data := "grant_type=" + util.URLEscape("urn:ietf:params:oauth:grant-type:jwt-bearer") +
		"&assertion=" + jwt +
		"&scope=" + strings.Join(scope, "+")
	fmt.Printf("encoded params: %v\n\n", data)
	req, err := http.NewRequest("POST", remoteUrl, bytes.NewBuffer([]byte(data)))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %s", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer res.Body.Close()

	return io.ReadAll(res.Body)
}

func (client *Client) AddTrustedIssuer(remoteUrl string, idp *oidc.IdentityProvider, subject string, duration time.Duration, scope []string) ([]byte, error) {
	// hydra endpoint: /admin/trust/grants/jwt-bearer/issuers
	if idp == nil {
		return nil, fmt.Errorf("identity provided is nil")
	}
	jwkstr, err := json.Marshal(idp.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %v", err)
	}
	data := []byte(fmt.Sprintf(`{
		"allow_any_subject": true,
		"issuer": "%s",
		"subject": "%s"
		"expires_at": "%v"
		"jwk": %v,
		"scope": [ %s ],
	}`, idp.Issuer, subject, time.Now().Add(duration), string(jwkstr), strings.Join(scope, ",")))

	req, err := http.NewRequest("POST", remoteUrl, bytes.NewBuffer(data))
	// req.Header.Add("X-CSRF-Token", client.CsrfToken.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	// req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", idToken))
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer res.Body.Close()

	return io.ReadAll(res.Body)
}

func (client *Client) CreateIdentity(remoteUrl string, idToken string) ([]byte, error) {
	// kratos endpoint: /admin/identities
	data := []byte(`{
		"schema_id": "preset://email",
		"traits": {
			"email": "docs@example.org"
		}
	}`)

	req, err := http.NewRequest("POST", remoteUrl, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create a new request: %v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", idToken))
	// req.Header.Add("X-CSRF-Token", client.CsrfToken.Value)
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}

	return io.ReadAll(res.Body)
}

func (client *Client) FetchIdentities(remoteUrl string) ([]byte, error) {
	req, err := http.NewRequest("GET", remoteUrl, bytes.NewBuffer([]byte{}))
	if err != nil {
		return nil, fmt.Errorf("failed to create a new request: %v", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}

	return io.ReadAll(res.Body)
}

func hasRequiredParams(config *Config) bool {
	return config.Client.Id != "" && config.Client.Secret != ""
}
