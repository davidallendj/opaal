package opaal

import (
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"log"
	"os"
	"path/filepath"
	"time"

	"davidallendj/opaal/internal/server"

	goutil "github.com/davidallendj/go-utils/util"

	"gopkg.in/yaml.v3"
)

type FlowOptions map[string]string
type Flows map[string]FlowOptions
type Providers map[string]string

type Options struct {
	RunOnce     bool   `yaml:"run-once"`
	OpenBrowser bool   `yaml:"open-browser"`
	FlowType    string `yaml:"flow"`
	CachePath   string `yaml:"cache"`
	CacheOnly   bool   `yaml:"cache-only"`
	Verbose     bool   `yaml:"verbose"`
}

type Endpoints struct {
	Issuer         string `yaml:"issuer"`
	Config         string `yaml:"config"`
	JwksUri        string `yaml:"jwks"`
	Identities     string `yaml:"identities"`
	TrustedIssuers string `yaml:"trusted-issuers"`
	Login          string `yaml:"login"`
	Clients        string `yaml:"clients"`
	Token          string `yaml:"token"`
	Authorize      string `yaml:"authorize"`
	Register       string `yaml:"register"`
}

type TokenOptions struct {
	Duration   time.Duration `yaml:"duration"`
	Forwarding bool          `yaml:"forwarding"`
	Refresh    bool          `yaml:"refresh"`
	Scope      []string      `yaml:"scope"`
	//TODO: allow specifying audience in returned token
}

type Authentication struct {
	Clients        []oauth.Client `yaml:"clients"`
	Flows          Flows          `yaml:"flows"`
	TestAllClients bool           `yaml:"test-all"`
	State          string         `yaml:"state"`
}

type Authorization struct {
	Token     TokenOptions `yaml:"token"`
	Endpoints Endpoints    `yaml:"endpoints"`
	KeyPath   string       `yaml:"key-path"`
	Audience  []string     `yaml:"audience"` // NOTE: overrides the "aud" claim in token sent to authorization server
}

type Config struct {
	Version        string         `yaml:"version"`
	Server         server.Server  `yaml:"server"`
	Providers      Providers      `yaml:"providers"`
	Options        Options        `yaml:"options"`
	Authentication Authentication `yaml:"authentication"`
	Authorization  Authorization  `yaml:"authorization"`
}

func NewConfig() Config {
	config := Config{
		Version: goutil.GetCommit(),
		Server: server.Server{
			Host: "127.0.0.1",
			Port: 3333,
			Issuer: server.IdentityProviderServer{
				Host: "127.0.0.1",
				Port: 3332,
				Endpoints: oidc.Endpoints{
					Authorization: "",
					Token:         "",
					JwksUri:       "",
				},
			},
		},
		Options: Options{
			RunOnce:     true,
			OpenBrowser: false,
			CachePath:   "opaal.db",
			FlowType:    "authorization_code",
			CacheOnly:   false,
			Verbose:     false,
		},
		Authentication: Authentication{
			TestAllClients: false,
		},
		Authorization: Authorization{
			KeyPath: "./keys",
			Token: TokenOptions{
				Forwarding: false,
				Duration:   1 * time.Hour,
				Refresh:    true,
				Scope:      []string{},
			},
		},
	}
	return config
}

func LoadConfig(path string) Config {
	var c Config = NewConfig()
	file, err := os.ReadFile(path)
	if err != nil {
		log.Printf("failed to read config file: %v\n", err)
		return c
	}
	err = yaml.Unmarshal(file, &c)
	if err != nil {
		log.Fatalf("failed to unmarshal config: %v\n", err)
		return c
	}
	return c
}

func SaveDefaultConfig(path string) {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		path = "config.yaml"
	}
	var c = NewConfig()
	data, err := yaml.Marshal(c)
	if err != nil {
		log.Printf("failed to marshal config: %v\n", err)
		return
	}
	err = os.WriteFile(path, data, os.ModePerm)
	if err != nil {
		log.Printf("failed to write default config file: %v\n", err)
		return
	}
}

func HasRequiredConfigParams(config *Config) bool {
	// must have athe requirements to perform login
	hasClients := len(config.Authentication.Clients) > 0
	hasServer := config.Server.Host != "" && config.Server.Port != 0 && config.Server.Callback != ""
	hasEndpoints := config.Authorization.Endpoints.TrustedIssuers != "" &&
		config.Authorization.Endpoints.Login != "" &&
		config.Authorization.Endpoints.Clients != "" &&
		config.Authorization.Endpoints.Authorize != "" &&
		config.Authorization.Endpoints.Token != ""
	return hasClients && hasServer && hasEndpoints
}
