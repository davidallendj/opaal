package opaal

import (
	"davidallendj/opaal/internal/oidc"
	"davidallendj/opaal/internal/util"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Version           string                `yaml:"version"`
	Server            Server                `yaml:"server"`
	Client            Client                `yaml:"client"`
	IdentityProvider  oidc.IdentityProvider `yaml:"oidc"`
	State             string                `yaml:"state"`
	ResponseType      string                `yaml:"response-type"`
	Scope             []string              `yaml:"scope"`
	ActionUrls        ActionUrls            `yaml:"urls"`
	OpenBrowser       bool                  `yaml:"open-browser"`
	DecodeIdToken     bool                  `yaml:"decode-id-token"`
	DecodeAccessToken bool                  `yaml:"decode-access-token"`
}

func NewConfig() Config {
	return Config{
		Version: util.GetCommit(),
		Server: Server{
			Host: "127.0.0.1",
			Port: 3333,
		},
		Client: Client{
			Id:           "",
			Secret:       "",
			RedirectUris: []string{""},
		},
		IdentityProvider: *oidc.NewIdentityProvider(),
		State:            util.RandomString(20),
		ResponseType:     "code",
		Scope:            []string{"openid", "profile", "email"},
		ActionUrls: ActionUrls{
			Identities:     "",
			AccessToken:    "",
			TrustedIssuers: "",
			ServerConfig:   "",
		},
		OpenBrowser:       false,
		DecodeIdToken:     false,
		DecodeAccessToken: false,
	}
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
