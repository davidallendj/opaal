package cmd

import (
	"davidallendj/opal/internal/oauth"
	"davidallendj/opal/internal/oidc"
	"davidallendj/opal/internal/util"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

type Server struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type AuthEndpoints struct {
	Identities     string `yaml:"identities"`
	TrustedIssuers string `yaml:"trusted-issuers"`
	AccessToken    string `yaml:"access-token"`
	ServerConfig   string `yaml:"server-config"`
}

type Config struct {
	Server           Server                `yaml:"server"`
	Client           oauth.Client          `yaml:"client"`
	IdentityProvider oidc.IdentityProvider `yaml:"oidc"`
	State            string                `yaml:"state"`
	ResponseType     string                `yaml:"response-type"`
	Scope            []string              `yaml:"scope"`
	AuthEndpoints    AuthEndpoints         `yaml:"urls"`
	OpenBrowser      bool                  `yaml:"open-browser"`
}

func NewConfig() Config {
	return Config{
		Server: Server{
			Host: "127.0.0.1",
			Port: 3333,
		},
		Client: oauth.Client{
			Id:           "",
			Secret:       "",
			RedirectUris: []string{""},
		},
		IdentityProvider: *oidc.NewIdentityProvider(),
		State:            util.RandomString(20),
		ResponseType:     "code",
		Scope:            []string{"openid", "profile", "email"},
		AuthEndpoints: AuthEndpoints{
			Identities:     "",
			AccessToken:    "",
			TrustedIssuers: "",
			ServerConfig:   "",
		},
		OpenBrowser: false,
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

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Create a new default config file",
	Run: func(cmd *cobra.Command, args []string) {
		// create a new config at all args (paths)
		for _, path := range args {
			// check and make sure something doesn't exist first
			if exists, err := util.PathExists(path); exists || err != nil {
				fmt.Printf("file or directory exists\n")
				continue
			}
			SaveDefaultConfig(path)
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
