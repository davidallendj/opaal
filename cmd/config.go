package cmd

import (
	"davidallendj/oidc-auth/internal/util"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	Host          string   `yaml:"host"`
	Port          int      `yaml:"port"`
	RedirectUri   []string `yaml:"redirect-uri"`
	State         string   `yaml:"state"`
	ResponseType  string   `yaml:"response-type"`
	Scope         []string `yaml:"scope"`
	ClientId      string   `yaml:"client.id"`
	ClientSecret  string   `yaml:"client.secret"`
	OIDCHost      string   `yaml:"oidc.host"`
	OIDCPort      int      `yaml:"oidc.port"`
	IdentitiesUrl string   `yaml:"identities-url"`
}

func NewConfig() Config {
	return Config{
		Host:          "127.0.0.1",
		Port:          3333,
		RedirectUri:   []string{""},
		State:         util.RandomString(20),
		ResponseType:  "code",
		Scope:         []string{"openid", "profile", "email"},
		ClientId:      "",
		ClientSecret:  "",
		OIDCHost:      "127.0.0.1",
		OIDCPort:      80,
		IdentitiesUrl: "",
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
			SaveDefaultConfig(path)
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
