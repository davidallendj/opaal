package opaal

import (
	"log"
	"os"
	"path/filepath"

	goutil "github.com/davidallendj/go-utils/util"

	"gopkg.in/yaml.v2"
)

type FlowOptions map[string]string
type Flows map[string]FlowOptions
type Providers map[string]string

type Options struct {
	DecodeIdToken     bool   `yaml:"decode-id-token"`
	DecodeAccessToken bool   `yaml:"decode-access-token"`
	RunOnce           bool   `yaml:"run-once"`
	OpenBrowser       bool   `yaml:"open-browser"`
	FlowType          string `yaml:"flow"`
	CachePath         string `yaml:"cache"`
	LocalOnly         bool   `yaml:"local-only"`
}

type RequestUrls struct {
	Identities     string `yaml:"identities"`
	TrustedIssuers string `yaml:"trusted-issuers"`
	Login          string `yaml:"login"`
	Clients        string `yaml:"clients"`
	Token          string `yaml:"token"`
	Authorize      string `yaml:"authorize"`
	Register       string `yaml:"register"`
}

type Authentication struct {
	Clients []Client `yaml:"clients"`
	Flows   Flows    `yaml:"flows"`
}

type Authorization struct {
	RequestUrls RequestUrls `yaml:"urls"`
}

type Config struct {
	Version        string         `yaml:"version"`
	Server         Server         `yaml:"server"`
	Providers      Providers      `yaml:"providers"`
	Options        Options        `yaml:"options"`
	Authentication Authentication `yaml:"authentication"`
	Authorization  Authorization  `yaml:"authorization"`
}

func NewConfig() Config {
	return Config{
		Version: goutil.GetCommit(),
		Server: Server{
			Host: "127.0.0.1",
			Port: 3333,
		},
		Options: Options{
			DecodeIdToken:     true,
			DecodeAccessToken: true,
			RunOnce:           true,
			OpenBrowser:       false,
			CachePath:         "opaal.db",
			FlowType:          "authorization_code",
			LocalOnly:         false,
		},
		Authentication: Authentication{},
		Authorization:  Authorization{},
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

func HasRequiredConfigParams(config *Config) bool {
	// must have athe requirements to perform login
	hasClients := len(config.Authentication.Clients) > 0
	hasServer := config.Server.Host != "" && config.Server.Port != 0 && config.Server.Callback != ""
	hasEndpoints := config.Authorization.RequestUrls.TrustedIssuers != "" &&
		config.Authorization.RequestUrls.Login != "" &&
		config.Authorization.RequestUrls.Clients != "" &&
		config.Authorization.RequestUrls.Authorize != "" &&
		config.Authorization.RequestUrls.Token != ""
	return hasClients && hasServer && hasEndpoints
}
