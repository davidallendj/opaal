package opaal

import (
	"net/http"
	"net/http/cookiejar"
	"slices"

	"github.com/davidallendj/go-utils/mathx"
	"golang.org/x/net/publicsuffix"
)

type Client struct {
	http.Client
	Id                      string   `yaml:"id"`
	Secret                  string   `yaml:"secret"`
	Name                    string   `yaml:"name"`
	Description             string   `yaml:"description"`
	Issuer                  string   `yaml:"issuer"`
	RegistrationAccessToken string   `yaml:"registration-access-token"`
	RedirectUris            []string `yaml:"redirect-uris"`
	Scope                   []string `yaml:"scope"`
	FlowId                  string
	CsrfToken               string
}

func NewClient() *Client {
	return &Client{}
}

func NewClientWithConfig(config *Config) *Client {
	// make sure config is valid
	if config == nil {
		return nil
	}

	// make sure we have at least one client
	clients := config.Authentication.Clients
	if len(clients) <= 0 {
		return nil
	}

	// use the first client found by default
	return &Client{
		Id:           clients[0].Id,
		Secret:       clients[0].Secret,
		Name:         clients[0].Name,
		Issuer:       clients[0].Issuer,
		Scope:        clients[0].Scope,
		RedirectUris: clients[0].RedirectUris,
	}
}

func NewClientWithConfigByIndex(config *Config, index int) *Client {
	size := len(config.Authentication.Clients)
	index = mathx.Clamp(index, 0, size)
	return nil
}

func NewClientWithConfigByName(config *Config, name string) *Client {
	index := slices.IndexFunc(config.Authentication.Clients, func(c Client) bool {
		return c.Name == name
	})
	if index >= 0 {
		return &config.Authentication.Clients[index]
	}
	return nil
}

func NewClientWithConfigByProvider(config *Config, issuer string) *Client {
	index := slices.IndexFunc(config.Authentication.Clients, func(c Client) bool {
		return c.Issuer == issuer
	})

	if index >= 0 {
		return &config.Authentication.Clients[index]
	}
	return nil
}

func NewClientWithConfigById(config *Config, id string) *Client {
	index := slices.IndexFunc(config.Authentication.Clients, func(c Client) bool {
		return c.Id == id
	})
	if index >= 0 {
		return &config.Authentication.Clients[index]
	}
	return nil
}

func (client *Client) ClearCookies() {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	client.Jar = jar
}
