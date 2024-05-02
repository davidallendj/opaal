package opaal

import (
	"davidallendj/opaal/internal/oauth"
	"fmt"
	"net/http"
	"slices"

	"davidallendj/opaal/internal/flows"
	"davidallendj/opaal/internal/server"

	"github.com/davidallendj/go-utils/mathx"
)

func NewClientWithConfig(config *Config) *oauth.Client {
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
	return &oauth.Client{
		Id:           clients[0].Id,
		Secret:       clients[0].Secret,
		Name:         clients[0].Name,
		Provider:     clients[0].Provider,
		Scope:        clients[0].Scope,
		RedirectUris: clients[0].RedirectUris,
	}
}

func NewClientWithConfigByIndex(config *Config, index int) *oauth.Client {
	size := len(config.Authentication.Clients)
	index = mathx.Clamp(index, 0, size)
	return nil
}

func NewClientWithConfigByName(config *Config, name string) *oauth.Client {
	index := slices.IndexFunc(config.Authentication.Clients, func(c oauth.Client) bool {
		return c.Name == name
	})
	if index >= 0 {
		return &config.Authentication.Clients[index]
	}
	return nil
}

func NewClientWithConfigByProvider(config *Config, issuer string) *oauth.Client {
	index := slices.IndexFunc(config.Authentication.Clients, func(c oauth.Client) bool {
		return c.Provider.Issuer == issuer
	})

	if index >= 0 {
		return &config.Authentication.Clients[index]
	}
	return nil
}

func NewClientWithConfigById(config *Config, id string) *oauth.Client {
	index := slices.IndexFunc(config.Authentication.Clients, func(c oauth.Client) bool {
		return c.Id == id
	})
	if index >= 0 {
		return &config.Authentication.Clients[index]
	}
	return nil
}

func NewClientCredentialsFlowWithConfig(config *Config, params flows.ClientCredentialsFlowParams) (string, error) {
	eps := flows.ClientCredentialsFlowEndpoints{
		Clients:   config.Authorization.Endpoints.Clients,
		Authorize: config.Authorization.Endpoints.Authorize,
		Token:     config.Authorization.Endpoints.Token,
	}
	return flows.NewClientCredentialsFlow(eps, params)
}

func NewServerWithConfig(conf *Config) *server.Server {
	host := conf.Server.Host
	port := conf.Server.Port
	server := &server.Server{
		Server: &http.Server{
			Addr: fmt.Sprintf("%s:%d", host, port),
		},
		Host: host,
		Port: port,
		Issuer: server.IdentityProviderServer{
			Host:      conf.Server.Issuer.Host,
			Port:      conf.Server.Issuer.Port,
			Endpoints: conf.Server.Issuer.Endpoints,
			Clients:   conf.Server.Issuer.Clients,
		},
	}
	return server
}
