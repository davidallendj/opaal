package opaal

import (
	cache "davidallendj/opaal/internal/cache/sqlite"
	"davidallendj/opaal/internal/flows"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"davidallendj/opaal/internal/server"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func Login(config *Config) error {
	if config == nil {
		return fmt.Errorf("invalid config")
	}

	// make cache if it's not where expect
	_, err := cache.CreateIdentityProvidersIfNotExists(config.Options.CachePath)
	if err != nil {
		fmt.Printf("failed to create cache: %v\n", err)
	}

	if config.Options.FlowType == "authorization_code" {
		// build the authorization URL to redirect user for social sign-in
		var state = ""
		if config.Authentication.Flows["authorization-code"]["state"] != "" {
			state = config.Authentication.Flows["authorization-code"]["state"]
		}

		// print the authorization URL for sharing
		s := NewServerWithConfig(config)
		s.State = state

		var authzClient = oauth.NewClient()
		authzClient.Scope = config.Authorization.Token.Scope

		params := server.ServerParams{
			Verbose: config.Options.Verbose,
			AuthProvider: &oidc.IdentityProvider{
				Issuer: config.Authorization.Endpoints.Issuer,
				Endpoints: oidc.Endpoints{
					Config:  config.Authorization.Endpoints.Config,
					JwksUri: config.Authorization.Endpoints.JwksUri,
				},
			},
			JwtBearerEndpoints: flows.JwtBearerFlowEndpoints{
				Token:          config.Authorization.Endpoints.Token,
				TrustedIssuers: config.Authorization.Endpoints.TrustedIssuers,
				Register:       config.Authorization.Endpoints.Register,
			},
			JwtBearerParams: flows.JwtBearerFlowParams{
				Client: authzClient,
				TrustedIssuer: &oauth.TrustedIssuer{
					AllowAnySubject: false,
					Issuer:          s.Addr,
					Subject:         "opaal",
					ExpiresAt:       time.Now().Add(config.Authorization.Token.Duration),
					Scope:           []string{},
				},
				Verbose:  config.Options.Verbose,
				Refresh:  config.Authorization.Token.Refresh,
				Audience: config.Authorization.Audience,
			},
			ClientCredentialsEndpoints: flows.ClientCredentialsFlowEndpoints{
				Clients:   config.Authorization.Endpoints.Clients,
				Authorize: config.Authorization.Endpoints.Authorize,
				Token:     config.Authorization.Endpoints.Token,
			},
			ClientCredentialsParams: flows.ClientCredentialsFlowParams{
				Client: authzClient,
			},
		}
		err = s.StartLogin(config.Authentication.Clients, params)
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("\n=========================================\nServer closed.\n=========================================\n\n")
		} else if err != nil {
			return fmt.Errorf("failed to start server: %s", err)
		}

	} else if config.Options.FlowType == "client_credentials" {
		params := flows.ClientCredentialsFlowParams{
			Client: nil, // # FIXME: need to do something about this being nil I think
		}
		_, err := NewClientCredentialsFlowWithConfig(config, params)
		if err != nil {
			fmt.Printf("failed to complete client credentials flow: %v", err)
		}
	} else {
		return fmt.Errorf("invalid grant type (options: authorization_code, client_credentials)")
	}

	return nil
}
