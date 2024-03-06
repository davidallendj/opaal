package opaal

import (
	"davidallendj/opaal/internal/db"
	"davidallendj/opaal/internal/oidc"
	"fmt"
)

func Login(config *Config, client *Client, provider *oidc.IdentityProvider) error {
	if config == nil {
		return fmt.Errorf("config is not valid")
	}

	// make cache if it's not where expect
	_, err := db.CreateIdentityProvidersIfNotExists(config.Options.CachePath)
	if err != nil {
		fmt.Printf("failed to create cache: %v\n", err)
	}

	if config.Options.FlowType == "authorization_code" {
		// create a server if doing authorization code flow
		server := NewServerWithConfig(config)
		err := AuthorizationCodeWithConfig(config, server, client, provider)
		if err != nil {
			fmt.Printf("failed to complete authorization code flow: %v\n", err)
		}
	} else if config.Options.FlowType == "client_credentials" {
		err := ClientCredentialsWithConfig(config, client)
		if err != nil {
			fmt.Printf("failed to complete client credentials flow: %v", err)
		}
	} else {
		return fmt.Errorf("invalid grant type (options: authorization_code, client_credentials)")
	}

	return nil
}
