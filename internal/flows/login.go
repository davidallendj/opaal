package flows

import (
	opaal "davidallendj/opaal/internal"
	"fmt"
)

func Login(config *opaal.Config) error {
	if config == nil {
		return fmt.Errorf("config is not valid")
	}

	// initialize client that will be used throughout login flow
	server := opaal.NewServerWithConfig(config)
	client := opaal.NewClientWithConfig(config)

	fmt.Printf("grant type: %v\n", config.GrantType)

	if config.GrantType == "authorization_code" {
		AuthorizationCode(config, server, client)
	} else if config.GrantType == "client_credentials" {
		ClientCredentials(config, server, client)
	} else {
		return fmt.Errorf("invalid grant type")
	}

	return nil
}
