package flows

import (
	opaal "davidallendj/opaal/internal"
	"fmt"
)

func ClientCredentials(config *opaal.Config, server *opaal.Server, client *opaal.Client) error {
	// register a new OAuth 2 client with authorization srever
	_, err := client.RegisterOAuthClient(config.ActionUrls.RegisterClient, nil)
	if err != nil {
		return fmt.Errorf("failed to register OAuth client: %v", err)
	}

	// authorize the client
	_, err = client.AuthorizeClient(config.ActionUrls.AuthorizeClient)
	if err != nil {
		return fmt.Errorf("failed to authorize client: %v", err)
	}

	// request a token from the authorization server
	res, err := client.FetchTokenFromAuthorizationServer(config.ActionUrls.AccessToken, "", nil)
	if err != nil {
		return fmt.Errorf("failed to fetch token from authorization server: %v", err)
	}

	fmt.Printf("token: %v\n", string(res))
	return nil
}
