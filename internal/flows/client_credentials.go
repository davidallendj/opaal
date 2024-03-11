package flows

import (
	"davidallendj/opaal/internal/oauth"
	"fmt"
)

type ClientCredentialsFlowParams struct {
	State        string `yaml:"state"`
	ResponseType string `yaml:"response-type"`
}

type ClientCredentialsFlowEndpoints struct {
	Create    string
	Authorize string
	Token     string
}

func NewClientCredentialsFlow(eps ClientCredentialsFlowEndpoints, client *oauth.Client) error {
	// register a new OAuth 2 client with authorization srever
	_, err := client.CreateOAuthClient(eps.Create)
	if err != nil {
		return fmt.Errorf("failed to register OAuth client: %v", err)
	}

	// authorize the client
	_, err = client.AuthorizeOAuthClient(eps.Authorize)
	if err != nil {
		return fmt.Errorf("failed to authorize client: %v", err)
	}

	// request a token from the authorization server
	res, err := client.PerformTokenGrant(eps.Token, "")
	if err != nil {
		return fmt.Errorf("failed to fetch token from authorization server: %v", err)
	}

	fmt.Printf("token: %v\n", string(res))
	return nil
}
