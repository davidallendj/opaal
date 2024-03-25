package flows

import (
	"davidallendj/opaal/internal/oauth"
	"fmt"
)

type ClientCredentialsFlowParams struct {
	State        string `yaml:"state"`
	ResponseType string `yaml:"response-type"`
	Client       *oauth.Client
}

type ClientCredentialsFlowEndpoints struct {
	Clients   string
	Authorize string
	Token     string
}

func NewClientCredentialsFlow(eps ClientCredentialsFlowEndpoints, params ClientCredentialsFlowParams) (string, error) {
	// register a new OAuth 2 client with authorization srever
	res, err := params.Client.CreateOAuthClient(eps.Clients, []oauth.GrantType{oauth.ClientCredentials})
	if err != nil {
		return "", fmt.Errorf("failed to register OAuth client: %v", err)
	}

	// authorize the client
<<<<<<< HEAD
	res, err = params.Client.AuthorizeOAuthClient(eps.Authorize)
	if err != nil {
		return "", fmt.Errorf("failed to authorize client: %v", err)
	}
=======
	// _, err = client.AuthorizeOAuthClient(eps.Authorize)
	// if err != nil {
	// 	return fmt.Errorf("failed to authorize client: %v", err)
	// }
>>>>>>> f49f3c8 (Removed the client authorization for client credentials flow)

	// request a token from the authorization server
	res, err = params.Client.PerformClientCredentialsTokenGrant(eps.Token)
	if err != nil {
		return "", fmt.Errorf("failed to fetch token from authorization server: %v", err)
	}

	fmt.Printf("token: %v\n", string(res))
	return string(res), nil
}
