package flows

import (
	opaal "davidallendj/opaal/internal"
	"davidallendj/opaal/internal/oidc"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/davidallendj/go-utils/util"
)

func AuthorizationCode(config *opaal.Config, server *opaal.Server, client *opaal.Client) error {
	// initiate the login flow and get a flow ID and CSRF token
	{
		err := client.InitiateLoginFlow(config.ActionUrls.Login)
		if err != nil {
			return fmt.Errorf("failed to initiate login flow: %v", err)
		}
		err = client.FetchCSRFToken(config.ActionUrls.LoginFlowId)
		if err != nil {
			return fmt.Errorf("failed to fetch CSRF token: %v", err)
		}
	}

	// try and fetch server configuration if provided URL
	idp := oidc.NewIdentityProvider()
	if config.ActionUrls.ServerConfig != "" {
		fmt.Printf("Fetching server configuration: %s\n", config.ActionUrls.ServerConfig)
		err := idp.FetchServerConfig(config.ActionUrls.ServerConfig)
		if err != nil {
			return fmt.Errorf("failed to fetch server config: %v", err)
		}
	} else {
		// otherwise, use what's provided in config file
		idp.Issuer = config.IdentityProvider.Issuer
		idp.Endpoints = config.IdentityProvider.Endpoints
		idp.Supported = config.IdentityProvider.Supported
	}

	// check if all appropriate parameters are set in config
	if !opaal.HasRequiredParams(config) {
		return fmt.Errorf("client ID must be set")
	}

	// build the authorization URL to redirect user for social sign-in
	var authorizationUrl = client.BuildAuthorizationUrl(
		idp.Endpoints.Authorization,
		config.State,
		config.ResponseType,
		config.Scope,
	)

	// print the authorization URL for sharing
	fmt.Printf("Login with identity provider:\n\n  %s/login\n  %s\n\n",
		server.GetListenAddr(), authorizationUrl,
	)

	// automatically open browser to initiate login flow (only useful for testing)
	if config.OpenBrowser {
		util.OpenUrl(authorizationUrl)
	}

	// authorize oauth client and listen for callback from provider
	fmt.Printf("Waiting for authorization code redirect @%s/oidc/callback...\n", server.GetListenAddr())
	code, err := server.WaitForAuthorizationCode(authorizationUrl)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("\n=========================================\nServer closed.\n=========================================\n\n")
	} else if err != nil {
		return fmt.Errorf("failed to start server: %s", err)
	}

	if client == nil {
		fmt.Printf("client did not initialize\n")
	}

	// start up another serve in background to listen for success or failures
	d := make(chan []byte)
	quit := make(chan bool)
	var access_token []byte
	go server.Serve(d)
	go func() {
		select {
		case <-d:
			fmt.Printf("got access token")
			quit <- true
		case <-quit:
			close(d)
			close(quit)
			return
		default:
		}
	}()

	// use code from response and exchange for bearer token (with ID token)
	bearerToken, err := client.FetchTokenFromAuthenticationServer(
		code,
		idp.Endpoints.Token,
		config.State,
	)
	if err != nil {
		return fmt.Errorf("failed to fetch token from issuer: %v", err)
	}

	// unmarshal data to get id_token and access_token
	var data map[string]any
	err = json.Unmarshal([]byte(bearerToken), &data)
	if err != nil || data == nil {
		return fmt.Errorf("failed to unmarshal token: %v", err)
	}

	// extract ID token from bearer as JSON string for easy consumption
	idToken := data["id_token"].(string)
	idJwtSegments, err := util.DecodeJwt(idToken)
	if err != nil {
		fmt.Printf("failed to parse ID token: %v\n", err)
	} else {
		fmt.Printf("id_token: %v\n", idToken)
		if config.DecodeIdToken {
			if err != nil {
				fmt.Printf("failed to decode JWT: %v\n", err)
			} else {
				for i, segment := range idJwtSegments {
					// don't print last segment (signatures)
					if i == len(idJwtSegments)-1 {
						break
					}
					fmt.Printf("%s\n", string(segment))
				}
			}
		}
		fmt.Println()
	}

	// extract the access token to get the scopes
	accessToken := data["access_token"].(string)
	accessJwtSegments, err := util.DecodeJwt(accessToken)
	if err != nil || len(accessJwtSegments) <= 0 {
		fmt.Printf("failed to parse access token: %v\n", err)
	} else {
		fmt.Printf("access_token: %v\n", accessToken)
		if config.DecodeIdToken {
			if err != nil {
				fmt.Printf("failed to decode JWT: %v\n", err)
			} else {
				for i, segment := range accessJwtSegments {
					// don't print last segment (signatures)
					if i == len(accessJwtSegments)-1 {
						break
					}
					fmt.Printf("%s\n", string(segment))
				}
			}
		}
		fmt.Println()
	}

	// extract the scope from access token claims
	// var scope []string
	// var accessJsonPayload map[string]any
	// var accessJwtPayload []byte = accessJwtSegments[1]
	// if accessJsonPayload != nil {
	// 	err := json.Unmarshal(accessJwtPayload, &accessJsonPayload)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to unmarshal JWT: %v", err)
	// 	}
	// 	scope = idJsonPayload["scope"].([]string)
	// }

	// create a new identity with identity and session manager if url is provided
	if config.ActionUrls.Identities != "" {
		fmt.Printf("Attempting to create a new identity...\n")
		_, err := client.CreateIdentity(config.ActionUrls.Identities, idToken)
		if err != nil {
			return fmt.Errorf("failed to create new identity: %v", err)
		}
		_, err = client.FetchIdentities(config.ActionUrls.Identities)
		if err != nil {
			return fmt.Errorf("failed to fetch identities: %v", err)
		}
		fmt.Printf("Created new identity successfully.\n\n")
	}

	// extract the subject from ID token claims
	var subject string
	var audience []string
	var idJsonPayload map[string]any
	var idJwtPayload []byte = idJwtSegments[1]
	if idJwtPayload != nil {
		err := json.Unmarshal(idJwtPayload, &idJsonPayload)
		if err != nil {
			return fmt.Errorf("failed to unmarshal JWT: %v", err)
		}
		subject = idJsonPayload["sub"].(string)
		audType := reflect.ValueOf(idJsonPayload["aud"])
		switch audType.Kind() {
		case reflect.String:
			audience = append(audience, idJsonPayload["aud"].(string))
		case reflect.Array:
			audience = idJsonPayload["aud"].([]string)
		}
	} else {
		return fmt.Errorf("failed to extract subject from ID token claims")
	}

	// fetch JWKS and add issuer to authentication server to submit ID token
	fmt.Printf("Fetching JWKS from authentication server for verification...\n")
	err = idp.FetchJwk(config.ActionUrls.JwksUri)
	if err != nil {
		return fmt.Errorf("failed to fetch JWK: %v", err)
	} else {
		fmt.Printf("Successfully retrieved JWK from authentication server.\n\n")
		fmt.Printf("Attempting to add issuer to authorization server...\n")
		res, err := client.AddTrustedIssuer(config.ActionUrls.TrustedIssuers, idp, subject, time.Duration(1000), config.Scope)
		if err != nil {
			return fmt.Errorf("failed to add trusted issuer: %v", err)
		}
		fmt.Printf("%v\n", string(res))
	}

	// try and register a new client with authorization server
	fmt.Printf("Registering new OAuth2 client with authorization server...\n")
	res, err := client.RegisterOAuthClient("http://127.0.0.1:4445/clients", audience)
	if err != nil {
		return fmt.Errorf("failed to register client: %v", err)
	}
	fmt.Printf("%v\n", string(res))

	// extract the client info from response
	var clientData map[string]any
	err = json.Unmarshal(res, &clientData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal client data: %v", err)
	} else {
		client.Id = clientData["client_id"].(string)
		client.Secret = clientData["client_secret"].(string)
	}

	// use ID token/user info to fetch access token from authentication server
	if config.ActionUrls.AccessToken != "" {
		fmt.Printf("Fetching access token from authorization server...\n")
		res, err := client.FetchTokenFromAuthorizationServer(config.ActionUrls.AccessToken, idToken, config.Scope)
		if err != nil {
			return fmt.Errorf("failed to fetch access token: %v", err)
		}
		fmt.Printf("%s\n", res)
	}

	d <- access_token
	return nil
}
