package opaal

import (
	"davidallendj/opaal/internal/oidc"
	"davidallendj/opaal/internal/util"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func Login(config *Config) error {
	if config == nil {
		return fmt.Errorf("config is not valid")
	}

	// initialize client that will be used throughout login flow
	server := NewServerWithConfig(config)
	client := NewClientWithConfig(config)

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
	if !hasRequiredParams(config) {
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
		fmt.Printf("Server closed.\n")
	} else if err != nil {
		return fmt.Errorf("failed to start server: %s", err)
	}

	if client == nil {
		fmt.Printf("client did not initialize\n")
	}

	// use code from response and exchange for bearer token (with ID token)
	tokenString, err := client.FetchTokenFromAuthenticationServer(
		code,
		idp.Endpoints.Token,
		config.State,
	)
	if err != nil {
		return fmt.Errorf("failed to fetch token from issuer: %v", err)
	}

	// unmarshal data to get id_token and access_token
	var data map[string]any
	err = json.Unmarshal([]byte(tokenString), &data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal token: %v", err)
	}

	// extract ID token from bearer as JSON string for easy consumption
	idToken := data["id_token"].(string)
	idJwtSegments, err := util.DecodeJwt(idToken)
	if err != nil {
		fmt.Printf("failed to parse ID token: %v\n", err)
	} else {
		if config.DecodeIdToken {
			if err != nil {
				fmt.Printf("failed to decode JWT: %v\n", err)
			} else {
				fmt.Printf("id_token.header: %s\nid_token.payload: %s\n", string(idJwtSegments[0]), string(idJwtSegments[1]))
			}
		}
	}

	// extract the access token to get the scopes
	// accessToken := data["access_token"].(string)
	// accessJwtSegments, err := util.DecodeJwt(accessToken)
	// if err != nil || len(accessJwtSegments) <=  {
	// 	fmt.Printf("failed to parse access token: %v\n", err)
	// } else {
	// 	if config.DecodeIdToken {
	// 		if err != nil {
	// 			fmt.Printf("failed to decode JWT: %v\n", err)
	// 		} else {
	// 			fmt.Printf("access_token.header: %s\naccess_token.payload: %s\n", string(accessJwtSegments[0]), string(accessJwtSegments[1]))
	// 		}
	// 	}
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
	}

	// extract the subject from ID token claims
	var subject string
	var idJsonPayload map[string]any
	var idJwtPayload []byte = idJwtSegments[1]
	if idJwtPayload != nil {
		err := json.Unmarshal(idJwtPayload, &idJsonPayload)
		if err != nil {
			return fmt.Errorf("failed to unmarshal JWT: %v", err)
		}
		subject = idJsonPayload["sub"].(string)
	} else {
		return fmt.Errorf("failed to extract subject from ID token claims")
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

	// fetch JWKS and add issuer to authentication server to submit ID token
	fmt.Printf("Fetching JWKS from authentication server for verification...\n")
	err = idp.FetchJwk(config.ActionUrls.JwksUri)
	if err != nil {
		fmt.Printf("failed to fetch JWK: %v\n", err)
	} else {
		fmt.Printf("Attempting to add issuer to authorization server...\n")
		_, err = client.AddTrustedIssuer(config.ActionUrls.TrustedIssuers, idp, subject, time.Duration(1000), config.Scope)
		if err != nil {
			return fmt.Errorf("failed to add trusted issuer: %v", err)
		}
	}

	// use ID token/user info to fetch access token from authentication server
	if config.ActionUrls.AccessToken != "" {
		fmt.Printf("Fetching access token from authorization server...\n")
		accessToken, err := client.FetchTokenFromAuthorizationServer(config.ActionUrls.AccessToken, idToken, config.Scope)
		if err != nil {
			return fmt.Errorf("failed to fetch access token: %v", err)
		}
		fmt.Printf("%s\n", accessToken)
	}

	fmt.Printf("Success!")
	return nil
}
