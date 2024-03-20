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
		Issuer:       clients[0].Issuer,
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
		return c.Issuer == issuer
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
	}
	return server
}

// func NewAuthorizationCodeFlowWithConfig(config *Config, client *oauth.Client, idp *oidc.IdentityProvider) error {
// 	// create new server and client to use for flow
// 	server := NewServerWithConfig(config)

// 	// build the authorization URL to redirect user for social sign-in
// 	state := config.Authentication.Flows["authorization_code"]["state"]
// 	var authorizationUrl = client.BuildAuthorizationUrl(idp.Endpoints.Authorization, state)

// 	// print the authorization URL for sharing
// 	fmt.Printf("Login with identity provider:\n\n  %s/login\n  %s\n\n",
// 		server.GetListenAddr(), authorizationUrl,
// 	)

// 	// automatically open browser to initiate login flow (only useful for testing and debugging)
// 	if config.Options.OpenBrowser {
// 		util.OpenUrl(authorizationUrl)
// 	}

// 	// authorize oauth client and listen for callback from provider
// 	fmt.Printf("Waiting for authorization code redirect @%s/oidc/callback...\n", server.GetListenAddr())
// 	err := server.Login(authorizationUrl, c)
// 	if errors.Is(err, http.ErrServerClosed) {
// 		fmt.Printf("\n=========================================\nServer closed.\n=========================================\n\n")
// 	} else if err != nil {
// 		return fmt.Errorf("failed to start server: %s", err)
// 	}

// 	// start up another server in background to listen for success or failures
// 	d := StartListener(server)

// 	// use code from response and exchange for bearer token (with ID token)
// 	bearerToken, err := client.FetchTokenFromAuthenticationServer(
// 		code,
// 		idp.Endpoints.Token,
// 		state,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to fetch token from issuer: %v", err)
// 	}

// 	// unmarshal data to get id_token and access_token
// 	var data map[string]any
// 	err = json.Unmarshal([]byte(bearerToken), &data)
// 	if err != nil || data == nil {
// 		return fmt.Errorf("failed to unmarshal token: %v", err)
// 	}

// 	// make sure we have an ID token
// 	if data["id_token"] == nil {
// 		return fmt.Errorf("no ID token found...aborting")
// 	}

// 	// extract ID token from bearer as JSON string for easy consumption
// 	idToken := data["id_token"].(string)
// 	idJwtSegments, err := util.DecodeJwt(idToken)
// 	if err != nil {
// 		fmt.Printf("failed to parse ID token: %v\n", err)
// 	} else {
// 		fmt.Printf("id_token: %v\n", idToken)
// 		fmt.Println()
// 	}

// 	// extract the access token to get the scopes
// 	accessToken := data["access_token"].(string)
// 	accessJwtSegments, err := util.DecodeJwt(accessToken)
// 	if err != nil || len(accessJwtSegments) <= 0 {
// 		fmt.Printf("failed to parse access token: %v\n", err)
// 	} else {
// 		fmt.Printf("access_token (from identity provider): %v\n", accessToken)
// 		fmt.Println()
// 	}

// 	if !config.Options.TokenForwarding {
// 		// 1. verify that the JWT from the issuer is valid using all keys
// 		_, err = jws.Verify([]byte(idToken), jws.WithKeySet(idp.KeySet), jws.WithValidateKey(true))
// 		if err != nil {
// 			return fmt.Errorf("failed to verify JWT: %v", err)
// 		}

// 		// 2. Check if we are already registered as a trusted issuer with authorization server...

// 		// 3.a if not, create a new JWKS (or just JWK) to be verified
// 		var (
// 			keyPath    string
// 			privateJwk jwk.Key
// 			publicJwk  jwk.Key
// 		)
// 		if config.Authorization.KeyPath != "" {
// 			keyPath = config.Authorization.Endpoints.Authorize
// 		}
// 		privateKey, err := os.ReadFile(keyPath)
// 		if err != nil {
// 			privateJwk, publicJwk, err = cryptox.GenerateJwkKeyPair()
// 			if err != nil {
// 				return fmt.Errorf("failed to generate JWK pair: %v", err)
// 			}
// 		} else {
// 			privateJwk, publicJwk, err = cryptox.GenerateJwkKeyPairFromPrivateKey(privateKey)
// 			if err != nil {
// 				return fmt.Errorf("failed to generate JWK pair from private key: %v", err)
// 			}
// 		}
// 		privateJwk.Set("kid", uuid.New().String())
// 		publicJwk.Set("kid", uuid.New().String())

// 		// 3.b ...and then, add opaal's server host as a trusted issuer with JWK
// 		fmt.Printf("Attempting to add issuer to authorization server...\n")
// 		ti := oauth.NewTrustedIssuer()
// 		ti.Issuer = server.Addr
// 		ti.PublicKey = publicJwk
// 		ti.Subject = "1"
// 		ti.ExpiresAt = time.Now().Add(time.Second * 3600)
// 		res, err := client.AddTrustedIssuer(
// 			config.Authorization.Endpoints.TrustedIssuers,
// 			ti,
// 		)
// 		if err != nil {
// 			return fmt.Errorf("failed to add trusted issuer: %v", err)
// 		}
// 		fmt.Printf("%v\n", string(res))

// 		// 4. create a new JWT based on the claims from the identity provider and sign
// 		parsedIdToken, err := jwt.ParseString(idToken, jwt.WithKeySet(idp.KeySet))
// 		if err != nil {
// 			return fmt.Errorf("failed to parse ID token: %v", err)
// 		}
// 		payload := parsedIdToken.PrivateClaims()
// 		payload["iss"] = server.Addr
// 		payload["aud"] = []string{config.Authorization.Endpoints.Token}
// 		payload["iat"] = time.Now().Unix()
// 		payload["nbf"] = time.Now().Unix()
// 		payload["exp"] = time.Now().Add(time.Second * 3600).Unix()
// 		payload["sub"] = "1"
// 		payloadJson, err := json.Marshal(payload)
// 		if err != nil {
// 			return fmt.Errorf("failed to marshal payload: %v", err)
// 		}
// 		newToken, err := jws.Sign(payloadJson, jws.WithJSON(), jws.WithKey(jwa.RS256, privateJwk))
// 		if err != nil {
// 			return fmt.Errorf("failed to sign token: %v", err)
// 		}

// 		// 5. dynamically register new OAuth client and authorize it to make jwt_bearer request
// 		fmt.Printf("Registering new OAuth2 client with authorization server...\n")
// 		res, err = client.RegisterOAuthClient(config.Authorization.Endpoints.Register, []string{})
// 		if err != nil {
// 			return fmt.Errorf("failed to register client: %v", err)
// 		}
// 		fmt.Printf("%v\n", string(res))

// 		// extract the client info from response
// 		var clientData map[string]any
// 		err = json.Unmarshal(res, &clientData)
// 		if err != nil {
// 			return fmt.Errorf("failed to unmarshal client data: %v", err)
// 		} else {
// 			// check for error first
// 			errJson := clientData["error"]
// 			if errJson == nil {
// 				client.Id = clientData["client_id"].(string)
// 				client.Secret = clientData["client_secret"].(string)
// 			} else {
// 				// delete client and try to create again
// 				fmt.Printf("Attempting to delete client...\n")
// 				err := client.DeleteOAuthClient(config.Authorization.Endpoints.Clients)
// 				if err != nil {
// 					return fmt.Errorf("failed to delete OAuth client: %v", err)
// 				}
// 				fmt.Printf("Attempting to re-create client...\n")
// 				res, err := client.CreateOAuthClient(config.Authorization.Endpoints.Clients, []string{})
// 				if err != nil {
// 					return fmt.Errorf("failed to register client: %v", err)
// 				}
// 				fmt.Printf("%v\n", string(res))
// 			}
// 		}

// 		// authorize the client
// 		// fmt.Printf("Attempting to authorize client...\n")
// 		// res, err = client.AuthorizeOAuthClient(config.Authorization.RequestUrls.Authorize)
// 		// if err != nil {
// 		// 	return fmt.Errorf("failed to authorize client: %v", err)
// 		// }
// 		// fmt.Printf("%v\n", string(res))

// 		// 6. send JWT to authorization server and receive a access token
// 		if config.Authorization.Endpoints.Token != "" {
// 			fmt.Printf("Fetching access token from authorization server...\n")
// 			res, err := client.PerformTokenGrant(config.Authorization.Endpoints.Token, string(newToken))
// 			if err != nil {
// 				return fmt.Errorf("failed to fetch access token: %v", err)
// 			}
// 			fmt.Printf("%s\n", res)
// 		}
// 	} else {
// 		// extract the scope from access token claims
// 		// var scope []string
// 		// var accessJsonPayload map[string]any
// 		// var accessJwtPayload []byte = accessJwtSegments[1]
// 		// if accessJsonPayload != nil {
// 		// 	err := json.Unmarshal(accessJwtPayload, &accessJsonPayload)
// 		// 	if err != nil {
// 		// 		return fmt.Errorf("failed to unmarshal JWT: %v", err)
// 		// 	}
// 		// 	scope = idJsonPayload["scope"].([]string)
// 		// }

// 		// create a new identity with identity and session manager if url is provided
// 		// if config.RequestUrls.Identities != "" {
// 		// 	fmt.Printf("Attempting to create a new identity...\n")
// 		// 	err := client.CreateIdentity(config.RequestUrls.Identities, idToken)
// 		// 	if err != nil {
// 		// 		return fmt.Errorf("failed to create new identity: %v", err)
// 		// 	}
// 		// 	_, err = client.FetchIdentities(config.RequestUrls.Identities)
// 		// 	if err != nil {
// 		// 		return fmt.Errorf("failed to fetch identities: %v", err)
// 		// 	}
// 		// 	fmt.Printf("Created new identity successfully.\n\n")
// 		// }

// 		// extract the subject from ID token claims
// 		var subject string
// 		var audience []string
// 		var idJsonPayload map[string]any
// 		var idJwtPayload []byte = idJwtSegments[1]
// 		if idJwtPayload != nil {
// 			err := json.Unmarshal(idJwtPayload, &idJsonPayload)
// 			if err != nil {
// 				return fmt.Errorf("failed to unmarshal JWT: %v", err)
// 			}
// 			subject = idJsonPayload["sub"].(string)
// 			audType := reflect.ValueOf(idJsonPayload["aud"])
// 			switch audType.Kind() {
// 			case reflect.String:
// 				audience = append(audience, idJsonPayload["aud"].(string))
// 			case reflect.Array:
// 				audience = idJsonPayload["aud"].([]string)
// 			}
// 		} else {
// 			return fmt.Errorf("failed to extract subject from ID token claims")
// 		}

// 		// fetch JWKS and add issuer to authentication server to submit ID token
// 		fmt.Printf("Fetching JWKS from authentication server for verification...\n")
// 		err = idp.FetchJwks()
// 		if err != nil {
// 			return fmt.Errorf("failed to fetch JWK: %v", err)
// 		} else {
// 			fmt.Printf("Successfully retrieved JWK from authentication server.\n\n")
// 			fmt.Printf("Attempting to add issuer to authorization server...\n")
// 			res, err := client.AddTrustedIssuerWithIdentityProvider(
// 				config.Authorization.Endpoints.TrustedIssuers,
// 				idp,
// 				subject,
// 				time.Duration(1000),
// 			)
// 			if err != nil {
// 				return fmt.Errorf("failed to add trusted issuer: %v", err)
// 			}
// 			fmt.Printf("%v\n", string(res))
// 		}

// 		// add client ID to audience
// 		audience = append(audience, client.Id)
// 		audience = append(audience, "http://127.0.0.1:4444/oauth2/token")

// 		// try and register a new client with authorization server
// 		fmt.Printf("Registering new OAuth2 client with authorization server...\n")
// 		res, err := client.RegisterOAuthClient(config.Authorization.Endpoints.Register, audience)
// 		if err != nil {
// 			return fmt.Errorf("failed to register client: %v", err)
// 		}
// 		fmt.Printf("%v\n", string(res))

// 		// extract the client info from response
// 		var clientData map[string]any
// 		err = json.Unmarshal(res, &clientData)
// 		if err != nil {
// 			return fmt.Errorf("failed to unmarshal client data: %v", err)
// 		} else {
// 			// check for error first
// 			errJson := clientData["error"]
// 			if errJson == nil {
// 				client.Id = clientData["client_id"].(string)
// 				client.Secret = clientData["client_secret"].(string)
// 			} else {
// 				// delete client and create again
// 				fmt.Printf("Attempting to delete client...\n")
// 				err := client.DeleteOAuthClient(config.Authorization.Endpoints.Clients)
// 				if err != nil {
// 					return fmt.Errorf("failed to delete OAuth client: %v", err)
// 				}
// 				fmt.Printf("Attempting to re-create client...\n")
// 				res, err := client.CreateOAuthClient(config.Authorization.Endpoints.Clients, audience)
// 				if err != nil {
// 					return fmt.Errorf("failed to register client: %v", err)
// 				}
// 				fmt.Printf("%v\n", string(res))
// 			}
// 		}

// 		// authorize the client
// 		// fmt.Printf("Attempting to authorize client...\n")
// 		// res, err = client.AuthorizeOAuthClient(config.Authorization.RequestUrls.Authorize)
// 		// if err != nil {
// 		// 	return fmt.Errorf("failed to authorize client: %v", err)
// 		// }
// 		// fmt.Printf("%v\n", string(res))

// 		// use ID token/user info to fetch access token from authentication server
// 		if config.Authorization.Endpoints.Token != "" {
// 			fmt.Printf("Fetching access token from authorization server...\n")
// 			res, err := client.PerformTokenGrant(config.Authorization.Endpoints.Token, idToken)
// 			if err != nil {
// 				return fmt.Errorf("failed to fetch access token: %v", err)
// 			}
// 			fmt.Printf("%s\n", res)
// 		}
// 	}
// 	var access_token []byte
// 	d <- access_token
// 	return nil
// }
