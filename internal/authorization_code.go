package opaal

import (
	"crypto/rand"
	"crypto/rsa"
	"davidallendj/opaal/internal/oidc"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/davidallendj/go-utils/util"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TODO: change authorization code flow to use these instead
type AuthorizationCodeFlowEndpoints struct {
	Login         string
	Token         string
	Identities    string
	TrustedIssuer string
	Register      string
}

func AuthorizationCodeWithConfig(config *Config, server *Server, client *Client, idp *oidc.IdentityProvider) error {
	// check preconditions are met
	err := verifyParams(config, server, client, idp)
	if err != nil {
		return err
	}

	// build the authorization URL to redirect user for social sign-in
	state := config.Authentication.Flows["authorization_code"]["state"]
	var authorizationUrl = client.BuildAuthorizationUrl(idp.Endpoints.Authorization, state)

	// print the authorization URL for sharing
	fmt.Printf("Login with identity provider:\n\n  %s/login\n  %s\n\n",
		server.GetListenAddr(), authorizationUrl,
	)

	// automatically open browser to initiate login flow (only useful for testing and debugging)
	if config.Options.OpenBrowser {
		util.OpenUrl(authorizationUrl)
	}

	// authorize oauth client and listen for callback from provider
	fmt.Printf("Waiting for authorization code redirect @%s/oidc/callback...\n", server.GetListenAddr())
	code, err := server.WaitForAuthorizationCode(authorizationUrl, "")
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("\n=========================================\nServer closed.\n=========================================\n\n")
	} else if err != nil {
		return fmt.Errorf("failed to start server: %s", err)
	}

	// start up another server in background to listen for success or failures
	d := StartListener(server)

	// use code from response and exchange for bearer token (with ID token)
	bearerToken, err := client.FetchTokenFromAuthenticationServer(
		code,
		idp.Endpoints.Token,
		state,
	)
	if err != nil {
		return fmt.Errorf("failed to fetch token from issuer: %v", err)
	}
	// fmt.Printf("%v\n", string(bearerToken))

	// unmarshal data to get id_token and access_token
	var data map[string]any
	err = json.Unmarshal([]byte(bearerToken), &data)
	if err != nil || data == nil {
		return fmt.Errorf("failed to unmarshal token: %v", err)
	}

	// make sure we have an ID token
	if data["id_token"] == nil {
		return fmt.Errorf("no ID token found...aborting")
	}

	// extract ID token from bearer as JSON string for easy consumption
	idToken := data["id_token"].(string)
	idJwtSegments, err := util.DecodeJwt(idToken)
	if err != nil {
		fmt.Printf("failed to parse ID token: %v\n", err)
	} else {
		fmt.Printf("id_token: %v\n", idToken)
		if config.Options.DecodeIdToken {
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
		fmt.Printf("access_token (from identity provider): %v\n", accessToken)
		if config.Options.DecodeIdToken {
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

	if !config.Options.ForwardToken {

		// TODO: implement our own JWT to send to Hydra
		// 1. verify that the JWT from the issuer is valid
		key, ok := idp.Jwks.Key(0)
		if !ok {
			return fmt.Errorf("no key found in key set")
		}

		parsedIdToken, err := jwt.ParseString(idToken, jwt.WithKey(jwa.RS256, key))
		if err != nil {
			return fmt.Errorf("failed to parse ID token: %v", err)
		}
		_, err = jwt.ParseString(accessToken, jwt.WithKeySet(idp.Jwks))
		if err != nil {
			return fmt.Errorf("failed to parse access token: %v", err)
		}

		_, err = jws.Verify([]byte(idToken), jws.WithKeySet(idp.Jwks), jws.WithValidateKey(true))
		if err != nil {
			return fmt.Errorf("failed to verify JWT: %v", err)
		}

		// 2. create a new JWKS (or just JWK) to be verified
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate private RSA k-ey: %v", err)
		}
		privateJwk, err := jwk.FromRaw(privateKey)
		if err != nil {
			return fmt.Errorf("failed to create private JWK: %v", err)
		}
		publicJwk, err := jwk.PublicKeyOf(privateJwk)
		if err != nil {
			return fmt.Errorf("failed to create public JWK: %v", err)
		}
		publicJwk.Set("kid", uuid.New().String())

		// 3. add opaal's server host as a trusted issuer with JWK
		fmt.Printf("Attempting to add issuer to authorization server...\n")
		res, err := client.AddTrustedIssuer(
			config.Authorization.RequestUrls.TrustedIssuers,
			server.Addr,
			publicJwk,
			"1",
			time.Second*3600,
		)
		if err != nil {
			return fmt.Errorf("failed to add trusted issuer: %v", err)
		}
		fmt.Printf("%v\n", string(res))

		// 4. create a new JWT based on the claims from the identity provider and sign
		payload := parsedIdToken.PrivateClaims()
		payload["iss"] = server.Addr
		payload["aud"] = []string{config.Authorization.RequestUrls.Token}
		payload["iat"] = time.Now().Unix()
		payload["nbf"] = time.Now().Unix()
		payload["exp"] = time.Now().Add(time.Second * 3600).Unix()
		payload["sub"] = "1"
		payloadJson, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %v", err)
		}
		newToken, err := jws.Sign(payloadJson, jws.WithJSON(), jws.WithKey(jwa.RS256, privateJwk))
		if err != nil {
			return fmt.Errorf("failed to sign token: %v", err)
		}

		// sig = rsasha256(b64urlencode(header) + "." + b64urlencode(payload))
		// signature := util.EncodeBase64() + util.EncodeBase64() +

		// 5. dynamically register new OAuth client and authorize it
		fmt.Printf("Registering new OAuth2 client with authorization server...\n")
		res, err = client.RegisterOAuthClient(config.Authorization.RequestUrls.Register, []string{})
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
			// check for error first
			errJson := clientData["error"]
			if errJson == nil {
				client.Id = clientData["client_id"].(string)
				client.Secret = clientData["client_secret"].(string)
			} else {
				// delete client and create again
				fmt.Printf("Attempting to delete client...\n")
				err := client.DeleteOAuthClient(config.Authorization.RequestUrls.Clients)
				if err != nil {
					return fmt.Errorf("failed to delete OAuth client: %v", err)
				}
				fmt.Printf("Attempting to re-create client...\n")
				res, err := client.CreateOAuthClient(config.Authorization.RequestUrls.Clients, []string{})
				if err != nil {
					return fmt.Errorf("failed to register client: %v", err)
				}
				fmt.Printf("%v\n", string(res))
			}
		}

		// authorize the client
		// fmt.Printf("Attempting to authorize client...\n")
		// res, err = client.AuthorizeOAuthClient(config.Authorization.RequestUrls.Authorize)
		// if err != nil {
		// 	return fmt.Errorf("failed to authorize client: %v", err)
		// }
		// fmt.Printf("%v\n", string(res))

		// 6. send JWT to authorization server and receive a access token
		if config.Authorization.RequestUrls.Token != "" {
			fmt.Printf("Fetching access token from authorization server...\n")
			res, err := client.PerformTokenGrant(config.Authorization.RequestUrls.Token, string(newToken))
			if err != nil {
				return fmt.Errorf("failed to fetch access token: %v", err)
			}
			fmt.Printf("%s\n", res)
		}
	} else {
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
		// if config.RequestUrls.Identities != "" {
		// 	fmt.Printf("Attempting to create a new identity...\n")
		// 	err := client.CreateIdentity(config.RequestUrls.Identities, idToken)
		// 	if err != nil {
		// 		return fmt.Errorf("failed to create new identity: %v", err)
		// 	}
		// 	_, err = client.FetchIdentities(config.RequestUrls.Identities)
		// 	if err != nil {
		// 		return fmt.Errorf("failed to fetch identities: %v", err)
		// 	}
		// 	fmt.Printf("Created new identity successfully.\n\n")
		// }

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
		err = idp.FetchJwks()
		if err != nil {
			return fmt.Errorf("failed to fetch JWK: %v", err)
		} else {
			fmt.Printf("Successfully retrieved JWK from authentication server.\n\n")
			fmt.Printf("Attempting to add issuer to authorization server...\n")
			res, err := client.AddTrustedIssuerWithIdentityProvider(
				config.Authorization.RequestUrls.TrustedIssuers,
				idp,
				subject,
				time.Duration(1000),
			)
			if err != nil {
				return fmt.Errorf("failed to add trusted issuer: %v", err)
			}
			fmt.Printf("%v\n", string(res))
		}

		// add client ID to audience
		audience = append(audience, client.Id)
		audience = append(audience, "http://127.0.0.1:4444/oauth2/token")

		// try and register a new client with authorization server
		fmt.Printf("Registering new OAuth2 client with authorization server...\n")
		res, err := client.RegisterOAuthClient(config.Authorization.RequestUrls.Register, audience)
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
			// check for error first
			errJson := clientData["error"]
			if errJson == nil {
				client.Id = clientData["client_id"].(string)
				client.Secret = clientData["client_secret"].(string)
			} else {
				// delete client and create again
				fmt.Printf("Attempting to delete client...\n")
				err := client.DeleteOAuthClient(config.Authorization.RequestUrls.Clients)
				if err != nil {
					return fmt.Errorf("failed to delete OAuth client: %v", err)
				}
				fmt.Printf("Attempting to re-create client...\n")
				res, err := client.CreateOAuthClient(config.Authorization.RequestUrls.Clients, audience)
				if err != nil {
					return fmt.Errorf("failed to register client: %v", err)
				}
				fmt.Printf("%v\n", string(res))
			}
		}

		// authorize the client
		// fmt.Printf("Attempting to authorize client...\n")
		// res, err = client.AuthorizeOAuthClient(config.Authorization.RequestUrls.Authorize)
		// if err != nil {
		// 	return fmt.Errorf("failed to authorize client: %v", err)
		// }
		// fmt.Printf("%v\n", string(res))

		// use ID token/user info to fetch access token from authentication server
		if config.Authorization.RequestUrls.Token != "" {
			fmt.Printf("Fetching access token from authorization server...\n")
			res, err := client.PerformTokenGrant(config.Authorization.RequestUrls.Token, idToken)
			if err != nil {
				return fmt.Errorf("failed to fetch access token: %v", err)
			}
			fmt.Printf("%s\n", res)
		}
	}
	var access_token []byte
	d <- access_token
	return nil
}

func verifyParams(config *Config, server *Server, client *Client, idp *oidc.IdentityProvider) error {
	// make sure we have a valid server and client
	if server == nil {
		return fmt.Errorf("server not initialized or valid (server == nil)")
	}
	if client == nil {
		return fmt.Errorf("client not initialized or valid (client == nil)")
	}
	if idp == nil {
		return fmt.Errorf("identity provider not initialized or valid (idp == nil)")
	}
	// check if all appropriate parameters are set in config
	if !HasRequiredConfigParams(config) {
		return fmt.Errorf("required params not set correctly or missing")
	}
	return nil
}

func StartListener(server *Server) chan []byte {
	d := make(chan []byte)
	quit := make(chan bool)

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
	return d
}
