package flows

import (
	"crypto/rand"
	"crypto/rsa"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/davidallendj/go-utils/cryptox"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JwtBearerFlowParams struct {
	AccessToken      string
	IdToken          string
	IdentityProvider *oidc.IdentityProvider
	TrustedIssuer    *oauth.TrustedIssuer
	Client           *oauth.Client
	Refresh          bool
	Verbose          bool
	KeyPath          string
}

type JwtBearerFlowEndpoints struct {
	TrustedIssuers string
	Token          string
	Clients        string
	Register       string
}

func NewJwtBearerFlow(eps JwtBearerFlowEndpoints, params JwtBearerFlowParams) (string, error) {
	// 1. verify that the JWT from the issuer is valid using all keys
	var (
		idp           = params.IdentityProvider
		accessToken   = params.AccessToken
		idToken       = params.IdToken
		client        = params.Client
		trustedIssuer = params.TrustedIssuer
		verbose       = params.Verbose
	)
	if accessToken != "" {
		_, err := jws.Verify([]byte(accessToken), jws.WithKeySet(idp.KeySet), jws.WithValidateKey(true))
		if err != nil {
			return "", fmt.Errorf("failed to verify access token: %v", err)
		}
	}

	if idToken != "" {
		_, err := jws.Verify([]byte(idToken), jws.WithKeySet(idp.KeySet), jws.WithValidateKey(true))
		if err != nil {
			return "", fmt.Errorf("failed to verify ID token: %v", err)
		}
	}

	// TODO: 2. Check if we are already registered as a trusted issuer with authorization server...

	// 3.a if not, create a new JWKS (or just JWK) to be verified
	var (
		keyPath    string = params.KeyPath
		privateJwk jwk.Key
		publicJwk  jwk.Key
	)
	rawPrivateKey, err := os.ReadFile(keyPath)
	if err != nil {
		if verbose {
			fmt.Printf("failed to read private key...generating a new one.\n")
		}
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", fmt.Errorf("failed to generate new RSA key: %v", err)
		}
		privateJwk, publicJwk, err = GenerateJwkKeyPairFromPrivateKey(privateKey) // FIXME: needs to pull correct version from cryptox
		if err != nil {
			return "", fmt.Errorf("failed to generate JWK pair from private key: %v", err)
		}
		// save new key to key path to reuse later
		b := cryptox.MarshalRSAPrivateKey(privateKey)
		err = os.WriteFile(keyPath, b, os.ModePerm)
		if err != nil {
			fmt.Printf("failed to write private key to file: %v\n", err)
		}
	} else {
		privateKey, err := cryptox.GenerateRSAPrivateKey(rawPrivateKey)
		if err != nil {
			return "", fmt.Errorf("failed to generate RSA key from string: %v", err)
		}
		privateJwk, publicJwk, err = cryptox.GenerateJwkKeyPairFromPrivateKey(privateKey)
		if err != nil {
			return "", fmt.Errorf("failed to generate JWK pair from private key: %v", err)
		}
	}

	// add more required claims and validate
	publicJwk.Set("kid", uuid.New().String())
	publicJwk.Set("use", "sig")
	if err := publicJwk.Validate(); err != nil {
		return "", fmt.Errorf("failed to validate public JWK: %v", err)
	}
	trustedIssuer.PublicKey = publicJwk

	// add offline_access scope to enable refresh tokens
	if params.Refresh {
		trustedIssuer.Scope = append(trustedIssuer.Scope, "offline_access")
	}

	// 3.b ...and then, add opaal's server host as a trusted issuer with JWK
	if verbose {
		fmt.Printf("Attempting to add issuer to authorization server...\n")
	}
	res, err := client.AddTrustedIssuer(
		eps.TrustedIssuers,
		trustedIssuer,
	)
	if err != nil {
		return "", fmt.Errorf("failed to add trusted issuer: %v", err)
	}
	fmt.Printf("trusted issuer: %v\n", string(res))
	// TODO: add trusted issuer to cache if successful

	// 4. create a new JWT based on the claims from the identity provider and sign
	parsedIdToken, err := jwt.ParseString(idToken, jwt.WithKeySet(idp.KeySet))
	if err != nil {
		return "", fmt.Errorf("failed to parse ID token: %v", err)
	}

	payload := parsedIdToken.PrivateClaims()
	payload["iss"] = trustedIssuer.Issuer
	payload["aud"] = []string{eps.Token}
	payload["iat"] = time.Now().Unix()
	payload["nbf"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(time.Second * 3600 * 16).Unix()
	payload["sub"] = "opaal"

	// include the offline_access scope if refresh tokens are enabled
	if params.Refresh {
		v, ok := payload["scope"]
		if !ok {
			payload["scope"] = []string{"offline_access"}
		} else {
			// FIXME: probably should not assume scope is []string even though it should be
			scope := v.([]string)
			scope = append(scope, "offline_access")
			payload["scope"] = scope
		}

		// also include offline_access in client to make request
		client.Scope = append(client.Scope, "offline_access")
	}
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %v", err)
	}
	newJwt, err := jws.Sign(payloadJson, jws.WithJSON(), jws.WithKey(jwa.RS256, privateJwk))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	// 5. dynamically register new OAuth client and authorize it to make jwt_bearer request
	fmt.Printf("Registering new OAuth2 client with authorization server...\n")
	res, err = client.RegisterOAuthClient(eps.Register, []oauth.GrantType{oauth.JwtBearer})
	if err != nil {
		return "", fmt.Errorf("failed to register client: %v", err)
	}
	fmt.Printf("%v\n", string(res))

	// extract the client info from response
	var clientData map[string]any
	err = json.Unmarshal(res, &clientData)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal client data: %v", err)
	} else {
		// check for error first
		errJson := clientData["error"]
		if errJson == nil {
			client.Id = clientData["client_id"].(string)
			client.Secret = clientData["client_secret"].(string)
		} else {
			// delete client and try to create again
			fmt.Printf("Attempting to delete client...\n")
			err := client.DeleteOAuthClient(eps.Clients)
			if err != nil {
				return "", fmt.Errorf("failed to delete OAuth client: %v", err)
			}
			fmt.Printf("Attempting to re-create client...\n")
			res, err := client.CreateOAuthClient(eps.Clients, []oauth.GrantType{oauth.JwtBearer})
			if err != nil {
				return "", fmt.Errorf("failed to register client: %v", err)
			}
			fmt.Printf("%v\n", string(res))
		}
	}
	// TODO: add OAuth client to cache if successfully

	// authorize the client
	// fmt.Printf("Attempting to authorize client...\n")
	// res, err = client.AuthorizeOAuthClient(config.Authorization.RequestUrls.Authorize)
	// if err != nil {
	// 	return fmt.Errorf("failed to authorize client: %v", err)
	// }
	// fmt.Printf("%v\n", string(res))

	// 6. send JWT to authorization server and receive a access token
	if eps.Token != "" {
		fmt.Printf("Fetching access token from authorization server...\n")
		fmt.Printf("jwt: %s\n", string(newJwt))
		res, err := client.PerformJwtBearerTokenGrant(eps.Token, string(newJwt))
		if err != nil {
			return "", fmt.Errorf("failed to fetch access token: %v", err)
		}
		// extract token from response if there are no errors
		var data map[string]any
		err = json.Unmarshal(res, &data)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal response: %v", err)
		}
		if data["error"] != nil {
			return "", fmt.Errorf("the authorization server returned an error (%v): %v", data["error"], data["error_description"])
		}
		fmt.Printf("%s\n", res)

		err = json.Unmarshal(res, &data)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal access token: %v", err)
		}
		return data["access_token"].(string), nil
	} else {
		return "", fmt.Errorf("token endpoint not set")
	}

	return string(res), nil
}

func ForwardToken(eps JwtBearerFlowEndpoints, params JwtBearerFlowParams) error {
	var (
		client  = params.Client
		idToken = params.IdToken
		idp     = params.IdentityProvider
		verbose = params.Verbose
	)

	// fetch JWKS and add issuer to authentication server to submit ID token
	if verbose {
		fmt.Printf("Fetching JWKS from authentication server for verification...\n")
	}
	err := idp.FetchJwks()
	if err != nil {
		return fmt.Errorf("failed to fetch JWK: %v", err)
	} else {
		if verbose {
			fmt.Printf("Successfully retrieved JWK from authentication server.\n\n")
			fmt.Printf("Attempting to add issuer to authorization server...\n")
		}

		ti := &oauth.TrustedIssuer{
			Issuer:    idp.Issuer,
			Subject:   "1",
			ExpiresAt: time.Now().Add(time.Second * 3600),
		}
		res, err := client.AddTrustedIssuer(
			eps.TrustedIssuers,
			ti,
		)
		if err != nil {
			return fmt.Errorf("failed to add trusted issuer: %v", err)
		}
		if verbose {
			fmt.Printf("%v\n", string(res))
		}
	}

	// try and register a new client with authorization server
	if verbose {
		fmt.Printf("Registering new OAuth2 client with authorization server...\n")
	}
	res, err := client.RegisterOAuthClient(eps.Register, []oauth.GrantType{oauth.JwtBearer})
	if err != nil {
		return fmt.Errorf("failed to register client: %v", err)
	}
	if verbose {
		fmt.Printf("%v\n", string(res))
	}

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
			err := client.DeleteOAuthClient(eps.Clients)
			if err != nil {
				return fmt.Errorf("failed to delete OAuth client: %v", err)
			}
			fmt.Printf("Attempting to re-create client...\n")
			res, err := client.CreateOAuthClient(eps.Clients, []oauth.GrantType{oauth.JwtBearer})
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
	if eps.Token != "" {
		if verbose {
			fmt.Printf("Fetching access token from authorization server...\n")
		}
		res, err := client.PerformJwtBearerTokenGrant(eps.Token, idToken)
		if err != nil {
			return fmt.Errorf("failed to fetch access token: %v", err)
		}
		if verbose {
			fmt.Printf("%s\n", res)
		}
	} else {
		return fmt.Errorf("token endpoint is not set")
	}
	return nil
}

func GenerateJwkKeyPairFromPrivateKey(privateKey *rsa.PrivateKey) (jwk.Key, jwk.Key, error) {
	privateJwk, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create private JWK: %v", err)
	}
	publicJwk, err := jwk.PublicKeyOf(privateJwk)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create public JWK: %v", err)
	}
	return privateJwk, publicJwk, nil
}
