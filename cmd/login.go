package cmd

import (
	"davidallendj/opal/internal/api"
	"davidallendj/opal/internal/oidc"
	"davidallendj/opal/internal/util"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func hasRequiredParams(config *Config) bool {
	return config.Client.Id != "" && config.Client.Secret != ""
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Start the login flow",
	Run: func(cmd *cobra.Command, args []string) {
		// load config if found
		if configPath != "" {
			exists, err := util.PathExists(configPath)
			if err != nil {
				fmt.Printf("failed to load config")
				os.Exit(1)
			} else if exists {
				config = LoadConfig(configPath)
			} else {
				config = NewConfig()
			}
		}
		// try and fetch server configuration if provided URL
		idp := oidc.NewIdentityProvider()
		if config.AuthEndpoints.ServerConfig != "" {
			idp.FetchServerConfig(config.AuthEndpoints.ServerConfig)
		} else {
			// otherwise, use what's provided in config file
			idp.Issuer = config.IdentityProvider.Issuer
			idp.Endpoints = config.IdentityProvider.Endpoints
			idp.Supported = config.IdentityProvider.Supported
		}

		// check if all appropriate parameters are set in config
		if !hasRequiredParams(&config) {
			fmt.Printf("client ID must be set\n")
			os.Exit(1)
		}

		// build the authorization URL to redirect user for social sign-in
		var authorizationUrl = util.BuildAuthorizationUrl(
			idp.Endpoints.Authorize,
			config.Client.Id,
			config.Client.RedirectUris,
			config.State,
			config.ResponseType,
			config.Scope,
		)

		// print the authorization URL for sharing
		serverAddr := fmt.Sprintf("%s:%d", config.IdentityProvider.Issuer)
		fmt.Printf(`Login with identity provider: 
			%s/login
			%s\n`,
			serverAddr, authorizationUrl,
		)

		// automatically open browser to initiate login flow (only useful for testing)
		if config.OpenBrowser {
			util.OpenUrl(authorizationUrl)
		}

		// authorize oauth client and listen for callback from provider
		fmt.Printf("Waiting for authorization code redirect @%s/oidc/callback...\n", serverAddr)
		code, err := api.WaitForAuthorizationCode(serverAddr, authorizationUrl)
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Server closed.\n")
		} else if err != nil {
			fmt.Printf("Error starting server: %s\n", err)
			os.Exit(1)
		}

		// use code from response and exchange for bearer token (with ID token)
		tokenString, err := api.FetchIssuerToken(
			code,
			idp.Endpoints.Token,
			config.Client,
			config.State,
		)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		// extract ID token from bearer as JSON string for easy consumption
		var data map[string]any
		json.Unmarshal([]byte(tokenString), &data)
		idToken := data["id_token"].(string)

		// create a new identity with identity and session manager if url is provided
		if config.AuthEndpoints.Identities != "" {
			api.CreateIdentity(config.AuthEndpoints.Identities, idToken)
			api.FetchIdentities(config.AuthEndpoints.Identities)
		}

		// fetch JWKS and add issuer to authentication server to submit ID token
		err = idp.FetchJwk("")
		if err != nil {
			fmt.Printf("failed to fetch JWK: %v\n", err)
		} else {
			api.AddTrustedIssuer(config.AuthEndpoints.TrustedIssuers, idp.Key)
		}

		// use ID token/user info to fetch access token from authentication server
		if config.AuthEndpoints.AccessToken != "" {
			api.FetchAccessToken(config.AuthEndpoints.AccessToken, config.Client.Id, idToken, config.Scope)
		}
	},
}

func init() {
	loginCmd.Flags().StringVar(&config.Client.Id, "client.id", config.Client.Id, "set the client ID")
	loginCmd.Flags().StringVar(&config.Client.Secret, "client.secret", config.Client.Secret, "set the client secret")
	loginCmd.Flags().StringSliceVar(&config.Client.RedirectUris, "redirect-uri", config.Client.RedirectUris, "set the redirect URI")
	loginCmd.Flags().StringVar(&config.ResponseType, "response-type", config.ResponseType, "set the response-type")
	loginCmd.Flags().StringSliceVar(&config.Scope, "scope", config.Scope, "set the scopes")
	loginCmd.Flags().StringVar(&config.State, "state", config.State, "set the state")
	loginCmd.Flags().StringVar(&config.Server.Host, "host", config.Server.Host, "set the listening host")
	loginCmd.Flags().IntVar(&config.Server.Port, "port", config.Server.Port, "set the listening port")
	loginCmd.Flags().BoolVar(&config.OpenBrowser, "open-browser", config.OpenBrowser, "automatically open link in browser")
	rootCmd.AddCommand(loginCmd)
}
