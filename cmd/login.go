package cmd

import (
	"davidallendj/oidc-auth/internal/oidc"
	"davidallendj/oidc-auth/internal/server"
	"davidallendj/oidc-auth/internal/util"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Start the login flow",
	Run: func(cmd *cobra.Command, args []string) {
		if configPath != "" {
			config = LoadConfig(configPath)
		} else {
			config = NewConfig()
		}
		oidcProvider := oidc.NewOIDCProvider()
		oidcProvider.Host = config.OIDCHost
		oidcProvider.Port = config.OIDCPort
		var authorizationUrl = util.BuildAuthorizationUrl(
			oidcProvider.GetAuthorizeUrl(),
			config.ClientId,
			config.RedirectUri,
			config.State,
			config.ResponseType,
			config.Scope,
		)

		// print the authorization URL for the user to log in
		fmt.Printf("Login with identity provider: %s\n", authorizationUrl)

		// authorize oauth client and listen for callback from provider
		fmt.Printf("Waiting for response from OIDC provider...\n")
		code, err := server.WaitForAuthorizationCode(config.Host, config.Port)
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("server closed\n")
		} else if err != nil {
			fmt.Printf("error starting server: %s\n", err)
			os.Exit(1)
		}

		// use code from response and exchange for bearer token
		server.FetchToken(code, oidcProvider.GetTokenUrl(), config.ClientId, config.ClientSecret, config.State, config.RedirectUri)

		// extract ID token and save user info

		// create a new identity with Ory Kratos

		// use ID token/user info to get access token from Ory Hydra
	},
}

func init() {
	loginCmd.Flags().StringVar(&config.ClientId, "client.id", config.ClientId, "set the client ID")
	loginCmd.Flags().StringSliceVar(&config.RedirectUri, "redirect-uri", config.RedirectUri, "set the redirect URI")
	loginCmd.Flags().StringVar(&config.ResponseType, "response-type", config.ResponseType, "set the response-type")
	loginCmd.Flags().StringSliceVar(&config.Scope, "scope", config.Scope, "set the scopes")
	loginCmd.Flags().StringVar(&config.State, "state", config.State, "set the state")
	loginCmd.Flags().StringVar(&config.Host, "host", config.Host, "set the listening host")
	loginCmd.Flags().IntVar(&config.Port, "port", config.Port, "set the listening port")
	rootCmd.AddCommand(loginCmd)
}
