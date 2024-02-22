package cmd

import (
	"davidallendj/oidc-auth/internal/oauth"
	"davidallendj/oidc-auth/internal/oidc"
	"davidallendj/oidc-auth/internal/server"
	"davidallendj/oidc-auth/internal/util"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var (
	host         string
	port         int
	redirectUri  = []string{""}
	state        = ""
	responseType = "code"
	scope        = []string{"email", "profile", "openid"}
	client       oauth.Client
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Start the login flow",
	Run: func(cmd *cobra.Command, args []string) {
		oidcProvider := oidc.NewOIDCProvider()
		var authorizationUrl = util.BuildAuthorizationUrl(
			oidcProvider.GetAuthorizeUrl(),
			client.Id,
			redirectUri,
			util.RandomString(20),
			responseType,
			[]string{"email", "profile", "openid"},
		)

		// print the authorization URL for the user to log in
		fmt.Printf("Login with identity provider: %s\n", authorizationUrl)

		// start a HTTP server to listen for callback responses
		fmt.Printf("Waiting for response from OIDC provider...\n")
		err := server.Start(host, port)
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("server closed\n")
		} else if err != nil {
			fmt.Printf("error starting server: %s\n", err)
			os.Exit(1)
		}

		// extract code from response and exchange for bearer token

		// extract ID token and save user info

		// create a new identity with Ory Kratos

		// use ID token/user info to get access token from Ory Hydra
	},
}

func init() {
	loginCmd.Flags().StringVar(&client.Id, "client.id", "", "set the client ID")
	loginCmd.Flags().StringSliceVar(&redirectUri, "redirect-uri", []string{""}, "set the redirect URI")
	loginCmd.Flags().StringVar(&responseType, "response-type", "code", "set the response-type")
	loginCmd.Flags().StringSliceVar(&scope, "scope", []string{"openid", "email"}, "set the scopes")
	loginCmd.Flags().StringVar(&state, "state", util.RandomString(20), "set the state")
	loginCmd.Flags().StringVar(&host, "host", "127.0.0.1", "set the listening host")
	loginCmd.Flags().IntVar(&port, "port", 3333, "set the listening port")
	rootCmd.AddCommand(loginCmd)
}
