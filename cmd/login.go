package cmd

import (
	opaal "davidallendj/opaal/internal"
	"davidallendj/opaal/internal/db"
	"davidallendj/opaal/internal/oidc"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	client opaal.Client
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Start the login flow",
	Run: func(cmd *cobra.Command, args []string) {
		for {
			// try and find client with valid identity provider config
			var provider *oidc.IdentityProvider
			for _, c := range config.Authentication.Clients {
				// try to get identity provider info locally first
				_, err := db.GetIdentityProvider(config.Options.CachePath, c.Issuer)
				if err != nil && !config.Options.LocalOnly {
					fmt.Printf("fetching config from issuer: %v\n", c.Issuer)
					// try to get info remotely by fetching
					provider, err = oidc.FetchServerConfig(c.Issuer)
					if err != nil {
						fmt.Printf("failed to fetch server config: %v\n", err)
						continue
					}
					client = c
					// fetch the provider's JWKS
					err := provider.FetchJwks()
					if err != nil {
						fmt.Printf("failed to fetch JWKS: %v\n", err)
					}
					break
				}
			}

			if provider == nil {
				fmt.Printf("failed to retrieve provider config\n")
				os.Exit(1)
			}

			err := opaal.Login(&config, &client, provider)
			if err != nil {
				fmt.Printf("%v\n", err)
				os.Exit(1)
			} else if config.Options.RunOnce {
				break
			}
		}
	},
}

func init() {
	loginCmd.Flags().StringVar(&client.Id, "client.id", client.Id, "set the client ID")
	loginCmd.Flags().StringVar(&client.Secret, "client.secret", client.Secret, "set the client secret")
	loginCmd.Flags().StringSliceVar(&client.RedirectUris, "client.redirect-uris", client.RedirectUris, "set the redirect URI")
	loginCmd.Flags().StringSliceVar(&client.Scope, "client.scope", client.Scope, "set the scopes")
	loginCmd.Flags().StringVar(&config.Server.Host, "server.host", config.Server.Host, "set the listening host")
	loginCmd.Flags().IntVar(&config.Server.Port, "server.port", config.Server.Port, "set the listening port")
	loginCmd.Flags().BoolVar(&config.Options.OpenBrowser, "open-browser", config.Options.OpenBrowser, "automatically open link in browser")
	loginCmd.Flags().BoolVar(&config.Options.DecodeIdToken, "decode-id-token", config.Options.DecodeIdToken, "decode and print ID token from identity provider")
	loginCmd.Flags().BoolVar(&config.Options.DecodeAccessToken, "decore-access-token", config.Options.DecodeAccessToken, "decode and print access token from authorization server")
	loginCmd.Flags().BoolVar(&config.Options.RunOnce, "once", config.Options.RunOnce, "set whether to run login once and exit")
	loginCmd.Flags().StringVar(&config.Options.FlowType, "flow", config.Options.FlowType, "set the grant-type/authorization flow")
	loginCmd.Flags().BoolVar(&config.Options.LocalOnly, "local", config.Options.LocalOnly, "only fetch identity provider configs stored locally")
	rootCmd.AddCommand(loginCmd)
}
