package cmd

import (
	opaal "davidallendj/opaal/internal"
	cache "davidallendj/opaal/internal/cache/sqlite"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
)

var (
	client      oauth.Client
	target      string = ""
	targetIndex int    = -1
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Start the login flow",
	Run: func(cmd *cobra.Command, args []string) {
		for {
			// try and find client with valid identity provider config
			var provider *oidc.IdentityProvider
			if target != "" {
				// only try to use client with name give
				index := slices.IndexFunc(config.Authentication.Clients, func(c oauth.Client) bool {
					return target == c.Name
				})
				if index < 0 {
					fmt.Printf("could not find the target client listed by name")
					os.Exit(1)
				}
				client := config.Authentication.Clients[index]
				_, err := cache.GetIdentityProvider(config.Options.CachePath, client.Issuer)
				if err != nil {

				}

			} else if targetIndex >= 0 {
				// only try to use client by index
				targetCount := len(config.Authentication.Clients) - 1
				if targetIndex > targetCount {
					fmt.Printf("target index out of range (found %d)", targetCount)
				}
				client := config.Authentication.Clients[targetIndex]
				_, err := cache.GetIdentityProvider(config.Options.CachePath, client.Issuer)
				if err != nil {

				}
			} else {
				for _, c := range config.Authentication.Clients {
					// try to get identity provider info locally first
					_, err := cache.GetIdentityProvider(config.Options.CachePath, c.Issuer)
					if err != nil && !config.Options.CacheOnly {
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
					// only test the first if --run-all flag is not set
					if !config.Authentication.TestAllClients {
						fmt.Printf("stopping after first test...\n\n\n")
						break
					}
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
	loginCmd.Flags().BoolVar(&config.Options.RunOnce, "once", config.Options.RunOnce, "set whether to run login once and exit")
	loginCmd.Flags().StringVar(&config.Options.FlowType, "flow", config.Options.FlowType, "set the grant-type/authorization flow")
	loginCmd.Flags().BoolVar(&config.Options.CacheOnly, "cache-only", config.Options.CacheOnly, "only fetch identity provider configs stored locally")
	loginCmd.Flags().BoolVar(&config.Authentication.TestAllClients, "test-all", config.Authentication.TestAllClients, "test all clients in config for a valid provider")
	loginCmd.Flags().StringVar(&target, "target", "", "set target client to use from config by name")
	loginCmd.Flags().IntVar(&targetIndex, "index", -1, "set target client to use from config by index")
	loginCmd.MarkFlagsMutuallyExclusive("target", "index")
	rootCmd.AddCommand(loginCmd)
}
