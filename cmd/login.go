package cmd

import (
	opaal "davidallendj/opaal/internal"
	"davidallendj/opaal/internal/oauth"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	client      oauth.Client
	scope       []string
	target      string = ""
	targetIndex int    = -1
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Start the login flow",
	Run: func(cmd *cobra.Command, args []string) {
		for {
			// start the listener
			err := opaal.Login(&config)
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
	loginCmd.Flags().StringSliceVar(&client.Scope, "client.scope", client.Scope, "set the identity provider scopes")
	loginCmd.Flags().StringSliceVar(&config.Authorization.Token.Scope, "token.scope", scope, "set the access token scope")
	loginCmd.Flags().StringVar(&config.Server.Host, "server.host", config.Server.Host, "set the listening host")
	loginCmd.Flags().IntVar(&config.Server.Port, "server.port", config.Server.Port, "set the listening port")
	loginCmd.Flags().BoolVar(&config.Options.OpenBrowser, "open-browser", config.Options.OpenBrowser, "automatically open link in browser")
	loginCmd.Flags().BoolVar(&config.Options.RunOnce, "once", config.Options.RunOnce, "set whether to run login once and exit")
	loginCmd.Flags().StringVar(&config.Options.FlowType, "flow", config.Options.FlowType, "set the grant-type/authorization flow")
	loginCmd.Flags().BoolVar(&config.Options.CacheOnly, "cache-only", config.Options.CacheOnly, "only fetch identity provider configs stored locally")
	loginCmd.Flags().BoolVar(&config.Authentication.TestAllClients, "test-all", config.Authentication.TestAllClients, "test all clients in config for a valid provider")
	loginCmd.Flags().StringVar(&target, "target.name", "", "set target client to use from config by name")
	loginCmd.Flags().IntVar(&targetIndex, "target.index", -1, "set target client to use from config by index")
	loginCmd.MarkFlagsMutuallyExclusive("target.name", "target.index")
	rootCmd.AddCommand(loginCmd)
}

func MakeButton(url string, text string) string {
	// check if we have http:// a
	html := "<input type=\"button\" "
	html += "class=\"button\" "
	html += fmt.Sprintf("onclick=\"window.location.href='%s';\" ", url)
	html += fmt.Sprintf("value=\"%s\"", text)
	return html
	// return "<a href=\"" + url + "\"> " + text + "</a>"
}
