package cmd

import (
	opaal "davidallendj/opaal/internal"
	"davidallendj/opaal/internal/oidc"
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

var (
	endpoints oidc.Endpoints
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start an simple, bare minimal identity provider server",
	Long:  "The built-in identity provider is not (nor meant to be) a complete OIDC implementation and behaves like an external IdP",
	Run: func(cmd *cobra.Command, args []string) {
		s := opaal.NewServerWithConfig(&config)
		// FIXME: change how the server address is set with `NewServerWithConfig`
		s.Server.Addr = fmt.Sprintf("%s:%d", s.Issuer.Host, s.Issuer.Port)
		err := s.StartIdentityProvider(endpoints)
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Identity provider server closed.\n")
		} else if err != nil {
			fmt.Printf("failed to start server: %v", err)
		}
	},
}

func init() {
	serveCmd.Flags().StringVar(&endpoints.Authorization, "endpoints.authorization", "", "set the authorization endpoint for the identity provider")
	serveCmd.Flags().StringVar(&endpoints.Token, "endpoints.token", "", "set the token endpoint for the identity provider")
	serveCmd.Flags().StringVar(&endpoints.JwksUri, "endpoints.jwks_uri", "", "set the JWKS endpoints for the identity provider")

	rootCmd.AddCommand(serveCmd)
}
