package cmd

import (
	opaal "davidallendj/opaal/internal"
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

var exampleCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start an simple identity provider server",
	Long:  "The built-in identity provider is not (nor meant to be) a complete OIDC implementation and behaves like an external IdP",
	Run: func(cmd *cobra.Command, args []string) {
		s := opaal.NewServerWithConfig(&config)
		// FIXME: change how the server address is set with `NewServerWithConfig`
		s.Server.Addr = fmt.Sprintf("%s:%d", s.Issuer.Host, s.Issuer.Port)
		err := s.StartIdentityProvider()
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("Identity provider server closed.\n")
		} else if err != nil {
			fmt.Errorf("failed to start server: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(exampleCmd)
}
