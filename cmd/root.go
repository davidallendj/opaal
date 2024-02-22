package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configPath = ""
var rootCmd = &cobra.Command{
	Use:   "oidc",
	Short: "An experimental OIDC helper tool for handling logins",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&configPath, "config", "", "set the config path")
}
