package cmd

import (
	opaal "davidallendj/opaal/internal"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	configPath = ""
	config     opaal.Config
)
var rootCmd = &cobra.Command{
	Use:   "oidc",
	Short: "An experimental OIDC helper tool for handling logins",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start CLI: %s", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "set the config path")
}
