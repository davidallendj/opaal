package cmd

import (
	opaal "davidallendj/opaal/internal"
	"fmt"
	"os"

	"github.com/davidallendj/go-utils/pathx"
	"github.com/spf13/cobra"
)

var (
	configPath = ""
	config     opaal.Config
)
var rootCmd = &cobra.Command{
	Use:   "opaal",
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
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "set the config path")
}

func initConfig() {
	// load config if found or create a new one
	if configPath != "" {
		exists, err := pathx.PathExists(configPath)
		if err != nil {
			fmt.Printf("failed to load config")
			os.Exit(1)
		} else if exists {
			config = opaal.LoadConfig(configPath)
		} else {
			config = opaal.NewConfig()
		}
	}
}
