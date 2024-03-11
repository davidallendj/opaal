package cmd

import (
	opaal "davidallendj/opaal/internal"
	"fmt"
	"os"

	"github.com/davidallendj/go-utils/pathx"
	"github.com/spf13/cobra"
)

var (
	confPath = ""
	config   opaal.Config
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
	rootCmd.PersistentFlags().StringVarP(&confPath, "config", "c", "", "set the config path")
	rootCmd.PersistentFlags().StringVar(&config.Options.CachePath, "cache", "", "set the cache path")
}

func initConfig() {
	// load config if found or create a new one
	if confPath != "" {
		exists, err := pathx.PathExists(confPath)
		if err != nil {
			fmt.Printf("failed to load config")
			os.Exit(1)
		} else if exists {
			config = opaal.LoadConfig(confPath)
		} else {
			config = opaal.NewConfig()
		}
	}
}
