package cmd

import "github.com/spf13/cobra"

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Create a new default config file",
	Run: func(cmd *cobra.Command, args []string) {
		// create a new config at all args (paths)
		for _, path := range args {
			_ = path
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
