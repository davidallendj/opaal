package cmd

import (
	opaal "davidallendj/opaal/internal"
	"fmt"
	"os"
	"strconv"
	"strings"

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
		// print help and exit
		if len(args) <= 0 {
			err := cmd.Help()
			if err != nil {
				fmt.Printf("failed to print help message: %v\n", err)
			}
			os.Exit(0)
		}
	},
}

func Execute() {
	initialize()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start CLI: %s", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&config.Options.Verbose, "verbose", "v", false, "set the verbose flag")
	rootCmd.PersistentFlags().StringVarP(&confPath, "config", "c", "", "set the config path")
	rootCmd.PersistentFlags().StringVar(&config.Options.CachePath, "cache", "", "set the cache path")
}

func initialize() {
	initConfig()
	initEnv()
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

func initEnv() {
	// set environment variables before by CLI, but after config
	err := parseEnv("OPAAL_LOGIN_HOST", &config.Server.Host)
	_ = err
	err = parseEnv("OPAAL_LOGIN_PORT", &config.Server.Port)
	err = parseEnv("OPAAL_IDP_HOST", &config.Server.Issuer.Host)
	err = parseEnv("OPAAL_IDP_PORT", &config.Server.Issuer.Port)

	// authentication env vars
	err = parseEnv("OPAAL_IDP_REGISTERED_CLIENTS", &config.Server.Issuer.Clients)
	err = parseEnv("OPAAL_AUTHN_CLIENTS", &config.Authentication.Clients)

	// authorization token env vars
	err = parseEnv("OPAAL_AUTHZ_TOKEN_FORWARDING", &config.Authorization)
	err = parseEnv("OPAAL_AUTHZ_TOKEN_REFRESH", &config.Authorization.Token.Refresh)
	err = parseEnv("OPAAL_AUTHZ_TOKEN_DURATION", &config.Authorization.Token.Duration)
	err = parseEnv("OPAAL_AUTHZ_TOKEN_SCOPE", &config.Authorization.Token.Scope)

	// authorization endpoint env vars
	err = parseEnv("OPAAL_AUTHZ_KEY_PATH", &config.Authorization.KeyPath)
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_ISSUER", &config.Authorization.Endpoints.Issuer)
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_CONFIG", &config.Authorization.Endpoints.Config)
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_JWKS", &config.Authorization.Endpoints.JwksUri)
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_TRUSTED_ISSUER", &config.Authorization.Endpoints.TrustedIssuers)
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_CLIENTS", &config.Authorization.Endpoints.Clients)
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_AUTHORIZE", &config.Authorization.Endpoints.Authorize)
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_REGISTER", &config.Authorization.Endpoints.Register)
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_TOKEN", &config.Authorization.Endpoints.Token)

	// other miscellaneous option env vars
	err = parseEnv("OPAAL_OPT_VERBOSE", &config.Options.Verbose)
	err = parseEnv("OPAAL_OPT_RUN_ONCE", &config.Options.RunOnce)
	err = parseEnv("OPAAL_OPT_OPEN_BROWSER", &config.Options.OpenBrowser)
	err = parseEnv("OPAAL_OPT_CACHE_ONLY", &config.Options.CacheOnly)
	err = parseEnv("OPAAL_OPT_CACHE_PATH", &config.Options.CachePath)

}

func parseEnv(evar string, v interface{}) error {
	if val := os.Getenv(evar); val != "" {
		switch vp := v.(type) {
		case *int:
			var temp int64
			temp, err := strconv.ParseInt(val, 0, 64)
			if err == nil {
				*vp = int(temp)
			}
		case *uint:
			var temp uint64
			temp, err := strconv.ParseUint(val, 0, 64)
			if err == nil {
				*vp = uint(temp)
			}
		case *string:
			*vp = val
		case *bool:
			switch strings.ToLower(val) {
			case "0", "off", "no", "false":
				*vp = false
			case "1", "on", "yes", "true":
				*vp = true
			default:
				return fmt.Errorf("unrecognized bool value: '%s'", val)
			}
		case *[]string:
			*vp = strings.Split(val, ",")
		default:
			// try unmarshaling into an object using JSON
			// err := json.Unmarshal([]byte(val), &v)
			// if err != nil {
			// 	return fmt.Errorf("invalid type for receiving ENV variable value %T", v)
			// }
			return fmt.Errorf("invalid type for receiving ENV variable value %T", v)
		}
	}
	return nil
}
