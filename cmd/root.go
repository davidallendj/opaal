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

func initEnv() error {
	// set environment variables before by CLI, but after config
	var errList []error
	err := parseEnv("OPAAL_LOGIN_HOST", &config.Server.Host)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_LOGIN_HOST: %q", err))
	}
	err = parseEnv("OPAAL_LOGIN_PORT", &config.Server.Port)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_LOGIN_PORT: %q", err))
	}
	err = parseEnv("OPAAL_IDP_HOST", &config.Server.Issuer.Host)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_IDP_HOST: %q", err))
	}
	err = parseEnv("OPAAL_IDP_PORT", &config.Server.Issuer.Port)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_IDP_PORT: %q", err))
	}

	// authentication env vars
	err = parseEnv("OPAAL_IDP_REGISTERED_CLIENTS", &config.Server.Issuer.Clients)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_IDP_REGISTERED_CLIENTS: %q", err))
	}
	err = parseEnv("OPAAL_AUTHN_CLIENTS", &config.Authentication.Clients)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHN_CLIENTS: %q", err))
	}

	// authorization token env vars
	err = parseEnv("OPAAL_AUTHZ_TOKEN_FORWARDING", &config.Authorization)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_TOKEN_FORWARDING: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_TOKEN_REFRESH", &config.Authorization.Token.Refresh)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_TOKEN_REFRESH: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_TOKEN_DURATION", &config.Authorization.Token.Duration)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_TOKEN_DURATION: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_TOKEN_SCOPE", &config.Authorization.Token.Scope)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_TOKEN_SCOPE: %q", err))
	}

	// authorization endpoint env vars
	err = parseEnv("OPAAL_AUTHZ_KEY_PATH", &config.Authorization.KeyPath)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_KEY_PATH: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_ISSUER", &config.Authorization.Endpoints.Issuer)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_ENDPOINT_ISSUER: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_CONFIG", &config.Authorization.Endpoints.Config)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_ENDPOINT_CONFIG: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_JWKS", &config.Authorization.Endpoints.JwksUri)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_ENDPOINT_JWKS: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_TRUSTED_ISSUER", &config.Authorization.Endpoints.TrustedIssuers)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_ENDPOINT_TRUSTED_ISSUER: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_CLIENTS", &config.Authorization.Endpoints.Clients)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_ENDPOINT_CILENTS: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_AUTHORIZE", &config.Authorization.Endpoints.Authorize)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_ENDPOINT_AUTHORIZE: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_REGISTER", &config.Authorization.Endpoints.Register)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_ENDPOINT_REGISTER: %q", err))
	}
	err = parseEnv("OPAAL_AUTHZ_ENDPOINT_TOKEN", &config.Authorization.Endpoints.Token)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_AUTHZ_ENDPOINT_TOKEN: %q", err))
	}

	// other miscellaneous option env vars
	err = parseEnv("OPAAL_OPT_VERBOSE", &config.Options.Verbose)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_OPT_VERBOSE: %q", err))
	}
	err = parseEnv("OPAAL_OPT_RUN_ONCE", &config.Options.RunOnce)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_OPT_RUN_ONCE: %q", err))
	}
	err = parseEnv("OPAAL_OPT_OPEN_BROWSER", &config.Options.OpenBrowser)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_OPT_OPEN_BROWSER: %q", err))
	}
	err = parseEnv("OPAAL_OPT_CACHE_ONLY", &config.Options.CacheOnly)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_OPT_CACHE_ONLY: %q", err))
	}
	err = parseEnv("OPAAL_OPT_CACHE_PATH", &config.Options.CachePath)
	if err != nil {
		errList = append(errList, fmt.Errorf("OPAAL_OPT_CACHE_PATH: %q", err))
	}
	if len(errList) > 0 {
		err = fmt.Errorf("Error(s) parsing environment variables: %v", errList)
	}
	return err
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
