package opaal

type ActionUrls struct {
	Identities      string `yaml:"identities"`
	TrustedIssuers  string `yaml:"trusted-issuers"`
	AccessToken     string `yaml:"access-token"`
	ServerConfig    string `yaml:"server-config"`
	JwksUri         string `yaml:"jwks_uri"`
	Login           string `yaml:"login"`
	LoginFlowId     string `yaml:"login-flow-id"`
	RegisterClient  string `yaml:"register-client"`
	AuthorizeClient string `yaml:"authorize-client"`
}

func HasRequiredParams(config *Config) bool {
	return config.Client.Id != "" && config.Client.Secret != ""
}
