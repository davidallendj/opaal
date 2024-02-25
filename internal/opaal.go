package opaal

type ActionUrls struct {
	Identities     string `yaml:"identities"`
	TrustedIssuers string `yaml:"trusted-issuers"`
	AccessToken    string `yaml:"access-token"`
	ServerConfig   string `yaml:"server-config"`
	JwksUri        string `yaml:"jwks_uri"`
}

func hasRequiredParams(config *Config) bool {
	return config.Client.Id != "" && config.Client.Secret != ""
}
