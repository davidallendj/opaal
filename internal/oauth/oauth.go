package oauth

type Client struct {
	Id           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	RedirectUris []string `yaml:"redirect_uris"`
}

func NewClient() *Client {
	return &Client{
		Id:           "",
		Secret:       "",
		RedirectUris: []string{""},
	}
}
