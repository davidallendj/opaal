package oauth

type Client struct {
	Id     string
	Secret string
	Issuer string
}

func NewClient() *Client {
	return &Client{
		Id:     "",
		Secret: "",
		Issuer: "",
	}
}
