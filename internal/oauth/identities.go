package oauth

import (
	"fmt"
	"net/http"

	"github.com/davidallendj/go-utils/httpx"
)

func (client *Client) CreateIdentity(url string, idToken string) error {
	// kratos endpoint: /admin/identities
	body := []byte(`{
		"schema_id": "preset://email",
		"traits": {
			"email": "docs@example.org"
		}
	}`)
	headers := httpx.Headers{
		"Content-Type":  "application/json",
		"Authorization": fmt.Sprintf("Bearer %s", idToken),
	}
	_, _, err := httpx.MakeHttpRequest(url, http.MethodPost, body, headers)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}
	return nil
}

func (client *Client) FetchIdentities(remoteUrl string) ([]byte, error) {
	_, b, err := httpx.MakeHttpRequest(remoteUrl, http.MethodGet, []byte{}, httpx.Headers{})
	return b, err
}
