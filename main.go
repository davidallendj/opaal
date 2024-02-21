package main

import (
	"davidallendj/ochami-auth/oidc"
	"strings"
)

var (
	clientId      = ""
	redirectUri   = ""
	state         = ""
	response_type = "code"
	userDB        = ""
)

func buildAuthorizationUrl(authEndpoint string, clientId string, redirectUri []string, state string, responseType string, scope []string) string {
	return authEndpoint + "?" + "cilent_id=" + clientId +
		"&redirect_url=" + strings.Join(redirectUri, ",") +
		"&response_type=" + responseType +
		"&state=" + state +
		"&scope=" + strings.Join(scope, "+")
}


func main() {
	client := oidc.NewOpenIDConnect()
	var authorizationUrl = buildAuthorizationUrl(
		client.
	)
	var tokenUrl = loginHost + tokenEndpoint
	// start a HTTP server to listen for callback responses
	// extract code from response and exchange for bearer token
	// extract ID token and save user info
	// use ID token/user info to get access token from Hydra
}
