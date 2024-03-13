package opaal

import (
	cache "davidallendj/opaal/internal/cache/sqlite"
	"davidallendj/opaal/internal/flows"
	"davidallendj/opaal/internal/oauth"
	"davidallendj/opaal/internal/oidc"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func Login(config *Config, client *oauth.Client, provider *oidc.IdentityProvider) error {
	if config == nil {
		return fmt.Errorf("config is not valid")
	}

	// make cache if it's not where expect
	_, err := cache.CreateIdentityProvidersIfNotExists(config.Options.CachePath)
	if err != nil {
		fmt.Printf("failed to create cache: %v\n", err)
	}

	if config.Options.FlowType == "authorization_code" {
		// build the authorization URL to redirect user for social sign-in
		var state = ""
		if config.Authentication.Flows["authorization-code"]["state"] != "" {
			state = config.Authentication.Flows["authorization-code"]["state"]
		}

		// print the authorization URL for sharing
		var authorizationUrl = client.BuildAuthorizationUrl(provider.Endpoints.Authorization, state)
		server := NewServerWithConfig(config)
		fmt.Printf("Login with identity provider:\n\n  %s/login\n  %s\n\n",
			server.GetListenAddr(), authorizationUrl,
		)

		var button = MakeButton(authorizationUrl, "Login with "+client.Name)

		// authorize oauth client and listen for callback from provider
		fmt.Printf("Waiting for authorization code redirect @%s/oidc/callback...\n", server.GetListenAddr())
		eps := flows.JwtBearerEndpoints{
			Token:          config.Authorization.Endpoints.Token,
			TrustedIssuers: config.Authorization.Endpoints.TrustedIssuers,
			Register:       config.Authorization.Endpoints.Register,
		}
		params := flows.JwtBearerFlowParams{
			Client:           oauth.NewClient(),
			IdentityProvider: provider,
			TrustedIssuer: &oauth.TrustedIssuer{
				AllowAnySubject: false,
				Issuer:          server.Addr,
				Subject:         "opaal",
				ExpiresAt:       time.Now().Add(time.Second * 3600),
			},
			Verbose: config.Options.Verbose,
		}
		err = server.Login(button, provider, client, eps, params)
		if errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("\n=========================================\nServer closed.\n=========================================\n\n")
		} else if err != nil {
			return fmt.Errorf("failed to start server: %s", err)
		}

	} else if config.Options.FlowType == "client_credentials" {
		err := NewClientCredentialsFlowWithConfig(config, client)
		if err != nil {
			fmt.Printf("failed to complete client credentials flow: %v", err)
		}
	} else {
		return fmt.Errorf("invalid grant type (options: authorization_code, client_credentials)")
	}

	return nil
}

func MakeButton(url string, text string) string {
	html := "<input type=\"button\" "
	html += "class=\"button\" "
	html += fmt.Sprintf("onclick=\"window.location.href='%s';\" ", url)
	html += fmt.Sprintf("value=\"%s\"", text)
	return html
	// return "<a href=\"" + url + "\"> " + text + "</a>"
}
