package server

import (
	"fmt"
	"net/http"
)

func Start(host string, port int) error {
	http.HandleFunc("/oauth/callback", getAuthorizationCode)
	err := http.ListenAndServe(host+":"+fmt.Sprintf("%d", port), nil)
	return err
}

func getAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("response from OIDC provider: %v\n", r)
}
