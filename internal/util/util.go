package util

import (
	"encoding/base64"
	"math/rand"
	"net/url"
	"os"
	"strings"
)

func RandomString(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)
	b := make([]byte, n)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax letters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func BuildAuthorizationUrl(authEndpoint string, clientId string, redirectUri []string, state string, responseType string, scope []string) string {
	return authEndpoint + "?" + "client_id=" + clientId +
		"&redirect_uri=" + EncodeURL(strings.Join(redirectUri, ",")) +
		"&response_type=" + responseType +
		"&state=" + state +
		"&scope=" + strings.Join(scope, "+")
}

func EncodeURL(s string) string {
	return url.QueryEscape(s)
}

func EncodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
