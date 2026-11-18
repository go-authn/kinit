// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-authn/rp"
)

// openBrowser is replaced by tests.
var openBrowser = rp.OpenBrowser

// interactiveToken logs a person in at the provider with the RFC 8252
// loopback flow (go-authn/rp): their browser, their passkey, a public client.
// It returns an access token for the "kerberos" scope.
func interactiveToken(ctx context.Context, issuer, clientID string) (string, error) {
	p, err := rp.Discover(ctx, http.DefaultClient, issuer)
	if err != nil {
		return "", err
	}
	_, tok, _, err := rp.Loopback(ctx, p, rp.Config{
		ClientID: clientID,
		Scopes:   []string{"openid", "kerberos"},
	}, openBrowser, url.Values{})
	if err != nil {
		return "", fmt.Errorf("the login did not complete: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return "", errors.New("the provider gave no access token")
	}
	return tok.AccessToken, nil
}
