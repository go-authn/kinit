// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-authn/rp"
)

// An unattended machine holds a key pair and no secret: it authenticates to
// the provider with private_key_jwt (RFC 7523 2.2, OpenID Connect Core 9), the
// client_credentials grant (RFC 6749 4.4), asking for the kerberos scope.
// go-authn/bridge's machine identities are what answers.

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// assertionLife is how long a client assertion is good for: bridge refuses
// more than five minutes.
const assertionLife = 2 * time.Minute

// loadMachineKey reads a PKCS#8 PEM private key: P-256 (ES256) or Ed25519
// (EdDSA). RSA is not offered: nothing here needs it.
func loadMachineKey(path string) (crypto.Signer, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, "", fmt.Errorf("%s: not a PKCS#8 PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, "", fmt.Errorf("%s: a P-256 key is needed (ES256)", path)
		}
		return k, "ES256", nil
	case ed25519.PrivateKey:
		return k, "EdDSA", nil
	}
	return nil, "", fmt.Errorf("%s: a P-256 or Ed25519 key is needed", path)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// clientAssertion signs the RFC 7523 2.2 assertion: iss and sub the client,
// aud the token endpoint, a short life and a jti nobody reuses.
func clientAssertion(key crypto.Signer, alg, kid, clientID, aud string, now time.Time) (string, error) {
	hdr := map[string]string{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss": clientID, "sub": clientID, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(assertionLife).Unix(), "jti": b64(jti),
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signing := b64(hb) + "." + b64(cb)
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		d := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			return "", err
		}
		// JWS ES256 (RFC 7518 3.4): R || S, 32 bytes each.
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(signing))
	default:
		return "", errors.New("unsupported key")
	}
	return signing + "." + b64(sig), nil
}

// machineToken gets an access token with the kerberos scope for the machine
// whose private key is in keyFile.
func machineToken(ctx context.Context, hc *http.Client, issuer, clientID, keyFile, kid string) (string, error) {
	key, alg, err := loadMachineKey(keyFile)
	if err != nil {
		return "", err
	}
	p, err := rp.Discover(ctx, hc, issuer)
	if err != nil {
		return "", err
	}
	// aud is the token endpoint (RFC 7523 3), which bridge takes, or its issuer.
	assertion, err := clientAssertion(key, alg, kid, clientID, p.TokenURL, time.Now())
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"kerberos"},
		"client_id":             {clientID},
		"client_assertion_type": {assertionType},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", httpError("the provider refused this machine", resp)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "bearer") {
		return "", errors.New("the provider's answer carries no bearer token")
	}
	return tok.AccessToken, nil
}

// publicJWKS is the JWK Set a provider registers for a machine key (bridge's
// client block: jwks = <<EOT ... EOT).
func publicJWKS(key crypto.Signer, alg, kid string) ([]byte, error) {
	var jwk map[string]string
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		pub, err := k.PublicKey.ECDH()
		if err != nil {
			return nil, err
		}
		raw := pub.Bytes() // 0x04 || X || Y
		if pub.Curve() != ecdh.P256() || len(raw) != 65 {
			return nil, errors.New("not a P-256 key")
		}
		jwk = map[string]string{"kty": "EC", "crv": "P-256", "x": b64(raw[1:33]), "y": b64(raw[33:])}
	case ed25519.PrivateKey:
		jwk = map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64(k.Public().(ed25519.PublicKey))}
	default:
		return nil, errors.New("unsupported key")
	}
	jwk["use"], jwk["alg"], jwk["kid"] = "sig", alg, kid
	return json.MarshalIndent(map[string]any{"keys": []any{jwk}}, "", "  ")
}
